//! LAN inventory views: filtering, segment grouping, device history, and
//! change reports.
//!
//! Change events are derived from per-session snapshots. They are deliberately
//! conservative: a device absent from a scan is `not_observed`, not offline, and
//! scans are only compared when their interface and target match.

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::application::model::{DeviceHistoryEntry, SegmentRecord, SessionRecord, SessionStatus};
use crate::domain::{
    ChangeContext, DEFAULT_STALE_AFTER_MS, DeviceChange, DeviceSummary, Freshness,
    IdentifierRecord, detect_changes,
};
use crate::infrastructure::storage::{StorageError, Store};

#[derive(Debug, Clone)]
pub struct DeviceFilter {
    pub search: Option<String>,
    pub segment: Option<IpNet>,
    pub stale_only: bool,
    pub stale_after_ms: i64,
}

impl Default for DeviceFilter {
    fn default() -> Self {
        Self {
            search: None,
            segment: None,
            stale_only: false,
            stale_after_ms: DEFAULT_STALE_AFTER_MS,
        }
    }
}

impl DeviceFilter {
    pub fn is_active(&self) -> bool {
        self.search.is_some() || self.segment.is_some() || self.stale_only
    }

    pub fn matches(&self, device: &DeviceSummary) -> bool {
        if self.stale_only && !device.freshness.is_stale() {
            return false;
        }
        if let Some(segment) = self.segment
            && !latest_ip(device).is_some_and(|ip| segment.contains(&ip))
        {
            return false;
        }
        if let Some(search) = &self.search {
            let needle = search.trim().to_lowercase();
            if !needle.is_empty() {
                let haystack = search_haystack(device);
                if !haystack.contains(&needle) {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentView {
    pub id: Uuid,
    pub interface: String,
    pub prefix: IpNet,
    pub gateway: Option<IpAddr>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub freshness: Freshness,
    pub devices: Vec<DeviceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMap {
    pub segments: Vec<SegmentView>,
    /// Devices whose most recent address does not fall inside a known segment.
    pub unassigned: Vec<DeviceSummary>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeReport {
    pub current: SessionRecord,
    pub previous: Option<SessionRecord>,
    pub comparable: bool,
    pub note: Option<String>,
    pub events: Vec<DeviceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHistory {
    pub summary: DeviceSummary,
    pub identifiers: Vec<IdentifierRecord>,
    pub sessions: Vec<DeviceHistoryEntry>,
    pub changes: Vec<DeviceChange>,
    pub note: Option<String>,
}

/// Load devices, apply filters, and recompute freshness at the requested
/// threshold.
pub fn list_devices(
    store: &Store,
    filter: &DeviceFilter,
    now_ms: i64,
) -> Result<Vec<DeviceSummary>, StorageError> {
    let mut devices = store.list_devices_at(None, now_ms)?;
    for device in &mut devices {
        device.freshness = Freshness::new(device.last_seen_ms, now_ms, filter.stale_after_ms);
    }
    devices.retain(|device| filter.matches(device));
    Ok(devices)
}

/// Group devices by the known IP segment containing their most recent address.
pub fn build_map(
    store: &Store,
    interface: Option<&str>,
    now_ms: i64,
) -> Result<SegmentMap, StorageError> {
    let segments: Vec<SegmentRecord> = store
        .list_segments()?
        .into_iter()
        .filter(|segment| interface.is_none_or(|name| segment.interface == name))
        .collect();
    let devices = store.list_devices_at(None, now_ms)?;

    let mut by_segment: HashMap<Uuid, Vec<DeviceSummary>> = HashMap::new();
    let mut unassigned = Vec::new();
    for device in devices {
        let Some(ip) = latest_ip(&device) else {
            unassigned.push(device);
            continue;
        };
        let matching = segments
            .iter()
            .filter(|segment| segment.prefix.contains(&ip))
            .max_by_key(|segment| segment.prefix.prefix_len());
        match matching {
            Some(segment) => by_segment.entry(segment.id).or_default().push(device),
            None => unassigned.push(device),
        }
    }

    let mut views = Vec::new();
    for segment in segments {
        let mut devices = by_segment.remove(&segment.id).unwrap_or_default();
        devices.sort_by(|left, right| {
            latest_ip(left)
                .cmp(&latest_ip(right))
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        views.push(SegmentView {
            id: segment.id,
            interface: segment.interface,
            prefix: segment.prefix,
            gateway: segment.gateway,
            first_seen_ms: segment.first_seen_ms,
            last_seen_ms: segment.last_seen_ms,
            freshness: Freshness::new(segment.last_seen_ms, now_ms, DEFAULT_STALE_AFTER_MS),
            devices,
        });
    }
    views.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.prefix.to_string().cmp(&right.prefix.to_string()))
    });

    unassigned.sort_by(|left, right| {
        latest_ip(left)
            .cmp(&latest_ip(right))
            .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
    });

    Ok(SegmentMap {
        segments: views,
        unassigned,
        note: "Segment grouping is derived from IP prefixes. It is logical inventory, not proof of physical switch, access-point, or VLAN topology.".to_string(),
    })
}

/// Compare a session with the most recent earlier scan of the same interface
/// and target.
pub fn changes_for_session(
    store: &Store,
    session_id: Option<Uuid>,
) -> Result<Option<ChangeReport>, StorageError> {
    let current = match session_id {
        Some(id) => store.get_session(id)?,
        None => store.latest_session()?,
    };
    let Some(current) = current else {
        return Ok(None);
    };

    if !current.status.is_comparable() {
        return Ok(Some(ChangeReport {
            previous: None,
            comparable: false,
            note: Some(format!(
                "The current session is {}; change comparison requires a completed or partial scan.",
                current.status.as_str()
            )),
            events: Vec::new(),
            current,
        }));
    }

    let previous = store.list_sessions()?.into_iter().find(|candidate| {
        candidate.id != current.id
            && candidate.started_at_ms < current.started_at_ms
            && candidate.status.is_comparable()
            && same_scope(candidate, &current)
    });

    let Some(previous) = previous else {
        return Ok(Some(ChangeReport {
            current,
            previous: None,
            comparable: false,
            note: Some(
                "No earlier completed or partial scan with the same interface and target was found; change comparison is unavailable."
                    .to_string(),
            ),
            events: Vec::new(),
        }));
    };

    let previous_snapshots = store.load_session_snapshots(previous.id)?;
    let current_snapshots = store.load_session_snapshots(current.id)?;
    if previous_snapshots.is_empty() || current_snapshots.is_empty() {
        return Ok(Some(ChangeReport {
            current,
            previous: Some(previous),
            comparable: false,
            note: Some(
                "One of the compared sessions has no inventory snapshots. Snapshots are recorded from the Phase 3 schema onward; older sessions cannot be compared."
                    .to_string(),
            ),
            events: Vec::new(),
        }));
    }

    let partial_scan =
        previous.status == SessionStatus::Partial || current.status == SessionStatus::Partial;
    let context = ChangeContext {
        previous_session_id: previous.id,
        current_session_id: current.id,
        observed_at_ms: current.started_at_ms,
        include_not_observed: true,
        partial_scan,
    };
    let events = detect_changes(&context, &previous_snapshots, &current_snapshots);
    let note = partial_scan.then(|| {
        "One or both compared sessions were partial. Missing devices or properties may be caused by a failed provider; absence is not proof that a device is offline."
            .to_string()
    });

    Ok(Some(ChangeReport {
        current,
        previous: Some(previous),
        comparable: true,
        note,
        events,
    }))
}

/// Load a device's per-session inventory history and derive changes between
/// consecutive recorded sessions.
pub fn device_history(
    store: &Store,
    device_id: Uuid,
    now_ms: i64,
) -> Result<Option<DeviceHistory>, StorageError> {
    let Some(detail) = store.get_device(device_id)? else {
        return Ok(None);
    };
    let sessions = store.load_device_history(device_id)?;
    let mut changes = Vec::new();
    for pair in sessions.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let context = ChangeContext {
            previous_session_id: previous.session.id,
            current_session_id: current.session.id,
            observed_at_ms: current.session.started_at_ms,
            include_not_observed: false,
            partial_scan: previous.session.status == SessionStatus::Partial
                || current.session.status == SessionStatus::Partial,
        };
        changes.extend(detect_changes(
            &context,
            std::slice::from_ref(&previous.snapshot),
            std::slice::from_ref(&current.snapshot),
        ));
    }

    let note = if sessions.is_empty() {
        Some(
            "No per-session inventory snapshot is recorded for this device yet. History begins with scans recorded after the Phase 3 schema migration."
                .to_string(),
        )
    } else {
        None
    };

    let mut summary = detail.summary;
    summary.freshness = Freshness::new(summary.last_seen_ms, now_ms, DEFAULT_STALE_AFTER_MS);
    Ok(Some(DeviceHistory {
        summary,
        identifiers: detail.identifiers,
        sessions,
        changes,
        note,
    }))
}

fn same_scope(left: &SessionRecord, right: &SessionRecord) -> bool {
    left.scope.interface == right.scope.interface && left.scope.target == right.scope.target
}

fn latest_ip(device: &DeviceSummary) -> Option<IpAddr> {
    device
        .ips
        .iter()
        .find_map(|value| value.parse::<IpAddr>().ok())
}

fn search_haystack(device: &DeviceSummary) -> String {
    let mut parts = Vec::new();
    if let Some(label) = &device.label {
        parts.push(label.clone());
    }
    parts.extend(device.ips.iter().cloned());
    parts.extend(device.macs.iter().cloned());
    parts.extend(device.hostnames.iter().cloned());
    parts.push(device.manufacturer.display_value());
    parts.push(device.category.display_value());
    parts.push(device.os.display_value());
    parts.push(device.model.display_value());
    parts.join(" ").to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{DeviceFilter, build_map, changes_for_session, device_history};
    use crate::application::identify;
    use crate::application::identity;
    use crate::application::model::{
        DiscoveryMethod, ExistingDevice, ScanConfig, ScanResult, ScanScope, SessionStatus,
    };
    use crate::domain::{
        HostObservation, HostProbe, InterfaceAddress, InterfaceInfo, NetworkContext, Source,
        ids::new_id,
    };
    use crate::infrastructure::storage::Store;

    fn scan(
        session_id: uuid::Uuid,
        started_at_ms: i64,
        target: &str,
        ip: &str,
        mac: &str,
        existing: &[ExistingDevice],
    ) -> ScanResult {
        let ip: IpAddr = ip.parse().unwrap();
        let mac = mac.parse().unwrap();
        let probe = HostProbe::neighbor(
            ip,
            Some(mac),
            Some("reachable".into()),
            Some("eth0"),
            started_at_ms,
        );
        let host = HostObservation {
            ip,
            interface: Some("eth0".into()),
            segment: None,
            mac: Some(mac),
            neighbor_state: Some("reachable".into()),
            icmp_rtt_ms: None,
            tcp: Vec::new(),
            hostname: None,
            first_seen_ms: started_at_ms,
            last_seen_ms: started_at_ms,
            sources: vec![Source::NeighborTable],
            probes: vec![probe],
        };
        let resolved = identity::resolve(
            std::slice::from_ref(&host),
            existing,
            started_at_ms,
            identity::DEFAULT_MAC_WINDOW_MS,
        );
        let identification = identify::identify(
            session_id,
            &resolved.devices,
            &[],
            "test",
            &identify::ProviderAvailability::default(),
            started_at_ms,
        );
        ScanResult {
            session_id,
            started_at_ms,
            finished_at_ms: started_at_ms + 10,
            status: SessionStatus::Completed,
            scope: ScanScope {
                interface: Some("eth0".into()),
                target: Some(target.to_string()),
                candidate_count: 254,
                discovered_count: 1,
            },
            config: ScanConfig {
                timeout_ms: 1_000,
                dns_timeout_ms: 1_500,
                mdns_window_ms: 3_000,
                concurrency: 4,
                max_hosts: 1_024,
                service_ports: vec![22, 80],
                methods: vec![DiscoveryMethod::Neighbor],
            },
            context: NetworkContext {
                interfaces: Vec::new(),
                routes: Vec::new(),
                neighbors: Vec::new(),
                default_interface: None,
                default_gateway: None,
                warnings: Vec::new(),
                captured_at_ms: started_at_ms,
            },
            hosts: vec![host],
            devices: resolved.devices,
            services: Vec::new(),
            observations: identification.observations,
            evidence: identification.evidence,
            inferences: identification.inferences,
            identity_links: resolved.links,
            provider_reports: Vec::new(),
        }
    }

    #[test]
    fn compares_matching_scopes_and_ignores_other_targets() {
        let mut store = Store::open_in_memory().unwrap();
        let first = scan(
            new_id(),
            1_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &[],
        );
        store.save_scan(&first).unwrap();
        let existing = store
            .load_existing_devices(2_000, identity::DEFAULT_MAC_WINDOW_MS)
            .unwrap();
        let other = scan(
            new_id(),
            2_000,
            "10.0.0.0/24",
            "10.0.0.10",
            "00:11:22:33:44:55",
            &existing,
        );
        store.save_scan(&other).unwrap();
        let existing = store
            .load_existing_devices(3_000, identity::DEFAULT_MAC_WINDOW_MS)
            .unwrap();
        let second = scan(
            new_id(),
            3_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &existing,
        );
        store.save_scan(&second).unwrap();

        let report = changes_for_session(&store, Some(second.session_id))
            .unwrap()
            .unwrap();
        assert!(report.comparable);
        assert_eq!(report.previous.unwrap().id, first.session_id);
        assert!(report.events.is_empty());
    }

    #[test]
    fn reports_new_device_profiles_and_not_observed_profiles() {
        let mut store = Store::open_in_memory().unwrap();
        let first = scan(
            new_id(),
            1_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &[],
        );
        store.save_scan(&first).unwrap();
        let existing = store
            .load_existing_devices(3_000, identity::DEFAULT_MAC_WINDOW_MS)
            .unwrap();
        let second = scan(
            new_id(),
            3_000,
            "192.168.1.0/24",
            "192.168.1.11",
            "00:11:22:33:44:66",
            &existing,
        );
        store.save_scan(&second).unwrap();

        let report = changes_for_session(&store, None).unwrap().unwrap();
        assert!(report.comparable);
        let kinds: Vec<_> = report
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect();
        assert!(kinds.contains(&"new_device"));
        assert!(kinds.contains(&"not_observed"));
    }

    #[test]
    fn device_history_and_filters_work() {
        let mut store = Store::open_in_memory().unwrap();
        let first = scan(
            new_id(),
            1_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &[],
        );
        let device_id = first.devices[0].id;
        store.save_scan(&first).unwrap();
        let existing = store
            .load_existing_devices(3_000, identity::DEFAULT_MAC_WINDOW_MS)
            .unwrap();
        let second = scan(
            new_id(),
            3_000,
            "192.168.1.0/24",
            "192.168.1.11",
            "00:11:22:33:44:55",
            &existing,
        );
        store.save_scan(&second).unwrap();

        let history = device_history(&store, device_id, 4_000).unwrap().unwrap();
        assert_eq!(history.sessions.len(), 2);
        assert!(
            history
                .changes
                .iter()
                .any(|event| event.kind.as_str() == "ip_changed")
        );

        let filter = DeviceFilter {
            search: Some("192.168.1.11".to_string()),
            ..DeviceFilter::default()
        };
        let devices = super::list_devices(&store, &filter, 4_000).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, device_id);
    }

    #[test]
    fn map_groups_devices_by_longest_matching_segment() {
        let mut store = Store::open_in_memory().unwrap();
        let mut scan = scan(
            new_id(),
            1_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &[],
        );
        scan.context.interfaces.push(InterfaceInfo {
            name: "eth0".to_string(),
            index: 1,
            mac: None,
            mtu: Some(1_500),
            is_up: true,
            is_loopback: false,
            oper_state: Some("up".to_string()),
            addresses: vec![InterfaceAddress {
                address: "192.168.1.1".parse().unwrap(),
                prefix_len: 24,
                family: 4,
                scope: Some("global".to_string()),
            }],
        });
        scan.context.default_interface = Some("eth0".to_string());
        scan.context.default_gateway = Some("192.168.1.1".parse().unwrap());
        store.save_scan(&scan).unwrap();

        let map = build_map(&store, None, 2_000).unwrap();
        assert_eq!(map.segments.len(), 1);
        assert_eq!(
            map.segments[0].prefix,
            "192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()
        );
        assert_eq!(map.segments[0].devices.len(), 1);
        assert!(map.unassigned.is_empty());
    }

    #[test]
    fn map_without_segments_marks_devices_unassigned() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = scan(
            new_id(),
            1_000,
            "192.168.1.0/24",
            "192.168.1.10",
            "00:11:22:33:44:55",
            &[],
        );
        store.save_scan(&scan).unwrap();
        let map = build_map(&store, None, 2_000).unwrap();
        assert!(map.segments.is_empty());
        assert_eq!(map.unassigned.len(), 1);
    }
}
