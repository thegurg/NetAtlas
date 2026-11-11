//! Logical device identity resolution.
//!
//! Rules implemented here (see `docs/data-model.md` section 3):
//!
//! - A globally administered MAC observed within the freshness window links to
//!   the device that last held it.
//! - A locally administered MAC is weak evidence and never merges devices on
//!   its own; an uncertain link is recorded instead.
//! - An IP address never merges devices. Reuse produces a separate device, an
//!   `address_reuse_suspected` observation, and an uncertain link.
//! - Hostnames never merge devices on their own.
//! - Ambiguous MAC matches keep the most recently seen device and record
//!   uncertain links to the competing devices.
//!
//! This module is pure: it accepts observations and stored devices, and returns
//! the resolved devices, links, and any address-reuse observations.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use crate::application::model::{ExistingDevice, ResolvedDevice};
use crate::domain::{
    Confidence, HostObservation, HostProbe, IdentifierKind, IdentifierRecord, IdentityLink,
    LinkStatus, MacAddress, ProtocolObservation, Source, ids::new_id,
};

/// Default window in which a MAC address is considered the same device.
pub const DEFAULT_MAC_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;

/// Default window in which an IP address is still considered a previous holder.
pub const DEFAULT_IP_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone)]
pub struct IdentityResolution {
    pub devices: Vec<ResolvedDevice>,
    pub links: Vec<IdentityLink>,
    /// Address-reuse observations, paired with the new device they describe.
    pub reuse_probes: Vec<(Uuid, HostProbe)>,
}

/// Resolve observed hosts into logical devices.
pub fn resolve(
    hosts: &[HostObservation],
    existing: &[ExistingDevice],
    now_ms: i64,
    mac_window_ms: i64,
) -> IdentityResolution {
    let existing_by_id: HashMap<Uuid, &ExistingDevice> =
        existing.iter().map(|device| (device.id, device)).collect();
    let mut builders: BTreeMap<Uuid, DeviceBuilder> = BTreeMap::new();
    let mut links = Vec::new();
    let mut reuse_probes = Vec::new();
    let mut mac_to_device: HashMap<MacAddress, Uuid> = HashMap::new();
    let mut strong_to_device: HashMap<(IdentifierKind, String), Uuid> = HashMap::new();

    for host in hosts {
        let device_id = select_device(
            host,
            existing,
            now_ms,
            mac_window_ms,
            &strong_to_device,
            &mac_to_device,
            &mut links,
        );
        if let Some(mac) = host.mac {
            mac_to_device.insert(mac, device_id);
        }
        for identifier in strong_identifiers(host) {
            strong_to_device.insert(identifier, device_id);
        }

        record_address_reuse(
            host,
            device_id,
            existing,
            now_ms,
            &mut links,
            &mut reuse_probes,
        );

        let builder = builders.entry(device_id).or_insert_with(|| {
            existing_by_id
                .get(&device_id)
                .map(|device| DeviceBuilder::from_existing(device))
                .unwrap_or_else(|| DeviceBuilder::new(device_id, host))
        });
        builder.add_host(host);
        builder.add_identifiers(host);
    }

    let devices = builders
        .into_values()
        .map(|builder| builder.finish(&existing_by_id))
        .collect();

    IdentityResolution {
        devices,
        links,
        reuse_probes,
    }
}

fn select_device(
    host: &HostObservation,
    existing: &[ExistingDevice],
    now_ms: i64,
    mac_window_ms: i64,
    strong_to_device: &HashMap<(IdentifierKind, String), Uuid>,
    mac_to_device: &HashMap<MacAddress, Uuid>,
    links: &mut Vec<IdentityLink>,
) -> Uuid {
    let strong = strong_identifiers(host);

    // A strong identifier observed on two addresses in this same scan is one
    // device. UPnP UDNs and mDNS instance names are self-reported, but they are
    // considerably more stable than an IP address and more specific than a
    // hostname.
    for identifier in &strong {
        if let Some(device_id) = strong_to_device.get(identifier) {
            return *device_id;
        }
    }

    // Match strong identifiers against stored devices before falling back to a
    // MAC address. This keeps a device linked when a randomized MAC changes but
    // its UPnP UDN or mDNS instance name remains the same.
    let mut strong_matches: Vec<(Uuid, &'static str)> = Vec::new();
    for (kind, value) in &strong {
        for device in existing {
            let found = match kind {
                IdentifierKind::UpnpUdn => device.upnp_udns.iter().any(|(candidate, last_seen)| {
                    candidate == value && *last_seen >= now_ms - mac_window_ms
                }),
                IdentifierKind::MdnsInstance => {
                    device.mdns_instances.iter().any(|(candidate, last_seen)| {
                        candidate == value && *last_seen >= now_ms - mac_window_ms
                    })
                }
                _ => false,
            };
            if found && !strong_matches.iter().any(|(id, _)| *id == device.id) {
                strong_matches.push((device.id, kind.as_str()));
            }
        }
    }

    if let Some((chosen, _)) = strong_matches.first() {
        let chosen = *chosen;
        for (other, basis) in &strong_matches[1..] {
            if *other != chosen {
                links.push(uncertain_link(
                    chosen,
                    *other,
                    "strong_identifier_conflict",
                    Confidence::Medium,
                    format!(
                        "Different strong identifiers ({basis}) matched different stored devices. The devices were kept separate and the competing match was recorded as uncertain."
                    ),
                    now_ms,
                ));
            }
        }

        // A strong identifier and a MAC address disagreeing about the device is
        // also a conflict. The strong identifier wins, but the competing MAC
        // match is preserved instead of being silently discarded.
        if let Some(mac) = host.mac {
            for device in existing.iter().filter(|device| {
                device.id != chosen
                    && device.macs.iter().any(|(candidate, last_seen)| {
                        *candidate == mac && *last_seen >= now_ms - mac_window_ms
                    })
            }) {
                links.push(uncertain_link(
                    chosen,
                    device.id,
                    "strong_identifier_conflict",
                    Confidence::Medium,
                    "A strong protocol identifier matched this device, but its MAC address matched a different stored device. The strong identifier was preferred and the MAC conflict was preserved.",
                    now_ms,
                ));
            }
        }
        return chosen;
    }

    let Some(mac) = host.mac else {
        return new_id();
    };

    // A MAC observed on two addresses in this same scan is one device.
    if let Some(device_id) = mac_to_device.get(&mac) {
        return *device_id;
    }

    let matches: Vec<&ExistingDevice> = existing
        .iter()
        .filter(|device| {
            device.macs.iter().any(|(candidate, last_seen)| {
                *candidate == mac && *last_seen >= now_ms - mac_window_ms
            })
        })
        .collect();

    if mac.is_locally_administered() {
        // Local MACs can be randomized by clients and assigned by hypervisors.
        // Without a strong corroborating identifier they must not merge.
        let device_id = new_id();
        if let Some(previous) = matches.iter().max_by_key(|device| device.last_seen_ms) {
            links.push(uncertain_link(
                device_id,
                previous.id,
                "locally_administered_mac",
                Confidence::Low,
                "The locally administered MAC matches a previously seen device, but this kind of address is weak identity evidence; the devices were kept separate.",
                now_ms,
            ));
        }
        return device_id;
    }

    match matches.len() {
        0 => new_id(),
        1 => matches[0].id,
        _ => {
            let chosen = matches
                .iter()
                .max_by_key(|device| device.last_seen_ms)
                .copied();
            let Some(chosen) = chosen else {
                return new_id();
            };
            for other in matches.iter().filter(|device| device.id != chosen.id) {
                links.push(uncertain_link(
                    chosen.id,
                    other.id,
                    "ambiguous_mac",
                    Confidence::Low,
                    "The same MAC matched more than one stored device. The most recently seen device was reused and the competing matches were recorded as uncertain links.",
                    now_ms,
                ));
            }
            chosen.id
        }
    }
}

/// Extract normalized strong identifiers from a host's protocol probes.
fn strong_identifiers(host: &HostObservation) -> Vec<(IdentifierKind, String)> {
    let mut identifiers = Vec::new();
    for probe in &host.probes {
        match &probe.protocol {
            Some(ProtocolObservation::Upnp(device)) => {
                if let Some(udn) = &device.udn {
                    let normalized = normalize_udn(udn);
                    if !normalized.is_empty() {
                        identifiers.push((IdentifierKind::UpnpUdn, normalized));
                    }
                }
            }
            Some(ProtocolObservation::Mdns(service)) => {
                let normalized = normalize_mdns_instance(&service.fullname);
                if !normalized.is_empty() {
                    identifiers.push((IdentifierKind::MdnsInstance, normalized));
                }
            }
            _ => {}
        }
    }
    identifiers.sort_by(|left, right| {
        left.0
            .as_str()
            .cmp(right.0.as_str())
            .then_with(|| left.1.cmp(&right.1))
    });
    identifiers.dedup();
    identifiers
}

pub(crate) fn normalize_udn(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("uuid:")
        .trim()
        .to_ascii_lowercase()
}

pub(crate) fn normalize_mdns_instance(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn record_address_reuse(
    host: &HostObservation,
    device_id: Uuid,
    existing: &[ExistingDevice],
    now_ms: i64,
    links: &mut Vec<IdentityLink>,
    reuse_probes: &mut Vec<(Uuid, HostProbe)>,
) {
    let holders: Vec<&ExistingDevice> = existing
        .iter()
        .filter(|device| device.id != device_id)
        .filter(|device| {
            device.ips.iter().any(|(ip, last_seen)| {
                *ip == host.ip && *last_seen >= now_ms - DEFAULT_IP_WINDOW_MS
            })
        })
        .collect();

    if holders.is_empty() {
        return;
    }

    match host.mac {
        Some(observed_mac) => {
            for holder in holders {
                if holder.macs.iter().any(|(mac, _)| *mac == observed_mac) {
                    continue;
                }
                let previous_mac = holder
                    .macs
                    .iter()
                    .max_by_key(|(_, last_seen)| *last_seen)
                    .map(|(mac, _)| *mac);
                reuse_probes.push((
                    device_id,
                    HostProbe::address_reuse(host.ip, previous_mac, observed_mac, now_ms),
                ));
                links.push(uncertain_link(
                    device_id,
                    holder.id,
                    "address_reuse",
                    Confidence::Medium,
                    format!(
                        "{} was previously associated with another device. The IP address is not a device identity, so the devices were kept separate.",
                        host.ip
                    ),
                    now_ms,
                ));
            }
        }
        None => {
            if let Some(holder) = holders.iter().max_by_key(|device| device.last_seen_ms) {
                links.push(uncertain_link(
                    device_id,
                    holder.id,
                    "ip_only",
                    Confidence::Low,
                    format!(
                        "{} matches a stored device address, but no MAC was observed. IP alone never merges devices.",
                        host.ip
                    ),
                    now_ms,
                ));
            }
        }
    }
}

fn uncertain_link(
    from_device_id: Uuid,
    to_device_id: Uuid,
    basis: &str,
    confidence: Confidence,
    rationale: impl Into<String>,
    now_ms: i64,
) -> IdentityLink {
    IdentityLink {
        id: new_id(),
        from_device_id,
        to_device_id,
        basis: basis.to_string(),
        confidence,
        status: LinkStatus::Uncertain,
        rationale: rationale.into(),
        created_at_ms: now_ms,
    }
}

struct DeviceBuilder {
    id: Uuid,
    label: Option<String>,
    first_seen_ms: i64,
    last_seen_ms: i64,
    is_new: bool,
    identifiers: Vec<IdentifierRecord>,
    hosts: Vec<HostObservation>,
    mac_values: HashSet<String>,
    ip_values: HashSet<String>,
    hostname_values: HashSet<String>,
    extra_values: HashSet<(IdentifierKind, String)>,
}

impl DeviceBuilder {
    fn new(id: Uuid, host: &HostObservation) -> Self {
        Self {
            id,
            label: None,
            first_seen_ms: host.first_seen_ms,
            last_seen_ms: host.last_seen_ms,
            is_new: true,
            identifiers: Vec::new(),
            hosts: Vec::new(),
            mac_values: HashSet::new(),
            ip_values: HashSet::new(),
            hostname_values: HashSet::new(),
            extra_values: HashSet::new(),
        }
    }

    fn from_existing(device: &ExistingDevice) -> Self {
        Self {
            id: device.id,
            label: device.label.clone(),
            first_seen_ms: device.first_seen_ms,
            last_seen_ms: device.last_seen_ms,
            is_new: false,
            identifiers: Vec::new(),
            hosts: Vec::new(),
            mac_values: HashSet::new(),
            ip_values: HashSet::new(),
            hostname_values: HashSet::new(),
            extra_values: HashSet::new(),
        }
    }

    fn add_host(&mut self, host: &HostObservation) {
        self.first_seen_ms = self.first_seen_ms.min(host.first_seen_ms);
        self.last_seen_ms = self.last_seen_ms.max(host.last_seen_ms);
        self.hosts.push(host.clone());
    }

    fn add_identifiers(&mut self, host: &HostObservation) {
        if let Some(mac) = host.mac {
            let normalized = mac.to_string();
            if self.mac_values.insert(normalized.clone()) {
                let confidence = if mac.is_locally_administered() {
                    Confidence::Low
                } else {
                    Confidence::High
                };
                self.identifiers.push(IdentifierRecord {
                    id: new_id(),
                    device_id: self.id,
                    kind: IdentifierKind::Mac,
                    value: normalized.clone(),
                    normalized,
                    source: Source::NeighborTable,
                    first_seen_ms: host.first_seen_ms,
                    last_seen_ms: host.last_seen_ms,
                    confidence,
                    details: json!({
                        "locally_administered": mac.is_locally_administered(),
                        "note": "a MAC address is an identifier, not a permanent device identity",
                    }),
                });
            }
        }

        let normalized_ip = host.ip.to_string();
        if self.ip_values.insert(normalized_ip.clone()) {
            self.identifiers.push(IdentifierRecord {
                id: new_id(),
                device_id: self.id,
                kind: IdentifierKind::Ip,
                value: normalized_ip.clone(),
                normalized: normalized_ip,
                source: presence_source(host),
                first_seen_ms: host.first_seen_ms,
                last_seen_ms: host.last_seen_ms,
                confidence: Confidence::Medium,
                details: json!({
                    "interface": host.interface,
                    "segment": host.segment.map(|segment| segment.to_string()),
                    "note": "an IP address is a current identifier; it is never sufficient to merge devices",
                }),
            });
        }

        if let Some(hostname) = &host.hostname {
            let normalized = hostname
                .name
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !normalized.is_empty() && self.hostname_values.insert(normalized.clone()) {
                self.identifiers.push(IdentifierRecord {
                    id: new_id(),
                    device_id: self.id,
                    kind: IdentifierKind::DnsName,
                    value: hostname.name.clone(),
                    normalized,
                    source: hostname.source,
                    first_seen_ms: hostname.observed_at_ms,
                    last_seen_ms: hostname.observed_at_ms,
                    confidence: Confidence::Low,
                    details: json!({
                        "note": "reverse DNS is a naming hint, not a verified identity",
                    }),
                });
            }
        }

        for probe in &host.probes {
            match &probe.protocol {
                Some(ProtocolObservation::Upnp(device)) => {
                    if let Some(udn) = &device.udn {
                        let normalized = normalize_udn(udn);
                        if !normalized.is_empty()
                            && self
                                .extra_values
                                .insert((IdentifierKind::UpnpUdn, normalized.clone()))
                        {
                            self.identifiers.push(IdentifierRecord {
                                id: new_id(),
                                device_id: self.id,
                                kind: IdentifierKind::UpnpUdn,
                                value: udn.clone(),
                                normalized,
                                source: Source::Ssdp,
                                first_seen_ms: probe.observed_at_ms,
                                last_seen_ms: probe.observed_at_ms,
                                confidence: Confidence::High,
                                details: json!({
                                    "location": device.location,
                                    "friendly_name": device.friendly_name,
                                    "model_name": device.model_name,
                                    "note": "a UPnP UDN is self-reported but is intended to be stable across addresses",
                                }),
                            });
                        }
                    }
                }
                Some(ProtocolObservation::Mdns(service)) => {
                    let normalized = normalize_mdns_instance(&service.fullname);
                    if !normalized.is_empty()
                        && self
                            .extra_values
                            .insert((IdentifierKind::MdnsInstance, normalized.clone()))
                    {
                        self.identifiers.push(IdentifierRecord {
                            id: new_id(),
                            device_id: self.id,
                            kind: IdentifierKind::MdnsInstance,
                            value: service.fullname.clone(),
                            normalized,
                            source: Source::Mdns,
                            first_seen_ms: probe.observed_at_ms,
                            last_seen_ms: probe.observed_at_ms,
                            confidence: Confidence::Medium,
                            details: json!({
                                "service_type": service.service_type,
                                "host": service.host,
                                "port": service.port,
                                "note": "an mDNS instance name is self-published and can change when the device is renamed",
                            }),
                        });
                    }

                    let host_normalized = service
                        .host
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if !host_normalized.is_empty()
                        && self.hostname_values.insert(host_normalized.clone())
                    {
                        self.identifiers.push(IdentifierRecord {
                            id: new_id(),
                            device_id: self.id,
                            kind: IdentifierKind::DnsName,
                            value: service.host.clone(),
                            normalized: host_normalized,
                            source: Source::Mdns,
                            first_seen_ms: probe.observed_at_ms,
                            last_seen_ms: probe.observed_at_ms,
                            confidence: Confidence::Low,
                            details: json!({
                                "note": "mDNS host names are self-published and are not used to merge devices on their own",
                            }),
                        });
                    }
                }
                Some(ProtocolObservation::Netbios(name)) => {
                    let normalized = name.name.trim().to_ascii_lowercase();
                    if !normalized.is_empty()
                        && self
                            .extra_values
                            .insert((IdentifierKind::NetbiosName, normalized.clone()))
                    {
                        self.identifiers.push(IdentifierRecord {
                            id: new_id(),
                            device_id: self.id,
                            kind: IdentifierKind::NetbiosName,
                            value: name.name.clone(),
                            normalized,
                            source: Source::Netbios,
                            first_seen_ms: probe.observed_at_ms,
                            last_seen_ms: probe.observed_at_ms,
                            confidence: Confidence::Low,
                            details: json!({
                                "suffix": name.suffix,
                                "group": name.group,
                                "note": "a NetBIOS name is a legacy naming claim and is never used to merge devices on its own",
                            }),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    fn finish(self, existing_by_id: &HashMap<Uuid, &ExistingDevice>) -> ResolvedDevice {
        let existing = existing_by_id.get(&self.id);
        ResolvedDevice {
            id: self.id,
            label: self.label,
            identifiers: self.identifiers,
            hosts: self.hosts,
            first_seen_ms: existing
                .map(|device| device.first_seen_ms)
                .unwrap_or(self.first_seen_ms),
            last_seen_ms: existing
                .map(|device| device.last_seen_ms.max(self.last_seen_ms))
                .unwrap_or(self.last_seen_ms),
            is_new: self.is_new,
        }
    }
}

fn presence_source(host: &HostObservation) -> Source {
    if host.icmp_rtt_ms.is_some() {
        Source::IcmpEcho
    } else if host.tcp.iter().any(|probe| probe.outcome.is_presence()) {
        Source::TcpProbe
    } else {
        Source::NeighborTable
    }
}

/// Convenience for tests and callers that only need the current address.
pub fn primary_ip(device: &ResolvedDevice) -> Option<IpAddr> {
    device.hosts.first().map(|host| host.ip)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use serde_json::json;

    use super::resolve;
    use crate::application::model::ExistingDevice;
    use crate::domain::{
        Confidence, HostObservation, HostProbe, IdentifierKind, LinkStatus, MacAddress,
        MdnsServiceObservation, Source, UpnpObservation,
    };

    fn mac(value: &str) -> MacAddress {
        value.parse().unwrap()
    }

    fn host(ip: &str, mac: Option<MacAddress>) -> HostObservation {
        let ip: IpAddr = ip.parse().unwrap();
        let probe =
            HostProbe::neighbor(ip, mac, Some("reachable".to_string()), Some("eth0"), 1_000);
        HostObservation {
            ip,
            interface: Some("eth0".to_string()),
            segment: None,
            mac,
            neighbor_state: Some("reachable".to_string()),
            icmp_rtt_ms: None,
            tcp: Vec::new(),
            hostname: None,
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            sources: vec![Source::NeighborTable],
            probes: vec![probe],
        }
    }

    fn existing(mac_value: &str, ip: &str) -> ExistingDevice {
        ExistingDevice {
            id: uuid::Uuid::now_v7(),
            label: None,
            first_seen_ms: 500,
            last_seen_ms: 900,
            macs: vec![(mac(mac_value), 900)],
            ips: vec![(ip.parse().unwrap(), 900)],
            hostnames: Vec::new(),
            upnp_udns: Vec::new(),
            mdns_instances: Vec::new(),
        }
    }

    #[test]
    fn same_mac_new_ip_keeps_device() {
        let previous = existing("00:11:22:33:44:55", "192.168.1.10");
        let resolved = resolve(
            &[host("192.168.1.11", Some(mac("00:11:22:33:44:55")))],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices.len(), 1);
        assert_eq!(resolved.devices[0].id, previous.id);
        assert!(!resolved.devices[0].is_new);
        assert!(
            resolved.devices[0]
                .identifiers
                .iter()
                .any(|identifier| identifier.kind == IdentifierKind::Ip
                    && identifier.value == "192.168.1.11")
        );
    }

    #[test]
    fn same_ip_different_mac_stays_separate_and_records_reuse() {
        let previous = existing("00:11:22:33:44:55", "192.168.1.10");
        let resolved = resolve(
            &[host("192.168.1.10", Some(mac("aa:bb:cc:dd:ee:ff")))],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices.len(), 1);
        assert_ne!(resolved.devices[0].id, previous.id);
        assert!(resolved.devices[0].is_new);
        assert_eq!(resolved.reuse_probes.len(), 1);
        assert!(
            resolved
                .links
                .iter()
                .any(|link| link.basis == "address_reuse" && link.status == LinkStatus::Uncertain)
        );
    }

    #[test]
    fn locally_administered_mac_does_not_merge() {
        let previous = existing("02:11:22:33:44:55", "192.168.1.10");
        let resolved = resolve(
            &[host("192.168.1.10", Some(mac("02:11:22:33:44:55")))],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_ne!(resolved.devices[0].id, previous.id);
        assert!(
            resolved
                .links
                .iter()
                .any(|link| link.basis == "locally_administered_mac")
        );
        let mac_identifier = resolved.devices[0]
            .identifiers
            .iter()
            .find(|identifier| identifier.kind == IdentifierKind::Mac)
            .unwrap();
        assert_eq!(mac_identifier.confidence, Confidence::Low);
        assert_eq!(
            mac_identifier.details,
            json!({
                "locally_administered": true,
                "note": "a MAC address is an identifier, not a permanent device identity",
            })
        );
    }

    #[test]
    fn one_mac_on_two_ips_is_one_device() {
        let resolved = resolve(
            &[
                host("192.168.1.10", Some(mac("00:11:22:33:44:55"))),
                host("192.168.1.11", Some(mac("00:11:22:33:44:55"))),
            ],
            &[],
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices.len(), 1);
        assert_eq!(resolved.devices[0].hosts.len(), 2);
    }

    #[test]
    fn expired_mac_does_not_link() {
        let previous = existing("00:11:22:33:44:55", "192.168.1.10");
        let resolved = resolve(
            &[host("192.168.1.11", Some(mac("00:11:22:33:44:55")))],
            std::slice::from_ref(&previous),
            10_000_000,
            1_000,
        );
        assert_ne!(resolved.devices[0].id, previous.id);
    }

    #[test]
    fn ip_only_host_never_merges() {
        let previous = existing("00:11:22:33:44:55", "192.168.1.10");
        let resolved = resolve(
            &[host("192.168.1.10", None)],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_ne!(resolved.devices[0].id, previous.id);
        assert!(
            resolved
                .links
                .iter()
                .any(|link| link.basis == "ip_only" && link.status == LinkStatus::Uncertain)
        );
    }

    #[test]
    fn hostname_is_recorded_as_a_low_confidence_identifier() {
        let mut observation = host("192.168.1.10", Some(mac("00:11:22:33:44:55")));
        observation.hostname = Some(crate::domain::HostnameObservation {
            name: "printer.lan.".to_string(),
            source: Source::ReverseDns,
            observed_at_ms: 1_000,
        });
        let resolved = resolve(&[observation], &[], 2_000, super::DEFAULT_MAC_WINDOW_MS);
        let hostname = resolved.devices[0]
            .identifiers
            .iter()
            .find(|identifier| identifier.kind == IdentifierKind::DnsName)
            .unwrap();
        assert_eq!(hostname.normalized, "printer.lan");
        assert_eq!(hostname.confidence, Confidence::Low);
    }

    fn with_probe(mut observation: HostObservation, probe: HostProbe) -> HostObservation {
        observation.probes.push(probe);
        observation
    }

    fn upnp_probe(ip: &str, udn: &str) -> HostProbe {
        let ip: IpAddr = ip.parse().unwrap();
        HostProbe::upnp(
            ip,
            UpnpObservation {
                udn: Some(udn.to_string()),
                source_ip: ip,
                location: format!("http://{ip}:49152/desc.xml"),
                device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".to_string()),
                friendly_name: None,
                manufacturer: None,
                model_name: None,
                model_number: None,
                model_description: None,
                serial_number: None,
                source_unit: format!("ssdp:{udn}:description:test"),
            },
            1_000,
        )
    }

    fn mdns_probe(ip: &str, fullname: &str) -> HostProbe {
        let ip: IpAddr = ip.parse().unwrap();
        HostProbe::mdns(
            ip,
            MdnsServiceObservation {
                fullname: fullname.to_string(),
                service_type: "_airplay._tcp.local.".to_string(),
                host: "living-room.local.".to_string(),
                port: 7000,
                addresses: vec![ip],
                properties: std::collections::BTreeMap::new(),
                source_unit: format!("mdns:{fullname}"),
            },
            1_000,
        )
    }

    #[test]
    fn same_upnp_udn_on_two_ips_is_one_device() {
        let first = with_probe(
            host("192.168.1.10", None),
            upnp_probe("192.168.1.10", "uuid:1234"),
        );
        let second = with_probe(
            host("192.168.1.11", None),
            upnp_probe("192.168.1.11", "uuid:1234"),
        );
        let resolved = resolve(&[first, second], &[], 2_000, super::DEFAULT_MAC_WINDOW_MS);
        assert_eq!(resolved.devices.len(), 1);
        assert_eq!(resolved.devices[0].hosts.len(), 2);
        assert!(
            resolved.devices[0]
                .identifiers
                .iter()
                .any(|identifier| identifier.kind == IdentifierKind::UpnpUdn)
        );
    }

    #[test]
    fn upnp_udn_links_existing_device_across_mac_change() {
        let mut previous = existing("00:11:22:33:44:55", "192.168.1.10");
        previous.upnp_udns.push(("1234".to_string(), 900));
        let observation = with_probe(
            host("192.168.1.11", Some(mac("aa:bb:cc:dd:ee:ff"))),
            upnp_probe("192.168.1.11", "uuid:1234"),
        );
        let resolved = resolve(
            &[observation],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices.len(), 1);
        assert_eq!(resolved.devices[0].id, previous.id);
        assert!(!resolved.devices[0].is_new);
    }

    #[test]
    fn mdns_instance_links_existing_device() {
        let mut previous = existing("00:11:22:33:44:55", "192.168.1.10");
        previous
            .mdns_instances
            .push(("living room._airplay._tcp.local".to_string(), 900));
        let observation = with_probe(
            host("192.168.1.11", None),
            mdns_probe("192.168.1.11", "Living Room._airplay._tcp.local."),
        );
        let resolved = resolve(
            &[observation],
            std::slice::from_ref(&previous),
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices[0].id, previous.id);
    }

    #[test]
    fn strong_identifier_and_mac_conflict_is_preserved() {
        let mut udn_device = existing("00:11:22:33:44:55", "192.168.1.10");
        udn_device.upnp_udns.push(("1234".to_string(), 900));
        let mac_device = existing("aa:bb:cc:dd:ee:ff", "192.168.1.20");
        let observation = with_probe(
            host("192.168.1.30", Some(mac("aa:bb:cc:dd:ee:ff"))),
            upnp_probe("192.168.1.30", "uuid:1234"),
        );
        let resolved = resolve(
            &[observation],
            &[udn_device.clone(), mac_device],
            2_000,
            super::DEFAULT_MAC_WINDOW_MS,
        );
        assert_eq!(resolved.devices[0].id, udn_device.id);
        assert!(
            resolved
                .links
                .iter()
                .any(|link| link.basis == "strong_identifier_conflict"
                    && link.status == LinkStatus::Uncertain)
        );
    }
}
