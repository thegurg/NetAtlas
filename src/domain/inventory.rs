//! Inventory snapshots, freshness indicators, and change detection.
//!
//! Inventory history is append-oriented: each scan records a compact snapshot
//! of the devices it observed. Change events are derived from two snapshots;
//! they are not stored as independent truth. Absence from a scan is reported as
//! `not_observed`, never as proof that a device is offline.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::domain::{Confidence, InferenceRecord, InferenceStatus, Property, UnknownReason};

/// Default age after which an inventory record is marked stale.
///
/// This is a presentation threshold, not an offline determination. A stale
/// device may still be present; it simply has not been observed recently.
pub const DEFAULT_STALE_AFTER_MS: i64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessState {
    Fresh,
    Stale,
}

impl FreshnessState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

/// How old a record is relative to a caller-supplied threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    pub state: FreshnessState,
    pub age_ms: i64,
    pub stale_after_ms: i64,
}

impl Freshness {
    pub fn new(last_seen_ms: i64, now_ms: i64, stale_after_ms: i64) -> Self {
        let age_ms = now_ms.saturating_sub(last_seen_ms).max(0);
        let state = if age_ms > stale_after_ms {
            FreshnessState::Stale
        } else {
            FreshnessState::Fresh
        };
        Self {
            state,
            age_ms,
            stale_after_ms,
        }
    }

    pub fn is_stale(self) -> bool {
        self.state == FreshnessState::Stale
    }

    /// A short, honest explanation suitable for terminal output.
    pub fn note(self) -> &'static str {
        match self.state {
            FreshnessState::Fresh => "observed within the freshness threshold",
            FreshnessState::Stale => {
                "not observed recently; stale data is not proof that the device is offline"
            }
        }
    }
}

/// Compact per-device inventory state recorded for one scan session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceSessionSnapshot {
    pub session_id: Uuid,
    pub device_id: Uuid,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub ips: Vec<String>,
    pub macs: Vec<String>,
    pub hostnames: Vec<String>,
    pub inferences: Vec<InferenceSnapshot>,
}

/// One inferred property as it appeared in a session snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceSnapshot {
    pub property: Property,
    pub value: Option<serde_json::Value>,
    pub confidence: Confidence,
    pub status: InferenceStatus,
    pub unknown_reason: Option<UnknownReason>,
}

impl From<&InferenceRecord> for InferenceSnapshot {
    fn from(record: &InferenceRecord) -> Self {
        Self {
            property: record.property,
            value: record.value.clone(),
            confidence: record.confidence,
            status: record.status,
            unknown_reason: record.unknown_reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    NewDevice,
    NotObserved,
    IpChanged,
    MacChanged,
    HostnameChanged,
    InferenceChanged,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewDevice => "new_device",
            Self::NotObserved => "not_observed",
            Self::IpChanged => "ip_changed",
            Self::MacChanged => "mac_changed",
            Self::HostnameChanged => "hostname_changed",
            Self::InferenceChanged => "inference_changed",
        }
    }
}

/// One derived change event. `session_id` is the session in which the change
/// was observed (the newer of the compared sessions).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceChange {
    pub session_id: Uuid,
    pub device_id: Uuid,
    pub kind: ChangeKind,
    pub summary: String,
    pub details: serde_json::Value,
    pub observed_at_ms: i64,
}

/// Context for comparing two session snapshots.
#[derive(Debug, Clone)]
pub struct ChangeContext {
    pub previous_session_id: Uuid,
    pub current_session_id: Uuid,
    pub observed_at_ms: i64,
    /// Emit `not_observed` events for devices present previously but absent now.
    pub include_not_observed: bool,
    /// True when either compared session was partial. Absence may then be a
    /// provider failure rather than a missing device.
    pub partial_scan: bool,
}

/// Compare two device snapshots and return deterministic change events.
pub fn detect_changes(
    context: &ChangeContext,
    previous: &[DeviceSessionSnapshot],
    current: &[DeviceSessionSnapshot],
) -> Vec<DeviceChange> {
    let previous_by_id: BTreeMap<Uuid, &DeviceSessionSnapshot> =
        previous.iter().map(|item| (item.device_id, item)).collect();
    let current_by_id: BTreeMap<Uuid, &DeviceSessionSnapshot> =
        current.iter().map(|item| (item.device_id, item)).collect();

    let mut events = Vec::new();

    for (device_id, snapshot) in &current_by_id {
        if !previous_by_id.contains_key(device_id) {
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::NewDevice,
                summary: format!(
                    "new device profile observed ({})",
                    addresses_label(&snapshot.ips)
                ),
                details: json!({
                    "ips": snapshot.ips,
                    "macs": snapshot.macs,
                    "hostnames": snapshot.hostnames,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }
    }

    if context.include_not_observed {
        for (device_id, snapshot) in &previous_by_id {
            if current_by_id.contains_key(device_id) {
                continue;
            }
            let summary = if context.partial_scan {
                "not observed in this scan (partial scan; absence may be a provider failure and is not proof the device is offline)"
            } else {
                "not observed in this scan; absence is not proof the device is offline"
            };
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::NotObserved,
                summary: summary.to_string(),
                details: json!({
                    "last_seen_ms": snapshot.last_seen_ms,
                    "ips": snapshot.ips,
                    "macs": snapshot.macs,
                    "hostnames": snapshot.hostnames,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }
    }

    for (device_id, current_snapshot) in &current_by_id {
        let Some(previous_snapshot) = previous_by_id.get(device_id) else {
            continue;
        };

        let previous_ips = sorted_set(&previous_snapshot.ips);
        let current_ips = sorted_set(&current_snapshot.ips);
        if previous_ips != current_ips {
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::IpChanged,
                summary: format!(
                    "addresses changed from {} to {}",
                    addresses_label(&previous_snapshot.ips),
                    addresses_label(&current_snapshot.ips)
                ),
                details: json!({
                    "previous": previous_snapshot.ips,
                    "current": current_snapshot.ips,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }

        let previous_macs = sorted_set(&previous_snapshot.macs);
        let current_macs = sorted_set(&current_snapshot.macs);
        if previous_macs != current_macs {
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::MacChanged,
                summary: format!(
                    "MAC addresses changed from {} to {}",
                    addresses_label(&previous_snapshot.macs),
                    addresses_label(&current_snapshot.macs)
                ),
                details: json!({
                    "previous": previous_snapshot.macs,
                    "current": current_snapshot.macs,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }

        let previous_hostnames = sorted_set(&previous_snapshot.hostnames);
        let current_hostnames = sorted_set(&current_snapshot.hostnames);
        if previous_hostnames != current_hostnames {
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::HostnameChanged,
                summary: format!(
                    "hostnames changed from {} to {}",
                    addresses_label(&previous_snapshot.hostnames),
                    addresses_label(&current_snapshot.hostnames)
                ),
                details: json!({
                    "previous": previous_snapshot.hostnames,
                    "current": current_snapshot.hostnames,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }

        let previous_inferences = inference_map(&previous_snapshot.inferences);
        let current_inferences = inference_map(&current_snapshot.inferences);
        for property in [
            Property::Manufacturer,
            Property::Category,
            Property::Os,
            Property::Model,
        ] {
            let previous_inference = previous_inferences.get(&property);
            let current_inference = current_inferences.get(&property);
            if previous_inference == current_inference {
                continue;
            }
            events.push(DeviceChange {
                session_id: context.current_session_id,
                device_id: *device_id,
                kind: ChangeKind::InferenceChanged,
                summary: format!(
                    "{} changed from {} to {}",
                    property.as_str(),
                    previous_inference
                        .map(|inference| inference_label(inference))
                        .unwrap_or_else(|| "not recorded".to_string()),
                    current_inference
                        .map(|inference| inference_label(inference))
                        .unwrap_or_else(|| "not recorded".to_string())
                ),
                details: json!({
                    "property": property.as_str(),
                    "previous": previous_inference,
                    "current": current_inference,
                }),
                observed_at_ms: context.observed_at_ms,
            });
        }
    }

    events.sort_by(|left, right| {
        left.device_id
            .cmp(&right.device_id)
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
            .then_with(|| left.summary.cmp(&right.summary))
    });
    events
}

fn sorted_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn inference_map(inferences: &[InferenceSnapshot]) -> BTreeMap<Property, &InferenceSnapshot> {
    inferences
        .iter()
        .map(|inference| (inference.property, inference))
        .collect()
}

fn inference_label(inference: &InferenceSnapshot) -> String {
    match (inference.status, &inference.value, inference.unknown_reason) {
        (InferenceStatus::Conflicted, _, _) => "conflicted".to_string(),
        (_, Some(serde_json::Value::String(value)), _) => value.clone(),
        (_, Some(value), _) => value.to_string(),
        (_, None, Some(reason)) => format!("unknown ({})", reason.as_str()),
        (_, None, None) => "unknown".to_string(),
    }
}

fn addresses_label(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ChangeContext, ChangeKind, DeviceSessionSnapshot, Freshness, FreshnessState,
        InferenceSnapshot, detect_changes,
    };
    use crate::domain::{Confidence, InferenceStatus, Property};

    fn snapshot(
        device_id: u128,
        ips: &[&str],
        macs: &[&str],
        hostnames: &[&str],
        manufacturer: Option<&str>,
    ) -> DeviceSessionSnapshot {
        DeviceSessionSnapshot {
            session_id: uuid::Uuid::from_u128(1),
            device_id: uuid::Uuid::from_u128(device_id),
            first_seen_ms: 1_000,
            last_seen_ms: 2_000,
            ips: ips.iter().map(|value| value.to_string()).collect(),
            macs: macs.iter().map(|value| value.to_string()).collect(),
            hostnames: hostnames.iter().map(|value| value.to_string()).collect(),
            inferences: vec![InferenceSnapshot {
                property: Property::Manufacturer,
                value: manufacturer.map(|value| json!(value)),
                confidence: Confidence::Medium,
                status: if manufacturer.is_some() {
                    InferenceStatus::Supported
                } else {
                    InferenceStatus::Unknown
                },
                unknown_reason: manufacturer
                    .is_none()
                    .then_some(crate::domain::UnknownReason::NoEvidence),
            }],
        }
    }

    fn context(partial: bool) -> ChangeContext {
        ChangeContext {
            previous_session_id: uuid::Uuid::from_u128(1),
            current_session_id: uuid::Uuid::from_u128(2),
            observed_at_ms: 3_000,
            include_not_observed: true,
            partial_scan: partial,
        }
    }

    #[test]
    fn freshness_marks_old_records_stale() {
        let fresh = Freshness::new(1_000, 1_500, 1_000);
        assert_eq!(fresh.state, FreshnessState::Fresh);
        let stale = Freshness::new(1_000, 2_500, 1_000);
        assert_eq!(stale.state, FreshnessState::Stale);
        assert!(stale.note().contains("not proof"));
    }

    #[test]
    fn detects_new_and_not_observed_devices() {
        let previous = vec![snapshot(1, &["192.168.1.10"], &[], &[], None)];
        let current = vec![snapshot(2, &["192.168.1.11"], &[], &[], None)];
        let events = detect_changes(&context(false), &previous, &current);
        assert_eq!(events.len(), 2);
        let kinds: Vec<ChangeKind> = events.iter().map(|event| event.kind).collect();
        assert!(kinds.contains(&ChangeKind::NewDevice));
        assert!(kinds.contains(&ChangeKind::NotObserved));
        assert!(
            events
                .iter()
                .find(|event| event.kind == ChangeKind::NotObserved)
                .unwrap()
                .summary
                .contains("not proof")
        );
    }

    #[test]
    fn partial_scan_absence_is_explained() {
        let previous = vec![snapshot(1, &["192.168.1.10"], &[], &[], None)];
        let events = detect_changes(&context(true), &previous, &[]);
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("provider failure"));
    }

    #[test]
    fn detects_address_mac_hostname_and_inference_changes() {
        let previous = vec![snapshot(
            1,
            &["192.168.1.10"],
            &["00:11:22:33:44:55"],
            &["old.local"],
            Some("Vendor A"),
        )];
        let current = vec![snapshot(
            1,
            &["192.168.1.11"],
            &["00:11:22:33:44:66"],
            &["new.local"],
            Some("Vendor B"),
        )];
        let events = detect_changes(&context(false), &previous, &current);
        let kinds: Vec<ChangeKind> = events.iter().map(|event| event.kind).collect();
        assert!(kinds.contains(&ChangeKind::IpChanged));
        assert!(kinds.contains(&ChangeKind::MacChanged));
        assert!(kinds.contains(&ChangeKind::HostnameChanged));
        assert!(kinds.contains(&ChangeKind::InferenceChanged));
    }

    #[test]
    fn unchanged_devices_produce_no_events() {
        let previous = vec![snapshot(1, &["192.168.1.10"], &[], &[], Some("Vendor A"))];
        let current = previous.clone();
        assert!(detect_changes(&context(false), &previous, &current).is_empty());
    }
}
