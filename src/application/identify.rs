//! Evidence extraction and property inference for resolved devices.
//!
//! Phase 1 deliberately extracts evidence for only one property: the OUI
//! address-block association for manufacturer. Category, OS, and model are
//! reported as `unknown` with an explicit reason because no Phase 1 provider
//! observes protocol fields that could support them.

use std::net::Ipv4Addr;

use serde_json::json;
use uuid::Uuid;

use crate::application::model::ResolvedDevice;
use crate::domain::{
    Confidence, EvidenceRecord, HostProbe, IdentifierKind, InferenceRecord, InferenceStatus,
    MacAddress, ObservationRecord, Property, Source, SubjectType, UnknownReason, ids::new_id,
};
use crate::infrastructure::oui::{self, OuiEntry};

#[derive(Debug, Clone, Default)]
pub struct Identification {
    pub observations: Vec<ObservationRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub inferences: Vec<InferenceRecord>,
}

/// Extract evidence and compute inferences for each device.
pub fn identify(
    session_id: Uuid,
    devices: &[ResolvedDevice],
    oui_entries: &[OuiEntry],
    oui_version: &str,
    now_ms: i64,
) -> Identification {
    let mut result = Identification::default();

    for device in devices {
        for host in &device.hosts {
            for probe in &host.probes {
                result
                    .observations
                    .push(observation_from_probe(session_id, device.id, probe));
            }
        }

        let mut manufacturer_evidence = Vec::new();
        let mut global_macs = Vec::new();
        let mut has_local_mac = false;
        for identifier in &device.identifiers {
            if identifier.kind != IdentifierKind::Mac {
                continue;
            }
            let Ok(mac) = identifier.value.parse::<MacAddress>() else {
                continue;
            };
            if mac.is_locally_administered() {
                has_local_mac = true;
            } else {
                global_macs.push(mac);
            }
        }
        global_macs.sort_unstable();
        global_macs.dedup();

        let host_ip = device
            .hosts
            .first()
            .map(|host| host.ip)
            .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let mut seen_units = std::collections::HashSet::new();
        for mac in global_macs {
            let Some(entry) = oui::lookup(oui_entries, mac) else {
                continue;
            };
            let source_unit = format!(
                "oui:{}:{oui_version}",
                entry.prefix_hex.to_ascii_lowercase()
            );
            if !seen_units.insert(source_unit.clone()) {
                continue;
            }

            let observation = HostProbe::oui_lookup(
                host_ip,
                mac,
                &entry.organization,
                &entry.prefix_hex,
                entry.prefix_bits,
                oui_version,
                now_ms,
            );
            let observation_id = new_id();
            result.observations.push(ObservationRecord {
                id: observation_id,
                session_id: Some(session_id),
                subject_type: SubjectType::Device,
                subject_id: device.id.to_string(),
                kind: observation.kind,
                property: None,
                value: observation.value,
                source: observation.source,
                method: observation.method,
                observed_at_ms: observation.observed_at_ms,
                expires_at_ms: observation.expires_at_ms,
                details: observation.details,
            });

            manufacturer_evidence.push(EvidenceRecord {
                id: new_id(),
                observation_id,
                device_id: device.id,
                property: Property::Manufacturer,
                candidate: json!(entry.organization),
                source: Source::OuiRegistry,
                source_unit,
                confidence: Confidence::Medium,
                rationale: format!(
                    "MAC prefix {}/{} is registered to {} in the IEEE registry. This is an address-block association, not proof of the device model or owner.",
                    entry.prefix_hex, entry.prefix_bits, entry.organization
                ),
                observed_at_ms: now_ms,
                expires_at_ms: None,
            });
        }

        if manufacturer_evidence.is_empty() {
            let (reason, rationale) = if has_local_mac {
                (
                    UnknownReason::LocallyAdministeredMac,
                    "The observed MAC address is locally administered. OUI data cannot attribute a manufacturer, and no other Phase 1 provider supplied manufacturer evidence.".to_string(),
                )
            } else {
                (
                    UnknownReason::NoEvidence,
                    "No OUI association or protocol field supports a manufacturer for this device."
                        .to_string(),
                )
            };
            result.inferences.push(unknown_inference(
                device.id,
                Property::Manufacturer,
                reason,
                rationale,
                now_ms,
            ));
        } else {
            result
                .inferences
                .push(crate::domain::inference::infer_property_for(
                    device.id,
                    Property::Manufacturer,
                    &manufacturer_evidence,
                    now_ms,
                ));
        }

        for property in [Property::Category, Property::Os, Property::Model] {
            result
                .inferences
                .push(crate::domain::inference::infer_property_for(
                    device.id,
                    property,
                    &[],
                    now_ms,
                ));
        }

        result.evidence.extend(manufacturer_evidence);
    }

    result
}

fn observation_from_probe(
    session_id: Uuid,
    device_id: Uuid,
    probe: &HostProbe,
) -> ObservationRecord {
    ObservationRecord {
        id: new_id(),
        session_id: Some(session_id),
        subject_type: SubjectType::Device,
        subject_id: device_id.to_string(),
        kind: probe.kind,
        property: None,
        value: probe.value.clone(),
        source: probe.source,
        method: probe.method.clone(),
        observed_at_ms: probe.observed_at_ms,
        expires_at_ms: probe.expires_at_ms,
        details: probe.details.clone(),
    }
}

fn unknown_inference(
    device_id: Uuid,
    property: Property,
    reason: UnknownReason,
    rationale: impl Into<String>,
    now_ms: i64,
) -> InferenceRecord {
    InferenceRecord {
        id: new_id(),
        device_id,
        property,
        value: None,
        confidence: Confidence::Unknown,
        status: InferenceStatus::Unknown,
        rationale: rationale.into(),
        evidence_ids: Vec::new(),
        unknown_reason: Some(reason),
        computed_at_ms: now_ms,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use serde_json::json;

    use super::identify;
    use crate::application::model::ResolvedDevice;
    use crate::domain::{
        Confidence, HostObservation, HostProbe, IdentifierKind, IdentifierRecord, InferenceStatus,
        Property, Source, UnknownReason, ids::new_id,
    };
    use crate::infrastructure::oui::{OuiEntry, parse_csv};

    fn device(mac: &str, locally_administered: bool) -> ResolvedDevice {
        let mac_address = mac.parse().unwrap();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let probe = HostProbe::neighbor(
            ip,
            Some(mac_address),
            Some("reachable".into()),
            Some("eth0"),
            1_000,
        );
        ResolvedDevice {
            id: new_id(),
            label: None,
            identifiers: vec![IdentifierRecord {
                id: new_id(),
                device_id: new_id(),
                kind: IdentifierKind::Mac,
                value: mac.to_string(),
                normalized: mac.to_string(),
                source: Source::NeighborTable,
                first_seen_ms: 1_000,
                last_seen_ms: 1_000,
                confidence: if locally_administered {
                    Confidence::Low
                } else {
                    Confidence::High
                },
                details: json!({}),
            }],
            hosts: vec![HostObservation {
                ip,
                interface: Some("eth0".into()),
                segment: None,
                mac: Some(mac_address),
                neighbor_state: Some("reachable".into()),
                icmp_rtt_ms: None,
                tcp: Vec::new(),
                hostname: None,
                first_seen_ms: 1_000,
                last_seen_ms: 1_000,
                sources: vec![Source::NeighborTable],
                probes: vec![probe],
            }],
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            is_new: true,
        }
    }

    fn entries() -> Vec<OuiEntry> {
        parse_csv("Registry,Assignment,Organization Name\nMA-L,001122,Example Networks\n")
            .unwrap()
            .entries
    }

    #[test]
    fn oui_supports_manufacturer_at_medium() {
        let devices = vec![device("00:11:22:33:44:55", false)];
        let result = identify(new_id(), &devices, &entries(), "test", 2_000);
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.status, InferenceStatus::Supported);
        assert_eq!(manufacturer.confidence, Confidence::Medium);
        assert_eq!(manufacturer.value, Some(json!("Example Networks")));
        assert_eq!(result.evidence.len(), 1);
    }

    #[test]
    fn locally_administered_mac_gets_reason() {
        let devices = vec![device("02:11:22:33:44:55", true)];
        let result = identify(new_id(), &devices, &entries(), "test", 2_000);
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.status, InferenceStatus::Unknown);
        assert_eq!(
            manufacturer.unknown_reason,
            Some(UnknownReason::LocallyAdministeredMac)
        );
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn category_os_and_model_are_explicitly_unknown() {
        let devices = vec![device("00:11:22:33:44:55", false)];
        let result = identify(new_id(), &devices, &entries(), "test", 2_000);
        for property in [Property::Category, Property::Os, Property::Model] {
            let inference = result
                .inferences
                .iter()
                .find(|inference| inference.property == property)
                .unwrap();
            assert_eq!(inference.status, InferenceStatus::Unknown);
            assert_eq!(inference.unknown_reason, Some(UnknownReason::NoEvidence));
            assert!(inference.evidence_ids.is_empty());
        }
    }

    #[test]
    fn unknown_oui_produces_no_manufacturer_claim() {
        let devices = vec![device("00:aa:bb:cc:dd:ee", false)];
        let result = identify(new_id(), &devices, &entries(), "test", 2_000);
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.status, InferenceStatus::Unknown);
        assert_eq!(manufacturer.unknown_reason, Some(UnknownReason::NoEvidence));
    }
}
