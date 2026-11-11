//! Evidence extraction and property inference for resolved devices.
//!
//! Phase 2 adds protocol evidence from mDNS, SSDP/UPnP, NetBIOS, and safe TCP
//! service banners. Every candidate still carries provenance and is aggregated
//! with the same conflict-aware rubric used in Phase 1. Facts, measurements,
//! self-reported protocol claims, and inferences remain separate.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde_json::json;
use uuid::Uuid;

use crate::application::model::ResolvedDevice;
use crate::domain::{
    Confidence, EvidenceRecord, HostProbe, IdentifierKind, InferenceRecord, InferenceStatus,
    MacAddress, MdnsServiceObservation, ObservationRecord, Property, ProtocolObservation, Source,
    SubjectType, UnknownReason, UpnpObservation, ids::new_id,
};
use crate::infrastructure::mdns;
use crate::infrastructure::oui::{self, OuiEntry};

/// Which evidence providers were actually available during this scan.
///
/// A disabled or failed provider is not the same as a provider that ran and
/// found nothing. The distinction is preserved in unknown reasons.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProviderAvailability {
    pub oui: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub netbios: bool,
    pub service_banner: bool,
}

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
    providers: &ProviderAvailability,
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

        let mut all_evidence = Vec::new();

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

            all_evidence.push(EvidenceRecord {
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

        for host in &device.hosts {
            for probe in &host.probes {
                all_evidence.extend(protocol_evidence(device.id, probe));
            }
        }

        let manufacturer_evidence: Vec<EvidenceRecord> = all_evidence
            .iter()
            .filter(|evidence| evidence.property == Property::Manufacturer)
            .cloned()
            .collect();
        if manufacturer_evidence.is_empty() {
            let (reason, rationale) = if has_local_mac {
                (
                    UnknownReason::LocallyAdministeredMac,
                    "The observed MAC address is locally administered. OUI data cannot attribute a manufacturer, and no protocol provider supplied manufacturer evidence.".to_string(),
                )
            } else {
                let reason = manufacturer_unknown_reason(providers);
                let rationale = unknown_rationale(Property::Manufacturer, reason, providers);
                (reason, rationale)
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
                    &all_evidence,
                    now_ms,
                ));
        }

        for property in [Property::Category, Property::Os, Property::Model] {
            let has_evidence = all_evidence
                .iter()
                .any(|evidence| evidence.property == property);
            if has_evidence {
                result
                    .inferences
                    .push(crate::domain::inference::infer_property_for(
                        device.id,
                        property,
                        &all_evidence,
                        now_ms,
                    ));
            } else {
                let reason = unknown_reason_for(property, providers);
                let rationale = unknown_rationale(property, reason, providers);
                result.inferences.push(unknown_inference(
                    device.id, property, reason, rationale, now_ms,
                ));
            }
        }

        result.evidence.extend(all_evidence);
    }

    result
}

fn protocol_evidence(device_id: Uuid, probe: &HostProbe) -> Vec<EvidenceRecord> {
    let mut evidence = Vec::new();
    match &probe.protocol {
        Some(ProtocolObservation::Upnp(device)) => {
            upnp_evidence(device_id, device, probe.observed_at_ms, &mut evidence);
        }
        Some(ProtocolObservation::Mdns(service)) => {
            mdns_evidence(device_id, service, probe.observed_at_ms, &mut evidence);
        }
        Some(ProtocolObservation::Service(service)) => {
            if let Some(os_hint) = &service.os_hint
                && let Some(os) = os_family(os_hint)
            {
                evidence.push(EvidenceRecord {
                    id: new_id(),
                    observation_id: new_id(),
                    device_id,
                    property: Property::Os,
                    candidate: json!(os),
                    source: Source::ServiceBanner,
                    source_unit: service.source_unit.clone(),
                    confidence: Confidence::Low,
                    rationale: format!(
                        "The {} service banner self-reports an operating-system hint ({os_hint}). A banner can be stripped, proxied, or misleading.",
                        service.protocol.as_deref().unwrap_or("network")
                    ),
                    observed_at_ms: probe.observed_at_ms,
                    expires_at_ms: Some(probe.observed_at_ms + 24 * 60 * 60 * 1000),
                });
            }
        }
        Some(ProtocolObservation::Netbios(_)) | None => {}
    }
    evidence
}

fn upnp_evidence(
    device_id: Uuid,
    device: &UpnpObservation,
    observed_at_ms: i64,
    evidence: &mut Vec<EvidenceRecord>,
) {
    if let Some(manufacturer) = clean_text(device.manufacturer.as_deref()) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Manufacturer,
            candidate: json!(manufacturer),
            source: Source::Ssdp,
            source_unit: device.source_unit.clone(),
            confidence: Confidence::Medium,
            rationale: "The UPnP device description self-reports this manufacturer. It is a device claim, not a registry-verified fact.".to_string(),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }

    if let Some(model) = upnp_model(device) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Model,
            candidate: json!(model),
            source: Source::Ssdp,
            source_unit: device.source_unit.clone(),
            confidence: Confidence::Medium,
            rationale: "The UPnP device description self-reports this model name or number. The field is not independently verified.".to_string(),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }

    if let Some(category) = upnp_category(device.device_type.as_deref()) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Category,
            candidate: json!(category),
            source: Source::Ssdp,
            source_unit: device.source_unit.clone(),
            confidence: Confidence::Medium,
            rationale: format!(
                "The UPnP device type {:?} maps conservatively to the category {category}. The type is self-reported by the device.",
                device.device_type.as_deref().unwrap_or("unknown")
            ),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }
}

fn mdns_evidence(
    device_id: Uuid,
    service: &MdnsServiceObservation,
    observed_at_ms: i64,
    evidence: &mut Vec<EvidenceRecord>,
) {
    if let Some(manufacturer) = txt_value(
        &service.properties,
        &["manufacturer", "vendor", "mfg", "make", "manuf"],
    ) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Manufacturer,
            candidate: json!(manufacturer),
            source: Source::Mdns,
            source_unit: service.source_unit.clone(),
            confidence: Confidence::Low,
            rationale: "An mDNS TXT record self-reports this manufacturer. TXT records are optional, self-published, and can be stale.".to_string(),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }

    if let Some(model) = txt_value(
        &service.properties,
        &["model", "modelname", "model-name", "md", "modelnumber"],
    ) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Model,
            candidate: json!(model),
            source: Source::Mdns,
            source_unit: service.source_unit.clone(),
            confidence: Confidence::Low,
            rationale: "An mDNS TXT record self-reports this model identifier. TXT records are optional and not independently verified.".to_string(),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }

    if let Some(category) = mdns::category_for_service_type(&service.service_type) {
        evidence.push(EvidenceRecord {
            id: new_id(),
            observation_id: new_id(),
            device_id,
            property: Property::Category,
            candidate: json!(category),
            source: Source::Mdns,
            source_unit: service.source_unit.clone(),
            confidence: Confidence::Medium,
            rationale: format!(
                "The mDNS service type {} maps conservatively to the category {category}. A service type describes a published service, not necessarily the whole device.",
                service.service_type
            ),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
        });
    }

    let os_value = txt_value(&service.properties, &["os", "osxvers", "osversion"]);
    if let Some(os_value) = os_value {
        let os = os_family(os_value).or_else(|| {
            service
                .properties
                .contains_key("osxvers")
                .then_some("macOS")
        });
        if let Some(os) = os {
            evidence.push(EvidenceRecord {
                id: new_id(),
                observation_id: new_id(),
                device_id,
                property: Property::Os,
                candidate: json!(os),
                source: Source::Mdns,
                source_unit: service.source_unit.clone(),
                confidence: Confidence::Low,
                rationale: "An mDNS TXT record self-reports an operating-system hint. The field is optional and can be stale or spoofed.".to_string(),
                observed_at_ms,
                expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
            });
        }
    }
}

fn clean_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(200).collect())
}

fn txt_value<'a>(properties: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        properties
            .get(*key)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn upnp_model(device: &UpnpObservation) -> Option<String> {
    let name = clean_text(device.model_name.as_deref());
    let number = clean_text(device.model_number.as_deref());
    match (name, number) {
        (Some(name), Some(number)) if name != number => Some(format!("{name} ({number})")),
        (Some(name), _) => Some(name),
        (None, Some(number)) => Some(number),
        (None, None) => None,
    }
}

/// Map unambiguous UPnP device types to conservative categories.
fn upnp_category(device_type: Option<&str>) -> Option<&'static str> {
    let device_type = device_type?.to_ascii_lowercase();
    let known = [
        ("mediarenderer", "media_renderer"),
        ("mediaserver", "media_server"),
        ("internetgatewaydevice", "router"),
        ("wandevice", "router"),
        ("printer", "printer"),
        ("scanner", "scanner"),
        ("digitalsecuritycamera", "camera"),
        ("binarylight", "smart_light"),
        ("dimmablelight", "smart_light"),
        ("thermostat", "thermostat"),
        ("zoneplayer", "speaker"),
        ("mediaplayer", "media_player"),
        ("television", "television"),
    ];
    known
        .into_iter()
        .find_map(|(needle, category)| device_type.contains(needle).then_some(category))
}

/// Map an OS hint to a broad family. Broad families avoid false conflicts
/// between, for example, `Ubuntu` and `Linux`.
fn os_family(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("ubuntu")
        || lower.contains("debian")
        || lower.contains("fedora")
        || lower.contains("centos")
        || lower.contains("red hat")
        || lower.contains("rocky")
        || lower.contains("alpine")
        || lower.contains("linux")
    {
        Some("Linux")
    } else if lower.contains("freebsd") {
        Some("FreeBSD")
    } else if lower.contains("openbsd") {
        Some("OpenBSD")
    } else if lower.contains("netbsd") {
        Some("NetBSD")
    } else if lower.contains("windows") || lower.contains("win64") || lower.contains("win32") {
        Some("Windows")
    } else if lower.contains("macos") || lower.contains("darwin") || lower.contains("osx") {
        Some("macOS")
    } else {
        None
    }
}

fn manufacturer_unknown_reason(providers: &ProviderAvailability) -> UnknownReason {
    if !providers.oui && !providers.ssdp && !providers.mdns {
        UnknownReason::ProviderUnavailable
    } else {
        UnknownReason::NoEvidence
    }
}

fn unknown_reason_for(property: Property, providers: &ProviderAvailability) -> UnknownReason {
    let available = match property {
        Property::Manufacturer => providers.oui || providers.ssdp || providers.mdns,
        Property::Category => providers.mdns || providers.ssdp,
        Property::Os => providers.service_banner || providers.mdns,
        Property::Model => providers.mdns || providers.ssdp,
    };
    if available {
        UnknownReason::NoEvidence
    } else {
        UnknownReason::ProviderUnavailable
    }
}

fn unknown_rationale(
    property: Property,
    reason: UnknownReason,
    providers: &ProviderAvailability,
) -> String {
    if reason == UnknownReason::ProviderUnavailable {
        let relevant = match property {
            Property::Manufacturer => "OUI, mDNS, and UPnP",
            Property::Category => "mDNS and UPnP",
            Property::Os => "service-banner and mDNS",
            Property::Model => "mDNS and UPnP",
        };
        format!(
            "No {relevant} provider was available during this scan, so {} could not be assessed.",
            property.as_str()
        )
    } else {
        let _ = providers;
        format!(
            "The available providers returned no observation that supports {} for this device.",
            property.as_str()
        )
    }
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

    use super::{ProviderAvailability, identify};
    use crate::application::model::ResolvedDevice;
    use crate::domain::{
        Confidence, HostObservation, HostProbe, IdentifierKind, IdentifierRecord, InferenceStatus,
        MdnsServiceObservation, Property, ServiceObservation, Source, Transport, UnknownReason,
        UpnpObservation, ids::new_id,
    };
    use crate::infrastructure::oui::{OuiEntry, parse_csv};

    fn all_providers() -> ProviderAvailability {
        ProviderAvailability {
            oui: true,
            mdns: true,
            ssdp: true,
            netbios: true,
            service_banner: true,
        }
    }

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
        let result = identify(
            new_id(),
            &devices,
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
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
        let result = identify(
            new_id(),
            &devices,
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
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
        let result = identify(
            new_id(),
            &devices,
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
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
        let result = identify(
            new_id(),
            &devices,
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.status, InferenceStatus::Unknown);
        assert_eq!(manufacturer.unknown_reason, Some(UnknownReason::NoEvidence));
    }

    fn device_with_probes(probes: Vec<HostProbe>) -> ResolvedDevice {
        let ip = probes
            .first()
            .map(|probe| probe.ip)
            .unwrap_or_else(|| "192.168.1.10".parse().unwrap());
        ResolvedDevice {
            id: new_id(),
            label: None,
            identifiers: Vec::new(),
            hosts: vec![HostObservation {
                ip,
                interface: Some("eth0".into()),
                segment: None,
                mac: None,
                neighbor_state: None,
                icmp_rtt_ms: None,
                tcp: Vec::new(),
                hostname: None,
                first_seen_ms: 1_000,
                last_seen_ms: 1_000,
                sources: Vec::new(),
                probes,
            }],
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            is_new: true,
        }
    }

    fn upnp_probe(
        ip: &str,
        manufacturer: Option<&str>,
        model_name: Option<&str>,
        device_type: Option<&str>,
    ) -> HostProbe {
        let ip: IpAddr = ip.parse().unwrap();
        HostProbe::upnp(
            ip,
            UpnpObservation {
                udn: Some("uuid:test".to_string()),
                source_ip: ip,
                location: format!("http://{ip}:49152/desc.xml"),
                device_type: device_type.map(ToString::to_string),
                friendly_name: None,
                manufacturer: manufacturer.map(ToString::to_string),
                model_name: model_name.map(ToString::to_string),
                model_number: None,
                model_description: None,
                serial_number: None,
                source_unit: "ssdp:uuid:test:description:test".to_string(),
            },
            1_000,
        )
    }

    fn mdns_probe(ip: &str, service_type: &str, properties: &[(&str, &str)]) -> HostProbe {
        let ip: IpAddr = ip.parse().unwrap();
        let properties = properties
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        HostProbe::mdns(
            ip,
            MdnsServiceObservation {
                fullname: "Test._ipp._tcp.local.".to_string(),
                service_type: service_type.to_string(),
                host: "test.local.".to_string(),
                port: 631,
                addresses: vec![ip],
                properties,
                source_unit: "mdns:Test._ipp._tcp.local.".to_string(),
            },
            1_000,
        )
    }

    fn service_probe(ip: &str, os_hint: &str) -> HostProbe {
        let ip: IpAddr = ip.parse().unwrap();
        HostProbe::service(
            ip,
            ServiceObservation {
                port: 22,
                transport: Transport::Tcp,
                protocol: Some("ssh".to_string()),
                product: Some("OpenSSH".to_string()),
                version: Some("9.6".to_string()),
                banner: Some("SSH-2.0-OpenSSH_9.6 Ubuntu".to_string()),
                os_hint: Some(os_hint.to_string()),
                source_unit: format!("service:{ip}:22"),
            },
            1_000,
        )
    }

    #[test]
    fn upnp_supplies_manufacturer_model_and_category() {
        let devices = vec![device_with_probes(vec![upnp_probe(
            "192.168.1.10",
            Some("Example Audio"),
            Some("SoundOne"),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1"),
        )])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let find = |property| {
            result
                .inferences
                .iter()
                .find(|inference| inference.property == property)
                .unwrap()
        };
        assert_eq!(
            find(Property::Manufacturer).value,
            Some(json!("Example Audio"))
        );
        assert_eq!(find(Property::Manufacturer).confidence, Confidence::Medium);
        assert_eq!(find(Property::Model).value, Some(json!("SoundOne")));
        assert_eq!(
            find(Property::Category).value,
            Some(json!("media_renderer"))
        );
        assert_eq!(find(Property::Category).status, InferenceStatus::Supported);
    }

    #[test]
    fn upnp_fields_share_one_source_unit() {
        let devices = vec![device_with_probes(vec![upnp_probe(
            "192.168.1.10",
            Some("Example Audio"),
            Some("SoundOne"),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1"),
        )])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let units: Vec<String> = result
            .evidence
            .iter()
            .filter(|evidence| evidence.source == Source::Ssdp)
            .map(|evidence| evidence.source_unit.clone())
            .collect();
        assert_eq!(units.len(), 3);
        assert!(units.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn upnp_and_mdns_category_disagreement_is_conflicted() {
        let devices = vec![device_with_probes(vec![
            upnp_probe(
                "192.168.1.10",
                None,
                None,
                Some("urn:schemas-upnp-org:device:MediaRenderer:1"),
            ),
            mdns_probe("192.168.1.10", "_ipp._tcp.local.", &[]),
        ])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let category = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Category)
            .unwrap();
        assert_eq!(category.status, InferenceStatus::Conflicted);
        assert_eq!(category.value, None);
        assert!(category.rationale.contains("media_renderer"));
        assert!(category.rationale.contains("printer"));
    }

    #[test]
    fn mdns_printer_service_supplies_category_and_txt_fields() {
        let devices = vec![device_with_probes(vec![mdns_probe(
            "192.168.1.10",
            "_ipp._tcp.local.",
            &[
                ("manufacturer", "Example Printers"),
                ("model", "Laser 9000"),
            ],
        )])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let find = |property| {
            result
                .inferences
                .iter()
                .find(|inference| inference.property == property)
                .unwrap()
        };
        assert_eq!(find(Property::Category).value, Some(json!("printer")));
        assert_eq!(
            find(Property::Manufacturer).value,
            Some(json!("Example Printers"))
        );
        assert_eq!(find(Property::Manufacturer).confidence, Confidence::Low);
        assert_eq!(find(Property::Model).value, Some(json!("Laser 9000")));
    }

    #[test]
    fn mdns_device_info_supplies_macos_hint() {
        let devices = vec![device_with_probes(vec![mdns_probe(
            "192.168.1.10",
            "_device-info._tcp.local.",
            &[("model", "MacBookPro18,3"), ("osxvers", "14.5")],
        )])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let os = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Os)
            .unwrap();
        assert_eq!(os.value, Some(json!("macOS")));
        assert_eq!(os.confidence, Confidence::Low);
    }

    #[test]
    fn service_banner_supplies_os_family() {
        let devices = vec![device_with_probes(vec![service_probe(
            "192.168.1.10",
            "Ubuntu",
        )])];
        let result = identify(new_id(), &devices, &[], "test", &all_providers(), 2_000);
        let os = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Os)
            .unwrap();
        assert_eq!(os.value, Some(json!("Linux")));
        assert_eq!(os.confidence, Confidence::Low);
    }

    #[test]
    fn independent_manufacturer_sources_raise_confidence() {
        let mut device = device("00:11:22:33:44:55", false);
        device.hosts[0].probes.push(upnp_probe(
            "192.168.1.10",
            Some("Example Networks"),
            None,
            None,
        ));
        let result = identify(
            new_id(),
            std::slice::from_ref(&device),
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.confidence, Confidence::High);
        assert_eq!(manufacturer.status, InferenceStatus::Supported);
    }

    #[test]
    fn conflicting_manufacturer_sources_are_preserved() {
        let mut device = device("00:11:22:33:44:55", false);
        device.hosts[0]
            .probes
            .push(upnp_probe("192.168.1.10", Some("Other Vendor"), None, None));
        let result = identify(
            new_id(),
            std::slice::from_ref(&device),
            &entries(),
            "test",
            &all_providers(),
            2_000,
        );
        let manufacturer = result
            .inferences
            .iter()
            .find(|inference| inference.property == Property::Manufacturer)
            .unwrap();
        assert_eq!(manufacturer.status, InferenceStatus::Conflicted);
        assert_eq!(manufacturer.value, None);
        assert!(manufacturer.rationale.contains("Example Networks"));
        assert!(manufacturer.rationale.contains("Other Vendor"));
    }

    #[test]
    fn disabled_providers_produce_provider_unavailable() {
        let devices = vec![device("00:aa:bb:cc:dd:ee", false)];
        let result = identify(
            new_id(),
            &devices,
            &[],
            "test",
            &ProviderAvailability::default(),
            2_000,
        );
        for property in [
            Property::Manufacturer,
            Property::Category,
            Property::Os,
            Property::Model,
        ] {
            let inference = result
                .inferences
                .iter()
                .find(|inference| inference.property == property)
                .unwrap();
            assert_eq!(inference.status, InferenceStatus::Unknown);
            assert_eq!(
                inference.unknown_reason,
                Some(UnknownReason::ProviderUnavailable)
            );
        }
    }
}
