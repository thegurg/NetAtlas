//! Observed facts and normalized host observations.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::domain::MacAddress;
use crate::domain::NetworkSegment;
use crate::domain::service::Transport;

/// Where a fact or measurement came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    NeighborTable,
    IcmpEcho,
    ReverseDns,
    Mdns,
    Ssdp,
    Netbios,
    TcpProbe,
    ServiceBanner,
    OuiRegistry,
    UserSupplied,
    Import,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeighborTable => "neighbor_table",
            Self::IcmpEcho => "icmp_echo",
            Self::ReverseDns => "reverse_dns",
            Self::Mdns => "mdns",
            Self::Ssdp => "ssdp",
            Self::Netbios => "netbios",
            Self::TcpProbe => "tcp_probe",
            Self::ServiceBanner => "service_banner",
            Self::OuiRegistry => "oui_registry",
            Self::UserSupplied => "user_supplied",
            Self::Import => "import",
        }
    }
}

impl std::str::FromStr for Source {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "neighbor_table" => Ok(Self::NeighborTable),
            "icmp_echo" => Ok(Self::IcmpEcho),
            "reverse_dns" => Ok(Self::ReverseDns),
            "mdns" => Ok(Self::Mdns),
            "ssdp" => Ok(Self::Ssdp),
            "netbios" => Ok(Self::Netbios),
            "tcp_probe" => Ok(Self::TcpProbe),
            "service_banner" => Ok(Self::ServiceBanner),
            "oui_registry" => Ok(Self::OuiRegistry),
            "user_supplied" => Ok(Self::UserSupplied),
            "import" => Ok(Self::Import),
            other => Err(crate::domain::DomainError::InvalidSource(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    NeighborEntry,
    IcmpReply,
    TcpConnect,
    ReverseDns,
    OuiLookup,
    AddressReuseSuspected,
    MdnsService,
    UpnpDescription,
    NetbiosName,
    ServiceBanner,
}

impl ObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeighborEntry => "neighbor_entry",
            Self::IcmpReply => "icmp_reply",
            Self::TcpConnect => "tcp_connect",
            Self::ReverseDns => "reverse_dns",
            Self::OuiLookup => "oui_lookup",
            Self::AddressReuseSuspected => "address_reuse_suspected",
            Self::MdnsService => "mdns_service",
            Self::UpnpDescription => "upnp_description",
            Self::NetbiosName => "netbios_name",
            Self::ServiceBanner => "service_banner",
        }
    }
}

impl std::str::FromStr for ObservationKind {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "neighbor_entry" => Ok(Self::NeighborEntry),
            "icmp_reply" => Ok(Self::IcmpReply),
            "tcp_connect" => Ok(Self::TcpConnect),
            "reverse_dns" => Ok(Self::ReverseDns),
            "oui_lookup" => Ok(Self::OuiLookup),
            "address_reuse_suspected" => Ok(Self::AddressReuseSuspected),
            "mdns_service" => Ok(Self::MdnsService),
            "upnp_description" => Ok(Self::UpnpDescription),
            "netbios_name" => Ok(Self::NetbiosName),
            "service_banner" => Ok(Self::ServiceBanner),
            other => Err(crate::domain::DomainError::InvalidObservationKind(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    Device,
    Identifier,
    Segment,
    Interface,
}

impl SubjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Identifier => "identifier",
            Self::Segment => "segment",
            Self::Interface => "interface",
        }
    }
}

impl std::str::FromStr for SubjectType {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "device" => Ok(Self::Device),
            "identifier" => Ok(Self::Identifier),
            "segment" => Ok(Self::Segment),
            "interface" => Ok(Self::Interface),
            other => Err(crate::domain::DomainError::InvalidSubjectType(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpProbeOutcome {
    Open,
    Refused,
    Timeout,
    Error,
}

impl TcpProbeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    /// A refused connection is still a positive reachability signal: the host
    /// answered with a TCP reset. A timeout is not evidence of absence.
    pub fn is_presence(self) -> bool {
        matches!(self, Self::Open | Self::Refused)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbe {
    pub port: u16,
    pub outcome: TcpProbeOutcome,
    pub rtt_ms: Option<f64>,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostnameObservation {
    pub name: String,
    pub source: Source,
    pub observed_at_ms: i64,
}

/// One resolved mDNS service instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsServiceObservation {
    pub fullname: String,
    pub service_type: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub properties: BTreeMap<String, String>,
    pub source_unit: String,
}

/// One SSDP/UPnP device description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpObservation {
    pub udn: Option<String>,
    pub source_ip: IpAddr,
    pub location: String,
    pub device_type: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    pub serial_number: Option<String>,
    pub source_unit: String,
}

/// One NetBIOS name from an NBSTAT response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetbiosObservation {
    pub name: String,
    pub suffix: u8,
    pub group: bool,
    pub source_unit: String,
}

/// One service banner or protocol response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub port: u16,
    pub transport: Transport,
    pub protocol: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub os_hint: Option<String>,
    pub source_unit: String,
}

/// Structured protocol data attached to a normalized host probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolObservation {
    Mdns(MdnsServiceObservation),
    Upnp(UpnpObservation),
    Netbios(NetbiosObservation),
    Service(ServiceObservation),
}

/// A normalized observation produced by a discovery provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProbe {
    pub ip: IpAddr,
    pub source: Source,
    pub method: String,
    pub kind: ObservationKind,
    pub value: serde_json::Value,
    pub details: serde_json::Value,
    pub observed_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub rtt_ms: Option<f64>,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub neighbor_state: Option<String>,
    pub tcp_port: Option<u16>,
    pub tcp_outcome: Option<TcpProbeOutcome>,
    pub protocol: Option<ProtocolObservation>,
}

impl HostProbe {
    pub fn neighbor(
        ip: IpAddr,
        mac: Option<MacAddress>,
        state: Option<String>,
        interface: Option<&str>,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            ip,
            source: Source::NeighborTable,
            method: "netlink_rtm_getneigh".to_string(),
            kind: ObservationKind::NeighborEntry,
            value: json!({
                "ip": ip.to_string(),
                "mac": mac.map(|mac| mac.to_string()),
                "state": state,
                "interface": interface,
            }),
            details: json!({
                "note": "kernel neighbour cache entry; observed_at records when NetAtlas read it"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 10 * 60 * 1000),
            rtt_ms: None,
            mac,
            hostname: None,
            neighbor_state: state,
            tcp_port: None,
            tcp_outcome: None,
            protocol: None,
        }
    }

    pub fn icmp(ip: IpAddr, rtt_ms: f64, observed_at_ms: i64) -> Self {
        Self {
            ip,
            source: Source::IcmpEcho,
            method: "icmp_echo".to_string(),
            kind: ObservationKind::IcmpReply,
            value: json!({ "ip": ip.to_string(), "rtt_ms": rtt_ms }),
            details: json!({ "note": "ICMP echo reply within the configured timeout" }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 10 * 60 * 1000),
            rtt_ms: Some(rtt_ms),
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: None,
        }
    }

    pub fn tcp(
        ip: IpAddr,
        port: u16,
        outcome: TcpProbeOutcome,
        rtt_ms: Option<f64>,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            ip,
            source: Source::TcpProbe,
            method: "tcp_connect".to_string(),
            kind: ObservationKind::TcpConnect,
            value: json!({
                "ip": ip.to_string(),
                "port": port,
                "outcome": outcome.as_str(),
            }),
            details: json!({
                "note": "refused means the host answered with a reset; timeout is not evidence of absence"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 10 * 60 * 1000),
            rtt_ms,
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: Some(port),
            tcp_outcome: Some(outcome),
            protocol: None,
        }
    }

    pub fn reverse_dns(ip: IpAddr, name: String, observed_at_ms: i64) -> Self {
        Self {
            ip,
            source: Source::ReverseDns,
            method: "ptr_lookup".to_string(),
            kind: ObservationKind::ReverseDns,
            value: json!({ "ip": ip.to_string(), "name": name }),
            details: json!({ "note": "reverse DNS is a naming hint, not a verified identity" }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 7 * 24 * 60 * 60 * 1000),
            rtt_ms: None,
            mac: None,
            hostname: Some(name),
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: None,
        }
    }

    pub fn oui_lookup(
        ip: IpAddr,
        mac: MacAddress,
        organization: &str,
        prefix_hex: &str,
        prefix_bits: u8,
        source_version: &str,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            ip,
            source: Source::OuiRegistry,
            method: "longest_prefix_match".to_string(),
            kind: ObservationKind::OuiLookup,
            value: json!({
                "mac": mac.to_string(),
                "organization": organization,
                "prefix_hex": prefix_hex,
                "prefix_bits": prefix_bits,
                "oui_source_version": source_version,
            }),
            details: json!({
                "note": "OUI identifies an address-block association, not a device model or owner"
            }),
            observed_at_ms,
            expires_at_ms: None,
            rtt_ms: None,
            mac: Some(mac),
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: None,
        }
    }

    pub fn address_reuse(
        ip: IpAddr,
        previous_mac: Option<MacAddress>,
        observed_mac: MacAddress,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            ip,
            source: Source::NeighborTable,
            method: "identity_resolution".to_string(),
            kind: ObservationKind::AddressReuseSuspected,
            value: json!({
                "ip": ip.to_string(),
                "previous_mac": previous_mac.map(|mac| mac.to_string()),
                "observed_mac": observed_mac.to_string(),
            }),
            details: json!({
                "note": "the same address was seen with a different MAC; devices were kept separate"
            }),
            observed_at_ms,
            expires_at_ms: None,
            rtt_ms: None,
            mac: Some(observed_mac),
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: None,
        }
    }

    pub fn mdns(ip: IpAddr, service: MdnsServiceObservation, observed_at_ms: i64) -> Self {
        let value = json!({
            "ip": ip.to_string(),
            "fullname": service.fullname,
            "service_type": service.service_type,
            "host": service.host,
            "port": service.port,
            "addresses": service.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "properties": service.properties,
        });
        Self {
            ip,
            source: Source::Mdns,
            method: "mdns_browse".to_string(),
            kind: ObservationKind::MdnsService,
            value,
            details: json!({
                "note": "mDNS records are self-published by the device and can be stale or incomplete"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
            rtt_ms: None,
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: Some(ProtocolObservation::Mdns(service)),
        }
    }

    pub fn upnp(ip: IpAddr, device: UpnpObservation, observed_at_ms: i64) -> Self {
        let value = json!({
            "ip": ip.to_string(),
            "udn": device.udn,
            "source_ip": device.source_ip.to_string(),
            "location": device.location,
            "device_type": device.device_type,
            "friendly_name": device.friendly_name,
            "manufacturer": device.manufacturer,
            "model_name": device.model_name,
            "model_number": device.model_number,
            "model_description": device.model_description,
            "serial_number": device.serial_number,
        });
        Self {
            ip,
            source: Source::Ssdp,
            method: "ssdp_description".to_string(),
            kind: ObservationKind::UpnpDescription,
            value,
            details: json!({
                "note": "UPnP description fields are self-reported by the device"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 30 * 24 * 60 * 60 * 1000),
            rtt_ms: None,
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: Some(ProtocolObservation::Upnp(device)),
        }
    }

    pub fn netbios(ip: IpAddr, name: NetbiosObservation, observed_at_ms: i64) -> Self {
        let value = json!({
            "ip": ip.to_string(),
            "name": name.name,
            "suffix": name.suffix,
            "group": name.group,
        });
        Self {
            ip,
            source: Source::Netbios,
            method: "netbios_nbstat".to_string(),
            kind: ObservationKind::NetbiosName,
            value,
            details: json!({
                "note": "NetBIOS names are legacy naming claims; they are not verified identities"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 7 * 24 * 60 * 60 * 1000),
            rtt_ms: None,
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: None,
            tcp_outcome: None,
            protocol: Some(ProtocolObservation::Netbios(name)),
        }
    }

    pub fn service(ip: IpAddr, service: ServiceObservation, observed_at_ms: i64) -> Self {
        let value = json!({
            "ip": ip.to_string(),
            "port": service.port,
            "transport": service.transport.as_str(),
            "protocol": service.protocol,
            "product": service.product,
            "version": service.version,
            "banner": service.banner,
            "os_hint": service.os_hint,
        });
        Self {
            ip,
            source: Source::ServiceBanner,
            method: "tcp_service_banner".to_string(),
            kind: ObservationKind::ServiceBanner,
            value,
            details: json!({
                "note": "service banners are self-reported and may be proxied, stripped, or misleading"
            }),
            observed_at_ms,
            expires_at_ms: Some(observed_at_ms + 24 * 60 * 60 * 1000),
            rtt_ms: None,
            mac: None,
            hostname: None,
            neighbor_state: None,
            tcp_port: Some(service.port),
            tcp_outcome: Some(TcpProbeOutcome::Open),
            protocol: Some(ProtocolObservation::Service(service)),
        }
    }
}

/// Merged, per-address view used by identity resolution and presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostObservation {
    pub ip: IpAddr,
    pub interface: Option<String>,
    pub segment: Option<IpNet>,
    pub mac: Option<MacAddress>,
    pub neighbor_state: Option<String>,
    pub icmp_rtt_ms: Option<f64>,
    pub tcp: Vec<TcpProbe>,
    pub hostname: Option<HostnameObservation>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub sources: Vec<Source>,
    pub probes: Vec<HostProbe>,
}

impl HostObservation {
    pub fn has_presence_evidence(&self) -> bool {
        self.icmp_rtt_ms.is_some()
            || self.tcp.iter().any(|probe| probe.outcome.is_presence())
            || (self.mac.is_some()
                && self
                    .neighbor_state
                    .as_deref()
                    .is_some_and(neighbor_state_is_present))
    }

    pub fn segment_or_interface(&self) -> Option<NetworkSegment> {
        self.segment.map(|prefix| NetworkSegment {
            interface: self.interface.clone().unwrap_or_default(),
            prefix,
            gateway: None,
        })
    }
}

fn neighbor_state_is_present(state: &str) -> bool {
    matches!(
        state,
        "reachable" | "stale" | "delay" | "probe" | "permanent" | "noarp"
    )
}

/// A persisted fact, measurement, or derived observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub id: uuid::Uuid,
    pub session_id: Option<uuid::Uuid>,
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub kind: ObservationKind,
    pub property: Option<String>,
    pub value: serde_json::Value,
    pub source: Source,
    pub method: String,
    pub observed_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub details: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::{TcpProbeOutcome, neighbor_state_is_present};

    #[test]
    fn refused_is_presence_but_timeout_is_not() {
        assert!(TcpProbeOutcome::Refused.is_presence());
        assert!(TcpProbeOutcome::Open.is_presence());
        assert!(!TcpProbeOutcome::Timeout.is_presence());
        assert!(!TcpProbeOutcome::Error.is_presence());
    }

    #[test]
    fn only_live_neighbor_states_count_as_presence() {
        assert!(neighbor_state_is_present("reachable"));
        assert!(neighbor_state_is_present("stale"));
        assert!(!neighbor_state_is_present("failed"));
        assert!(!neighbor_state_is_present("incomplete"));
    }
}
