//! Logical device profiles and their identifiers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    Confidence, EvidenceRecord, InferenceStatus, ObservationRecord, Source, UnknownReason,
};

/// A kind of identifier attached to a logical device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Ip,
    Mac,
    Hostname,
    DnsName,
    NetbiosName,
    MdnsInstance,
    UpnpUdn,
    SshHostKey,
    TlsCertificate,
}

impl IdentifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Mac => "mac",
            Self::Hostname => "hostname",
            Self::DnsName => "dns_name",
            Self::NetbiosName => "netbios_name",
            Self::MdnsInstance => "mdns_instance",
            Self::UpnpUdn => "upnp_udn",
            Self::SshHostKey => "ssh_host_key",
            Self::TlsCertificate => "tls_certificate",
        }
    }
}

impl std::str::FromStr for IdentifierKind {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ip" => Ok(Self::Ip),
            "mac" => Ok(Self::Mac),
            "hostname" => Ok(Self::Hostname),
            "dns_name" => Ok(Self::DnsName),
            "netbios_name" => Ok(Self::NetbiosName),
            "mdns_instance" => Ok(Self::MdnsInstance),
            "upnp_udn" => Ok(Self::UpnpUdn),
            "ssh_host_key" => Ok(Self::SshHostKey),
            "tls_certificate" => Ok(Self::TlsCertificate),
            other => Err(crate::domain::DomainError::InvalidIdentifierKind(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub label: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub merged_into: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierRecord {
    pub id: Uuid,
    pub device_id: Uuid,
    pub kind: IdentifierKind,
    pub value: String,
    pub normalized: String,
    pub source: Source,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub confidence: Confidence,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    Accepted,
    Rejected,
    Uncertain,
}

impl LinkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Uncertain => "uncertain",
        }
    }
}

impl std::str::FromStr for LinkStatus {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "uncertain" => Ok(Self::Uncertain),
            other => Err(crate::domain::DomainError::InvalidLinkStatus(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLink {
    pub id: Uuid,
    pub from_device_id: Uuid,
    pub to_device_id: Uuid,
    pub basis: String,
    pub confidence: Confidence,
    pub status: LinkStatus,
    pub rationale: String,
    pub created_at_ms: i64,
}

/// A compact, presentation-oriented view of one inferred property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceView {
    pub value: Option<serde_json::Value>,
    pub confidence: Confidence,
    pub status: InferenceStatus,
    pub unknown_reason: Option<UnknownReason>,
    pub rationale: String,
}

impl InferenceView {
    pub fn display_value(&self) -> String {
        match (&self.value, self.unknown_reason) {
            (Some(serde_json::Value::String(value)), _) => value.clone(),
            (Some(value), _) => value.to_string(),
            (None, Some(reason)) => format!("unknown ({})", reason.as_str()),
            (None, None) => "unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub id: Uuid,
    pub label: Option<String>,
    pub ips: Vec<String>,
    pub macs: Vec<String>,
    pub hostnames: Vec<String>,
    pub manufacturer: InferenceView,
    pub category: InferenceView,
    pub os: InferenceView,
    pub model: InferenceView,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub last_session_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDetail {
    pub summary: DeviceSummary,
    pub identifiers: Vec<IdentifierRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub observations: Vec<ObservationRecord>,
    pub inferences: Vec<crate::domain::InferenceRecord>,
    pub links: Vec<IdentityLink>,
}
