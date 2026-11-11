//! Application-level result types shared by services, storage, and presentation.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    DeviceRecord, EvidenceRecord, HostObservation, IdentityLink, InferenceRecord, MacAddress,
    NetworkContext, ObservationRecord, ServiceRecord,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    Icmp,
    Tcp,
    Neighbor,
    ReverseDns,
    Mdns,
    Ssdp,
    Netbios,
    ServiceProbe,
}

impl DiscoveryMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Neighbor => "neighbor",
            Self::ReverseDns => "reverse_dns",
            Self::Mdns => "mdns",
            Self::Ssdp => "ssdp",
            Self::Netbios => "netbios",
            Self::ServiceProbe => "service_probe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Partial,
    Cancelled,
    Failed,
    Interrupted,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Ok,
    Failed,
    Skipped,
    Cancelled,
}

impl ProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    PermissionDenied,
    Unavailable,
    Timeout,
    Io,
    Parse,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderErrorInfo {
    pub kind: ProviderErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderReport {
    pub name: String,
    pub method: DiscoveryMethod,
    pub status: ProviderStatus,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub observations: usize,
    pub error: Option<ProviderErrorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanScope {
    pub interface: Option<String>,
    pub target: Option<String>,
    pub candidate_count: usize,
    pub discovered_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout_ms: u64,
    pub dns_timeout_ms: u64,
    pub mdns_window_ms: u64,
    pub concurrency: usize,
    pub max_hosts: usize,
    pub service_ports: Vec<u16>,
    pub methods: Vec<DiscoveryMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedDevice {
    pub id: Uuid,
    pub label: Option<String>,
    pub identifiers: Vec<crate::domain::IdentifierRecord>,
    pub hosts: Vec<HostObservation>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub is_new: bool,
}

impl ResolvedDevice {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            label: self.label.clone(),
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            merged_into: None,
        }
    }
}

/// A device loaded from storage for identity matching.
#[derive(Debug, Clone)]
pub struct ExistingDevice {
    pub id: Uuid,
    pub label: Option<String>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub macs: Vec<(MacAddress, i64)>,
    pub ips: Vec<(IpAddr, i64)>,
    pub hostnames: Vec<(String, i64)>,
    pub upnp_udns: Vec<(String, i64)>,
    pub mdns_instances: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub session_id: Uuid,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub status: SessionStatus,
    pub scope: ScanScope,
    pub config: ScanConfig,
    pub context: NetworkContext,
    pub hosts: Vec<HostObservation>,
    pub devices: Vec<ResolvedDevice>,
    pub services: Vec<ServiceRecord>,
    pub observations: Vec<ObservationRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub inferences: Vec<InferenceRecord>,
    pub identity_links: Vec<IdentityLink>,
    pub provider_reports: Vec<ProviderReport>,
}
