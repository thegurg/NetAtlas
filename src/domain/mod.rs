//! Pure domain types and rules.
//!
//! This module must not depend on sockets, SQLite, Tokio, or terminal libraries.

pub mod confidence;
pub mod device;
pub mod dns;
pub mod error;
pub mod evidence;
pub mod ids;
pub mod inference;
pub mod inventory;
pub mod network;
pub mod observation;
pub mod service;
pub mod time;

pub use confidence::Confidence;
pub use device::{
    DeviceDetail, DeviceRecord, DeviceSummary, IdentifierKind, IdentifierRecord, IdentityLink,
    InferenceView, LinkStatus,
};
pub use dns::{
    DnsComparison, DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecord, DnsRecordType,
    DnsRecordValue, DnsResponse, DnsResponseCode, DnssecInfo, DnssecValidation, ResolverEndpoint,
    compare_measurements,
};
pub use error::DomainError;
pub use evidence::{EvidenceRecord, Property};
pub use inference::{InferenceRecord, InferenceStatus, UnknownReason};
pub use inventory::{
    ChangeContext, ChangeKind, DEFAULT_STALE_AFTER_MS, DeviceChange, DeviceSessionSnapshot,
    Freshness, FreshnessState, InferenceSnapshot, detect_changes,
};
pub use network::{
    InterfaceAddress, InterfaceInfo, MacAddress, NeighborEntry, NeighborState, NetworkContext,
    NetworkSegment, RouteInfo,
};
pub use observation::{
    HostObservation, HostProbe, HostnameObservation, MdnsServiceObservation, NetbiosObservation,
    ObservationKind, ObservationRecord, ProtocolObservation, ServiceObservation, Source,
    SubjectType, TcpProbe, TcpProbeOutcome, UpnpObservation,
};
pub use service::{ServiceRecord, Transport};
