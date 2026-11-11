//! Domain error type.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid MAC address: {0}")]
    InvalidMac(String),
    #[error("invalid network prefix: {0}")]
    InvalidPrefix(String),
    #[error("invalid confidence value: {0}")]
    InvalidConfidence(String),
    #[error("invalid identifier kind: {0}")]
    InvalidIdentifierKind(String),
    #[error("invalid source value: {0}")]
    InvalidSource(String),
    #[error("invalid observation kind: {0}")]
    InvalidObservationKind(String),
    #[error("invalid subject type: {0}")]
    InvalidSubjectType(String),
    #[error("invalid property value: {0}")]
    InvalidProperty(String),
    #[error("invalid inference status: {0}")]
    InvalidInferenceStatus(String),
    #[error("invalid unknown reason: {0}")]
    InvalidUnknownReason(String),
    #[error("invalid link status: {0}")]
    InvalidLinkStatus(String),
    #[error("invalid MAC prefix length {0}; expected 24, 28, or 36 bits")]
    InvalidPrefixBits(u8),
    #[error("IP prefix {0} is too large to enumerate safely")]
    PrefixTooLarge(String),
    #[error("IPv6 sweeps are not supported; supply an explicit address instead")]
    UnsupportedIpv6Sweep,
}
