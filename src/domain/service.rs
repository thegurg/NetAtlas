//! Observed network services.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::Source;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::str::FromStr for Transport {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(crate::domain::DomainError::InvalidTransport(
                other.to_string(),
            )),
        }
    }
}

/// A service observation persisted for a device.
///
/// `protocol`, `product`, and `version` are claims parsed from the observed
/// exchange. They are not promoted to verified device properties without
/// separate evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub id: Uuid,
    pub device_id: Uuid,
    pub ip: IpAddr,
    pub port: u16,
    pub transport: Transport,
    pub protocol: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub source: Source,
    pub observed_at_ms: i64,
    pub details: serde_json::Value,
}
