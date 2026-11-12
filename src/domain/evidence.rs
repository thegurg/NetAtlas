//! Evidence records that support property candidates.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Confidence, Source};

/// A device property that can be inferred from evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Property {
    Manufacturer,
    Category,
    Os,
    Model,
}

impl Property {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manufacturer => "manufacturer",
            Self::Category => "category",
            Self::Os => "os",
            Self::Model => "model",
        }
    }
}

impl std::str::FromStr for Property {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "manufacturer" => Ok(Self::Manufacturer),
            "category" => Ok(Self::Category),
            "os" => Ok(Self::Os),
            "model" => Ok(Self::Model),
            other => Err(crate::domain::DomainError::InvalidProperty(
                other.to_string(),
            )),
        }
    }
}

/// A single piece of evidence supporting one candidate value.
///
/// `source_unit` is the independence key. Multiple fields extracted from one
/// protocol exchange must share a source unit and therefore count as one source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: Uuid,
    pub observation_id: Uuid,
    pub device_id: Uuid,
    pub property: Property,
    pub candidate: serde_json::Value,
    pub source: Source,
    pub source_unit: String,
    pub confidence: Confidence,
    pub rationale: String,
    pub observed_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}
