//! Confidence levels and the qualitative aggregation rubric.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A qualitative confidence label.
///
/// NetAtlas deliberately does not present a numeric probability. The label is
/// explained by the evidence and rationale attached to an inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Unknown,
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Raise confidence one level, capped at high.
    pub fn upgrade(self) -> Self {
        match self {
            Self::Unknown => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium | Self::High => Self::High,
        }
    }

    /// Lower confidence one level, floored at unknown.
    pub fn downgrade(self) -> Self {
        match self {
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low | Self::Unknown => Self::Unknown,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Confidence {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            other => Err(crate::domain::DomainError::InvalidConfidence(
                other.to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Confidence;

    #[test]
    fn upgrade_and_downgrade_are_bounded() {
        assert_eq!(Confidence::High.upgrade(), Confidence::High);
        assert_eq!(Confidence::Unknown.downgrade(), Confidence::Unknown);
        assert_eq!(Confidence::Low.upgrade(), Confidence::Medium);
        assert_eq!(Confidence::Medium.downgrade(), Confidence::Low);
    }

    #[test]
    fn ordering_matches_strength() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
        assert!(Confidence::Low > Confidence::Unknown);
    }
}
