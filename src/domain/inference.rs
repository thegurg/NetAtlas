//! Inference aggregation and unknown/conflict handling.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::device::InferenceView;
use crate::domain::{Confidence, EvidenceRecord, Property};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceStatus {
    Supported,
    Conflicted,
    Unknown,
}

impl InferenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Conflicted => "conflicted",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for InferenceStatus {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "supported" => Ok(Self::Supported),
            "conflicted" => Ok(Self::Conflicted),
            "unknown" => Ok(Self::Unknown),
            other => Err(crate::domain::DomainError::InvalidInferenceStatus(
                other.to_string(),
            )),
        }
    }
}

/// Why a property remains unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    NoEvidence,
    ProviderUnavailable,
    InsufficientPermissions,
    ClientIsolationSuspected,
    DeviceSleeping,
    ConflictingEvidence,
    UnsupportedProtocol,
    ModelNotExposed,
    LocallyAdministeredMac,
    StaleEvidence,
}

impl UnknownReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEvidence => "no_evidence",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::InsufficientPermissions => "insufficient_permissions",
            Self::ClientIsolationSuspected => "client_isolation_suspected",
            Self::DeviceSleeping => "device_sleeping",
            Self::ConflictingEvidence => "conflicting_evidence",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::ModelNotExposed => "model_not_exposed",
            Self::LocallyAdministeredMac => "locally_administered_mac",
            Self::StaleEvidence => "stale_evidence",
        }
    }
}

impl std::fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UnknownReason {
    type Err = crate::domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "no_evidence" => Ok(Self::NoEvidence),
            "provider_unavailable" => Ok(Self::ProviderUnavailable),
            "insufficient_permissions" => Ok(Self::InsufficientPermissions),
            "client_isolation_suspected" => Ok(Self::ClientIsolationSuspected),
            "device_sleeping" => Ok(Self::DeviceSleeping),
            "conflicting_evidence" => Ok(Self::ConflictingEvidence),
            "unsupported_protocol" => Ok(Self::UnsupportedProtocol),
            "model_not_exposed" => Ok(Self::ModelNotExposed),
            "locally_administered_mac" => Ok(Self::LocallyAdministeredMac),
            "stale_evidence" => Ok(Self::StaleEvidence),
            other => Err(crate::domain::DomainError::InvalidUnknownReason(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRecord {
    pub id: Uuid,
    pub device_id: Uuid,
    pub property: Property,
    pub value: Option<serde_json::Value>,
    pub confidence: Confidence,
    pub status: InferenceStatus,
    pub rationale: String,
    pub evidence_ids: Vec<Uuid>,
    pub unknown_reason: Option<UnknownReason>,
    pub computed_at_ms: i64,
}

impl InferenceRecord {
    pub fn view(&self) -> InferenceView {
        InferenceView {
            value: self.value.clone(),
            confidence: self.confidence,
            status: self.status,
            unknown_reason: self.unknown_reason,
            rationale: self.rationale.clone(),
        }
    }
}

/// Aggregate fresh evidence for one property using the documented rubric.
///
/// 1. Start at the strongest evidence level.
/// 2. Raise one level when at least two independent source units agree.
/// 3. Preserve conflicting candidates and lower confidence one level.
/// 4. Never report more than low from weak-only evidence.
/// 5. Expired evidence yields unknown with a stale reason.
pub fn infer_property(
    property: Property,
    evidence: &[EvidenceRecord],
    now_ms: i64,
) -> InferenceRecord {
    let mut fresh = Vec::new();
    let mut expired = 0_usize;
    for item in evidence.iter().filter(|item| item.property == property) {
        if item.expires_at_ms.is_some_and(|expires| expires <= now_ms) {
            expired += 1;
        } else {
            fresh.push(item);
        }
    }

    if fresh.is_empty() {
        let unknown_reason = if expired > 0 {
            UnknownReason::StaleEvidence
        } else {
            UnknownReason::NoEvidence
        };
        let rationale = if expired > 0 {
            format!(
                "{expired} evidence record(s) exist but are outside their freshness window; no current evidence supports {}.",
                property.as_str()
            )
        } else {
            format!(
                "No observation supports {} for this device.",
                property.as_str()
            )
        };
        return InferenceRecord {
            id: crate::domain::ids::new_id(),
            device_id: evidence
                .first()
                .map(|item| item.device_id)
                .unwrap_or_default(),
            property,
            value: None,
            confidence: Confidence::Unknown,
            status: InferenceStatus::Unknown,
            rationale,
            evidence_ids: evidence.iter().map(|item| item.id).collect(),
            unknown_reason: Some(unknown_reason),
            computed_at_ms: now_ms,
        };
    }

    let mut groups: BTreeMap<String, Vec<&EvidenceRecord>> = BTreeMap::new();
    for item in &fresh {
        let key = candidate_key(property, &item.candidate);
        groups.entry(key).or_default().push(item);
    }

    if groups.len() > 1 {
        let mut candidate_descriptions = Vec::new();
        let mut evidence_ids = Vec::new();
        let mut strongest = Confidence::Unknown;
        for items in groups.values() {
            let candidate = items
                .first()
                .map(|item| display_candidate(&item.candidate))
                .unwrap_or_else(|| "unknown".to_string());
            let units: HashSet<&str> = items.iter().map(|item| item.source_unit.as_str()).collect();
            candidate_descriptions.push(format!(
                "{candidate} ({} source unit{})",
                units.len(),
                if units.len() == 1 { "" } else { "s" }
            ));
            for item in items {
                evidence_ids.push(item.id);
                strongest = strongest.max(item.confidence);
            }
        }
        return InferenceRecord {
            id: crate::domain::ids::new_id(),
            device_id: fresh[0].device_id,
            property,
            value: None,
            confidence: strongest.downgrade(),
            status: InferenceStatus::Conflicted,
            rationale: format!(
                "Conflicting candidates for {} were preserved: {}.",
                property.as_str(),
                candidate_descriptions.join(", ")
            ),
            evidence_ids,
            unknown_reason: None,
            computed_at_ms: now_ms,
        };
    }

    let Some((_, items)) = groups.into_iter().next() else {
        return InferenceRecord {
            id: crate::domain::ids::new_id(),
            device_id: evidence
                .first()
                .map(|item| item.device_id)
                .unwrap_or_default(),
            property,
            value: None,
            confidence: Confidence::Unknown,
            status: InferenceStatus::Unknown,
            rationale: format!("No observation supports {}.", property.as_str()),
            evidence_ids: Vec::new(),
            unknown_reason: Some(UnknownReason::NoEvidence),
            computed_at_ms: now_ms,
        };
    };
    let units: HashSet<&str> = items.iter().map(|item| item.source_unit.as_str()).collect();
    let base = items
        .iter()
        .map(|item| item.confidence)
        .max()
        .unwrap_or(Confidence::Unknown);
    let confidence = if units.len() >= 2 {
        base.upgrade()
    } else {
        base
    };
    let mut unit_list: Vec<&str> = units.into_iter().collect();
    unit_list.sort_unstable();
    let rationale = format!(
        "Supported by {} independent source unit(s): {}.",
        unit_list.len(),
        unit_list.join(", ")
    );

    InferenceRecord {
        id: crate::domain::ids::new_id(),
        device_id: fresh[0].device_id,
        property,
        value: items.first().map(|item| item.candidate.clone()),
        confidence,
        status: InferenceStatus::Supported,
        rationale,
        evidence_ids: items.iter().map(|item| item.id).collect(),
        unknown_reason: None,
        computed_at_ms: now_ms,
    }
}

/// Aggregate evidence for a known device.
///
/// `infer_property` derives the device from the evidence, which cannot work
/// when there is no evidence at all. Callers that always know the device should
/// use this function so an `unknown` inference still references it.
pub fn infer_property_for(
    device_id: Uuid,
    property: Property,
    evidence: &[EvidenceRecord],
    now_ms: i64,
) -> InferenceRecord {
    let mut record = infer_property(property, evidence, now_ms);
    record.device_id = device_id;
    record
}

fn display_candidate(candidate: &serde_json::Value) -> String {
    match candidate {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// Group candidates that differ only by case, punctuation, or common corporate
/// suffixes. This avoids reporting a false conflict between, for example,
/// `Example Networks, Inc.` and `Example Networks`.
fn candidate_key(property: Property, candidate: &serde_json::Value) -> String {
    match candidate {
        serde_json::Value::String(value) => {
            let mut normalized = value.trim().to_lowercase();
            if property == Property::Manufacturer {
                normalized = normalize_manufacturer(&normalized);
            }
            normalized.split_whitespace().collect::<Vec<_>>().join(" ")
        }
        other => other.to_string(),
    }
}

fn normalize_manufacturer(value: &str) -> String {
    let replaced: String = value
        .chars()
        .map(|character| {
            if matches!(character, ',' | '.' | ';' | '-') {
                ' '
            } else {
                character
            }
        })
        .collect();
    let mut words: Vec<String> = replaced
        .split_whitespace()
        .map(|word| {
            word.trim_matches(|character: char| !character.is_alphanumeric())
                .to_string()
        })
        .filter(|word| !word.is_empty())
        .collect();
    let suffixes = [
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "ltd",
        "limited",
        "llc",
        "co",
        "company",
        "gmbh",
        "ag",
        "bv",
        "nv",
        "oy",
        "ab",
        "as",
        "kk",
        "plc",
        "pty",
    ];
    while words
        .last()
        .is_some_and(|word| suffixes.contains(&word.as_str()))
    {
        words.pop();
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use uuid::Uuid;

    use super::{InferenceStatus, UnknownReason, infer_property};
    use crate::domain::{Confidence, EvidenceRecord, Property, Source};

    fn evidence(
        candidate: &str,
        unit: &str,
        confidence: Confidence,
        expires_at_ms: Option<i64>,
    ) -> EvidenceRecord {
        EvidenceRecord {
            id: Uuid::now_v7(),
            observation_id: Uuid::now_v7(),
            device_id: Uuid::now_v7(),
            property: Property::Manufacturer,
            candidate: json!(candidate),
            source: Source::OuiRegistry,
            source_unit: unit.to_string(),
            confidence,
            rationale: "test".to_string(),
            observed_at_ms: 1_000,
            expires_at_ms,
        }
    }

    #[test]
    fn single_medium_source_stays_medium() {
        let record = infer_property(
            Property::Manufacturer,
            &[evidence("Vendor A", "oui:1", Confidence::Medium, None)],
            2_000,
        );
        assert_eq!(record.confidence, Confidence::Medium);
        assert_eq!(record.status, InferenceStatus::Supported);
        assert_eq!(record.value, Some(json!("Vendor A")));
    }

    #[test]
    fn two_independent_agreeing_sources_raise_confidence() {
        let record = infer_property(
            Property::Manufacturer,
            &[
                evidence("Vendor A", "oui:1", Confidence::Medium, None),
                evidence("Vendor A", "ssdp:2", Confidence::Medium, None),
            ],
            2_000,
        );
        assert_eq!(record.confidence, Confidence::High);
        assert_eq!(record.status, InferenceStatus::Supported);
    }

    #[test]
    fn correlated_fields_count_once() {
        let record = infer_property(
            Property::Manufacturer,
            &[
                evidence("Vendor A", "ssdp:description:1", Confidence::Medium, None),
                evidence("Vendor A", "ssdp:description:1", Confidence::Medium, None),
            ],
            2_000,
        );
        assert_eq!(record.confidence, Confidence::Medium);
    }

    #[test]
    fn conflicting_sources_are_preserved() {
        let record = infer_property(
            Property::Manufacturer,
            &[
                evidence("Vendor A", "oui:1", Confidence::Medium, None),
                evidence("Vendor B", "ssdp:2", Confidence::Medium, None),
            ],
            2_000,
        );
        assert_eq!(record.status, InferenceStatus::Conflicted);
        assert_eq!(record.value, None);
        assert_eq!(record.confidence, Confidence::Low);
        assert!(record.rationale.contains("Vendor A"));
        assert!(record.rationale.contains("Vendor B"));
    }

    #[test]
    fn expired_evidence_is_stale_unknown() {
        let record = infer_property(
            Property::Manufacturer,
            &[evidence(
                "Vendor A",
                "oui:1",
                Confidence::Medium,
                Some(1_500),
            )],
            2_000,
        );
        assert_eq!(record.status, InferenceStatus::Unknown);
        assert_eq!(record.unknown_reason, Some(UnknownReason::StaleEvidence));
    }

    #[test]
    fn no_evidence_is_unknown() {
        let record = infer_property(Property::Model, &[], 2_000);
        assert_eq!(record.status, InferenceStatus::Unknown);
        assert_eq!(record.unknown_reason, Some(UnknownReason::NoEvidence));
        assert_eq!(record.confidence, Confidence::Unknown);
    }

    #[test]
    fn manufacturer_punctuation_and_suffixes_do_not_conflict() {
        let record = infer_property(
            Property::Manufacturer,
            &[
                evidence("Example Networks, Inc.", "oui:1", Confidence::Medium, None),
                evidence("example networks", "ssdp:2", Confidence::Medium, None),
            ],
            2_000,
        );
        assert_eq!(record.status, InferenceStatus::Supported);
        assert_eq!(record.confidence, Confidence::High);
        assert_eq!(record.value, Some(json!("Example Networks, Inc.")));
    }

    #[test]
    fn genuinely_different_manufacturers_still_conflict() {
        let record = infer_property(
            Property::Manufacturer,
            &[
                evidence("Example Networks", "oui:1", Confidence::Medium, None),
                evidence("Other Vendor", "ssdp:2", Confidence::Medium, None),
            ],
            2_000,
        );
        assert_eq!(record.status, InferenceStatus::Conflicted);
    }
}
