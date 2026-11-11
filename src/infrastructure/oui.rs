//! IEEE OUI registry parsing and lookup.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::MacAddress;

pub const EMBEDDED_OUI_VERSION: &str = "2026-11-11";
pub const EMBEDDED_OUI_NAME: &str = "IEEE MA-L/MA-M/MA-S";
pub const EMBEDDED_OUI_SOURCE_URL: &str =
    "https://standards-oui.ieee.org/ (oui.csv, oui28/mam.csv, oui36/oui36.csv)";

const EMBEDDED_FILES: &[(&str, &str)] = &[
    ("MA-L", include_str!("../../data/oui/oui.csv")),
    ("MA-M", include_str!("../../data/oui/mam.csv")),
    ("MA-S", include_str!("../../data/oui/oui36.csv")),
];

#[derive(Debug, Error)]
pub enum OuiError {
    #[error("invalid OUI CSV: {0}")]
    Csv(String),
    #[error("OUI CSV is missing required column {0:?}")]
    MissingColumn(&'static str),
    #[error("OUI CSV has no valid assignment rows")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuiEntry {
    pub prefix_hex: String,
    pub prefix_bits: u8,
    pub organization: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuiMatch {
    pub prefix_hex: String,
    pub prefix_bits: u8,
    pub organization: String,
}

#[derive(Debug, Clone)]
pub struct OuiParseResult {
    pub entries: Vec<OuiEntry>,
    pub skipped: usize,
}

#[derive(Debug, Clone)]
pub struct OuiSourceMeta {
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub content_sha256: String,
    pub record_count: usize,
}

/// Parse an IEEE registry CSV (MA-L, MA-M, or MA-S).
pub fn parse_csv(contents: &str) -> Result<OuiParseResult, OuiError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(contents.as_bytes());

    let headers = reader
        .headers()
        .map_err(|error| OuiError::Csv(error.to_string()))?;
    let assignment_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("Assignment"))
        .ok_or(OuiError::MissingColumn("Assignment"))?;
    let organization_index = headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case("Organization Name"))
        .ok_or(OuiError::MissingColumn("Organization Name"))?;

    let mut unique: HashMap<(String, u8), String> = HashMap::new();
    let mut skipped = 0_usize;

    for record in reader.records() {
        let record = record.map_err(|error| OuiError::Csv(error.to_string()))?;
        let Some(assignment) = record.get(assignment_index) else {
            skipped += 1;
            continue;
        };
        let Some(organization) = record.get(organization_index) else {
            skipped += 1;
            continue;
        };

        let prefix_hex = assignment.trim().to_ascii_uppercase();
        let organization = organization.trim();
        let Some(prefix_bits) = prefix_bits_for(&prefix_hex) else {
            skipped += 1;
            continue;
        };
        if organization.is_empty() {
            skipped += 1;
            continue;
        }

        unique.insert((prefix_hex, prefix_bits), organization.to_string());
    }

    if unique.is_empty() {
        return Err(OuiError::Empty);
    }

    let mut entries: Vec<OuiEntry> = unique
        .into_iter()
        .map(|((prefix_hex, prefix_bits), organization)| OuiEntry {
            prefix_hex,
            prefix_bits,
            organization,
        })
        .collect();
    entries.sort_by(|left, right| {
        right
            .prefix_bits
            .cmp(&left.prefix_bits)
            .then_with(|| left.prefix_hex.cmp(&right.prefix_hex))
    });

    Ok(OuiParseResult { entries, skipped })
}

fn prefix_bits_for(prefix_hex: &str) -> Option<u8> {
    if !prefix_hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    match prefix_hex.len() {
        6 => Some(24),
        7 => Some(28),
        9 => Some(36),
        _ => None,
    }
}

/// Parse all three embedded registry files into one entry list.
pub fn embedded_entries() -> Result<OuiParseResult, OuiError> {
    let mut entries = Vec::new();
    let mut skipped = 0_usize;
    for (_, contents) in EMBEDDED_FILES {
        let parsed = parse_csv(contents)?;
        entries.extend(parsed.entries);
        skipped += parsed.skipped;
    }
    Ok(OuiParseResult { entries, skipped })
}

/// Hash the embedded registry content for provenance.
pub fn embedded_content_hash() -> String {
    let mut hasher = Sha256::new();
    for (_, contents) in EMBEDDED_FILES {
        hasher.update(contents.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub fn embedded_source_meta(record_count: usize) -> OuiSourceMeta {
    OuiSourceMeta {
        name: EMBEDDED_OUI_NAME.to_string(),
        version: EMBEDDED_OUI_VERSION.to_string(),
        source_url: EMBEDDED_OUI_SOURCE_URL.to_string(),
        content_sha256: embedded_content_hash(),
        record_count,
    }
}

/// Longest-prefix OUI lookup. Callers must not use this for locally
/// administered MAC addresses.
pub fn lookup<'a>(entries: &'a [OuiEntry], mac: MacAddress) -> Option<&'a OuiEntry> {
    for bits in [36_u8, 28, 24] {
        let prefix = mac.prefix_hex(bits).ok()?;
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.prefix_bits == bits && entry.prefix_hex == prefix)
        {
            return Some(entry);
        }
    }
    None
}

/// Lookup that refuses locally administered addresses.
pub fn lookup_global<'a>(entries: &'a [OuiEntry], mac: MacAddress) -> Option<&'a OuiEntry> {
    if mac.is_locally_administered() {
        None
    } else {
        lookup(entries, mac)
    }
}

#[cfg(test)]
mod tests {
    use super::{lookup, lookup_global, parse_csv};
    use crate::domain::MacAddress;

    const FIXTURE: &str = r#"Registry,Assignment,Organization Name,Organization Address
MA-L,3CCD5D,"Xiaomi Communications Co Ltd","Beijing CN"
MA-L,001122,"Example Networks","Somewhere"
MA-M,C85CE27,"Synergy Systems","Faridabad"
MA-S,8C1F64AFA,"Data Electronic Devices","Salem"
MA-L,NOTHEX,"Invalid","Nowhere"
MA-L,123456,"","Empty organization"
"#;

    #[test]
    fn parses_registry_rows_and_skips_invalid() {
        let parsed = parse_csv(FIXTURE).unwrap();
        assert_eq!(parsed.entries.len(), 4);
        assert_eq!(parsed.skipped, 2);
    }

    #[test]
    fn longest_prefix_wins() {
        let parsed = parse_csv(FIXTURE).unwrap();
        let mac: MacAddress = "8c:1f:64:af:a0:01".parse().unwrap();
        let found = lookup(&parsed.entries, mac).unwrap();
        assert_eq!(found.prefix_bits, 36);
        assert_eq!(found.organization, "Data Electronic Devices");
    }

    #[test]
    fn local_mac_is_not_attributed() {
        let parsed = parse_csv(FIXTURE).unwrap();
        let mac: MacAddress = "02:11:22:33:44:55".parse().unwrap();
        assert!(lookup_global(&parsed.entries, mac).is_none());
    }

    #[test]
    fn missing_columns_are_rejected() {
        assert!(parse_csv("Registry,Assignment\nMA-L,001122\n").is_err());
    }
}
