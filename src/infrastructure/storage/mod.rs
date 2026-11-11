//! SQLite persistence.

mod migrations;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::application::model::{ExistingDevice, ScanResult};
use crate::domain::{
    Confidence, DeviceDetail, DeviceSummary, EvidenceRecord, IdentifierKind, IdentifierRecord,
    IdentityLink, InferenceRecord, InferenceStatus, InferenceView, MacAddress, ObservationRecord,
    UnknownReason, ids::new_id, time::now_ms,
};
use crate::infrastructure::oui::{
    self, OuiEntry, OuiError, OuiParseResult, OuiSourceMeta,
};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(#[from] migrations::MigrationError),
    #[error("OUI data error: {0}")]
    Oui(#[from] OuiError),
    #[error("invalid stored value: {0}")]
    InvalidValue(String),
}

#[derive(Debug, Clone)]
pub struct OuiSourceRow {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub content_sha256: String,
    pub imported_at_ms: i64,
    pub record_count: i64,
}

#[derive(Debug, Clone)]
pub struct OuiMatchRow {
    pub prefix_hex: String,
    pub prefix_bits: u8,
    pub organization: String,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OuiImportReport {
    pub source_id: String,
    pub record_count: usize,
    pub skipped: usize,
    pub version: String,
    pub content_sha256: String,
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                StorageError::InvalidValue(format!(
                    "creating database directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let connection = Connection::open(path)?;
        let mut store = Self::from_connection(connection)?;
        store.ensure_embedded_oui()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StorageError> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        migrations::migrate(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn schema_version(&self) -> Result<i64, StorageError> {
        Ok(self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    pub fn ensure_embedded_oui(&mut self) -> Result<(), StorageError> {
        if self.oui_source()?.is_some() {
            return Ok(());
        }
        let parsed = oui::embedded_entries()?;
        let meta = oui::embedded_source_meta(parsed.entries.len());
        self.insert_oui_entries(&parsed.entries, &meta)?;
        Ok(())
    }

    pub fn import_oui_csv(
        &mut self,
        contents: &str,
        version: Option<&str>,
    ) -> Result<OuiImportReport, StorageError> {
        let parsed: OuiParseResult = oui::parse_csv(contents)?;
        let hash = sha256_hex(contents.as_bytes());
        let version = version.unwrap_or("user-import").to_string();
        let meta = OuiSourceMeta {
            name: "IEEE OUI registry (user import)".to_string(),
            version: version.clone(),
            source_url: "user-supplied file".to_string(),
            content_sha256: hash.clone(),
            record_count: parsed.entries.len(),
        };
        let source_id = self.insert_oui_entries(&parsed.entries, &meta)?;
        Ok(OuiImportReport {
            source_id,
            record_count: parsed.entries.len(),
            skipped: parsed.skipped,
            version,
            content_sha256: hash,
        })
    }

    fn insert_oui_entries(
        &mut self,
        entries: &[OuiEntry],
        meta: &OuiSourceMeta,
    ) -> Result<String, StorageError> {
        let transaction = self.connection.transaction()?;
        let source_id = new_id().to_string();
        transaction.execute(
            "INSERT INTO oui_sources
             (id, name, version, source_url, content_sha256, imported_at_ms, record_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                source_id,
                meta.name,
                meta.version,
                meta.source_url,
                meta.content_sha256,
                now_ms(),
                meta.record_count as i64
            ],
        )?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO oui_prefixes
                 (prefix_hex, prefix_bits, organization, source_id)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for entry in entries {
                statement.execute(params![
                    entry.prefix_hex,
                    entry.prefix_bits as i64,
                    entry.organization,
                    source_id
                ])?;
            }
        }
        transaction.commit()?;
        Ok(source_id)
    }

    pub fn oui_source(&self) -> Result<Option<OuiSourceRow>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, name, version, source_url, content_sha256, imported_at_ms, record_count
                 FROM oui_sources ORDER BY imported_at_ms DESC LIMIT 1",
                [],
                |row| {
                    Ok(OuiSourceRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        version: row.get(2)?,
                        source_url: row.get(3)?,
                        content_sha256: row.get(4)?,
                        imported_at_ms: row.get(5)?,
                        record_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn lookup_oui(&self, mac: MacAddress) -> Result<Option<OuiMatchRow>, StorageError> {
        if mac.is_locally_administered() {
            return Ok(None);
        }
        for bits in [36_u8, 28, 24] {
            let prefix = mac
                .prefix_hex(bits)
                .map_err(|error| StorageError::InvalidValue(error.to_string()))?;
            let found = self
                .connection
                .query_row(
                    "SELECT p.prefix_hex, p.prefix_bits, p.organization, s.version
                     FROM oui_prefixes p
                     JOIN oui_sources s ON s.id = p.source_id
                     WHERE p.prefix_bits = ?1 AND p.prefix_hex = ?2
                     ORDER BY s.imported_at_ms DESC LIMIT 1",
                    params![bits as i64, prefix],
                    |row| {
                        Ok(OuiMatchRow {
                            prefix_hex: row.get(0)?,
                            prefix_bits: row.get::<_, i64>(1)? as u8,
                            organization: row.get(2)?,
                            source_version: row.get(3)?,
                        })
                    },
                )
                .optional()?;
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    pub fn load_existing_devices(
        &self,
        now_ms: i64,
        mac_window_ms: i64,
    ) -> Result<Vec<ExistingDevice>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT d.id, d.label, d.first_seen_ms, d.last_seen_ms,
                    i.kind, i.value, i.last_seen_ms
             FROM devices d
             LEFT JOIN device_identifiers i ON i.device_id = d.id
             WHERE d.merged_into IS NULL
             ORDER BY d.id",
        )?;
        let mut rows = statement.query([])?;
        let mut devices: HashMap<String, ExistingDevice> = HashMap::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let label: Option<String> = row.get(1)?;
            let first_seen_ms: i64 = row.get(2)?;
            let last_seen_ms: i64 = row.get(3)?;
            let entry = devices.entry(id.clone()).or_insert_with(|| ExistingDevice {
                id: Uuid::parse_str(&id).unwrap_or_default(),
                label,
                first_seen_ms,
                last_seen_ms,
                macs: Vec::new(),
                ips: Vec::new(),
                hostnames: Vec::new(),
            });

            let Some(kind) = row.get::<_, Option<String>>(4)? else {
                continue;
            };
            let Some(value) = row.get::<_, Option<String>>(5)? else {
                continue;
            };
            let Some(identifier_last_seen) = row.get::<_, Option<i64>>(6)? else {
                continue;
            };

            match kind.as_str() {
                "mac" => {
                    if identifier_last_seen >= now_ms - mac_window_ms {
                        if let Ok(mac) = value.parse::<MacAddress>() {
                            entry.macs.push((mac, identifier_last_seen));
                        }
                    }
                }
                "ip" => {
                    if let Ok(ip) = value.parse() {
                        entry.ips.push((ip, identifier_last_seen));
                    }
                }
                "hostname" | "dns_name" => {
                    entry.hostnames.push((value, identifier_last_seen));
                }
                _ => {}
            }
        }
        Ok(devices.into_values().collect())
    }

    pub fn save_scan(&mut self, scan: &ScanResult) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        Self::persist_context(&transaction, scan)?;
        Self::persist_session(&transaction, scan)?;

        for device in &scan.devices {
            transaction.execute(
                "INSERT INTO devices (id, label, first_seen_ms, last_seen_ms, merged_into)
                 VALUES (?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                    label = COALESCE(excluded.label, devices.label),
                    last_seen_ms = MAX(devices.last_seen_ms, excluded.last_seen_ms)",
                params![
                    device.id.to_string(),
                    device.label,
                    device.first_seen_ms,
                    device.last_seen_ms
                ],
            )?;

            for identifier in &device.identifiers {
                Self::upsert_identifier(&transaction, identifier)?;
            }
        }

        for observation in &scan.observations {
            Self::insert_observation(&transaction, observation)?;
        }
        for evidence in &scan.evidence {
            Self::insert_evidence(&transaction, evidence)?;
        }
        for inference in &scan.inferences {
            Self::insert_inference(&transaction, inference)?;
        }
        for link in &scan.identity_links {
            transaction.execute(
                "INSERT OR IGNORE INTO identity_links
                 (id, from_device_id, to_device_id, basis, confidence, status, rationale, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    link.id.to_string(),
                    link.from_device_id.to_string(),
                    link.to_device_id.to_string(),
                    link.basis,
                    link.confidence.as_str(),
                    link.status.as_str(),
                    link.rationale,
                    link.created_at_ms
                ],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }

    fn persist_context(
        transaction: &Transaction<'_>,
        scan: &ScanResult,
    ) -> Result<(), StorageError> {
        let now = scan.started_at_ms;
        let mut interface_ids: HashMap<String, String> = HashMap::new();
        for interface in &scan.context.interfaces {
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT id FROM interfaces WHERE name = ?1",
                    params![interface.name],
                    |row| row.get(0),
                )
                .optional()?;
            let interface_id = existing.unwrap_or_else(|| new_id().to_string());
            transaction.execute(
                "INSERT INTO interfaces
                 (id, name, index_no, mac, mtu, is_up, is_loopback, first_seen_ms, last_seen_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(name) DO UPDATE SET
                    index_no = excluded.index_no,
                    mac = excluded.mac,
                    mtu = excluded.mtu,
                    is_up = excluded.is_up,
                    is_loopback = excluded.is_loopback,
                    last_seen_ms = excluded.last_seen_ms",
                params![
                    interface_id,
                    interface.name,
                    interface.index as i64,
                    interface.mac.map(|mac| mac.to_string()),
                    interface.mtu.map(|mtu| mtu as i64),
                    interface.is_up as i64,
                    interface.is_loopback as i64,
                    now,
                    now
                ],
            )?;
            interface_ids.insert(interface.name.clone(), interface_id.clone());

            for address in &interface.addresses {
                let existing_address: Option<String> = transaction
                    .query_row(
                        "SELECT id FROM interface_addresses
                         WHERE interface_id = ?1 AND address = ?2 AND prefix_len = ?3",
                        params![interface_id, address.address.to_string(), address.prefix_len as i64],
                        |row| row.get(0),
                    )
                    .optional()?;
                match existing_address {
                    Some(id) => {
                        transaction.execute(
                            "UPDATE interface_addresses SET last_seen_ms = ?1 WHERE id = ?2",
                            params![now, id],
                        )?;
                    }
                    None => {
                        transaction.execute(
                            "INSERT INTO interface_addresses
                             (id, interface_id, address, prefix_len, family, scope, first_seen_ms, last_seen_ms)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                new_id().to_string(),
                                interface_id,
                                address.address.to_string(),
                                address.prefix_len as i64,
                                address.family as i64,
                                address.scope,
                                now,
                                now
                            ],
                        )?;
                    }
                }
            }
        }

        for segment in scan.context.segments() {
            let Some(interface_id) = interface_ids.get(&segment.interface) else {
                continue;
            };
            transaction.execute(
                "INSERT INTO network_segments
                 (id, interface_id, prefix, gateway, first_seen_ms, last_seen_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(interface_id, prefix) DO UPDATE SET
                    gateway = excluded.gateway,
                    last_seen_ms = excluded.last_seen_ms",
                params![
                    new_id().to_string(),
                    interface_id,
                    segment.prefix.to_string(),
                    segment.gateway.map(|gateway| gateway.to_string()),
                    now,
                    now
                ],
            )?;
        }

        Ok(())
    }

    fn persist_session(
        transaction: &Transaction<'_>,
        scan: &ScanResult,
    ) -> Result<(), StorageError> {
        let errors: Vec<_> = scan
            .provider_reports
            .iter()
            .filter_map(|report| report.error.clone())
            .collect();
        transaction.execute(
            "INSERT INTO scan_sessions
             (id, scope_json, methods_json, config_json, started_at_ms, finished_at_ms, status, errors_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                finished_at_ms = excluded.finished_at_ms,
                status = excluded.status,
                errors_json = excluded.errors_json",
            params![
                scan.session_id.to_string(),
                json_string(&scan.scope),
                json_string(&scan.config.methods),
                json_string(&scan.config),
                scan.started_at_ms,
                scan.finished_at_ms,
                scan.status.as_str(),
                json_string(&errors)
            ],
        )?;
        Ok(())
    }

    fn upsert_identifier(
        transaction: &Transaction<'_>,
        identifier: &IdentifierRecord,
    ) -> Result<(), StorageError> {
        let existing: Option<String> = transaction
            .query_row(
                "SELECT id FROM device_identifiers
                 WHERE device_id = ?1 AND kind = ?2 AND normalized = ?3
                 ORDER BY last_seen_ms DESC LIMIT 1",
                params![
                    identifier.device_id.to_string(),
                    identifier.kind.as_str(),
                    identifier.normalized
                ],
                |row| row.get(0),
            )
            .optional()?;

        match existing {
            Some(id) => {
                transaction.execute(
                    "UPDATE device_identifiers SET
                        value = ?1, source = ?2, last_seen_ms = ?3,
                        confidence = ?4, details_json = ?5
                     WHERE id = ?6",
                    params![
                        identifier.value,
                        identifier.source.as_str(),
                        identifier.last_seen_ms,
                        identifier.confidence.as_str(),
                        json_string(&identifier.details),
                        id
                    ],
                )?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO device_identifiers
                     (id, device_id, kind, value, normalized, source,
                      first_seen_ms, last_seen_ms, confidence, details_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        identifier.id.to_string(),
                        identifier.device_id.to_string(),
                        identifier.kind.as_str(),
                        identifier.value,
                        identifier.normalized,
                        identifier.source.as_str(),
                        identifier.first_seen_ms,
                        identifier.last_seen_ms,
                        identifier.confidence.as_str(),
                        json_string(&identifier.details)
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn insert_observation(
        transaction: &Transaction<'_>,
        observation: &ObservationRecord,
    ) -> Result<(), StorageError> {
        transaction.execute(
            "INSERT OR IGNORE INTO observations
             (id, session_id, subject_type, subject_id, kind, property,
              value_json, source, method, observed_at_ms, expires_at_ms, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                observation.id.to_string(),
                observation.session_id.map(|id| id.to_string()),
                observation.subject_type.as_str(),
                observation.subject_id,
                observation.kind.as_str(),
                observation.property,
                json_string(&observation.value),
                observation.source.as_str(),
                observation.method,
                observation.observed_at_ms,
                observation.expires_at_ms,
                json_string(&observation.details)
            ],
        )?;
        Ok(())
    }

    fn insert_evidence(
        transaction: &Transaction<'_>,
        evidence: &EvidenceRecord,
    ) -> Result<(), StorageError> {
        transaction.execute(
            "INSERT OR IGNORE INTO evidence
             (id, observation_id, device_id, property, candidate_json, source,
              source_unit, confidence, rationale, observed_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                evidence.id.to_string(),
                evidence.observation_id.to_string(),
                evidence.device_id.to_string(),
                evidence.property.as_str(),
                json_string(&evidence.candidate),
                evidence.source.as_str(),
                evidence.source_unit,
                evidence.confidence.as_str(),
                evidence.rationale,
                evidence.observed_at_ms,
                evidence.expires_at_ms
            ],
        )?;
        Ok(())
    }

    fn insert_inference(
        transaction: &Transaction<'_>,
        inference: &InferenceRecord,
    ) -> Result<(), StorageError> {
        transaction.execute(
            "INSERT OR IGNORE INTO inferences
             (id, device_id, property, value_json, confidence, status,
              rationale, evidence_ids_json, unknown_reason, computed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                inference.id.to_string(),
                inference.device_id.to_string(),
                inference.property.as_str(),
                inference.value.as_ref().map(json_string),
                inference.confidence.as_str(),
                inference.status.as_str(),
                inference.rationale,
                json_string(&inference.evidence_ids),
                inference.unknown_reason.map(|reason| reason.as_str()),
                inference.computed_at_ms
            ],
        )?;
        Ok(())
    }

    pub fn list_devices(&self, session: Option<Uuid>) -> Result<Vec<DeviceSummary>, StorageError> {
        let session_devices: Option<HashSet<String>> = match session {
            Some(session_id) => {
                let mut statement = self.connection.prepare(
                    "SELECT DISTINCT subject_id FROM observations
                     WHERE session_id = ?1 AND subject_type = 'device'",
                )?;
                let rows = statement.query_map(params![session_id.to_string()], |row| {
                    row.get::<_, String>(0)
                })?;
                let mut set = HashSet::new();
                for row in rows {
                    set.insert(row?);
                }
                Some(set)
            }
            None => None,
        };

        let mut statement = self.connection.prepare(
            "SELECT id FROM devices WHERE merged_into IS NULL ORDER BY last_seen_ms DESC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut summaries = Vec::new();
        for row in rows {
            let id = row?;
            if let Some(filter) = &session_devices {
                if !filter.contains(&id) {
                    continue;
                }
            }
            if let Some(summary) = self.load_summary(&id)? {
                summaries.push(summary);
            }
        }

        summaries.sort_by(|left, right| {
            let left_ip = left.ips.first().and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
            let right_ip = right.ips.first().and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
            left_ip
                .cmp(&right_ip)
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        Ok(summaries)
    }

    fn load_summary(&self, device_id: &str) -> Result<Option<DeviceSummary>, StorageError> {
        let device = self
            .connection
            .query_row(
                "SELECT id, label, first_seen_ms, last_seen_ms FROM devices WHERE id = ?1",
                params![device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, label, first_seen_ms, last_seen_ms)) = device else {
            return Ok(None);
        };

        let mut identifiers = self.load_identifiers(device_id)?;
        identifiers.sort_by(|left, right| right.last_seen_ms.cmp(&left.last_seen_ms));

        let ips = identifiers
            .iter()
            .filter(|identifier| identifier.kind == IdentifierKind::Ip)
            .map(|identifier| identifier.value.clone())
            .collect();
        let macs = identifiers
            .iter()
            .filter(|identifier| identifier.kind == IdentifierKind::Mac)
            .map(|identifier| identifier.value.clone())
            .collect();
        let hostnames = identifiers
            .iter()
            .filter(|identifier| {
                matches!(
                    identifier.kind,
                    IdentifierKind::Hostname | IdentifierKind::DnsName
                )
            })
            .map(|identifier| identifier.value.clone())
            .collect();

        let mut manufacturer = default_inference_view("manufacturer");
        let mut category = default_inference_view("category");
        let mut os = default_inference_view("os");
        let mut model = default_inference_view("model");

        let mut statement = self.connection.prepare(
            "SELECT property, value_json, confidence, status, unknown_reason, rationale
             FROM inferences WHERE device_id = ?1 ORDER BY computed_at_ms DESC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut seen = HashSet::new();
        for row in rows {
            let (property, value_json, confidence, status, unknown_reason, rationale) = row?;
            if !seen.insert(property.clone()) {
                continue;
            }
            let view = InferenceView {
                value: value_json
                    .as_deref()
                    .and_then(|value| serde_json::from_str::<Value>(value).ok()),
                confidence: confidence
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        StorageError::InvalidValue(error.to_string())
                    })?,
                status: status.parse().map_err(|error: crate::domain::DomainError| {
                    StorageError::InvalidValue(error.to_string())
                })?,
                unknown_reason: match unknown_reason {
                    Some(value) => Some(value.parse().map_err(
                        |error: crate::domain::DomainError| {
                            StorageError::InvalidValue(error.to_string())
                        },
                    )?),
                    None => None,
                },
                rationale,
            };
            match property.as_str() {
                "manufacturer" => manufacturer = view,
                "category" => category = view,
                "os" => os = view,
                "model" => model = view,
                _ => {}
            }
        }

        let last_session_id: Option<String> = self
            .connection
            .query_row(
                "SELECT session_id FROM observations
                 WHERE subject_type = 'device' AND subject_id = ?1
                 ORDER BY observed_at_ms DESC LIMIT 1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        Ok(Some(DeviceSummary {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            label,
            ips,
            macs,
            hostnames,
            manufacturer,
            category,
            os,
            model,
            first_seen_ms,
            last_seen_ms,
            last_session_id: last_session_id.and_then(|value| Uuid::parse_str(&value).ok()),
        }))
    }

    fn load_identifiers(&self, device_id: &str) -> Result<Vec<IdentifierRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, device_id, kind, value, normalized, source,
                    first_seen_ms, last_seen_ms, confidence, details_json
             FROM device_identifiers WHERE device_id = ?1 ORDER BY last_seen_ms DESC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(IdentifierRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                device_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                kind: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                value: row.get(3)?,
                normalized: row.get(4)?,
                source: row
                    .get::<_, String>(5)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                first_seen_ms: row.get(6)?,
                last_seen_ms: row.get(7)?,
                confidence: row
                    .get::<_, String>(8)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                details: serde_json::from_str(&row.get::<_, String>(9)?).unwrap_or(Value::Null),
            })
        })?;
        let mut identifiers = Vec::new();
        for row in rows {
            identifiers.push(row?);
        }
        Ok(identifiers)
    }

    pub fn get_device(&self, id: Uuid) -> Result<Option<DeviceDetail>, StorageError> {
        let device_id = id.to_string();
        let Some(summary) = self.load_summary(&device_id)? else {
            return Ok(None);
        };

        let identifiers = self.load_identifiers(&device_id)?;
        let evidence = self.load_evidence(&device_id)?;
        let observations = self.load_observations(&device_id)?;
        let inferences = self.load_inferences(&device_id)?;
        let links = self.load_links(&device_id)?;

        Ok(Some(DeviceDetail {
            summary,
            identifiers,
            evidence,
            observations,
            inferences,
            links,
        }))
    }

    fn load_evidence(&self, device_id: &str) -> Result<Vec<EvidenceRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, observation_id, device_id, property, candidate_json, source,
                    source_unit, confidence, rationale, observed_at_ms, expires_at_ms
             FROM evidence WHERE device_id = ?1 ORDER BY observed_at_ms DESC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(EvidenceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                observation_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                device_id: Uuid::parse_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                property: row
                    .get::<_, String>(3)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                candidate: serde_json::from_str(&row.get::<_, String>(4)?)
                    .unwrap_or(Value::Null),
                source: row
                    .get::<_, String>(5)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                source_unit: row.get(6)?,
                confidence: row
                    .get::<_, String>(7)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                rationale: row.get(8)?,
                observed_at_ms: row.get(9)?,
                expires_at_ms: row.get(10)?,
            })
        })?;
        let mut evidence = Vec::new();
        for row in rows {
            evidence.push(row?);
        }
        Ok(evidence)
    }

    fn load_observations(&self, device_id: &str) -> Result<Vec<ObservationRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, session_id, subject_type, subject_id, kind, property,
                    value_json, source, method, observed_at_ms, expires_at_ms, details_json
             FROM observations
             WHERE subject_type = 'device' AND subject_id = ?1
             ORDER BY observed_at_ms DESC LIMIT 500",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(ObservationRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                session_id: row
                    .get::<_, Option<String>>(1)?
                    .and_then(|value| Uuid::parse_str(&value).ok()),
                subject_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                subject_id: row.get(3)?,
                kind: row
                    .get::<_, String>(4)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                property: row.get(5)?,
                value: serde_json::from_str(&row.get::<_, String>(6)?)
                    .unwrap_or(Value::Null),
                source: row
                    .get::<_, String>(7)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                method: row.get(8)?,
                observed_at_ms: row.get(9)?,
                expires_at_ms: row.get(10)?,
                details: serde_json::from_str(&row.get::<_, String>(11)?)
                    .unwrap_or(Value::Null),
            })
        })?;
        let mut observations = Vec::new();
        for row in rows {
            observations.push(row?);
        }
        Ok(observations)
    }

    fn load_inferences(&self, device_id: &str) -> Result<Vec<InferenceRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, device_id, property, value_json, confidence, status,
                    rationale, evidence_ids_json, unknown_reason, computed_at_ms
             FROM inferences WHERE device_id = ?1 ORDER BY computed_at_ms DESC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(InferenceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                device_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                property: row
                    .get::<_, String>(2)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                value: row
                    .get::<_, Option<String>>(3)?
                    .and_then(|value| serde_json::from_str::<Value>(&value).ok()),
                confidence: row
                    .get::<_, String>(4)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                status: row
                    .get::<_, String>(5)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                rationale: row.get(6)?,
                evidence_ids: serde_json::from_str(&row.get::<_, String>(7)?)
                    .unwrap_or_default(),
                unknown_reason: match row.get::<_, Option<String>>(8)? {
                    Some(value) => Some(value.parse().map_err(
                        |error: crate::domain::DomainError| {
                            rusqlite::Error::InvalidParameterName(error.to_string())
                        },
                    )?),
                    None => None,
                },
                computed_at_ms: row.get(9)?,
            })
        })?;
        let mut inferences = Vec::new();
        for row in rows {
            inferences.push(row?);
        }
        Ok(inferences)
    }

    fn load_links(&self, device_id: &str) -> Result<Vec<IdentityLink>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, from_device_id, to_device_id, basis, confidence, status,
                    rationale, created_at_ms
             FROM identity_links
             WHERE from_device_id = ?1 OR to_device_id = ?1
             ORDER BY created_at_ms DESC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(IdentityLink {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                from_device_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                to_device_id: Uuid::parse_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                basis: row.get(3)?,
                confidence: row
                    .get::<_, String>(4)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                status: row
                    .get::<_, String>(5)?
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    })?,
                rationale: row.get(6)?,
                created_at_ms: row.get(7)?,
            })
        })?;
        let mut links = Vec::new();
        for row in rows {
            links.push(row?);
        }
        Ok(links)
    }
}

fn default_inference_view(property: &str) -> InferenceView {
    InferenceView {
        value: None,
        confidence: Confidence::Unknown,
        status: InferenceStatus::Unknown,
        unknown_reason: Some(UnknownReason::NoEvidence),
        rationale: format!("No inference recorded for {property}."),
    }
}

fn json_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
