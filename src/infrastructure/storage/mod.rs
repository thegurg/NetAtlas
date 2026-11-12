//! SQLite persistence.

mod migrations;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::application::model::{
    DeviceHistoryEntry, ExistingDevice, ScanResult, SegmentRecord, SessionRecord, SessionStatus,
};
use crate::domain::{
    Confidence, DEFAULT_STALE_AFTER_MS, DeviceDetail, DeviceSessionSnapshot, DeviceSummary,
    EvidenceRecord, Freshness, IdentifierKind, IdentifierRecord, IdentityLink, InferenceRecord,
    InferenceSnapshot, InferenceStatus, InferenceView, MacAddress, ObservationRecord,
    ServiceRecord, UnknownReason, ids::new_id, time::now_ms,
};
use crate::infrastructure::oui::{self, OuiEntry, OuiError, OuiParseResult, OuiSourceMeta};

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

#[derive(Debug, Clone, serde::Serialize)]
pub struct OuiSourceRow {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub content_sha256: String,
    pub imported_at_ms: i64,
    pub record_count: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
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
                 FROM oui_sources ORDER BY imported_at_ms DESC, id DESC LIMIT 1",
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
                     ORDER BY s.imported_at_ms DESC, s.id DESC LIMIT 1",
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

    /// Load the prefixes from the most recent OUI source for in-memory lookup.
    pub fn oui_entries(&self) -> Result<Vec<OuiEntry>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT prefix_hex, prefix_bits, organization
             FROM oui_prefixes
             WHERE source_id = (SELECT id FROM oui_sources ORDER BY imported_at_ms DESC, id DESC LIMIT 1)",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(OuiEntry {
                prefix_hex: row.get(0)?,
                prefix_bits: row.get::<_, i64>(1)? as u8,
                organization: row.get(2)?,
            })
        })?;
        let mut unique: HashMap<(String, u8), OuiEntry> = HashMap::new();
        for row in rows {
            let entry = row?;
            unique.insert((entry.prefix_hex.clone(), entry.prefix_bits), entry);
        }
        let mut entries: Vec<OuiEntry> = unique.into_values().collect();
        entries.sort_by(|left, right| {
            right
                .prefix_bits
                .cmp(&left.prefix_bits)
                .then_with(|| left.prefix_hex.cmp(&right.prefix_hex))
        });
        Ok(entries)
    }

    pub fn load_existing_devices(
        &self,
        now_ms: i64,
        mac_window_ms: i64,
    ) -> Result<Vec<ExistingDevice>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT d.id, d.label, d.first_seen_ms, d.last_seen_ms,
                    i.kind, i.value, i.normalized, i.last_seen_ms
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
                upnp_udns: Vec::new(),
                mdns_instances: Vec::new(),
            });

            let Some(kind) = row.get::<_, Option<String>>(4)? else {
                continue;
            };
            let Some(value) = row.get::<_, Option<String>>(5)? else {
                continue;
            };
            let Some(normalized) = row.get::<_, Option<String>>(6)? else {
                continue;
            };
            let Some(identifier_last_seen) = row.get::<_, Option<i64>>(7)? else {
                continue;
            };

            match kind.as_str() {
                "mac" => {
                    if identifier_last_seen >= now_ms - mac_window_ms
                        && let Ok(mac) = value.parse::<MacAddress>()
                    {
                        entry.macs.push((mac, identifier_last_seen));
                    }
                }
                "ip" => {
                    if let Ok(ip) = value.parse() {
                        entry.ips.push((ip, identifier_last_seen));
                    }
                }
                "hostname" | "dns_name" => {
                    entry.hostnames.push((normalized, identifier_last_seen));
                }
                "upnp_udn" => {
                    entry.upnp_udns.push((normalized, identifier_last_seen));
                }
                "mdns_instance" => {
                    entry
                        .mdns_instances
                        .push((normalized, identifier_last_seen));
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
        for service in &scan.services {
            Self::insert_service(&transaction, service)?;
        }
        for evidence in &scan.evidence {
            Self::insert_evidence(&transaction, evidence)?;
        }
        for inference in &scan.inferences {
            Self::insert_inference(&transaction, inference)?;
        }
        Self::insert_device_sessions(&transaction, scan)?;
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
                        params![
                            interface_id,
                            address.address.to_string(),
                            address.prefix_len as i64
                        ],
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

    fn insert_service(
        transaction: &Transaction<'_>,
        service: &ServiceRecord,
    ) -> Result<(), StorageError> {
        transaction.execute(
            "INSERT OR IGNORE INTO services
             (id, device_id, ip, port, transport, protocol, product, version,
              banner, tls_json, source, observed_at_ms, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12)",
            params![
                service.id.to_string(),
                service.device_id.to_string(),
                service.ip.to_string(),
                service.port as i64,
                service.transport.as_str(),
                service.protocol,
                service.product,
                service.version,
                service.banner,
                service.source.as_str(),
                service.observed_at_ms,
                json_string(&service.details)
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

    fn insert_device_sessions(
        transaction: &Transaction<'_>,
        scan: &ScanResult,
    ) -> Result<(), StorageError> {
        for device in &scan.devices {
            let mut ips = Vec::new();
            let mut macs = Vec::new();
            let mut hostnames = Vec::new();
            for identifier in &device.identifiers {
                match identifier.kind {
                    IdentifierKind::Ip => ips.push(identifier.value.clone()),
                    IdentifierKind::Mac => macs.push(identifier.value.clone()),
                    IdentifierKind::Hostname | IdentifierKind::DnsName => {
                        hostnames.push(identifier.value.clone());
                    }
                    _ => {}
                }
            }
            ips.sort();
            ips.dedup();
            macs.sort();
            macs.dedup();
            hostnames.sort();
            hostnames.dedup();

            let mut inferences: Vec<InferenceSnapshot> = scan
                .inferences
                .iter()
                .filter(|inference| inference.device_id == device.id)
                .map(InferenceSnapshot::from)
                .collect();
            inferences.sort_by_key(|inference| inference.property.as_str());

            transaction.execute(
                "INSERT INTO device_sessions
                 (session_id, device_id, first_seen_ms, last_seen_ms,
                  ips_json, macs_json, hostnames_json, inferences_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(session_id, device_id) DO UPDATE SET
                    first_seen_ms = excluded.first_seen_ms,
                    last_seen_ms = excluded.last_seen_ms,
                    ips_json = excluded.ips_json,
                    macs_json = excluded.macs_json,
                    hostnames_json = excluded.hostnames_json,
                    inferences_json = excluded.inferences_json",
                params![
                    scan.session_id.to_string(),
                    device.id.to_string(),
                    device.first_seen_ms,
                    device.last_seen_ms,
                    json_string(&ips),
                    json_string(&macs),
                    json_string(&hostnames),
                    json_string(&inferences),
                ],
            )?;
        }
        Ok(())
    }

    pub fn list_devices(&self, session: Option<Uuid>) -> Result<Vec<DeviceSummary>, StorageError> {
        self.list_devices_at(session, now_ms())
    }

    pub fn list_devices_at(
        &self,
        session: Option<Uuid>,
        now_ms: i64,
    ) -> Result<Vec<DeviceSummary>, StorageError> {
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
            if let Some(filter) = &session_devices
                && !filter.contains(&id)
            {
                continue;
            }
            if let Some(summary) = self.load_summary(&id, now_ms)? {
                summaries.push(summary);
            }
        }

        summaries.sort_by(|left, right| {
            let left_ip = left
                .ips
                .first()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
            let right_ip = right
                .ips
                .first()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
            left_ip
                .cmp(&right_ip)
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        Ok(summaries)
    }

    fn load_summary(
        &self,
        device_id: &str,
        now_ms: i64,
    ) -> Result<Option<DeviceSummary>, StorageError> {
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
        identifiers.sort_by_key(|left| std::cmp::Reverse(left.last_seen_ms));

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
                status: status
                    .parse()
                    .map_err(|error: crate::domain::DomainError| {
                        StorageError::InvalidValue(error.to_string())
                    })?,
                unknown_reason: match unknown_reason {
                    Some(value) => {
                        Some(value.parse().map_err(|error: crate::domain::DomainError| {
                            StorageError::InvalidValue(error.to_string())
                        })?)
                    }
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
            freshness: Freshness::new(last_seen_ms, now_ms, DEFAULT_STALE_AFTER_MS),
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
                kind: row.get::<_, String>(2)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                value: row.get(3)?,
                normalized: row.get(4)?,
                source: row.get::<_, String>(5)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                first_seen_ms: row.get(6)?,
                last_seen_ms: row.get(7)?,
                confidence: row.get::<_, String>(8)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
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
        let Some(summary) = self.load_summary(&device_id, now_ms())? else {
            return Ok(None);
        };

        let identifiers = self.load_identifiers(&device_id)?;
        let evidence = self.load_evidence(&device_id)?;
        let observations = self.load_observations(&device_id)?;
        let inferences = self.load_inferences(&device_id)?;
        let links = self.load_links(&device_id)?;
        let services = self.load_services(&device_id)?;

        Ok(Some(DeviceDetail {
            summary,
            identifiers,
            evidence,
            observations,
            inferences,
            links,
            services,
        }))
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.scope_json, s.methods_json, s.started_at_ms, s.finished_at_ms,
                    s.status, s.errors_json,
                    (SELECT COUNT(*) FROM device_sessions ds WHERE ds.session_id = s.id)
             FROM scan_sessions s
             ORDER BY s.started_at_ms DESC, s.id DESC",
        )?;
        let mut rows = statement.query([])?;
        let mut sessions = Vec::new();
        while let Some(row) = rows.next()? {
            sessions.push(session_from_row(row, 0)?);
        }
        Ok(sessions)
    }

    pub fn latest_session(&self) -> Result<Option<SessionRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.scope_json, s.methods_json, s.started_at_ms, s.finished_at_ms,
                    s.status, s.errors_json,
                    (SELECT COUNT(*) FROM device_sessions ds WHERE ds.session_id = s.id)
             FROM scan_sessions s
             ORDER BY s.started_at_ms DESC, s.id DESC
             LIMIT 1",
        )?;
        let mut rows = statement.query([])?;
        match rows.next()? {
            Some(row) => Ok(Some(session_from_row(row, 0)?)),
            None => Ok(None),
        }
    }

    pub fn get_session(&self, id: Uuid) -> Result<Option<SessionRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.scope_json, s.methods_json, s.started_at_ms, s.finished_at_ms,
                    s.status, s.errors_json,
                    (SELECT COUNT(*) FROM device_sessions ds WHERE ds.session_id = s.id)
             FROM scan_sessions s
             WHERE s.id = ?1",
        )?;
        let mut rows = statement.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => Ok(Some(session_from_row(row, 0)?)),
            None => Ok(None),
        }
    }

    pub fn load_session_snapshots(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<DeviceSessionSnapshot>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, device_id, first_seen_ms, last_seen_ms,
                    ips_json, macs_json, hostnames_json, inferences_json
             FROM device_sessions
             WHERE session_id = ?1
             ORDER BY device_id",
        )?;
        let mut rows = statement.query(params![session_id.to_string()])?;
        let mut snapshots = Vec::new();
        while let Some(row) = rows.next()? {
            snapshots.push(snapshot_from_row(row, 0)?);
        }
        Ok(snapshots)
    }

    pub fn load_device_history(
        &self,
        device_id: Uuid,
    ) -> Result<Vec<DeviceHistoryEntry>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT ds.session_id, ds.device_id, ds.first_seen_ms, ds.last_seen_ms,
                    ds.ips_json, ds.macs_json, ds.hostnames_json, ds.inferences_json,
                    s.id, s.scope_json, s.methods_json, s.started_at_ms, s.finished_at_ms,
                    s.status, s.errors_json,
                    (SELECT COUNT(*) FROM device_sessions x WHERE x.session_id = s.id)
             FROM device_sessions ds
             JOIN scan_sessions s ON s.id = ds.session_id
             WHERE ds.device_id = ?1
             ORDER BY s.started_at_ms ASC, s.id ASC",
        )?;
        let mut rows = statement.query(params![device_id.to_string()])?;
        let mut history = Vec::new();
        while let Some(row) = rows.next()? {
            history.push(DeviceHistoryEntry {
                snapshot: snapshot_from_row(row, 0)?,
                session: session_from_row(row, 8)?,
            });
        }
        Ok(history)
    }

    pub fn list_segments(&self) -> Result<Vec<SegmentRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT ns.id, i.name, ns.prefix, ns.gateway, ns.first_seen_ms, ns.last_seen_ms
             FROM network_segments ns
             JOIN interfaces i ON i.id = ns.interface_id
             ORDER BY i.name, ns.prefix",
        )?;
        let mut rows = statement.query([])?;
        let mut segments = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let interface: String = row.get(1)?;
            let prefix: String = row.get(2)?;
            let gateway: Option<String> = row.get(3)?;
            segments.push(SegmentRecord {
                id: Uuid::parse_str(&id).unwrap_or_default(),
                interface,
                prefix: prefix
                    .parse::<ipnet::IpNet>()
                    .map(|prefix| prefix.trunc())
                    .map_err(|error| {
                        StorageError::InvalidValue(format!(
                            "invalid stored segment prefix {prefix:?}: {error}"
                        ))
                    })?,
                gateway: gateway
                    .map(|value| {
                        value.parse().map_err(|error| {
                            StorageError::InvalidValue(format!(
                                "invalid stored segment gateway {value:?}: {error}"
                            ))
                        })
                    })
                    .transpose()?,
                first_seen_ms: row.get(4)?,
                last_seen_ms: row.get(5)?,
            });
        }
        Ok(segments)
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
                property: row.get::<_, String>(3)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                candidate: serde_json::from_str(&row.get::<_, String>(4)?).unwrap_or(Value::Null),
                source: row.get::<_, String>(5)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                source_unit: row.get(6)?,
                confidence: row.get::<_, String>(7)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
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
                subject_type: row.get::<_, String>(2)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                subject_id: row.get(3)?,
                kind: row.get::<_, String>(4)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                property: row.get(5)?,
                value: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or(Value::Null),
                source: row.get::<_, String>(7)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                method: row.get(8)?,
                observed_at_ms: row.get(9)?,
                expires_at_ms: row.get(10)?,
                details: serde_json::from_str(&row.get::<_, String>(11)?).unwrap_or(Value::Null),
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
                property: row.get::<_, String>(2)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                value: row
                    .get::<_, Option<String>>(3)?
                    .and_then(|value| serde_json::from_str::<Value>(&value).ok()),
                confidence: row.get::<_, String>(4)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                status: row.get::<_, String>(5)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                rationale: row.get(6)?,
                evidence_ids: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
                unknown_reason: match row.get::<_, Option<String>>(8)? {
                    Some(value) => {
                        Some(value.parse().map_err(|error: crate::domain::DomainError| {
                            rusqlite::Error::InvalidParameterName(error.to_string())
                        })?)
                    }
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

    fn load_services(&self, device_id: &str) -> Result<Vec<ServiceRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, device_id, ip, port, transport, protocol, product, version,
                    banner, source, observed_at_ms, details_json
             FROM services WHERE device_id = ?1
             ORDER BY observed_at_ms DESC, port ASC",
        )?;
        let rows = statement.query_map(params![device_id], |row| {
            Ok(ServiceRecord {
                id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap_or_default(),
                device_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                ip: row.get::<_, String>(2)?.parse().map_err(
                    |error: std::net::AddrParseError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                port: row.get::<_, i64>(3)? as u16,
                transport: row.get::<_, String>(4)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                protocol: row.get(5)?,
                product: row.get(6)?,
                version: row.get(7)?,
                banner: row.get(8)?,
                source: row.get::<_, String>(9)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                observed_at_ms: row.get(10)?,
                details: serde_json::from_str(&row.get::<_, String>(11)?).unwrap_or(Value::Null),
            })
        })?;
        let mut services = Vec::new();
        for row in rows {
            services.push(row?);
        }
        Ok(services)
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
                confidence: row.get::<_, String>(4)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
                status: row.get::<_, String>(5)?.parse().map_err(
                    |error: crate::domain::DomainError| {
                        rusqlite::Error::InvalidParameterName(error.to_string())
                    },
                )?,
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

fn session_from_row(row: &rusqlite::Row<'_>, offset: usize) -> Result<SessionRecord, StorageError> {
    let id: String = row.get(offset)?;
    let scope_json: String = row.get(offset + 1)?;
    let methods_json: String = row.get(offset + 2)?;
    let status_value: String = row.get(offset + 5)?;
    let errors_json: String = row.get(offset + 6)?;
    let device_count: i64 = row.get(offset + 7)?;

    Ok(SessionRecord {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        scope: parse_json(&scope_json, "scan scope")?,
        methods: parse_json(&methods_json, "scan methods")?,
        started_at_ms: row.get(offset + 3)?,
        finished_at_ms: row.get(offset + 4)?,
        status: SessionStatus::from_db(&status_value).ok_or_else(|| {
            StorageError::InvalidValue(format!("invalid stored session status {status_value:?}"))
        })?,
        errors: parse_json(&errors_json, "scan errors")?,
        device_count: device_count.max(0) as usize,
    })
}

fn snapshot_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<DeviceSessionSnapshot, StorageError> {
    let session_id: String = row.get(offset)?;
    let device_id: String = row.get(offset + 1)?;
    let ips_json: String = row.get(offset + 4)?;
    let macs_json: String = row.get(offset + 5)?;
    let hostnames_json: String = row.get(offset + 6)?;
    let inferences_json: String = row.get(offset + 7)?;

    Ok(DeviceSessionSnapshot {
        session_id: Uuid::parse_str(&session_id).unwrap_or_default(),
        device_id: Uuid::parse_str(&device_id).unwrap_or_default(),
        first_seen_ms: row.get(offset + 2)?,
        last_seen_ms: row.get(offset + 3)?,
        ips: parse_json(&ips_json, "snapshot addresses")?,
        macs: parse_json(&macs_json, "snapshot MAC addresses")?,
        hostnames: parse_json(&hostnames_json, "snapshot hostnames")?,
        inferences: parse_json(&inferences_json, "snapshot inferences")?,
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str, label: &str) -> Result<T, StorageError> {
    serde_json::from_str(value)
        .map_err(|error| StorageError::InvalidValue(format!("invalid stored {label}: {error}")))
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::Store;
    use crate::application::identify;
    use crate::application::identity;
    use crate::application::model::{
        DiscoveryMethod, ScanConfig, ScanResult, ScanScope, SessionStatus,
    };
    use crate::domain::{
        Confidence, HostObservation, HostProbe, IdentifierKind, IdentifierRecord, InferenceStatus,
        NetworkContext, ServiceRecord, Source, Transport, ids::new_id,
    };

    fn sample_scan() -> ScanResult {
        let now = 1_000_000_i64;
        let session_id = new_id();
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mac = "00:11:22:33:44:55".parse().unwrap();
        let probe = HostProbe::neighbor(ip, Some(mac), Some("reachable".into()), Some("eth0"), now);
        let host = HostObservation {
            ip,
            interface: Some("eth0".into()),
            segment: None,
            mac: Some(mac),
            neighbor_state: Some("reachable".into()),
            icmp_rtt_ms: None,
            tcp: Vec::new(),
            hostname: None,
            first_seen_ms: now,
            last_seen_ms: now,
            sources: vec![Source::NeighborTable],
            probes: vec![probe],
        };
        let resolved = identity::resolve(
            std::slice::from_ref(&host),
            &[],
            now,
            identity::DEFAULT_MAC_WINDOW_MS,
        );
        let identification = identify::identify(
            session_id,
            &resolved.devices,
            &[],
            "test",
            &identify::ProviderAvailability::default(),
            now,
        );
        ScanResult {
            session_id,
            started_at_ms: now,
            finished_at_ms: now,
            status: SessionStatus::Completed,
            scope: ScanScope {
                interface: Some("eth0".into()),
                target: Some("192.168.1.0/24".into()),
                candidate_count: 254,
                discovered_count: 1,
            },
            config: ScanConfig {
                timeout_ms: 1_000,
                dns_timeout_ms: 1_500,
                mdns_window_ms: 3_000,
                concurrency: 4,
                max_hosts: 1_024,
                service_ports: vec![22, 80],
                methods: vec![DiscoveryMethod::Neighbor],
            },
            context: NetworkContext {
                interfaces: Vec::new(),
                routes: Vec::new(),
                neighbors: Vec::new(),
                default_interface: None,
                default_gateway: None,
                warnings: Vec::new(),
                captured_at_ms: now,
            },
            hosts: vec![host],
            devices: resolved.devices,
            services: Vec::new(),
            observations: identification.observations,
            evidence: identification.evidence,
            inferences: identification.inferences,
            identity_links: resolved.links,
            provider_reports: Vec::new(),
        }
    }

    #[test]
    fn saves_and_loads_a_scan_round_trip() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = sample_scan();
        let device_id = scan.devices[0].id;
        store.save_scan(&scan).unwrap();

        assert_eq!(store.schema_version().unwrap(), 2);

        let devices = store.list_devices(None).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, device_id);
        assert!(devices[0].ips.contains(&"192.168.1.10".to_string()));
        assert!(devices[0].macs.contains(&"00:11:22:33:44:55".to_string()));
        assert_eq!(devices[0].manufacturer.status, InferenceStatus::Unknown);

        let detail = store.get_device(device_id).unwrap().unwrap();
        assert_eq!(detail.identifiers.len(), 2);
        assert!(
            detail
                .identifiers
                .iter()
                .any(|identifier| identifier.kind == IdentifierKind::Ip)
        );
        assert!(
            detail
                .identifiers
                .iter()
                .any(|identifier| identifier.kind == IdentifierKind::Mac)
        );
        assert_eq!(detail.inferences.len(), 4);
        assert!(!detail.observations.is_empty());
        assert_eq!(detail.summary.last_session_id, Some(scan.session_id));
    }

    #[test]
    fn inventory_snapshots_round_trip() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = sample_scan();
        let device_id = scan.devices[0].id;
        store.save_scan(&scan).unwrap();

        let snapshots = store.load_session_snapshots(scan.session_id).unwrap();
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(snapshot.device_id, device_id);
        assert!(snapshot.ips.contains(&"192.168.1.10".to_string()));
        assert!(snapshot.macs.contains(&"00:11:22:33:44:55".to_string()));
        assert_eq!(snapshot.inferences.len(), 4);

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, scan.session_id);
        assert_eq!(sessions[0].device_count, 1);
        assert_eq!(store.latest_session().unwrap().unwrap().id, scan.session_id);

        let history = store.load_device_history(device_id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].session.id, scan.session_id);
    }

    #[test]
    fn services_round_trip() {
        let mut store = Store::open_in_memory().unwrap();
        let mut scan = sample_scan();
        let device_id = scan.devices[0].id;
        scan.services.push(ServiceRecord {
            id: new_id(),
            device_id,
            ip: "192.168.1.10".parse().unwrap(),
            port: 22,
            transport: Transport::Tcp,
            protocol: Some("ssh".to_string()),
            product: Some("OpenSSH".to_string()),
            version: Some("9.6".to_string()),
            banner: Some("SSH-2.0-OpenSSH_9.6".to_string()),
            source: Source::ServiceBanner,
            observed_at_ms: 1_000,
            details: serde_json::json!({ "os_hint": "Ubuntu" }),
        });
        store.save_scan(&scan).unwrap();

        let detail = store.get_device(device_id).unwrap().unwrap();
        assert_eq!(detail.services.len(), 1);
        let service = &detail.services[0];
        assert_eq!(service.port, 22);
        assert_eq!(service.transport, Transport::Tcp);
        assert_eq!(service.protocol.as_deref(), Some("ssh"));
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.source, Source::ServiceBanner);
        assert_eq!(service.details["os_hint"], "Ubuntu");
    }

    #[test]
    fn strong_identifiers_are_loaded_for_linking() {
        let mut store = Store::open_in_memory().unwrap();
        let mut scan = sample_scan();
        let device = &mut scan.devices[0];
        let device_id = device.id;
        device.identifiers.push(IdentifierRecord {
            id: new_id(),
            device_id,
            kind: IdentifierKind::UpnpUdn,
            value: "uuid:1234".to_string(),
            normalized: "1234".to_string(),
            source: Source::Ssdp,
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            confidence: Confidence::High,
            details: serde_json::json!({}),
        });
        device.identifiers.push(IdentifierRecord {
            id: new_id(),
            device_id,
            kind: IdentifierKind::MdnsInstance,
            value: "Living Room._airplay._tcp.local.".to_string(),
            normalized: "living room._airplay._tcp.local.".to_string(),
            source: Source::Mdns,
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            confidence: Confidence::Medium,
            details: serde_json::json!({}),
        });
        store.save_scan(&scan).unwrap();

        let existing = store
            .load_existing_devices(1_000, identity::DEFAULT_MAC_WINDOW_MS)
            .unwrap();
        let loaded = existing
            .iter()
            .find(|device| device.id == device_id)
            .unwrap();
        assert!(loaded.upnp_udns.iter().any(|(value, _)| value == "1234"));
        assert!(
            loaded
                .mdns_instances
                .iter()
                .any(|(value, _)| value == "living room._airplay._tcp.local.")
        );
    }

    #[test]
    fn imports_oui_csv_and_uses_longest_prefix() {
        let mut store = Store::open_in_memory().unwrap();
        let fixture = "Registry,Assignment,Organization Name\nMA-L,001122,Example Networks\nMA-S,001122334,Example Sensors\n";
        let report = store.import_oui_csv(fixture, Some("fixture-1")).unwrap();
        assert_eq!(report.record_count, 2);

        let source = store.oui_source().unwrap().unwrap();
        assert_eq!(source.version.as_deref(), Some("fixture-1"));
        assert_eq!(source.record_count, 2);

        let mac: crate::domain::MacAddress = "00:11:22:33:44:55".parse().unwrap();
        let found = store.lookup_oui(mac).unwrap().unwrap();
        assert_eq!(found.organization, "Example Sensors");
        assert_eq!(found.prefix_bits, 36);

        let entries = store.oui_entries().unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn locally_administered_mac_is_never_attributed() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .import_oui_csv(
                "Registry,Assignment,Organization Name\nMA-L,001122,Example Networks\n",
                Some("fixture-1"),
            )
            .unwrap();
        let mac: crate::domain::MacAddress = "02:11:22:33:44:55".parse().unwrap();
        assert!(store.lookup_oui(mac).unwrap().is_none());
    }
}
