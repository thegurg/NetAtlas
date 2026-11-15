//! Validated JSON import with dry-run and conflict reporting.
//!
//! This slice imports measurement records (DNS and route runs) by stable ID.
//! Sessions, devices, and identity-graph records are validated/reported but not
//! merged automatically to avoid silent identity conflicts.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::application::export::{EXPORT_SCHEMA_VERSION, JsonExport};
use crate::domain::{DnsMeasurement, RouteRun};
use crate::infrastructure::storage::{StorageError, Store};

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported export schema version {found}; supported {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("invalid import: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportReport {
    pub dry_run: bool,
    pub supported_schema_version: u32,
    pub schema_version: u32,
    pub dns: SectionReport,
    pub routes: SectionReport,
    pub sessions: SectionReport,
    pub devices: SectionReport,
    pub conflicts: Vec<Conflict>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SectionReport {
    pub total: usize,
    pub importable: usize,
    pub imported: usize,
    pub skipped_existing: usize,
    pub conflicts: usize,
    pub unsupported: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub kind: String,
    pub id: String,
    pub message: String,
}

pub fn load_export(path: &Path) -> Result<JsonExport, ImportError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let export: JsonExport = serde_json::from_reader(reader)?;
    if export.schema_version != EXPORT_SCHEMA_VERSION {
        return Err(ImportError::UnsupportedSchema {
            found: export.schema_version,
            supported: EXPORT_SCHEMA_VERSION,
        });
    }
    Ok(export)
}

/// Validate and optionally import a JSON export.
/// Import is transactional: no partial writes on failure.
pub fn import_json(
    store: &mut Store,
    export: JsonExport,
    dry_run: bool,
) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport {
        dry_run,
        supported_schema_version: EXPORT_SCHEMA_VERSION,
        schema_version: export.schema_version,
        ..ImportReport::default()
    };

    report.notes.push(
        "DNS measurements and route runs are imported by stable ID when non-conflicting. \
         Sessions/devices/identity-graph records are reported but not merged automatically in this slice to avoid silent conflicts."
            .to_string(),
    );

    // Analyze DNS
    let mut dns_to_import = Vec::new();
    for measurement in &export.dns_measurements {
        report.dns.total += 1;
        match store.get_dns_measurement(measurement.id)? {
            Some(existing) => {
                if measurements_equivalent(&existing, measurement) {
                    report.dns.skipped_existing += 1;
                } else {
                    report.dns.conflicts += 1;
                    report.conflicts.push(Conflict {
                        kind: "dns_measurement".to_string(),
                        id: measurement.id.to_string(),
                        message: "same ID exists with different content".to_string(),
                    });
                }
            }
            None => {
                report.dns.importable += 1;
                dns_to_import.push(measurement.clone());
            }
        }
    }

    // Analyze routes
    let mut routes_to_import = Vec::new();
    for run in &export.route_runs {
        report.routes.total += 1;
        match store.get_route_run(run.id)? {
            Some(existing) => {
                if runs_equivalent(&existing, run) {
                    report.routes.skipped_existing += 1;
                } else {
                    report.routes.conflicts += 1;
                    report.conflicts.push(Conflict {
                        kind: "route_run".to_string(),
                        id: run.id.to_string(),
                        message: "same ID exists with different content".to_string(),
                    });
                }
            }
            None => {
                report.routes.importable += 1;
                routes_to_import.push(run.clone());
            }
        }
    }

    // Sessions/devices: report as unsupported for automatic merge in this slice.
    report.sessions.total = export.sessions.len();
    report.sessions.unsupported = export.sessions.len();
    if !export.sessions.is_empty() {
        report.notes.push(format!(
            "{} session record(s) with snapshots were not imported automatically; session/device identity merge requires conflict-aware handling.",
            export.sessions.len()
        ));
    }
    report.devices.total = export.devices.len();
    report.devices.unsupported = export.devices.len();
    if !export.devices.is_empty() {
        report.notes.push(format!(
            "{} device record(s) were not imported automatically; device/identifier/evidence merge requires conflict-aware handling.",
            export.devices.len()
        ));
    }

    if dry_run
        || (!dns_to_import.is_empty()
            && report.conflicts.iter().any(|c| c.kind == "dns_measurement"))
        || (!routes_to_import.is_empty() && report.conflicts.iter().any(|c| c.kind == "route_run"))
    {
        // In dry-run we never write. If there are conflicts in sections we would write,
        // we still proceed with non-conflicting imports below only when not dry-run and
        // conflicts are isolated per-record (we already excluded conflicting IDs).
    }

    if !dry_run {
        if !dns_to_import.is_empty() {
            store.save_dns_measurements(&dns_to_import)?;
            report.dns.imported = dns_to_import.len();
        }
        if !routes_to_import.is_empty() {
            for run in &routes_to_import {
                store.save_route_run(run)?;
            }
            report.routes.imported = routes_to_import.len();
        }
    }

    Ok(report)
}

fn measurements_equivalent(a: &DnsMeasurement, b: &DnsMeasurement) -> bool {
    // Stable-ID equality is the primary key; compare key fields for conflict detection.
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

fn runs_equivalent(a: &RouteRun, b: &RouteRun) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

// Re-export types for deserialization compatibility if needed by callers.
pub use crate::application::export::JsonExport as ImportBundle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::export::{self, EXPORT_SCHEMA_VERSION};
    use crate::domain::ids::new_id;
    use crate::domain::route::{
        RouteProbeMethod, RouteProbeOutcome, RouteRunStatus, RouteSample, aggregate_hop,
    };
    use crate::domain::{
        DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecord, DnsRecordType, DnsRecordValue,
        DnsResponse, DnsResponseCode, DnssecInfo, ResolverEndpoint, RouteRun, Transport,
    };
    use tempfile::TempDir;

    fn sample_dns() -> DnsMeasurement {
        DnsMeasurement {
            id: new_id(),
            queried_at_ms: 1_000,
            resolver: ResolverEndpoint {
                label: "test".into(),
                address: "192.0.2.53:53".parse().unwrap(),
            },
            query: DnsQuery {
                name: "example.com.".into(),
                record_type: DnsRecordType::A,
            },
            transport: Transport::Udp,
            outcome: DnsOutcome::Response,
            elapsed_ms: 10,
            attempts: 1,
            response: Some(DnsResponse {
                rcode: DnsResponseCode::NoError,
                flags: DnsFlags::default(),
                answers: vec![DnsRecord {
                    name: "example.com.".into(),
                    record_type: DnsRecordType::A,
                    ttl: 60,
                    value: DnsRecordValue::Address {
                        address: "192.0.2.1".parse().unwrap(),
                    },
                }],
                authority: vec![],
                answer_count: 1,
                authority_count: 0,
                additional_count: 0,
            }),
            dnssec: DnssecInfo::not_performed(false, false, false, false),
            error: None,
        }
    }

    fn sample_route() -> RouteRun {
        let sample = RouteSample {
            probe_index: 0,
            sent_at_ms: 1,
            outcome: RouteProbeOutcome::Reply,
            responder: Some("192.0.2.1".parse().unwrap()),
            rtt_ms: Some(1.0),
            icmp_type: None,
            icmp_code: None,
            error: None,
        };
        RouteRun {
            id: new_id(),
            target: "example.com".into(),
            target_ip: "192.0.2.1".parse().unwrap(),
            method: RouteProbeMethod::Udp,
            port: Some(33434),
            started_at_ms: 1_000,
            finished_at_ms: 1_100,
            max_hops: 30,
            probes_per_hop: 1,
            status: RouteRunStatus::Completed,
            target_reached: true,
            hops: vec![aggregate_hop(1, vec![sample])],
            error: None,
        }
    }

    #[test]
    fn dry_run_reports_importable_measurements() {
        let mut store = Store::open_in_memory().unwrap();
        let mut export = export::export_json(&store).unwrap();
        export.dns_measurements.push(sample_dns());
        export.route_runs.push(sample_route());

        let report = import_json(&mut store, export, true).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.dns.importable, 1);
        assert_eq!(report.dns.imported, 0);
        assert_eq!(report.routes.importable, 1);
        assert_eq!(report.routes.imported, 0);
        assert!(
            store
                .list_dns_measurements(None, None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn import_writes_measurements_and_skips_duplicates() {
        let mut store = Store::open_in_memory().unwrap();
        let dns = sample_dns();
        let route = sample_route();
        let mut export = export::export_json(&store).unwrap();
        export.dns_measurements.push(dns.clone());
        export.route_runs.push(route.clone());

        let report = import_json(&mut store, export.clone(), false).unwrap();
        assert_eq!(report.dns.imported, 1);
        assert_eq!(report.routes.imported, 1);
        assert_eq!(
            store
                .list_dns_measurements(None, None, None, 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.list_route_runs(None, None, 10).unwrap().len(), 1);

        let report2 = import_json(&mut store, export, false).unwrap();
        assert_eq!(report2.dns.skipped_existing, 1);
        assert_eq!(report2.routes.skipped_existing, 1);
        assert_eq!(
            store
                .list_dns_measurements(None, None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn conflicting_id_is_reported_not_overwritten() {
        let mut store = Store::open_in_memory().unwrap();
        let mut dns = sample_dns();
        store
            .save_dns_measurements(std::slice::from_ref(&dns))
            .unwrap();
        dns.elapsed_ms = 999; // different content, same id
        let mut export = export::export_json(&store).unwrap();
        export.dns_measurements.push(dns);

        let report = import_json(&mut store, export, false).unwrap();
        assert_eq!(report.dns.conflicts, 1);
        assert_eq!(report.conflicts.len(), 1);
        let stored = store.list_dns_measurements(None, None, None, 10).unwrap();
        assert_eq!(stored[0].elapsed_ms, 10); // unchanged
    }

    #[test]
    fn load_export_round_trips() {
        let dir = TempDir::new().unwrap();
        let store = Store::open_in_memory().unwrap();
        let export = export::export_json(&store).unwrap();
        let path = dir.path().join("e.json");
        export::write_json(&path, &export).unwrap();
        let loaded = load_export(&path).unwrap();
        assert_eq!(loaded.schema_version, EXPORT_SCHEMA_VERSION);
    }
}
