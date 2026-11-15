//! JSON/CSV export and SQLite backup/restore.
//!
//! JSON exports preserve records with evidence, inferences, and timestamps.
//! CSV exports are lossy and documented as such.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::domain::{DeviceDetail, DeviceSummary, DnsMeasurement, RouteRun};
use crate::infrastructure::storage::{StorageError, Store};

pub const EXPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("database backup error: {0}")]
    Backup(String),
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("invalid export: {0}")]
    Invalid(String),
}

#[derive(Debug, Serialize)]
pub struct JsonExport {
    pub schema_version: u32,
    pub exported_at_ms: i64,
    pub devices: Vec<DeviceExport>,
    pub dns_measurements: Vec<DnsMeasurement>,
    pub route_runs: Vec<RouteRun>,
}

#[derive(Debug, Serialize)]
pub struct DeviceExport {
    pub summary: DeviceSummary,
    pub detail: Option<DeviceDetail>,
}

/// Export the current database state as a versioned JSON document.
pub fn export_json(store: &Store) -> Result<JsonExport, ExportError> {
    let summaries = store.list_devices(None)?;
    let mut devices = Vec::with_capacity(summaries.len());
    for summary in &summaries {
        let detail = store.get_device(summary.id)?;
        devices.push(DeviceExport {
            summary: summary.clone(),
            detail,
        });
    }
    let dns_measurements = store.list_dns_measurements(None, None, None, 10_000)?;
    let route_runs = store.list_route_runs(None, None, 10_000)?;
    Ok(JsonExport {
        schema_version: EXPORT_SCHEMA_VERSION,
        exported_at_ms: crate::domain::time::now_ms(),
        devices,
        dns_measurements,
        route_runs,
    })
}

pub fn write_json(path: &Path, export: &JsonExport) -> Result<(), ExportError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, export)?;
    writeln!(writer)?;
    Ok(())
}

/// Write a lossy CSV of current device summaries.
/// Columns: id,first_seen_ms,last_seen_ms,ips,macs,hostnames,manufacturer,category,os,model,confidence_note
/// Omitted: evidence graph, observations, per-identifier history, DNS/route measurements, raw details.
pub fn write_devices_csv(path: &Path, devices: &[DeviceSummary]) -> Result<(), ExportError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = csv::Writer::from_writer(BufWriter::new(file));
    writer.write_record([
        "id",
        "first_seen_ms",
        "last_seen_ms",
        "ips",
        "macs",
        "hostnames",
        "manufacturer",
        "category",
        "os",
        "model",
        "confidence_note",
    ])?;
    for device in devices {
        writer.write_record([
            device.id.to_string(),
            device.first_seen_ms.to_string(),
            device.last_seen_ms.to_string(),
            device.ips.join(";"),
            device.macs.join(";"),
            device.hostnames.join(";"),
            inference_value(&device.manufacturer),
            inference_value(&device.category),
            inference_value(&device.os),
            inference_value(&device.model),
            "lossy export: evidence, observations, identifiers, DNS, and route data omitted"
                .to_string(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn inference_value(view: &crate::domain::InferenceView) -> String {
    match &view.value {
        Some(value) => match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        },
        None => format!("Unknown ({})", view.status.as_str()),
    }
}

/// Create a consistent SQLite backup at `destination` using the SQLite backup API.
pub fn backup_database(store: &Store, destination: &Path) -> Result<(), ExportError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    // rusqlite backup requires &mut Connection; Store exposes it via a helper.
    store.backup_to(destination).map_err(ExportError::Storage)?;
    // Verify integrity of the backup.
    let check = Store::open(destination)?;
    let result = check.integrity_check().map_err(ExportError::Storage)?;
    if result != "ok" {
        return Err(ExportError::Integrity(result));
    }
    Ok(())
}

/// Restore by replacing/copying a validated backup into place.
/// The caller must ensure no writers are active on the destination DB.
pub fn restore_database(backup: &Path, destination: &Path) -> Result<(), ExportError> {
    if !backup.exists() {
        return Err(ExportError::Invalid(format!(
            "backup file does not exist: {}",
            backup.display()
        )));
    }
    // Validate backup before overwriting destination.
    let check = Store::open(backup)?;
    let integrity = check.integrity_check().map_err(ExportError::Storage)?;
    if integrity != "ok" {
        return Err(ExportError::Integrity(integrity));
    }
    let schema = check.schema_version().map_err(ExportError::Storage)?;
    if schema <= 0 {
        return Err(ExportError::Invalid(
            "backup does not contain a valid NetAtlas schema".to_string(),
        ));
    }
    drop(check);

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(backup, destination)?;
    // Remove WAL/SHM sidecars of the old destination if present.
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", destination.display(), suffix));
        if sidecar.exists() {
            let _ = fs::remove_file(sidecar);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn json_export_has_schema_and_empty_collections() {
        let store = Store::open_in_memory().unwrap();
        let export = export_json(&store).unwrap();
        assert_eq!(export.schema_version, EXPORT_SCHEMA_VERSION);
        assert!(export.devices.is_empty());
        assert!(export.dns_measurements.is_empty());
        assert!(export.route_runs.is_empty());
    }

    #[test]
    fn json_export_writes_pretty_file() {
        let dir = TempDir::new().unwrap();
        let store = Store::open_in_memory().unwrap();
        let export = export_json(&store).unwrap();
        let path = dir.path().join("export.json");
        write_json(&path, &export).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(value["schema_version"], EXPORT_SCHEMA_VERSION);
    }

    #[test]
    fn csv_export_writes_header_and_rows() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("devices.csv");
        write_devices_csv(&path, &[]).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with("id,first_seen_ms"));
    }

    #[test]
    fn backup_and_restore_round_trip() {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("src.db");
        let backup = dir.path().join("backup.db");
        let restored = dir.path().join("restored.db");

        let store = Store::open(&db).unwrap();
        backup_database(&store, &backup).unwrap();
        drop(store);

        restore_database(&backup, &restored).unwrap();
        let reopened = Store::open(&restored).unwrap();
        assert!(reopened.schema_version().unwrap() >= 4);
    }
}
