//! Opt-in monitoring runs and recorded network events.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use tokio_util::sync::CancellationToken;

use crate::application::discovery::{self, ScanOptions};
use crate::application::inventory;
use crate::application::model::SessionStatus;
use crate::domain::ids::new_id;
use crate::domain::time::now_ms;
use crate::infrastructure::storage::{StorageError, Store};

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("discovery error: {0}")]
    Discovery(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorKind {
    Scan,
    Dns,
}

impl MonitorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Dns => "dns",
        }
    }
}

impl std::str::FromStr for MonitorKind {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "scan" => Ok(Self::Scan),
            "dns" => Ok(Self::Dns),
            other => Err(format!("invalid monitor kind: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorRunStatus {
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
    Interrupted,
}

impl MonitorRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }
}

impl std::str::FromStr for MonitorRunStatus {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "interrupted" => Ok(Self::Interrupted),
            other => Err(format!("invalid monitor run status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Change,
    Error,
}

impl EventSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Change => "change",
            Self::Error => "error",
        }
    }
}

impl std::str::FromStr for EventSeverity {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "change" => Ok(Self::Change),
            "error" => Ok(Self::Error),
            other => Err(format!("invalid event severity: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRun {
    pub id: Uuid,
    pub kind: MonitorKind,
    pub status: MonitorRunStatus,
    pub started_at_ms: i64,
    pub finished_at_ms: Option<i64>,
    pub target: Option<String>,
    pub config: serde_json::Value,
    pub summary: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: Uuid,
    pub run_id: Option<Uuid>,
    pub kind: String,
    pub severity: EventSeverity,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub message: String,
    pub details: serde_json::Value,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct MonitorRunFilter {
    pub kind: Option<MonitorKind>,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub run_id: Option<Uuid>,
    pub severity: Option<EventSeverity>,
    pub limit: usize,
}

pub fn list_runs(
    store: &Store,
    filter: &MonitorRunFilter,
) -> Result<Vec<MonitorRun>, StorageError> {
    let rows =
        store.list_monitor_runs(filter.kind.map(|value| value.as_str()), filter.limit.max(1))?;
    Ok(rows
        .into_iter()
        .map(|row| MonitorRun {
            id: row.id.parse().unwrap_or_else(|_| Uuid::new_v4()),
            kind: row.kind.parse().unwrap_or(MonitorKind::Scan),
            status: row.status.parse().unwrap_or(MonitorRunStatus::Failed),
            started_at_ms: row.started_at_ms,
            finished_at_ms: row.finished_at_ms,
            target: row.target,
            config: serde_json::from_str(&row.config_json).unwrap_or(serde_json::json!({})),
            summary: row
                .summary_json
                .and_then(|value| serde_json::from_str(&value).ok()),
            error: row.error,
        })
        .collect())
}

pub fn list_events(store: &Store, filter: &EventFilter) -> Result<Vec<NetworkEvent>, StorageError> {
    let run_id = filter.run_id.map(|value| value.to_string());
    let rows = store.list_network_events(
        run_id.as_deref(),
        filter.severity.map(|value| value.as_str()),
        filter.limit.max(1),
    )?;
    Ok(rows
        .into_iter()
        .map(|row| NetworkEvent {
            id: row.id.parse().unwrap_or_else(|_| Uuid::new_v4()),
            run_id: row.run_id.and_then(|value| value.parse().ok()),
            kind: row.kind,
            severity: row.severity.parse().unwrap_or(EventSeverity::Info),
            subject_type: row.subject_type,
            subject_id: row.subject_id,
            message: row.message,
            details: serde_json::from_str(&row.details_json).unwrap_or(serde_json::json!({})),
            observed_at_ms: row.observed_at_ms,
        })
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMonitorResult {
    pub run: MonitorRun,
    pub events: Vec<NetworkEvent>,
    pub scan_session_id: Uuid,
}

/// Run one discovery scan as a monitored check, persist a monitor run and derived
/// network events, and return the result.
pub async fn run_scan_once(
    store: &mut Store,
    options: ScanOptions,
    cancel: CancellationToken,
) -> Result<ScanMonitorResult, MonitorError> {
    let run_id = new_id();
    let started_at_ms = now_ms();
    let target = options.target.clone().or_else(|| options.interface.clone());
    let config = serde_json::json!({
        "interface": options.interface,
        "target": options.target,
        "enable_icmp": options.enable_icmp,
        "enable_tcp": options.enable_tcp,
        "enable_dns": options.enable_dns,
        "enable_mdns": options.enable_mdns,
        "enable_ssdp": options.enable_ssdp,
        "enable_netbios": options.enable_netbios,
        "enable_services": options.enable_services,
        "timeout_ms": options.timeout_ms,
        "dns_timeout_ms": options.dns_timeout_ms,
        "mdns_window_ms": options.mdns_window_ms,
        "concurrency": options.concurrency,
        "max_hosts": options.max_hosts,
    });

    store.insert_monitor_run(
        &run_id.to_string(),
        MonitorKind::Scan.as_str(),
        MonitorRunStatus::Running.as_str(),
        started_at_ms,
        None,
        target.as_deref(),
        &serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string()),
        None,
        None,
    )?;

    let scan = match discovery::run_scan(store, options, cancel.clone()).await {
        Ok(scan) => scan,
        Err(error) => {
            let finished_at_ms = now_ms();
            let summary = serde_json::json!({
                "error": error.to_string(),
            });
            store.update_monitor_run(
                &run_id.to_string(),
                MonitorRunStatus::Failed.as_str(),
                Some(finished_at_ms),
                Some(&serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string())),
                Some(&error.to_string()),
            )?;
            let event = NetworkEvent {
                id: new_id(),
                run_id: Some(run_id),
                kind: "monitor_run_failed".to_string(),
                severity: EventSeverity::Error,
                subject_type: Some("monitor_run".to_string()),
                subject_id: Some(run_id.to_string()),
                message: "Scan monitor run failed".to_string(),
                details: serde_json::json!({ "error": error.to_string() }),
                observed_at_ms: finished_at_ms,
            };
            store.insert_network_event(
                &event.id.to_string(),
                event.run_id.as_ref().map(|id| id.to_string()).as_deref(),
                &event.kind,
                event.severity.as_str(),
                event.subject_type.as_deref(),
                event.subject_id.as_deref(),
                &event.message,
                &serde_json::to_string(&event.details).unwrap_or_else(|_| "{}".to_string()),
                event.observed_at_ms,
            )?;
            return Err(MonitorError::Discovery(error));
        }
    };

    let changes = inventory::changes_for_session(store, Some(scan.session_id))?;
    let mut events = Vec::new();
    if let Some(report) = &changes {
        for change in &report.events {
            let (severity, kind, message) = match change.kind {
                crate::domain::ChangeKind::NewDevice => (
                    EventSeverity::Change,
                    "new_device",
                    "New device profile observed",
                ),
                crate::domain::ChangeKind::NotObserved => (
                    EventSeverity::Warning,
                    "device_not_observed",
                    "Previously observed device was not observed in this scan",
                ),
                crate::domain::ChangeKind::IpChanged => (
                    EventSeverity::Change,
                    "ip_changed",
                    "Device IP address changed",
                ),
                crate::domain::ChangeKind::MacChanged => (
                    EventSeverity::Warning,
                    "mac_changed",
                    "Device MAC association changed",
                ),
                crate::domain::ChangeKind::HostnameChanged => (
                    EventSeverity::Change,
                    "hostname_changed",
                    "Device hostname changed",
                ),
                crate::domain::ChangeKind::InferenceChanged => (
                    EventSeverity::Info,
                    "inference_changed",
                    "Device inference changed",
                ),
            };
            events.push(NetworkEvent {
                id: new_id(),
                run_id: Some(run_id),
                kind: kind.to_string(),
                severity,
                subject_type: Some("device".to_string()),
                subject_id: Some(change.device_id.to_string()),
                message: message.to_string(),
                details: serde_json::to_value(change).unwrap_or_else(|_| serde_json::json!({})),
                observed_at_ms: scan.finished_at_ms,
            });
        }
        if let Some(note) = &report.note {
            events.push(NetworkEvent {
                id: new_id(),
                run_id: Some(run_id),
                kind: "scan_note".to_string(),
                severity: EventSeverity::Info,
                subject_type: Some("scan_session".to_string()),
                subject_id: Some(scan.session_id.to_string()),
                message: note.clone(),
                details: serde_json::json!({ "note": note }),
                observed_at_ms: scan.finished_at_ms,
            });
        }
    }

    for event in &events {
        store.insert_network_event(
            &event.id.to_string(),
            event.run_id.as_ref().map(|id| id.to_string()).as_deref(),
            &event.kind,
            event.severity.as_str(),
            event.subject_type.as_deref(),
            event.subject_id.as_deref(),
            &event.message,
            &serde_json::to_string(&event.details).unwrap_or_else(|_| "{}".to_string()),
            event.observed_at_ms,
        )?;
    }

    let status = match scan.status {
        SessionStatus::Completed => MonitorRunStatus::Completed,
        SessionStatus::Partial | SessionStatus::Cancelled => MonitorRunStatus::Partial,
        SessionStatus::Failed => MonitorRunStatus::Failed,
        SessionStatus::Running | SessionStatus::Interrupted => MonitorRunStatus::Interrupted,
    };
    let finished_at_ms = now_ms();
    let summary = serde_json::json!({
        "scan_session_id": scan.session_id,
        "scan_status": scan.status.as_str(),
        "device_count": scan.devices.len(),
        "host_count": scan.hosts.len(),
        "change_events": events.iter().filter(|e| matches!(e.severity, EventSeverity::Change | EventSeverity::Warning)).count(),
    });
    store.update_monitor_run(
        &run_id.to_string(),
        status.as_str(),
        Some(finished_at_ms),
        Some(&serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string())),
        None,
    )?;

    let run = MonitorRun {
        id: run_id,
        kind: MonitorKind::Scan,
        status,
        started_at_ms,
        finished_at_ms: Some(finished_at_ms),
        target,
        config,
        summary: Some(summary),
        error: None,
    };
    Ok(ScanMonitorResult {
        run,
        events,
        scan_session_id: scan.session_id,
    })
}
