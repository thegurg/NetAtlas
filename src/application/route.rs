//! Route exploration orchestration, history, and comparison.
//!
//! A route run is a measurement. Transport failures and non-responsive hops are
//! recorded; they are never treated as proof that the route is broken.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::domain::route::{RouteComparison, RouteProbeMethod, RouteRun, compare_runs};
use crate::infrastructure::route::{RouteError, RouteOptions as ProbeOptions};
use crate::infrastructure::storage::{StorageError, Store};

pub use crate::infrastructure::route::RouteOptions;

/// Trace one target with bounded concurrency and cancellation.
pub async fn trace(
    options: &ProbeOptions,
    cancel: &CancellationToken,
) -> Result<RouteRun, RouteError> {
    crate::infrastructure::route::trace(options, cancel).await
}

#[derive(Debug, Clone)]
pub struct RouteHistoryFilter {
    pub target: Option<IpAddr>,
    pub method: Option<RouteProbeMethod>,
    pub limit: usize,
}

impl Default for RouteHistoryFilter {
    fn default() -> Self {
        Self {
            target: None,
            method: None,
            limit: 50,
        }
    }
}

pub fn history(store: &Store, filter: &RouteHistoryFilter) -> Result<Vec<RouteRun>, StorageError> {
    store.list_route_runs(filter.target, filter.method, filter.limit)
}

/// Compare the two most recent runs for a target, or a run against `--against-run`.
/// Returns `None` when fewer than two matching runs exist.
pub fn compare(
    store: &Store,
    target: IpAddr,
    method: RouteProbeMethod,
    port: Option<u16>,
    against_run: Option<uuid::Uuid>,
) -> Result<Option<RouteComparison>, StorageError> {
    let runs = store.list_route_runs_for_compare(target, method, port, 100)?;
    let Some(latest) = runs.first() else {
        return Ok(None);
    };

    let (left_id, right_id) = match against_run {
        Some(id) if id != latest.id => (latest.id, id),
        _ => {
            let Some(previous) = runs.get(1) else {
                return Ok(None);
            };
            (latest.id, previous.id)
        }
    };

    let left_owned;
    let left = if left_id == latest.id {
        latest
    } else {
        left_owned = match store.get_route_run(left_id)? {
            Some(run) => run,
            None => return Ok(None),
        };
        &left_owned
    };
    let right_owned;
    let right = if right_id == latest.id {
        latest
    } else {
        right_owned = match store.get_route_run(right_id)? {
            Some(run) => run,
            None => return Ok(None),
        };
        &right_owned
    };

    Ok(Some(compare_runs(left, right)))
}

pub fn persist(store: &mut Store, run: &RouteRun) -> Result<(), StorageError> {
    store.save_route_run(run)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRunSummary {
    pub run_id: uuid::Uuid,
    pub target: String,
    pub target_ip: IpAddr,
    pub method: RouteProbeMethod,
    pub status: crate::domain::route::RouteRunStatus,
    pub hop_count: usize,
    pub target_reached: bool,
    pub sample_count: usize,
    pub timeout_count: usize,
    pub elapsed_ms: i64,
}

impl From<&RouteRun> for RouteRunSummary {
    fn from(run: &RouteRun) -> Self {
        Self {
            run_id: run.id,
            target: run.target.clone(),
            target_ip: run.target_ip,
            method: run.method,
            status: run.status,
            hop_count: run.hops.len(),
            target_reached: run.target_reached,
            sample_count: run.sample_count(),
            timeout_count: run.timeout_count(),
            elapsed_ms: run.finished_at_ms.saturating_sub(run.started_at_ms),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteHistoryFilter, RouteOptions, RouteRunSummary};
    use crate::domain::ids::new_id;
    use crate::domain::route::{
        RouteProbeMethod, RouteProbeOutcome, RouteRun, RouteRunStatus, RouteSample, aggregate_hop,
    };
    use std::net::IpAddr;

    fn sample(outcome: RouteProbeOutcome, responder: Option<&str>) -> RouteSample {
        RouteSample {
            probe_index: 0,
            sent_at_ms: 1,
            outcome,
            responder: responder.map(|value| value.parse().unwrap()),
            rtt_ms: Some(1.0),
            icmp_type: None,
            icmp_code: None,
            error: None,
        }
    }

    #[test]
    fn summary_reports_samples_and_timeouts() {
        let run = RouteRun {
            id: new_id(),
            target: "example.com".to_string(),
            target_ip: "192.0.2.1".parse::<IpAddr>().unwrap(),
            method: RouteProbeMethod::Udp,
            port: Some(33434),
            started_at_ms: 1_000,
            finished_at_ms: 2_500,
            max_hops: 2,
            probes_per_hop: 2,
            status: RouteRunStatus::Partial,
            target_reached: false,
            hops: vec![
                aggregate_hop(
                    1,
                    vec![sample(RouteProbeOutcome::IcmpError, Some("192.0.2.254"))],
                ),
                aggregate_hop(2, vec![sample(RouteProbeOutcome::Timeout, None)]),
            ],
            error: None,
        };
        let summary = RouteRunSummary::from(&run);
        assert_eq!(summary.hop_count, 2);
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.timeout_count, 1);
        assert_eq!(summary.elapsed_ms, 1_500);
    }

    #[test]
    fn history_filter_defaults_are_explicit() {
        let filter = RouteHistoryFilter::default();
        assert_eq!(filter.limit, 50);
        assert!(filter.target.is_none());
        assert!(filter.method.is_none());
    }

    #[test]
    fn options_are_constructible() {
        let options = RouteOptions {
            target: "127.0.0.1".to_string(),
            method: RouteProbeMethod::Icmp,
            port: 33434,
            max_hops: 5,
            probes_per_hop: 2,
            timeout: std::time::Duration::from_millis(500),
            concurrency: 4,
        };
        assert_eq!(options.max_hops, 5);
    }
}
