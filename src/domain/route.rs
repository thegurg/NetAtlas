//! Route exploration types, aggregation, and comparison rules.
//!
//! A route run is a measurement, not a device property. A hop that does not answer
//! within the probe window is `no_response`; it is never proof that the route is broken.
//! Loss estimates always carry the sample count that produced them.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::DomainError;

/// Probe methods NetAtlas can use for route exploration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProbeMethod {
    Icmp,
    Udp,
    Tcp,
}

impl RouteProbeMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl fmt::Display for RouteProbeMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RouteProbeMethod {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "icmp" => Ok(Self::Icmp),
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            other => Err(DomainError::InvalidRouteProbeMethod(other.to_string())),
        }
    }
}

/// Outcome of one probe sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteProbeOutcome {
    /// A reply or an ICMP error from the target was received.
    Reply,
    /// An ICMP error from an intermediate router (for example Time Exceeded).
    IcmpError,
    /// No response within the probe timeout.
    Timeout,
    /// Socket or transport failure.
    TransportError,
    /// The run was cancelled.
    Cancelled,
}

impl RouteProbeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::IcmpError => "icmp_error",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_response(self) -> bool {
        matches!(self, Self::Reply | Self::IcmpError)
    }
}

impl fmt::Display for RouteProbeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RouteProbeOutcome {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "reply" => Ok(Self::Reply),
            "icmp_error" => Ok(Self::IcmpError),
            "timeout" => Ok(Self::Timeout),
            "transport_error" => Ok(Self::TransportError),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(DomainError::InvalidRouteProbeOutcome(other.to_string())),
        }
    }
}

/// Status of a complete route run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteRunStatus {
    /// The target answered within the hop limit.
    Completed,
    /// The hop limit was reached without an answer from the target.
    Partial,
    /// No hop answered within the probe window.
    NoResponse,
    /// Socket or setup failure prevented a meaningful run.
    Failed,
    /// The run was cancelled.
    Cancelled,
}

impl RouteRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::NoResponse => "no_response",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for RouteRunStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RouteRunStatus {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "completed" => Ok(Self::Completed),
            "partial" => Ok(Self::Partial),
            "no_response" => Ok(Self::NoResponse),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(DomainError::InvalidRouteRunStatus(other.to_string())),
        }
    }
}

/// One probe sent at one TTL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteSample {
    pub probe_index: u32,
    pub sent_at_ms: i64,
    pub outcome: RouteProbeOutcome,
    pub responder: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub error: Option<String>,
}

/// All probes for one TTL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteHop {
    pub ttl: u8,
    pub responder: Option<IpAddr>,
    pub hostname: Option<String>,
    pub samples: Vec<RouteSample>,
    pub reply_count: usize,
    pub timeout_count: usize,
    pub error_count: usize,
    pub best_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    /// Fraction of probes that timed out, in `[0, 1]`.
    pub loss_ratio: f64,
}

impl RouteHop {
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub fn responded(&self) -> bool {
        self.responder.is_some()
    }
}

/// Aggregate raw samples for one TTL into a hop.
pub fn aggregate_hop(ttl: u8, samples: Vec<RouteSample>) -> RouteHop {
    let mut responder: Option<IpAddr> = None;
    let mut reply_count = 0_usize;
    let mut timeout_count = 0_usize;
    let mut error_count = 0_usize;
    let mut rtts: Vec<f64> = Vec::new();

    for sample in &samples {
        match sample.outcome {
            RouteProbeOutcome::Reply => {
                reply_count += 1;
                responder = responder.or(sample.responder);
                if let Some(rtt) = sample.rtt_ms {
                    rtts.push(rtt);
                }
            }
            RouteProbeOutcome::IcmpError => {
                error_count += 1;
                responder = responder.or(sample.responder);
                if let Some(rtt) = sample.rtt_ms {
                    rtts.push(rtt);
                }
            }
            RouteProbeOutcome::Timeout => {
                timeout_count += 1;
            }
            RouteProbeOutcome::TransportError | RouteProbeOutcome::Cancelled => {
                error_count += 1;
            }
        }
    }

    let best_rtt_ms = rtts.iter().cloned().reduce(f64::min);
    let avg_rtt_ms = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };
    let loss_ratio = if samples.is_empty() {
        0.0
    } else {
        timeout_count as f64 / samples.len() as f64
    };

    RouteHop {
        ttl,
        responder,
        hostname: None,
        samples,
        reply_count,
        timeout_count,
        error_count,
        best_rtt_ms,
        avg_rtt_ms,
        loss_ratio,
    }
}

/// A complete route measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRun {
    pub id: Uuid,
    pub target: String,
    pub target_ip: IpAddr,
    pub method: RouteProbeMethod,
    pub port: Option<u16>,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub status: RouteRunStatus,
    pub target_reached: bool,
    pub hops: Vec<RouteHop>,
    pub error: Option<String>,
}

impl RouteRun {
    pub fn sample_count(&self) -> usize {
        self.hops.iter().map(RouteHop::sample_count).sum()
    }

    pub fn timeout_count(&self) -> usize {
        self.hops.iter().map(|hop| hop.timeout_count).sum()
    }

    pub fn responder_sequence(&self) -> Vec<Option<IpAddr>> {
        self.hops.iter().map(|hop| hop.responder).collect()
    }
}

/// Comparison of two route runs for the same target and method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteComparison {
    pub target: String,
    pub target_ip: IpAddr,
    pub method: RouteProbeMethod,
    pub port: Option<u16>,
    pub left_run_id: Uuid,
    pub right_run_id: Uuid,
    pub comparable: bool,
    pub route_changed: bool,
    pub hop_count_changed: bool,
    pub target_reached_left: bool,
    pub target_reached_right: bool,
    pub rtt_changed: bool,
    pub loss_changed: bool,
    pub notes: Vec<String>,
}

/// RTT differences below this absolute threshold are treated as jitter.
const RTT_ABSOLUTE_THRESHOLD_MS: f64 = 1.0;
/// RTT differences below this relative threshold are treated as jitter.
const RTT_RELATIVE_THRESHOLD: f64 = 0.10;
/// Loss differences below this are treated as noise.
const LOSS_THRESHOLD: f64 = 0.05;

fn rtt_changed(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            let absolute = (left - right).abs();
            let relative = absolute / left.abs().max(right.abs()).max(1.0);
            absolute > RTT_ABSOLUTE_THRESHOLD_MS && relative > RTT_RELATIVE_THRESHOLD
        }
        (None, None) => false,
        _ => true,
    }
}

/// Compare two runs. Only runs with the same target IP, method, and port are comparable.
pub fn compare_runs(left: &RouteRun, right: &RouteRun) -> RouteComparison {
    let comparable =
        left.target_ip == right.target_ip && left.method == right.method && left.port == right.port;
    let mut notes = Vec::new();

    if !comparable {
        notes.push(
            "Runs are not comparable: the target IP, probe method, or port differs.".to_string(),
        );
        return RouteComparison {
            target: left.target.clone(),
            target_ip: left.target_ip,
            method: left.method,
            port: left.port,
            left_run_id: left.id,
            right_run_id: right.id,
            comparable: false,
            route_changed: false,
            hop_count_changed: false,
            target_reached_left: left.target_reached,
            target_reached_right: right.target_reached,
            rtt_changed: false,
            loss_changed: false,
            notes,
        };
    }

    let left_sequence = left.responder_sequence();
    let right_sequence = right.responder_sequence();
    let route_changed = left_sequence != right_sequence;
    let hop_count_changed = left.hops.len() != right.hops.len();
    let target_reached_left = left.target_reached;
    let target_reached_right = right.target_reached;

    if route_changed {
        notes.push(
            "The sequence of responding hop addresses changed (non-responsive hops are included as unknown)."
                .to_string(),
        );
    }
    if hop_count_changed {
        notes.push(format!(
            "Hop count changed from {} to {}.",
            left.hops.len(),
            right.hops.len()
        ));
    }
    if target_reached_left != target_reached_right {
        notes.push(format!(
            "Target reachability changed: left={}, right={}.",
            if target_reached_left {
                "reached"
            } else {
                "not reached"
            },
            if target_reached_right {
                "reached"
            } else {
                "not reached"
            }
        ));
    }

    let mut rtt_changed_any = false;
    let mut loss_changed_any = false;
    for (index, left_hop) in left.hops.iter().enumerate() {
        let Some(right_hop) = right.hops.get(index) else {
            break;
        };
        if left_hop.responder != right_hop.responder {
            continue;
        }
        if rtt_changed(left_hop.avg_rtt_ms, right_hop.avg_rtt_ms) {
            rtt_changed_any = true;
            notes.push(format!(
                "Hop {} average RTT changed from {:?} ms to {:?} ms.",
                left_hop.ttl, left_hop.avg_rtt_ms, right_hop.avg_rtt_ms
            ));
        }
        let left_loss = left_hop.loss_ratio;
        let right_loss = right_hop.loss_ratio;
        if (left_loss - right_loss).abs() > LOSS_THRESHOLD {
            loss_changed_any = true;
            notes.push(format!(
                "Hop {} loss changed from {:.0}% to {:.0}% over {} sample(s).",
                left_hop.ttl,
                left_loss * 100.0,
                right_loss * 100.0,
                right_hop.sample_count()
            ));
        }
    }

    if !route_changed
        && !hop_count_changed
        && !rtt_changed_any
        && !loss_changed_any
        && target_reached_left == target_reached_right
    {
        notes.push(
            "Both runs produced the same hop sequence, reachability, RTTs, and loss within the documented thresholds."
                .to_string(),
        );
    }
    notes.push(format!(
        "Comparison is based on {} sample(s) in the left run and {} in the right run; it is a point-in-time measurement.",
        left.sample_count(),
        right.sample_count()
    ));

    RouteComparison {
        target: left.target.clone(),
        target_ip: left.target_ip,
        method: left.method,
        port: left.port,
        left_run_id: left.id,
        right_run_id: right.id,
        comparable,
        route_changed,
        hop_count_changed,
        target_reached_left,
        target_reached_right,
        rtt_changed: rtt_changed_any,
        loss_changed: loss_changed_any,
        notes,
    }
}

/// A set of unique responder addresses in a run, useful for reverse DNS.
pub fn responder_addresses(run: &RouteRun) -> Vec<IpAddr> {
    let set: BTreeSet<IpAddr> = run.hops.iter().filter_map(|hop| hop.responder).collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        RouteHop, RouteProbeMethod, RouteProbeOutcome, RouteRun, RouteRunStatus, RouteSample,
        aggregate_hop, compare_runs, responder_addresses,
    };
    use crate::domain::ids::new_id;
    use std::net::IpAddr;
    use uuid::Uuid;

    fn sample(
        index: u32,
        outcome: RouteProbeOutcome,
        responder: Option<&str>,
        rtt: Option<f64>,
    ) -> RouteSample {
        RouteSample {
            probe_index: index,
            sent_at_ms: 1_000 + i64::from(index),
            outcome,
            responder: responder.map(|value| value.parse().unwrap()),
            rtt_ms: rtt,
            icmp_type: None,
            icmp_code: None,
            error: None,
        }
    }

    fn run(
        id: Uuid,
        hops: Vec<RouteHop>,
        target_reached: bool,
        status: RouteRunStatus,
    ) -> RouteRun {
        RouteRun {
            id,
            target: "example.com".to_string(),
            target_ip: "192.0.2.1".parse().unwrap(),
            method: RouteProbeMethod::Udp,
            port: Some(33434),
            started_at_ms: 1_000,
            finished_at_ms: 2_000,
            max_hops: 3,
            probes_per_hop: 3,
            status,
            target_reached,
            hops,
            error: None,
        }
    }

    #[test]
    fn method_and_outcome_parse_and_display() {
        assert_eq!(
            "udp".parse::<RouteProbeMethod>().unwrap(),
            RouteProbeMethod::Udp
        );
        assert_eq!(
            "ICMP".parse::<RouteProbeMethod>().unwrap(),
            RouteProbeMethod::Icmp
        );
        assert_eq!(
            "tcp".parse::<RouteProbeMethod>().unwrap(),
            RouteProbeMethod::Tcp
        );
        assert!("gre".parse::<RouteProbeMethod>().is_err());

        assert_eq!(RouteProbeOutcome::IcmpError.as_str(), "icmp_error");
        assert!(RouteProbeOutcome::Reply.is_response());
        assert!(!RouteProbeOutcome::Timeout.is_response());
        assert_eq!(
            "cancelled".parse::<RouteProbeOutcome>().unwrap(),
            RouteProbeOutcome::Cancelled
        );
    }

    #[test]
    fn aggregation_counts_samples_and_loss() {
        let hop = aggregate_hop(
            1,
            vec![
                sample(
                    0,
                    RouteProbeOutcome::IcmpError,
                    Some("192.0.2.254"),
                    Some(2.0),
                ),
                sample(1, RouteProbeOutcome::Timeout, None, None),
                sample(2, RouteProbeOutcome::Timeout, None, None),
            ],
        );
        assert_eq!(
            hop.responder.unwrap(),
            "192.0.2.254".parse::<IpAddr>().unwrap()
        );
        assert_eq!(hop.reply_count, 0);
        assert_eq!(hop.timeout_count, 2);
        assert_eq!(hop.error_count, 1);
        assert_eq!(hop.sample_count(), 3);
        assert_eq!(hop.best_rtt_ms, Some(2.0));
        assert_eq!(hop.avg_rtt_ms, Some(2.0));
        assert!((hop.loss_ratio - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn comparison_detects_route_and_metric_changes() {
        let left = run(
            new_id(),
            vec![
                aggregate_hop(
                    1,
                    vec![sample(
                        0,
                        RouteProbeOutcome::IcmpError,
                        Some("192.0.2.254"),
                        Some(2.0),
                    )],
                ),
                aggregate_hop(
                    2,
                    vec![sample(
                        0,
                        RouteProbeOutcome::Reply,
                        Some("192.0.2.1"),
                        Some(10.0),
                    )],
                ),
            ],
            true,
            RouteRunStatus::Completed,
        );
        let right = run(
            new_id(),
            vec![
                aggregate_hop(
                    1,
                    vec![sample(
                        0,
                        RouteProbeOutcome::IcmpError,
                        Some("192.0.2.254"),
                        Some(2.0),
                    )],
                ),
                aggregate_hop(
                    2,
                    vec![sample(
                        0,
                        RouteProbeOutcome::IcmpError,
                        Some("192.0.2.1"),
                        Some(20.0),
                    )],
                ),
                aggregate_hop(
                    3,
                    vec![sample(
                        0,
                        RouteProbeOutcome::Reply,
                        Some("192.0.2.1"),
                        Some(15.0),
                    )],
                ),
            ],
            true,
            RouteRunStatus::Completed,
        );
        let comparison = compare_runs(&left, &right);
        assert!(comparison.comparable);
        assert!(comparison.route_changed);
        assert!(comparison.hop_count_changed);
        assert!(comparison.rtt_changed);
        assert!(comparison.target_reached_left);
        assert!(comparison.target_reached_right);
    }

    #[test]
    fn comparison_ignores_small_rtt_jitter() {
        let left = run(
            new_id(),
            vec![aggregate_hop(
                1,
                vec![sample(
                    0,
                    RouteProbeOutcome::IcmpError,
                    Some("192.0.2.254"),
                    Some(2.0),
                )],
            )],
            false,
            RouteRunStatus::Partial,
        );
        let right = run(
            new_id(),
            vec![aggregate_hop(
                1,
                vec![sample(
                    0,
                    RouteProbeOutcome::IcmpError,
                    Some("192.0.2.254"),
                    Some(2.2),
                )],
            )],
            false,
            RouteRunStatus::Partial,
        );
        let comparison = compare_runs(&left, &right);
        assert!(!comparison.route_changed);
        assert!(!comparison.rtt_changed);
        assert!(!comparison.loss_changed);
    }

    #[test]
    fn comparison_rejects_different_methods() {
        let mut left = run(new_id(), vec![], false, RouteRunStatus::Partial);
        left.method = RouteProbeMethod::Udp;
        let mut right = run(new_id(), vec![], false, RouteRunStatus::Partial);
        right.method = RouteProbeMethod::Tcp;
        let comparison = compare_runs(&left, &right);
        assert!(!comparison.comparable);
        assert!(!comparison.route_changed);
    }

    #[test]
    fn responder_addresses_are_unique() {
        let run = run(
            new_id(),
            vec![
                aggregate_hop(
                    1,
                    vec![sample(
                        0,
                        RouteProbeOutcome::IcmpError,
                        Some("192.0.2.254"),
                        Some(2.0),
                    )],
                ),
                aggregate_hop(
                    2,
                    vec![sample(
                        0,
                        RouteProbeOutcome::Reply,
                        Some("192.0.2.1"),
                        Some(10.0),
                    )],
                ),
                aggregate_hop(
                    3,
                    vec![sample(
                        0,
                        RouteProbeOutcome::Reply,
                        Some("192.0.2.1"),
                        Some(11.0),
                    )],
                ),
            ],
            true,
            RouteRunStatus::Completed,
        );
        assert_eq!(responder_addresses(&run).len(), 2);
    }
}
