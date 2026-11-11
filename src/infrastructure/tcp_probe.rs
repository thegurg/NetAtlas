//! Bounded TCP connect probing.
//!
//! A successful connection and a connection refusal both prove that the host
//! answered. A timeout proves nothing and is never treated as absence.

use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::domain::TcpProbeOutcome;

/// A small set of ports used only as a reachability fallback when ICMP is
/// unavailable or silent. These are not service-identification probes.
pub const DEFAULT_TCP_PORTS: &[u16] = &[80, 443, 22, 445];

#[derive(Debug, Clone, PartialEq)]
pub struct TcpProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub outcome: TcpProbeOutcome,
    pub rtt_ms: Option<f64>,
}

/// Probe `ports` on every address with bounded concurrency.
pub async fn probe_hosts(
    addresses: &[IpAddr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> Vec<TcpProbeResult> {
    let targets: Vec<(IpAddr, u16)> = addresses
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| (*ip, *port)))
        .collect();

    let mut results: Vec<TcpProbeResult> = stream::iter(targets)
        .map(|(ip, port)| {
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                Some(probe_one(ip, port, timeout).await)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|result| async move { result })
        .collect()
        .await;

    results.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then_with(|| left.port.cmp(&right.port))
    });
    results
}

async fn probe_one(ip: IpAddr, port: u16, timeout: Duration) -> TcpProbeResult {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect((ip, port))).await {
        Ok(Ok(stream)) => {
            drop(stream);
            TcpProbeResult {
                ip,
                port,
                outcome: TcpProbeOutcome::Open,
                rtt_ms: Some(started.elapsed().as_secs_f64() * 1_000.0),
            }
        }
        Ok(Err(error)) => TcpProbeResult {
            ip,
            port,
            outcome: outcome_for_error(&error),
            rtt_ms: Some(started.elapsed().as_secs_f64() * 1_000.0),
        },
        Err(_) => TcpProbeResult {
            ip,
            port,
            outcome: TcpProbeOutcome::Timeout,
            rtt_ms: None,
        },
    }
}

fn outcome_for_error(error: &io::Error) -> TcpProbeOutcome {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => TcpProbeOutcome::Refused,
        io::ErrorKind::TimedOut => TcpProbeOutcome::Timeout,
        _ => TcpProbeOutcome::Error,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::{probe_hosts, probe_one};
    use crate::domain::TcpProbeOutcome;

    #[tokio::test]
    async fn open_port_is_detected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = probe_one(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(result.outcome, TcpProbeOutcome::Open);
        assert!(result.rtt_ms.is_some());
    }

    #[tokio::test]
    async fn closed_port_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let result = probe_one(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(result.outcome, TcpProbeOutcome::Refused);
    }

    #[tokio::test]
    async fn cancellation_returns_no_results() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let results = probe_hosts(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[9],
            Duration::from_millis(500),
            4,
            &cancel,
        )
        .await;
        assert!(results.is_empty());
    }
}
