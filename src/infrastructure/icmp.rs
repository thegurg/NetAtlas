//! Unprivileged ICMP echo probing.
//!
//! Uses Linux ICMP datagram sockets through `surge-ping`. When the kernel's
//! `net.ipv4.ping_group_range` does not permit this user, setup fails with a
//! typed permission error and the caller records `insufficient_permissions`
//! instead of aborting the scan.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const PAYLOAD: &[u8] = b"netatlas";

#[derive(Debug, Error)]
pub enum IcmpError {
    #[error("ICMP datagram sockets are not permitted for this user: {0}")]
    PermissionDenied(String),
    #[error("ICMP probe setup failed: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IcmpReply {
    pub ip: IpAddr,
    pub rtt_ms: f64,
}

#[derive(Debug, Clone, Default)]
pub struct IcmpSweep {
    pub replies: Vec<IcmpReply>,
    pub failed: usize,
}

/// Probe every address, bounded by `concurrency`, and return the replies.
///
/// Timeouts and unreachable hosts are ordinary results, not errors: they are
/// counted in `failed` and never reported as proof that a host is offline.
pub async fn sweep(
    addresses: &[IpAddr],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> Result<IcmpSweep, IcmpError> {
    let v4: Vec<(usize, IpAddr)> = addresses
        .iter()
        .enumerate()
        .filter(|(_, ip)| ip.is_ipv4())
        .map(|(index, ip)| (index, *ip))
        .collect();
    let v6: Vec<(usize, IpAddr)> = addresses
        .iter()
        .enumerate()
        .filter(|(_, ip)| ip.is_ipv6())
        .map(|(index, ip)| (index, *ip))
        .collect();

    let mut sweep = IcmpSweep::default();
    if !v4.is_empty() {
        sweep
            .replies
            .extend(sweep_family(&v4, ICMP::V4, timeout, concurrency, cancel).await?);
    }
    if !v6.is_empty() {
        sweep
            .replies
            .extend(sweep_family(&v6, ICMP::V6, timeout, concurrency, cancel).await?);
    }

    sweep.replies.sort_by_key(|left| left.ip);
    sweep.failed = addresses.len().saturating_sub(sweep.replies.len());
    Ok(sweep)
}

async fn sweep_family(
    targets: &[(usize, IpAddr)],
    kind: ICMP,
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> Result<Vec<IcmpReply>, IcmpError> {
    let client = Client::new(&Config::builder().kind(kind).build()).map_err(map_setup_error)?;

    let results: Vec<Option<IcmpReply>> = stream::iter(targets.iter().copied())
        .map(|(index, ip)| {
            let client = client.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                let mut pinger = client
                    .pinger(ip, PingIdentifier((index % u16::MAX as usize) as u16))
                    .await;
                pinger.timeout(timeout);
                match pinger.ping(PingSequence(0), PAYLOAD).await {
                    Ok((_packet, duration)) => Some(IcmpReply {
                        ip,
                        rtt_ms: duration.as_secs_f64() * 1_000.0,
                    }),
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}

fn map_setup_error(error: io::Error) -> IcmpError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        IcmpError::PermissionDenied(error.to_string())
    } else {
        IcmpError::Unavailable(error.to_string())
    }
}
