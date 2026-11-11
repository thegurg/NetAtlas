//! Reverse DNS (PTR) lookups through the system resolver.
//!
//! A PTR answer is a naming hint, not a verified device identity. NXDOMAIN and
//! SERVFAIL are ordinary per-address results; only resolver setup failure is a
//! provider-level error.

use std::net::IpAddr;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("resolver setup failed: {0}")]
    Resolver(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrAnswer {
    pub ip: IpAddr,
    pub name: String,
    pub ttl: Option<u32>,
}

/// Resolve PTR records for each address with bounded concurrency.
pub async fn lookup(
    addresses: &[IpAddr],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> Result<Vec<PtrAnswer>, DnsError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|error| DnsError::Resolver(error.to_string()))?
        .build()
        .map_err(|error| DnsError::Resolver(error.to_string()))?;

    let mut answers: Vec<PtrAnswer> = stream::iter(addresses.iter().copied())
        .map(|ip| {
            let resolver = resolver.clone();
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return None;
                }
                match tokio::time::timeout(timeout, resolver.reverse_lookup(ip)).await {
                    Ok(Ok(lookup)) => lookup.answers().iter().find_map(|record| {
                        let RData::PTR(ptr) = &record.data else {
                            return None;
                        };
                        let name = ptr.0.to_utf8();
                        let name = name.trim_end_matches('.').to_string();
                        (!name.is_empty()).then_some(PtrAnswer {
                            ip,
                            name,
                            ttl: Some(record.ttl),
                        })
                    }),
                    Ok(Err(_)) | Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|answer| async move { answer })
        .collect()
        .await;

    answers.sort_by_key(|left| left.ip);
    Ok(answers)
}
