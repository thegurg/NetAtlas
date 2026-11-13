//! DNS query orchestration, resolver comparison, and history access.
//!
//! Transport failures are measurements, not orchestration errors. A DNS response with
//! NXDOMAIN, SERVFAIL, or REFUSED is a valid response for exit-code purposes.

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::domain::{
    DnsComparison, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecordType, ResolverEndpoint,
    Transport, compare_measurements,
};
use crate::infrastructure::dns::{DnsClientConfig, query as raw_query};
use crate::infrastructure::storage::{StorageError, Store};

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub queries: Vec<DnsQuery>,
    pub resolvers: Vec<ResolverEndpoint>,
    pub transport: Transport,
    pub timeout: Duration,
    pub attempts: u32,
    pub concurrency: usize,
    pub dnssec_ok: bool,
}

/// Run every query against every resolver with bounded concurrency.
pub async fn execute(options: &QueryOptions, cancel: &CancellationToken) -> Vec<DnsMeasurement> {
    let client = DnsClientConfig {
        timeout: options.timeout,
        attempts: options.attempts,
        transport: options.transport,
        dnssec_ok: options.dnssec_ok,
        max_payload: 1_232,
    };

    let mut jobs = Vec::new();
    for resolver in &options.resolvers {
        for query in &options.queries {
            jobs.push((resolver.clone(), query.clone()));
        }
    }

    let mut measurements: Vec<DnsMeasurement> = stream::iter(jobs)
        .map(|(resolver, query)| {
            let client = client.clone();
            async move { raw_query(&resolver, &query, &client, cancel).await }
        })
        .buffer_unordered(options.concurrency.max(1))
        .collect()
        .await;

    measurements.sort_by(|left, right| {
        left.resolver
            .label
            .cmp(&right.resolver.label)
            .then_with(|| left.resolver.address.cmp(&right.resolver.address))
            .then_with(|| left.query.record_type.cmp(&right.query.record_type))
    });
    measurements
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRunSummary {
    pub total: usize,
    pub responded: usize,
    pub failed: usize,
    pub cancelled: usize,
    pub note: String,
}

pub fn summarize(measurements: &[DnsMeasurement]) -> DnsRunSummary {
    let responded = measurements
        .iter()
        .filter(|measurement| measurement.responded())
        .count();
    let failed = measurements
        .iter()
        .filter(|measurement| measurement.is_transport_failure())
        .count();
    let cancelled = measurements
        .iter()
        .filter(|measurement| measurement.outcome == DnsOutcome::Cancelled)
        .count();
    DnsRunSummary {
        total: measurements.len(),
        responded,
        failed,
        cancelled,
        note: "A DNS response such as NXDOMAIN, SERVFAIL, or REFUSED is a valid response and is not a transport failure."
            .to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCompareReport {
    pub name: String,
    pub resolvers: Vec<ResolverEndpoint>,
    pub comparisons: Vec<DnsComparison>,
    pub consistent: bool,
    pub note: String,
}

/// Compare measurements grouped by record type.
pub fn compare(measurements: &[DnsMeasurement]) -> DnsCompareReport {
    let Some(first) = measurements.first() else {
        return DnsCompareReport {
            name: String::new(),
            resolvers: Vec::new(),
            comparisons: Vec::new(),
            consistent: false,
            note: "No DNS measurements were produced; comparison is unavailable.".to_string(),
        };
    };

    let mut resolvers: Vec<ResolverEndpoint> = measurements
        .iter()
        .map(|measurement| measurement.resolver.clone())
        .collect();
    resolvers.sort_by(|left, right| {
        left.label
            .cmp(&right.label)
            .then_with(|| left.address.cmp(&right.address))
    });
    resolvers.dedup();

    let mut grouped: BTreeMap<DnsQuery, Vec<DnsMeasurement>> = BTreeMap::new();
    for measurement in measurements {
        grouped
            .entry(measurement.query.clone())
            .or_default()
            .push(measurement.clone());
    }

    let comparisons: Vec<DnsComparison> = grouped
        .iter()
        .map(|(query, group)| compare_measurements(query, group))
        .collect();
    let consistent = !comparisons.is_empty() && comparisons.iter().all(|item| item.consistent);
    let note = if consistent {
        "All compared queries returned consistent RCODE and answer sets (TTL and name case excluded). Comparison is a point-in-time measurement, not proof of correct configuration."
            .to_string()
    } else {
        "Resolvers did not agree on every query. Differences are measurements at this time; cached answers and split-horizon DNS can differ legitimately."
            .to_string()
    };

    DnsCompareReport {
        name: first.query.name.clone(),
        resolvers,
        comparisons,
        consistent,
        note,
    }
}

#[derive(Debug, Clone)]
pub struct DnsHistoryFilter {
    /// Normalized fully qualified name.
    pub name: Option<String>,
    pub record_type: Option<DnsRecordType>,
    /// Matches either the resolver label or its socket address.
    pub resolver: Option<String>,
    pub limit: usize,
}

impl Default for DnsHistoryFilter {
    fn default() -> Self {
        Self {
            name: None,
            record_type: None,
            resolver: None,
            limit: 50,
        }
    }
}

pub fn history(
    store: &Store,
    filter: &DnsHistoryFilter,
) -> Result<Vec<DnsMeasurement>, StorageError> {
    store.list_dns_measurements(
        filter.name.as_deref(),
        filter.record_type,
        filter.resolver.as_deref(),
        filter.limit,
    )
}

pub fn persist(store: &mut Store, measurements: &[DnsMeasurement]) -> Result<(), StorageError> {
    store.save_dns_measurements(measurements)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{DnsHistoryFilter, QueryOptions, compare, summarize};
    use crate::domain::{
        DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecord, DnsRecordType, DnsRecordValue,
        DnsResponse, DnsResponseCode, DnssecInfo, ResolverEndpoint, Transport, ids::new_id,
    };

    fn measurement(
        label: &str,
        record_type: DnsRecordType,
        rcode: DnsResponseCode,
        answer: &str,
        outcome: DnsOutcome,
    ) -> DnsMeasurement {
        let query = DnsQuery {
            name: "example.com.".to_string(),
            record_type,
        };
        let response = (outcome == DnsOutcome::Response).then(|| DnsResponse {
            rcode,
            flags: DnsFlags::default(),
            answers: vec![DnsRecord {
                name: "example.com.".to_string(),
                record_type,
                ttl: 300,
                value: DnsRecordValue::Address {
                    address: answer.parse().unwrap(),
                },
            }],
            authority: Vec::new(),
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
        });
        DnsMeasurement {
            id: new_id(),
            queried_at_ms: 1_000,
            resolver: ResolverEndpoint {
                label: label.to_string(),
                address: "127.0.0.1:53".parse::<SocketAddr>().unwrap(),
            },
            query,
            transport: Transport::Udp,
            outcome,
            elapsed_ms: 5,
            attempts: 1,
            response,
            dnssec: DnssecInfo::not_performed(true, false, false, true),
            error: None,
        }
    }

    #[test]
    fn compare_groups_by_record_type_and_detects_differences() {
        let measurements = vec![
            measurement(
                "system",
                DnsRecordType::A,
                DnsResponseCode::NoError,
                "192.0.2.1",
                DnsOutcome::Response,
            ),
            measurement(
                "public",
                DnsRecordType::A,
                DnsResponseCode::NoError,
                "192.0.2.2",
                DnsOutcome::Response,
            ),
            measurement(
                "system",
                DnsRecordType::Aaaa,
                DnsResponseCode::NoError,
                "2001:db8::1",
                DnsOutcome::Response,
            ),
            measurement(
                "public",
                DnsRecordType::Aaaa,
                DnsResponseCode::NoError,
                "2001:db8::1",
                DnsOutcome::Response,
            ),
        ];
        let report = compare(&measurements);
        assert_eq!(report.name, "example.com.");
        assert_eq!(report.resolvers.len(), 2);
        assert_eq!(report.comparisons.len(), 2);
        assert!(!report.consistent);
        let a = report
            .comparisons
            .iter()
            .find(|comparison| comparison.query.record_type == DnsRecordType::A)
            .unwrap();
        assert!(!a.answers_consistent);
        let aaaa = report
            .comparisons
            .iter()
            .find(|comparison| comparison.query.record_type == DnsRecordType::Aaaa)
            .unwrap();
        assert!(aaaa.consistent);
    }

    #[test]
    fn summary_counts_transport_failures_separately() {
        let measurements = vec![
            measurement(
                "system",
                DnsRecordType::A,
                DnsResponseCode::NxDomain,
                "192.0.2.1",
                DnsOutcome::Response,
            ),
            measurement(
                "public",
                DnsRecordType::A,
                DnsResponseCode::NoError,
                "192.0.2.1",
                DnsOutcome::Timeout,
            ),
        ];
        let summary = summarize(&measurements);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.responded, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.note.contains("valid response"));
    }

    #[test]
    fn empty_compare_and_history_defaults_are_explicit() {
        let report = compare(&[]);
        assert!(!report.consistent);
        assert!(report.comparisons.is_empty());
        assert!(report.note.contains("unavailable"));
        let filter = DnsHistoryFilter::default();
        assert_eq!(filter.limit, 50);
        assert!(filter.name.is_none());
    }

    #[test]
    fn query_options_are_constructible() {
        let options = QueryOptions {
            queries: vec![DnsQuery {
                name: "example.com.".to_string(),
                record_type: DnsRecordType::A,
            }],
            resolvers: vec![ResolverEndpoint {
                label: "system".to_string(),
                address: "127.0.0.1:53".parse().unwrap(),
            }],
            transport: Transport::Udp,
            timeout: std::time::Duration::from_millis(500),
            attempts: 1,
            concurrency: 4,
            dnssec_ok: true,
        };
        assert_eq!(options.queries.len(), 1);
    }
}
