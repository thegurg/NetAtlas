//! DNS diagnostics types and comparison rules.
//!
//! A DNS measurement is a fact about one query sent to one resolver at one time. It is
//! not a device property and it is not proof that a name currently resolves elsewhere.
//! DNSSEC is reported as an explicit state; the presence of an AD flag or RRSIG record
//! is not local cryptographic validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{DomainError, Transport};

/// Record types NetAtlas can request explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Txt,
    Soa,
}

impl DnsRecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Soa => "SOA",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DnsRecordType {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "CNAME" => Ok(Self::Cname),
            "MX" => Ok(Self::Mx),
            "NS" => Ok(Self::Ns),
            "TXT" => Ok(Self::Txt),
            "SOA" => Ok(Self::Soa),
            other => Err(DomainError::InvalidDnsRecordType(other.to_string())),
        }
    }
}

/// A DNS response code, including the extended codes carried by EDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrSet,
    NxRrSet,
    NotAuth,
    NotZone,
    BadVers,
    BadKey,
    BadTime,
    BadMode,
    BadName,
    BadAlg,
    BadTrunc,
    BadCookie,
    Unknown(u16),
}

impl DnsResponseCode {
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrSet,
            8 => Self::NxRrSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            16 => Self::BadVers,
            17 => Self::BadKey,
            18 => Self::BadTime,
            19 => Self::BadMode,
            20 => Self::BadName,
            21 => Self::BadAlg,
            22 => Self::BadTrunc,
            23 => Self::BadCookie,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u16 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::YxRrSet => 7,
            Self::NxRrSet => 8,
            Self::NotAuth => 9,
            Self::NotZone => 10,
            Self::BadVers => 16,
            Self::BadKey => 17,
            Self::BadTime => 18,
            Self::BadMode => 19,
            Self::BadName => 20,
            Self::BadAlg => 21,
            Self::BadTrunc => 22,
            Self::BadCookie => 23,
            Self::Unknown(code) => code,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::YxDomain => "YXDOMAIN",
            Self::YxRrSet => "YXRRSET",
            Self::NxRrSet => "NXRRSET",
            Self::NotAuth => "NOTAUTH",
            Self::NotZone => "NOTZONE",
            Self::BadVers => "BADVERS",
            Self::BadKey => "BADKEY",
            Self::BadTime => "BADTIME",
            Self::BadMode => "BADMODE",
            Self::BadName => "BADNAME",
            Self::BadAlg => "BADALG",
            Self::BadTrunc => "BADTRUNC",
            Self::BadCookie => "BADCOOKIE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn is_no_error(self) -> bool {
        self == Self::NoError
    }
}

impl fmt::Display for DnsResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl FromStr for DnsResponseCode {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if let Ok(code) = trimmed.parse::<u16>() {
            return Ok(Self::from_code(code));
        }
        let normalized = trimmed.to_ascii_uppercase().replace(['-', '_'], "");
        let code = match normalized.as_str() {
            "NOERROR" => Self::NoError,
            "FORMERR" => Self::FormErr,
            "SERVFAIL" => Self::ServFail,
            "NXDOMAIN" => Self::NxDomain,
            "NOTIMP" => Self::NotImp,
            "REFUSED" => Self::Refused,
            "YXDOMAIN" => Self::YxDomain,
            "YXRRSET" => Self::YxRrSet,
            "NXRRSET" => Self::NxRrSet,
            "NOTAUTH" => Self::NotAuth,
            "NOTZONE" => Self::NotZone,
            "BADVERS" => Self::BadVers,
            "BADKEY" => Self::BadKey,
            "BADTIME" => Self::BadTime,
            "BADMODE" => Self::BadMode,
            "BADNAME" => Self::BadName,
            "BADALG" => Self::BadAlg,
            "BADTRUNC" => Self::BadTrunc,
            "BADCOOKIE" => Self::BadCookie,
            _ => {
                return Err(DomainError::InvalidDnsResponseCode(trimmed.to_string()));
            }
        };
        Ok(code)
    }
}

/// How one DNS query attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    /// A DNS response was received. The RCODE may still be an error such as NXDOMAIN.
    Response,
    /// No response arrived before the timeout.
    Timeout,
    /// The socket, framing, or message was unusable.
    TransportError,
    /// The operation was cancelled by the user.
    Cancelled,
}

impl DnsOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Response => "response",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_transport_failure(self) -> bool {
        matches!(self, Self::Timeout | Self::TransportError)
    }
}

impl fmt::Display for DnsOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DnsOutcome {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "response" => Ok(Self::Response),
            "timeout" => Ok(Self::Timeout),
            "transport_error" => Ok(Self::TransportError),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(DomainError::InvalidDnsOutcome(other.to_string())),
        }
    }
}

/// DNSSEC validation state.
///
/// NetAtlas currently only emits `NotPerformed`. The other states are reserved for a
/// future cryptographic validator and are never inferred from the AD bit or RRSIG
/// presence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DnssecValidation {
    #[default]
    NotPerformed,
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

impl DnssecValidation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotPerformed => "not_performed",
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }
}

impl fmt::Display for DnssecValidation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DnssecValidation {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "not_performed" => Ok(Self::NotPerformed),
            "secure" => Ok(Self::Secure),
            "insecure" => Ok(Self::Insecure),
            "bogus" => Ok(Self::Bogus),
            "indeterminate" => Ok(Self::Indeterminate),
            other => Err(DomainError::InvalidDnssecState(other.to_string())),
        }
    }
}

/// Explicit DNSSEC observations for one measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecInfo {
    pub validation: DnssecValidation,
    /// Whether this client set the EDNS DNSSEC OK (DO) bit.
    pub do_bit: bool,
    /// The AD bit in the response. This is the resolver's claim, not local validation.
    pub ad_flag: bool,
    /// Whether an RRSIG record was present in the response.
    pub rrsig_present: bool,
    /// Whether the response contained an EDNS OPT record.
    pub response_edns: bool,
    pub note: String,
}

impl DnssecInfo {
    pub fn not_performed(
        do_bit: bool,
        ad_flag: bool,
        rrsig_present: bool,
        response_edns: bool,
    ) -> Self {
        Self {
            validation: DnssecValidation::NotPerformed,
            do_bit,
            ad_flag,
            rrsig_present,
            response_edns,
            note: "No cryptographic DNSSEC validation was performed. AD and RRSIG are observations, not a validation result."
                .to_string(),
        }
    }

    pub fn no_response(do_bit: bool) -> Self {
        Self {
            validation: DnssecValidation::NotPerformed,
            do_bit,
            ad_flag: false,
            rrsig_present: false,
            response_edns: false,
            note: "No DNS response was received; no DNSSEC validation was performed.".to_string(),
        }
    }
}

/// DNS header flags that are useful for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DnsFlags {
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
}

/// Structured record data for the types NetAtlas requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsRecordValue {
    Address {
        address: IpAddr,
    },
    Name {
        target: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt {
        segments: Vec<String>,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
}

impl DnsRecordValue {
    /// A stable representation used for answer-set comparison.
    pub fn canonical(&self) -> String {
        match self {
            Self::Address { address } => address.to_string(),
            Self::Name { target } => target.to_ascii_lowercase(),
            Self::Mx {
                preference,
                exchange,
            } => format!("{preference} {}", exchange.to_ascii_lowercase()),
            Self::Txt { segments } => segments.join("\u{1f}"),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!(
                "{} {} {serial} {refresh} {retry} {expire} {minimum}",
                mname.to_ascii_lowercase(),
                rname.to_ascii_lowercase()
            ),
        }
    }

    pub fn display_value(&self) -> String {
        match self {
            Self::Address { address } => address.to_string(),
            Self::Name { target } => target.clone(),
            Self::Mx {
                preference,
                exchange,
            } => format!("{preference} {exchange}"),
            Self::Txt { segments } => segments
                .iter()
                .map(|segment| format!("\"{segment}\""))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
        }
    }
}

/// One resource record from an answer or authority section.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: u32,
    pub value: DnsRecordValue,
}

impl DnsRecord {
    /// Comparison key that excludes TTL and ignores DNS name case.
    pub fn canonical(&self) -> String {
        format!(
            "{}|{}|{}",
            self.record_type.as_str(),
            self.name.to_ascii_lowercase(),
            self.value.canonical()
        )
    }
}

/// A received DNS response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResponse {
    pub rcode: DnsResponseCode,
    pub flags: DnsFlags,
    /// Supported records from the answer section. `answer_count` may be larger when the
    /// response contains types NetAtlas does not model.
    pub answers: Vec<DnsRecord>,
    /// Supported records from the authority section.
    pub authority: Vec<DnsRecord>,
    pub answer_count: usize,
    pub authority_count: usize,
    pub additional_count: usize,
}

impl DnsResponse {
    pub fn answer_set(&self) -> BTreeSet<String> {
        self.answers.iter().map(DnsRecord::canonical).collect()
    }
}

/// A resolver endpoint selected for a measurement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolverEndpoint {
    /// Human label such as `system` or the socket address used for a custom resolver.
    pub label: String,
    pub address: SocketAddr,
}

impl fmt::Display for ResolverEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.label, self.address)
    }
}

/// A normalized query name and record type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Fully qualified, normalized name such as `example.com.`.
    pub name: String,
    pub record_type: DnsRecordType,
}

impl fmt::Display for DnsQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.name, self.record_type)
    }
}

/// One query to one resolver. Transport failures are measurements too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMeasurement {
    pub id: Uuid,
    pub queried_at_ms: i64,
    pub resolver: ResolverEndpoint,
    pub query: DnsQuery,
    /// The transport actually used for a successful exchange. On failure this records
    /// the requested transport.
    pub transport: Transport,
    pub outcome: DnsOutcome,
    pub elapsed_ms: u64,
    /// Number of exchange attempts made.
    pub attempts: u32,
    pub response: Option<DnsResponse>,
    pub dnssec: DnssecInfo,
    pub error: Option<String>,
}

impl DnsMeasurement {
    pub fn rcode(&self) -> Option<DnsResponseCode> {
        self.response.as_ref().map(|response| response.rcode)
    }

    pub fn responded(&self) -> bool {
        self.outcome == DnsOutcome::Response && self.response.is_some()
    }

    pub fn is_transport_failure(&self) -> bool {
        self.outcome.is_transport_failure()
    }

    pub fn answer_set(&self) -> BTreeSet<String> {
        self.response
            .as_ref()
            .map(DnsResponse::answer_set)
            .unwrap_or_default()
    }
}

/// Result of comparing the same query across resolvers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsComparison {
    pub query: DnsQuery,
    pub measurements: Vec<DnsMeasurement>,
    pub responded: usize,
    pub failed: usize,
    pub cancelled: usize,
    /// True when at least two resolvers returned a DNS response.
    pub comparable: bool,
    pub rcode_consistent: bool,
    /// Answer-set equality excludes TTL and DNS name case.
    pub answers_consistent: bool,
    pub ttl_varied: bool,
    pub dnssec_varied: bool,
    pub consistent: bool,
    pub notes: Vec<String>,
}

/// Compare the same query across resolvers.
///
/// Only DNS responses participate in RCODE and answer-set comparison. Timeouts and
/// transport errors are reported separately; they are not treated as a DNS answer.
pub fn compare_measurements(query: &DnsQuery, measurements: &[DnsMeasurement]) -> DnsComparison {
    let responded: Vec<&DnsMeasurement> = measurements
        .iter()
        .filter(|measurement| measurement.responded())
        .collect();
    let failed = measurements
        .iter()
        .filter(|measurement| measurement.is_transport_failure())
        .count();
    let cancelled = measurements
        .iter()
        .filter(|measurement| measurement.outcome == DnsOutcome::Cancelled)
        .count();

    let comparable = responded.len() >= 2;
    let mut notes = Vec::new();

    if failed > 0 {
        notes.push(format!(
            "{failed} query attempt(s) did not produce a DNS response; transport failures are not DNS answers."
        ));
    }
    if cancelled > 0 {
        notes.push(format!(
            "{cancelled} query attempt(s) were cancelled; the comparison is incomplete."
        ));
    }
    if !comparable {
        notes.push(format!(
            "Fewer than two resolvers returned a DNS response ({} responded); answer comparison is unavailable.",
            responded.len()
        ));
    }

    let rcode_consistent = if comparable {
        let codes: BTreeSet<DnsResponseCode> = responded
            .iter()
            .filter_map(|measurement| measurement.rcode())
            .collect();
        if codes.len() > 1 {
            let names = codes
                .iter()
                .map(|code| code.name().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            notes.push(format!("Response codes differed: {names}."));
        }
        codes.len() == 1
    } else {
        false
    };

    let answers_consistent = if comparable {
        let sets: Vec<BTreeSet<String>> = responded
            .iter()
            .map(|measurement| measurement.answer_set())
            .collect();
        let first = &sets[0];
        let same = sets.iter().all(|set| set == first);
        if !same {
            notes.push("Answer sets differed (TTL and name case excluded).".to_string());
        }
        same
    } else {
        false
    };

    let mut ttls: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for measurement in &responded {
        if let Some(response) = &measurement.response {
            for record in &response.answers {
                ttls.entry(record.canonical())
                    .or_default()
                    .insert(record.ttl);
            }
        }
    }
    let ttl_varied = ttls.values().any(|values| values.len() > 1);
    if ttl_varied {
        notes.push(
            "TTLs differed between resolvers; TTL differences are expected with caching and are excluded from answer-set equality."
                .to_string(),
        );
    }

    let dnssec_states: BTreeSet<(bool, bool, bool, DnssecValidation)> = responded
        .iter()
        .map(|measurement| {
            (
                measurement.dnssec.ad_flag,
                measurement.dnssec.rrsig_present,
                measurement.dnssec.response_edns,
                measurement.dnssec.validation,
            )
        })
        .collect();
    let dnssec_varied = dnssec_states.len() > 1;
    if dnssec_varied {
        notes.push(
            "DNSSEC-related response fields differed between resolvers; this is not a validation result."
                .to_string(),
        );
    }

    let consistent = comparable && rcode_consistent && answers_consistent;
    if consistent {
        notes.push(
            "All responding resolvers returned the same RCODE and answer set (TTL and name case excluded)."
                .to_string(),
        );
    }

    DnsComparison {
        query: query.clone(),
        measurements: measurements.to_vec(),
        responded: responded.len(),
        failed,
        cancelled,
        comparable,
        rcode_consistent,
        answers_consistent,
        ttl_varied,
        dnssec_varied,
        consistent,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{
        DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecord, DnsRecordType, DnsRecordValue,
        DnsResponse, DnsResponseCode, DnssecInfo, DnssecValidation, ResolverEndpoint,
        compare_measurements,
    };
    use crate::domain::{Transport, ids::new_id};

    fn measurement(
        label: &str,
        rcode: DnsResponseCode,
        answer: &str,
        ttl: u32,
        outcome: DnsOutcome,
    ) -> DnsMeasurement {
        let query = DnsQuery {
            name: "example.com.".to_string(),
            record_type: DnsRecordType::A,
        };
        let response = (outcome == DnsOutcome::Response).then(|| DnsResponse {
            rcode,
            flags: DnsFlags::default(),
            answers: vec![DnsRecord {
                name: "example.com.".to_string(),
                record_type: DnsRecordType::A,
                ttl,
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
    fn record_types_parse_and_display() {
        for (text, record_type) in [
            ("A", DnsRecordType::A),
            ("aaaa", DnsRecordType::Aaaa),
            ("CNAME", DnsRecordType::Cname),
            ("mx", DnsRecordType::Mx),
            ("NS", DnsRecordType::Ns),
            ("txt", DnsRecordType::Txt),
            ("SOA", DnsRecordType::Soa),
        ] {
            assert_eq!(text.parse::<DnsRecordType>().unwrap(), record_type);
            assert_eq!(record_type.as_str(), text.to_ascii_uppercase());
        }
        assert!("ANY".parse::<DnsRecordType>().is_err());
    }

    #[test]
    fn response_codes_cover_known_and_unknown_values() {
        assert_eq!(DnsResponseCode::from_code(0), DnsResponseCode::NoError);
        assert_eq!(DnsResponseCode::from_code(3), DnsResponseCode::NxDomain);
        assert_eq!(DnsResponseCode::from_code(23), DnsResponseCode::BadCookie);
        assert_eq!(DnsResponseCode::from_code(99), DnsResponseCode::Unknown(99));
        assert_eq!(DnsResponseCode::from_code(99).code(), 99);
        assert_eq!(DnsResponseCode::NxDomain.to_string(), "NXDOMAIN");
        assert_eq!(
            "servfail".parse::<DnsResponseCode>().unwrap(),
            DnsResponseCode::ServFail
        );
        assert_eq!(
            "2".parse::<DnsResponseCode>().unwrap(),
            DnsResponseCode::ServFail
        );
        assert!("not-a-code".parse::<DnsResponseCode>().is_err());
    }

    #[test]
    fn dnssec_states_parse_explicitly() {
        assert_eq!(
            "not_performed".parse::<DnssecValidation>().unwrap(),
            DnssecValidation::NotPerformed
        );
        assert_eq!(
            "bogus".parse::<DnssecValidation>().unwrap(),
            DnssecValidation::Bogus
        );
        assert!("validated".parse::<DnssecValidation>().is_err());
        let info = DnssecInfo::not_performed(true, false, true, true);
        assert_eq!(info.validation, DnssecValidation::NotPerformed);
        assert!(info.do_bit);
        assert!(info.rrsig_present);
        assert!(info.note.contains("not a validation result"));
    }

    #[test]
    fn record_values_display_and_canonicalize() {
        let address = DnsRecordValue::Address {
            address: "192.0.2.1".parse().unwrap(),
        };
        assert_eq!(address.display_value(), "192.0.2.1");

        let mx = DnsRecordValue::Mx {
            preference: 10,
            exchange: "Mail.Example.COM.".to_string(),
        };
        assert_eq!(mx.display_value(), "10 Mail.Example.COM.");
        assert_eq!(mx.canonical(), "10 mail.example.com.");

        let txt = DnsRecordValue::Txt {
            segments: vec!["v=spf1".to_string(), "-all".to_string()],
        };
        assert_eq!(txt.display_value(), "\"v=spf1\" \"-all\"");
        assert_eq!(txt.canonical(), "v=spf1\u{1f}-all");
    }

    #[test]
    fn comparison_detects_rcode_and_answer_differences() {
        let first = measurement(
            "system",
            DnsResponseCode::NoError,
            "192.0.2.1",
            300,
            DnsOutcome::Response,
        );
        let second = measurement(
            "public",
            DnsResponseCode::NxDomain,
            "192.0.2.2",
            300,
            DnsOutcome::Response,
        );
        let query = first.query.clone();
        let comparison = compare_measurements(&query, &[first, second]);
        assert!(comparison.comparable);
        assert!(!comparison.rcode_consistent);
        assert!(!comparison.answers_consistent);
        assert!(!comparison.consistent);
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.contains("codes differed"))
        );
    }

    #[test]
    fn comparison_ignores_ttl_but_reports_it() {
        let first = measurement(
            "system",
            DnsResponseCode::NoError,
            "192.0.2.1",
            300,
            DnsOutcome::Response,
        );
        let second = measurement(
            "public",
            DnsResponseCode::NoError,
            "192.0.2.1",
            60,
            DnsOutcome::Response,
        );
        let query = first.query.clone();
        let comparison = compare_measurements(&query, &[first, second]);
        assert!(comparison.comparable);
        assert!(comparison.rcode_consistent);
        assert!(comparison.answers_consistent);
        assert!(comparison.ttl_varied);
        assert!(comparison.consistent);
    }

    #[test]
    fn comparison_requires_two_responders() {
        let first = measurement(
            "system",
            DnsResponseCode::NoError,
            "192.0.2.1",
            300,
            DnsOutcome::Response,
        );
        let second = measurement(
            "public",
            DnsResponseCode::NoError,
            "192.0.2.1",
            300,
            DnsOutcome::Timeout,
        );
        let query = first.query.clone();
        let comparison = compare_measurements(&query, &[first, second]);
        assert!(!comparison.comparable);
        assert_eq!(comparison.responded, 1);
        assert_eq!(comparison.failed, 1);
        assert!(!comparison.consistent);
        assert!(
            comparison
                .notes
                .iter()
                .any(|note| note.contains("Fewer than two"))
        );
    }
}
