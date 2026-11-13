//! Raw DNS transport for diagnostics.
//!
//! The resolver crate is used for its protocol types and system resolver configuration,
//! but queries are sent directly so NetAtlas can report the exact RCODE, flags, TTLs,
//! EDNS presence, and timing. No cryptographic DNSSEC validation is performed.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_resolver::proto::op::{Edns, Message, MessageType, Query};
use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, NS};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::system_conf::read_system_conf;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::domain::{
    DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecord, DnsRecordType, DnsRecordValue,
    DnsResponse, DnsResponseCode, DnssecInfo, ResolverEndpoint, Transport, ids::new_id,
    time::now_ms,
};

const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_MAX_PAYLOAD: u16 = 1_232;
const MAX_UDP_RESPONSE: usize = 4_096;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid DNS resolver {value:?}: {message}")]
    InvalidResolver { value: String, message: String },
    #[error("no system DNS resolver was found")]
    NoSystemResolver,
    #[error("system DNS resolver configuration could not be read: {0}")]
    SystemResolver(String),
    #[error("invalid DNS name {value:?}: {message}")]
    InvalidName { value: String, message: String },
}

/// Options for one raw DNS query.
#[derive(Debug, Clone)]
pub struct DnsClientConfig {
    pub timeout: Duration,
    /// Number of exchange attempts. One attempt is the diagnostic default.
    pub attempts: u32,
    pub transport: Transport,
    /// Set the EDNS DNSSEC OK bit. This requests DNSSEC records; it does not validate.
    pub dnssec_ok: bool,
    pub max_payload: u16,
}

impl Default for DnsClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1_500),
            attempts: 1,
            transport: Transport::Udp,
            dnssec_ok: true,
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }
}

#[derive(Debug)]
enum ExchangeError {
    Timeout,
    Transport(String),
    Cancelled,
}

/// Normalize a user-supplied name to a fully qualified name.
pub fn normalize_name(value: &str) -> Result<String, DnsError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DnsError::InvalidName {
            value: value.to_string(),
            message: "the name is empty".to_string(),
        });
    }
    let mut name = Name::from_utf8(trimmed).map_err(|error| DnsError::InvalidName {
        value: value.to_string(),
        message: error.to_string(),
    })?;
    name.set_fqdn(true);
    Ok(name.to_utf8().to_lowercase())
}

/// Parse `system`, an IP address, `IP:PORT`, or `[IPv6]:PORT`.
pub fn parse_resolver(value: &str) -> Result<ResolverEndpoint, DnsError> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("system") {
        return system_resolvers()?
            .into_iter()
            .next()
            .ok_or(DnsError::NoSystemResolver);
    }

    let address = parse_socket_address(trimmed)?;
    Ok(ResolverEndpoint {
        label: address.to_string(),
        address,
    })
}

/// Read the system resolver list from `/etc/resolv.conf` (via hickory).
pub fn system_resolvers() -> Result<Vec<ResolverEndpoint>, DnsError> {
    let (config, _) =
        read_system_conf().map_err(|error| DnsError::SystemResolver(error.to_string()))?;
    let mut resolvers: Vec<ResolverEndpoint> = Vec::new();
    for server in config.name_servers {
        let port = server
            .connections
            .first()
            .map_or(DEFAULT_DNS_PORT, |connection| connection.port);
        let address = SocketAddr::new(server.ip, port);
        if resolvers.iter().any(|resolver| resolver.address == address) {
            continue;
        }
        let label = if resolvers.is_empty() {
            "system".to_string()
        } else {
            format!("system[{}]", resolvers.len())
        };
        resolvers.push(ResolverEndpoint { label, address });
    }
    if resolvers.is_empty() {
        return Err(DnsError::NoSystemResolver);
    }
    Ok(resolvers)
}

fn parse_socket_address(value: &str) -> Result<SocketAddr, DnsError> {
    let parsed = value
        .parse::<SocketAddr>()
        .or_else(|_| {
            value
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, DEFAULT_DNS_PORT))
        })
        .or_else(|_| {
            value
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .and_then(|inner| inner.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, DEFAULT_DNS_PORT))
                .ok_or(())
        })
        .map_err(|()| DnsError::InvalidResolver {
            value: value.to_string(),
            message: "expected system, an IP address, IP:PORT, or [IPv6]:PORT".to_string(),
        })?;
    if parsed.port() == 0 {
        return Err(DnsError::InvalidResolver {
            value: value.to_string(),
            message: "the port must be greater than zero".to_string(),
        });
    }
    Ok(parsed)
}

/// Run one DNS query. Transport failures are returned as measurements, not errors.
pub async fn query(
    endpoint: &ResolverEndpoint,
    query: &DnsQuery,
    config: &DnsClientConfig,
    cancel: &CancellationToken,
) -> DnsMeasurement {
    let started = Instant::now();
    let mut attempts = 0_u32;
    let max_attempts = config.attempts.max(1);
    let mut last_outcome = DnsOutcome::TransportError;
    let mut last_error = "query was not attempted".to_string();

    for _ in 0..max_attempts {
        attempts += 1;
        match exchange(endpoint, query, config, cancel).await {
            Ok((message, transport)) => {
                return response_measurement(
                    endpoint, query, config, transport, attempts, started, message,
                );
            }
            Err(ExchangeError::Cancelled) => {
                return failure_measurement(
                    endpoint,
                    query,
                    config,
                    DnsOutcome::Cancelled,
                    attempts,
                    started,
                    "cancelled by user".to_string(),
                );
            }
            Err(ExchangeError::Timeout) => {
                last_outcome = DnsOutcome::Timeout;
                last_error = format!("no DNS response within {} ms", config.timeout.as_millis());
            }
            Err(ExchangeError::Transport(error)) => {
                last_outcome = DnsOutcome::TransportError;
                last_error = error;
            }
        }
    }

    failure_measurement(
        endpoint,
        query,
        config,
        last_outcome,
        attempts,
        started,
        last_error,
    )
}

fn response_measurement(
    endpoint: &ResolverEndpoint,
    query: &DnsQuery,
    config: &DnsClientConfig,
    transport: Transport,
    attempts: u32,
    started: Instant,
    message: Message,
) -> DnsMeasurement {
    let flags = DnsFlags {
        authoritative: message.metadata.authoritative,
        truncated: message.metadata.truncation,
        recursion_desired: message.metadata.recursion_desired,
        recursion_available: message.metadata.recursion_available,
        authentic_data: message.metadata.authentic_data,
        checking_disabled: message.metadata.checking_disabled,
    };
    let rrsig_present = has_rrsig(&message);
    let response_edns = message.edns.is_some();
    let response = DnsResponse {
        rcode: response_code(&message),
        flags,
        answers: convert_records(&message.answers),
        authority: convert_records(&message.authorities),
        answer_count: message.answers.len(),
        authority_count: message.authorities.len(),
        additional_count: message.additionals.len(),
    };

    DnsMeasurement {
        id: new_id(),
        queried_at_ms: now_ms(),
        resolver: endpoint.clone(),
        query: query.clone(),
        transport,
        outcome: DnsOutcome::Response,
        elapsed_ms: started.elapsed().as_millis() as u64,
        attempts,
        response: Some(response),
        dnssec: DnssecInfo::not_performed(
            config.dnssec_ok,
            message.metadata.authentic_data,
            rrsig_present,
            response_edns,
        ),
        error: None,
    }
}

fn failure_measurement(
    endpoint: &ResolverEndpoint,
    query: &DnsQuery,
    config: &DnsClientConfig,
    outcome: DnsOutcome,
    attempts: u32,
    started: Instant,
    error: String,
) -> DnsMeasurement {
    DnsMeasurement {
        id: new_id(),
        queried_at_ms: now_ms(),
        resolver: endpoint.clone(),
        query: query.clone(),
        transport: config.transport,
        outcome,
        elapsed_ms: started.elapsed().as_millis() as u64,
        attempts,
        response: None,
        dnssec: DnssecInfo::no_response(config.dnssec_ok),
        error: Some(error),
    }
}

async fn exchange(
    endpoint: &ResolverEndpoint,
    query: &DnsQuery,
    config: &DnsClientConfig,
    cancel: &CancellationToken,
) -> Result<(Message, Transport), ExchangeError> {
    let name = Name::from_utf8(&query.name).map_err(|error| {
        ExchangeError::Transport(format!("invalid normalized query name: {error}"))
    })?;
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, to_record_type(query.record_type)));
    let mut edns = Edns::new();
    edns.set_max_payload(config.max_payload)
        .set_dnssec_ok(config.dnssec_ok);
    message.set_edns(edns);

    let expected_id = message.metadata.id;
    let request = message
        .to_vec()
        .map_err(|error| ExchangeError::Transport(format!("encoding DNS query: {error}")))?;
    let deadline = Instant::now() + config.timeout;

    match config.transport {
        Transport::Udp => {
            let response = run_bounded(
                deadline,
                cancel,
                udp_exchange(endpoint.address, &request, expected_id),
            )
            .await?;
            if response.metadata.truncation {
                let response = run_bounded(
                    deadline,
                    cancel,
                    tcp_exchange(endpoint.address, &request, expected_id),
                )
                .await
                .map_err(|error| match error {
                    ExchangeError::Cancelled => ExchangeError::Cancelled,
                    ExchangeError::Timeout => ExchangeError::Transport(
                        "UDP response was truncated and the TCP fallback timed out".to_string(),
                    ),
                    ExchangeError::Transport(message) => ExchangeError::Transport(format!(
                        "UDP response was truncated and the TCP fallback failed: {message}"
                    )),
                })?;
                Ok((response, Transport::Tcp))
            } else {
                Ok((response, Transport::Udp))
            }
        }
        Transport::Tcp => {
            let response = run_bounded(
                deadline,
                cancel,
                tcp_exchange(endpoint.address, &request, expected_id),
            )
            .await?;
            Ok((response, Transport::Tcp))
        }
    }
}

async fn run_bounded<F, T>(
    deadline: Instant,
    cancel: &CancellationToken,
    future: F,
) -> Result<T, ExchangeError>
where
    F: Future<Output = Result<T, ExchangeError>>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(ExchangeError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(result) => result,
            Err(_) => Err(ExchangeError::Timeout),
        },
    }
}

async fn udp_exchange(
    server: SocketAddr,
    request: &[u8],
    expected_id: u16,
) -> Result<Message, ExchangeError> {
    let bind_address = match server {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .map_err(|error| ExchangeError::Transport(format!("binding UDP socket: {error}")))?;
    socket
        .connect(server)
        .await
        .map_err(|error| ExchangeError::Transport(format!("connecting UDP socket: {error}")))?;
    socket
        .send(request)
        .await
        .map_err(|error| ExchangeError::Transport(format!("sending UDP query: {error}")))?;

    loop {
        let mut buffer = vec![0_u8; MAX_UDP_RESPONSE];
        let length = socket.recv(&mut buffer).await.map_err(|error| {
            ExchangeError::Transport(format!("receiving UDP response: {error}"))
        })?;
        let message = Message::from_vec(&buffer[..length])
            .map_err(|error| ExchangeError::Transport(format!("decoding UDP response: {error}")))?;
        if message.metadata.id != expected_id {
            continue;
        }
        if message.metadata.message_type != MessageType::Response {
            return Err(ExchangeError::Transport(
                "received a DNS message that was not a response".to_string(),
            ));
        }
        return Ok(message);
    }
}

async fn tcp_exchange(
    server: SocketAddr,
    request: &[u8],
    expected_id: u16,
) -> Result<Message, ExchangeError> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|error| ExchangeError::Transport(format!("connecting TCP: {error}")))?;
    let length = u16::try_from(request.len())
        .map_err(|_| ExchangeError::Transport("DNS query is too large for TCP".to_string()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| ExchangeError::Transport(format!("writing TCP length: {error}")))?;
    stream
        .write_all(request)
        .await
        .map_err(|error| ExchangeError::Transport(format!("writing TCP query: {error}")))?;

    let mut length_buffer = [0_u8; 2];
    stream
        .read_exact(&mut length_buffer)
        .await
        .map_err(|error| ExchangeError::Transport(format!("reading TCP length: {error}")))?;
    let response_length = u16::from_be_bytes(length_buffer) as usize;
    if response_length == 0 {
        return Err(ExchangeError::Transport(
            "TCP response had a zero length".to_string(),
        ));
    }
    let mut buffer = vec![0_u8; response_length];
    stream
        .read_exact(&mut buffer)
        .await
        .map_err(|error| ExchangeError::Transport(format!("reading TCP response: {error}")))?;
    let message = Message::from_vec(&buffer)
        .map_err(|error| ExchangeError::Transport(format!("decoding TCP response: {error}")))?;
    if message.metadata.id != expected_id {
        return Err(ExchangeError::Transport(
            "TCP response ID did not match the query ID".to_string(),
        ));
    }
    if message.metadata.message_type != MessageType::Response {
        return Err(ExchangeError::Transport(
            "received a DNS message that was not a response".to_string(),
        ));
    }
    Ok(message)
}

fn response_code(message: &Message) -> DnsResponseCode {
    let low = u16::from(message.metadata.response_code);
    let high = message
        .edns
        .as_ref()
        .map_or(0, |edns| u16::from(edns.rcode_high()) << 4);
    DnsResponseCode::from_code(low | high)
}

fn has_rrsig(message: &Message) -> bool {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .any(|record| record.record_type() == RecordType::RRSIG)
}

fn convert_records(records: &[Record]) -> Vec<DnsRecord> {
    records.iter().filter_map(convert_record).collect()
}

fn convert_record(record: &Record) -> Option<DnsRecord> {
    let record_type = match record.record_type() {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::Aaaa,
        RecordType::CNAME => DnsRecordType::Cname,
        RecordType::MX => DnsRecordType::Mx,
        RecordType::NS => DnsRecordType::Ns,
        RecordType::TXT => DnsRecordType::Txt,
        RecordType::SOA => DnsRecordType::Soa,
        _ => return None,
    };
    let value = match &record.data {
        RData::A(A(address)) => DnsRecordValue::Address {
            address: IpAddr::V4(*address),
        },
        RData::AAAA(AAAA(address)) => DnsRecordValue::Address {
            address: IpAddr::V6(*address),
        },
        RData::CNAME(CNAME(name)) => DnsRecordValue::Name {
            target: name.to_utf8(),
        },
        RData::NS(NS(name)) => DnsRecordValue::Name {
            target: name.to_utf8(),
        },
        RData::MX(mx) => DnsRecordValue::Mx {
            preference: mx.preference,
            exchange: mx.exchange.to_utf8(),
        },
        RData::TXT(txt) => DnsRecordValue::Txt {
            segments: txt
                .txt_data
                .iter()
                .map(|segment| String::from_utf8_lossy(segment).into_owned())
                .collect(),
        },
        RData::SOA(soa) => DnsRecordValue::Soa {
            mname: soa.mname.to_utf8(),
            rname: soa.rname.to_utf8(),
            serial: soa.serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minimum: soa.minimum,
        },
        _ => return None,
    };
    Some(DnsRecord {
        name: record.name.to_utf8(),
        record_type,
        ttl: record.ttl,
        value,
    })
}

fn to_record_type(record_type: DnsRecordType) -> RecordType {
    match record_type {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Soa => RecordType::SOA,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{RData, Record};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio_util::sync::CancellationToken;

    use super::{DnsClientConfig, normalize_name, parse_resolver, query};
    use crate::domain::{
        DnsOutcome, DnsQuery, DnsRecordType, DnsResponseCode, DnssecValidation, ResolverEndpoint,
        Transport,
    };

    fn response_for(request: &Message, address: Ipv4Addr, ttl: u32, truncated: bool) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.metadata.truncation = truncated;
        for query in &request.queries {
            response.add_query(query.clone());
        }
        if let Some(first) = request.queries.first() {
            response.add_answer(Record::from_rdata(
                first.name().clone(),
                ttl,
                RData::A(A(address)),
            ));
        }
        if !truncated {
            let mut edns = Edns::new();
            edns.set_max_payload(1_232).set_dnssec_ok(true);
            response.set_edns(edns);
        }
        response
    }

    async fn spawn_udp<F>(build: F) -> SocketAddr
    where
        F: Fn(&Message) -> Message + Send + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 4_096];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let response = build(&request).to_vec().unwrap();
            socket.send_to(&response, peer).await.unwrap();
        });
        address
    }

    async fn spawn_tcp<F>(build: F) -> SocketAddr
    where
        F: Fn(&Message) -> Message + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut length_buffer = [0_u8; 2];
            stream.read_exact(&mut length_buffer).await.unwrap();
            let length = u16::from_be_bytes(length_buffer) as usize;
            let mut buffer = vec![0_u8; length];
            stream.read_exact(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer).unwrap();
            let response = build(&request).to_vec().unwrap();
            let response_length = u16::try_from(response.len()).unwrap();
            stream
                .write_all(&response_length.to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        address
    }

    fn query_for_test() -> DnsQuery {
        DnsQuery {
            name: "example.com.".to_string(),
            record_type: DnsRecordType::A,
        }
    }

    fn config(transport: Transport) -> DnsClientConfig {
        DnsClientConfig {
            timeout: Duration::from_secs(1),
            attempts: 1,
            transport,
            dnssec_ok: true,
            max_payload: 1_232,
        }
    }

    #[test]
    fn names_and_resolvers_are_normalized() {
        assert_eq!(normalize_name("Example.COM").unwrap(), "example.com.");
        assert_eq!(normalize_name("example.com.").unwrap(), "example.com.");
        assert!(normalize_name("").is_err());

        let resolver = parse_resolver("127.0.0.1").unwrap();
        assert_eq!(
            resolver.address,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap()
        );
        let resolver = parse_resolver("127.0.0.1:5353").unwrap();
        assert_eq!(
            resolver.address,
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap()
        );
        let resolver = parse_resolver("[::1]:5353").unwrap();
        assert_eq!(
            resolver.address,
            "[::1]:5353".parse::<SocketAddr>().unwrap()
        );
        let resolver = parse_resolver("::1").unwrap();
        assert_eq!(resolver.address, "[::1]:53".parse::<SocketAddr>().unwrap());
        assert!(parse_resolver("not-an-ip").is_err());
        assert!(parse_resolver("127.0.0.1:0").is_err());
    }

    #[tokio::test]
    async fn udp_query_captures_rcode_ttl_and_dnssec_state() {
        let address =
            spawn_udp(|request| response_for(request, Ipv4Addr::new(192, 0, 2, 1), 300, false))
                .await;
        let endpoint = ResolverEndpoint {
            label: "test".to_string(),
            address,
        };
        let measurement = query(
            &endpoint,
            &query_for_test(),
            &config(Transport::Udp),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(measurement.outcome, DnsOutcome::Response);
        assert_eq!(measurement.rcode(), Some(DnsResponseCode::NoError));
        assert_eq!(measurement.transport, Transport::Udp);
        assert_eq!(measurement.attempts, 1);
        let response = measurement.response.as_ref().unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 300);
        assert_eq!(response.answers[0].value.display_value(), "192.0.2.1");
        assert!(response.flags.recursion_available);
        assert!(measurement.dnssec.do_bit);
        assert!(measurement.dnssec.response_edns);
        assert_eq!(
            measurement.dnssec.validation,
            DnssecValidation::NotPerformed
        );
    }

    #[tokio::test]
    async fn tcp_query_works_when_requested() {
        let address =
            spawn_tcp(|request| response_for(request, Ipv4Addr::new(198, 51, 100, 7), 60, false))
                .await;
        let endpoint = ResolverEndpoint {
            label: "test".to_string(),
            address,
        };
        let measurement = query(
            &endpoint,
            &query_for_test(),
            &config(Transport::Tcp),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(measurement.outcome, DnsOutcome::Response);
        assert_eq!(measurement.transport, Transport::Tcp);
        assert_eq!(
            measurement.response.unwrap().answers[0]
                .value
                .display_value(),
            "198.51.100.7"
        );
    }

    #[tokio::test]
    async fn truncated_udp_response_falls_back_to_tcp() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(address).await.unwrap();

        tokio::spawn(async move {
            let mut buffer = [0_u8; 4_096];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let response = response_for(&request, Ipv4Addr::new(192, 0, 2, 9), 10, true)
                .to_vec()
                .unwrap();
            udp.send_to(&response, peer).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut length_buffer = [0_u8; 2];
            stream.read_exact(&mut length_buffer).await.unwrap();
            let length = u16::from_be_bytes(length_buffer) as usize;
            let mut buffer = vec![0_u8; length];
            stream.read_exact(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer).unwrap();
            let response = response_for(&request, Ipv4Addr::new(192, 0, 2, 10), 20, false)
                .to_vec()
                .unwrap();
            let response_length = u16::try_from(response.len()).unwrap();
            stream
                .write_all(&response_length.to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let endpoint = ResolverEndpoint {
            label: "test".to_string(),
            address,
        };
        let measurement = query(
            &endpoint,
            &query_for_test(),
            &config(Transport::Udp),
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(measurement.outcome, DnsOutcome::Response);
        assert_eq!(measurement.transport, Transport::Tcp);
        assert_eq!(
            measurement.response.unwrap().answers[0]
                .value
                .display_value(),
            "192.0.2.10"
        );
    }

    #[tokio::test]
    async fn timeout_is_a_measurement_not_an_error() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let endpoint = ResolverEndpoint {
            label: "silent".to_string(),
            address,
        };
        let mut options = config(Transport::Udp);
        options.timeout = Duration::from_millis(100);
        let measurement = query(
            &endpoint,
            &query_for_test(),
            &options,
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(measurement.outcome, DnsOutcome::Timeout);
        assert!(measurement.response.is_none());
        assert!(measurement.error.unwrap().contains("no DNS response"));
        assert_eq!(
            measurement.dnssec.validation,
            DnssecValidation::NotPerformed
        );
        assert!(!measurement.dnssec.ad_flag);
    }

    #[tokio::test]
    async fn cancellation_is_reported() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let endpoint = ResolverEndpoint {
            label: "silent".to_string(),
            address,
        };
        let cancel = CancellationToken::new();
        cancel.cancel();
        let measurement = query(
            &endpoint,
            &query_for_test(),
            &config(Transport::Udp),
            &cancel,
        )
        .await;

        assert_eq!(measurement.outcome, DnsOutcome::Cancelled);
        assert!(measurement.response.is_none());
    }

    #[test]
    fn response_message_type_is_a_response() {
        let message = Message::response(7, OpCode::Query);
        assert_eq!(message.metadata.message_type, MessageType::Response);
    }
}
