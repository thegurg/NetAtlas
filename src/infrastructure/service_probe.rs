//! Bounded TCP service probes for a small set of plain-text protocols.
//!
//! Only protocols that can be identified from a short, bounded exchange are
//! probed. The adapter never sends credentials, never follows redirects, and
//! never treats a failed connection as proof that a service is absent. Banners
//! are self-reported claims and are stored as evidence, not as verified facts.
//!
//! TLS-only services are intentionally not probed: without a TLS stack the
//! banner cannot be obtained, and sending plaintext to a TLS port is not useful.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::domain::{ServiceObservation, Transport};

/// Ports with a well-defined plain-text banner or request/response exchange.
pub const DEFAULT_SERVICE_PORTS: &[u16] = &[21, 22, 25, 80, 8080];

const MAX_BANNER_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct ServiceProbeHost {
    pub ip: IpAddr,
    pub services: Vec<ServiceObservation>,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceProbeDiscovery {
    pub hosts: Vec<ServiceProbeHost>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceKind {
    Http,
    Ssh,
    Ftp,
    Smtp,
}

impl ServiceKind {
    fn for_port(port: u16) -> Option<Self> {
        match port {
            80 | 8000 | 8080 | 8888 => Some(Self::Http),
            22 => Some(Self::Ssh),
            21 => Some(Self::Ftp),
            25 | 587 => Some(Self::Smtp),
            _ => None,
        }
    }

    fn protocol(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Smtp => "smtp",
        }
    }

    fn sends_first(self) -> bool {
        matches!(self, Self::Http)
    }
}

/// Probe `ports` on every address with bounded concurrency.
///
/// A connection failure is not reported as a warning: closed ports and silent
/// hosts are normal. Only hosts with at least one open probed port appear in
/// the result.
pub async fn probe_hosts(
    addresses: &[IpAddr],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> ServiceProbeDiscovery {
    let targets: Vec<(IpAddr, u16)> = addresses
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| (*ip, *port)))
        .collect();

    let results: Vec<(IpAddr, Option<ServiceObservation>)> = stream::iter(targets)
        .map(|(ip, port)| {
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return (ip, None);
                }
                (ip, probe_one(ip, port, timeout).await)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut by_host: std::collections::BTreeMap<IpAddr, Vec<ServiceObservation>> =
        std::collections::BTreeMap::new();
    for (ip, service) in results {
        if let Some(service) = service {
            by_host.entry(ip).or_default().push(service);
        }
    }

    let mut hosts: Vec<ServiceProbeHost> = by_host
        .into_iter()
        .map(|(ip, mut services)| {
            services.sort_by_key(|service| service.port);
            ServiceProbeHost { ip, services }
        })
        .collect();
    hosts.sort_by_key(|host| host.ip);

    ServiceProbeDiscovery {
        hosts,
        warnings: Vec::new(),
    }
}

async fn probe_one(ip: IpAddr, port: u16, timeout: Duration) -> Option<ServiceObservation> {
    let kind = ServiceKind::for_port(port)?;
    probe_one_as(ip, port, kind, timeout).await
}

async fn probe_one_as(
    ip: IpAddr,
    port: u16,
    kind: ServiceKind,
    timeout: Duration,
) -> Option<ServiceObservation> {
    let deadline = Instant::now() + timeout;

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;

    let banner = if kind.sends_first() {
        let request = http_request(ip);
        let write_timeout = timeout.min(Duration::from_millis(1_000));
        if tokio::time::timeout(write_timeout, stream.write_all(request.as_bytes()))
            .await
            .is_err()
        {
            return Some(empty_service(ip, port, kind));
        }
        read_response(&mut stream, kind, deadline).await
    } else {
        read_response(&mut stream, kind, deadline).await
    };

    Some(parse_service(ip, port, kind, &banner))
}

async fn read_response(stream: &mut TcpStream, kind: ServiceKind, deadline: Instant) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || buffer.len() >= MAX_BANNER_BYTES {
            break;
        }
        let read = tokio::time::timeout(remaining, stream.read(&mut chunk)).await;
        let Ok(Ok(count)) = read else {
            break;
        };
        if count == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..count]);
        if response_is_complete(&buffer, kind) {
            break;
        }
    }
    buffer
}

fn response_is_complete(buffer: &[u8], kind: ServiceKind) -> bool {
    match kind {
        ServiceKind::Http => buffer.windows(4).any(|window| window == b"\r\n\r\n"),
        ServiceKind::Ssh | ServiceKind::Ftp | ServiceKind::Smtp => {
            buffer.windows(2).any(|window| window == b"\r\n") || buffer.contains(&b'\n')
        }
    }
}

fn http_request(ip: IpAddr) -> String {
    format!(
        "HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetAtlas/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
}

fn empty_service(ip: IpAddr, port: u16, kind: ServiceKind) -> ServiceObservation {
    ServiceObservation {
        port,
        transport: Transport::Tcp,
        protocol: Some(kind.protocol().to_string()),
        product: None,
        version: None,
        banner: None,
        os_hint: None,
        source_unit: source_unit(ip, port),
    }
}

fn parse_service(ip: IpAddr, port: u16, kind: ServiceKind, bytes: &[u8]) -> ServiceObservation {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_matches('\0');
    let (product, version, os_hint) = match kind {
        ServiceKind::Http => parse_http(text),
        ServiceKind::Ssh => parse_ssh(text),
        ServiceKind::Ftp => parse_ftp(text),
        ServiceKind::Smtp => parse_smtp(text),
    };
    let banner = compact_banner(text, kind);
    ServiceObservation {
        port,
        transport: Transport::Tcp,
        protocol: Some(kind.protocol().to_string()),
        product,
        version,
        banner,
        os_hint,
        source_unit: source_unit(ip, port),
    }
}

fn source_unit(ip: IpAddr, port: u16) -> String {
    format!("service:{ip}:{port}")
}

fn compact_banner(text: &str, kind: ServiceKind) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let compact = match kind {
        ServiceKind::Http => {
            let mut lines = text.lines();
            let status = lines.next().unwrap_or("").trim();
            let server = text.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("server")
                    .then(|| value.trim().to_string())
            });
            match server {
                Some(server) => format!("{status} Server: {server}"),
                None => status.to_string(),
            }
        }
        _ => text.lines().next().unwrap_or("").trim().to_string(),
    };
    let compact = compact.trim();
    if compact.is_empty() {
        None
    } else {
        Some(compact.chars().take(512).collect())
    }
}

fn parse_http(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let server = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("server")
            .then(|| value.trim().to_string())
    });
    let powered_by = text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("x-powered-by")
            .then(|| value.trim().to_string())
    });
    let value = server.or(powered_by);
    let Some(value) = value else {
        return (None, None, None);
    };
    let os_hint = os_hint_from_text(&value);
    let (main, _) = split_parenthetical(&value);
    let token = main.split_whitespace().next().unwrap_or("");
    let (product, version) = split_product_version(token);
    (product, version, os_hint)
}

fn parse_ssh(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("SSH-"))
        .unwrap_or_else(|| text.lines().next().unwrap_or("").trim());
    let os_hint = os_hint_from_text(line);
    let after_protocol = line
        .split_once("SSH-")
        .map(|(_, rest)| rest)
        .unwrap_or(line);
    let software = after_protocol
        .split_once('-')
        .map(|(_, rest)| rest)
        .unwrap_or(after_protocol);
    let software = software.split_whitespace().next().unwrap_or(software);

    let (product, version) = if let Some(rest) = software.strip_prefix("OpenSSH_for_Windows_") {
        (
            Some("OpenSSH".to_string()),
            version_like(rest).map(ToString::to_string),
        )
    } else if let Some((product, version)) = software.split_once('_') {
        (
            non_empty(product),
            version_like(version).map(ToString::to_string),
        )
    } else if let Some((product, version)) = software.split_once('/') {
        (
            non_empty(product),
            version_like(version).map(ToString::to_string),
        )
    } else {
        (non_empty(software), None)
    };
    (product, version, os_hint)
}

fn parse_ftp(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let line = text.lines().next().unwrap_or("").trim();
    let os_hint = os_hint_from_text(line);
    let body = strip_reply_code(line);
    let lower = body.to_ascii_lowercase();
    let known = [
        ("vsftpd", "vsFTPd"),
        ("proftpd", "ProFTPD"),
        ("filezilla server", "FileZilla Server"),
        ("pure-ftpd", "Pure-FTPd"),
        ("microsoft ftp service", "Microsoft FTP Service"),
        ("serv-u", "Serv-U"),
    ];
    for (needle, product) in known {
        if let Some(index) = lower.find(needle) {
            let tail = &body[index + needle.len()..];
            let version = tail
                .split_whitespace()
                .next()
                .and_then(version_like)
                .map(ToString::to_string);
            return (Some(product.to_string()), version, os_hint);
        }
    }
    (None, None, os_hint)
}

fn parse_smtp(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let line = text.lines().next().unwrap_or("").trim();
    let os_hint = os_hint_from_text(line);
    let body = strip_reply_code(line);
    let lower = body.to_ascii_lowercase();
    let known = [
        ("postfix", "Postfix"),
        ("exim", "Exim"),
        ("sendmail", "Sendmail"),
        ("microsoft esmtp", "Microsoft ESMTP"),
        ("opensmtpd", "OpenSMTPD"),
        ("qmail", "qmail"),
    ];
    for (needle, product) in known {
        if let Some(index) = lower.find(needle) {
            let tail = &body[index + needle.len()..];
            let version = tail
                .split_whitespace()
                .next()
                .and_then(version_like)
                .map(ToString::to_string);
            return (Some(product.to_string()), version, os_hint);
        }
    }
    (None, None, os_hint)
}

fn strip_reply_code(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix("220-") {
        return rest.trim_start();
    }
    if let Some(rest) = trimmed.strip_prefix("220 ") {
        return rest.trim_start();
    }
    trimmed
}

fn split_parenthetical(value: &str) -> (&str, Option<&str>) {
    match (value.find('('), value.rfind(')')) {
        (Some(start), Some(end)) if end > start => {
            (&value[..start], Some(value[start + 1..end].trim()))
        }
        _ => (value, None),
    }
}

fn split_product_version(token: &str) -> (Option<String>, Option<String>) {
    let token = token.trim_matches(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ';' | ')' | '(')
    });
    if token.is_empty() {
        return (None, None);
    }
    match token.split_once('/') {
        Some((product, version)) => (
            non_empty(product),
            version_like(version).map(ToString::to_string),
        ),
        None => (non_empty(token), None),
    }
}

fn version_like(value: &str) -> Option<&str> {
    let value = value.trim_matches(|character: char| {
        character.is_whitespace() || matches!(character, ',' | ';' | ')' | '(' | '/' | ']' | '[')
    });
    if value.is_empty() {
        return None;
    }
    let first = value.chars().next()?;
    if first.is_ascii_digit() && value.chars().any(|character| character.is_ascii_digit()) {
        Some(value)
    } else {
        None
    }
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Extract a conservative OS hint from self-reported banner text.
///
/// Only explicit, recognizable operating-system strings are returned. A
/// product name such as `nginx` is not an OS hint.
pub fn os_hint_from_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let known = [
        ("ubuntu", "Ubuntu"),
        ("debian", "Debian"),
        ("fedora", "Fedora"),
        ("centos", "CentOS"),
        ("red hat", "Red Hat"),
        ("rocky linux", "Rocky Linux"),
        ("alpine", "Alpine Linux"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("netbsd", "NetBSD"),
        ("windows", "Windows"),
        ("win64", "Windows"),
        ("win32", "Windows"),
        ("macos", "macOS"),
        ("darwin", "macOS"),
    ];
    for (needle, label) in known {
        if lower.contains(needle) {
            return Some(label.to_string());
        }
    }
    if lower.contains("linux") {
        return Some("Linux".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::{
        ServiceKind, parse_ftp, parse_http, parse_service, parse_smtp, parse_ssh, probe_hosts,
        probe_one_as,
    };

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
    }

    #[test]
    fn parses_nginx_server_header() {
        let (product, version, os) =
            parse_http("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(product.as_deref(), Some("nginx"));
        assert_eq!(version.as_deref(), Some("1.24.0"));
        assert_eq!(os, None);
    }

    #[test]
    fn parses_apache_server_header_with_os_hint() {
        let (product, version, os) =
            parse_http("HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Ubuntu)\r\n\r\n");
        assert_eq!(product.as_deref(), Some("Apache"));
        assert_eq!(version.as_deref(), Some("2.4.58"));
        assert_eq!(os.as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn parses_ssh_banner() {
        let (product, version, os) = parse_ssh("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("9.6p1"));
        assert_eq!(os.as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn parses_openssh_for_windows() {
        let (product, version, os) = parse_ssh("SSH-2.0-OpenSSH_for_Windows_9.5\r\n");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("9.5"));
        assert_eq!(os.as_deref(), Some("Windows"));
    }

    #[test]
    fn parses_vsftpd_banner() {
        let (product, version, os) = parse_ftp("220 (vsFTPd 3.0.5)\r\n");
        assert_eq!(product.as_deref(), Some("vsFTPd"));
        assert_eq!(version.as_deref(), Some("3.0.5"));
        assert_eq!(os, None);
    }

    #[test]
    fn parses_postfix_smtp_banner() {
        let (product, version, os) = parse_smtp("220 mail.example ESMTP Postfix (Ubuntu)\r\n");
        assert_eq!(product.as_deref(), Some("Postfix"));
        assert_eq!(version, None);
        assert_eq!(os.as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn unknown_banner_keeps_protocol_and_banner_only() {
        let service = parse_service(ip(), 22, ServiceKind::Ssh, b"SSH-2.0-Custom\r\n");
        assert_eq!(service.protocol.as_deref(), Some("ssh"));
        assert_eq!(service.product.as_deref(), Some("Custom"));
        assert_eq!(service.version, None);
        assert_eq!(service.banner.as_deref(), Some("SSH-2.0-Custom"));
    }

    #[tokio::test]
    async fn probes_a_local_ssh_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
                .await
                .unwrap();
        });

        let service = probe_one_as(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            ServiceKind::Ssh,
            Duration::from_millis(1_000),
        )
        .await
        .unwrap();
        assert_eq!(service.port, port);
        assert_eq!(service.protocol.as_deref(), Some("ssh"));
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.os_hint.as_deref(), Some("Ubuntu"));
    }

    #[tokio::test]
    async fn cancellation_returns_no_hosts() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let discovery = probe_hosts(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[22],
            Duration::from_millis(500),
            4,
            &cancel,
        )
        .await;
        assert!(discovery.hosts.is_empty());
    }
}
