//! SSDP discovery and UPnP description parsing.
//!
//! The adapter sends a bounded M-SEARCH to the SSDP multicast group and to the
//! discovered addresses, then fetches each unique description over plain HTTP.
//! Descriptions are self-reported device claims; the identification layer treats
//! them as evidence, never as verified facts.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures_util::{StreamExt, stream};
use roxmltree::Document;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio_util::sync::CancellationToken;

use crate::domain::UpnpObservation;

const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    IpAddr::V4(std::net::Ipv4Addr::new(239, 255, 255, 250)),
    1900,
);
const MAX_DESCRIPTION_BYTES: usize = 128 * 1024;
const DESCRIPTION_CONCURRENCY: usize = 8;

#[derive(Debug, Error)]
pub enum SsdpError {
    #[error("binding SSDP socket: {0}")]
    Bind(#[source] io::Error),
    #[error("no SSDP request could be sent: {0}")]
    Unavailable(String),
    #[error("invalid SSDP location {0:?}: {1}")]
    InvalidLocation(String, String),
    #[error("SSDP description request failed: {0}")]
    Http(String),
    #[error("malformed SSDP description: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Default)]
pub struct SsdpDiscovery {
    pub devices: Vec<UpnpObservation>,
    pub warnings: Vec<String>,
}

/// Discover SSDP devices and fetch their descriptions.
pub async fn discover(
    addresses: &[IpAddr],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<SsdpDiscovery, SsdpError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(SsdpError::Bind)?;
    let request = build_search_request(timeout);

    let mut warnings = Vec::new();
    let mut sent = 0_usize;
    match socket.send_to(request.as_bytes(), SSDP_MULTICAST).await {
        Ok(_) => sent += 1,
        Err(error) => warnings.push(format!("SSDP multicast send failed: {error}")),
    }
    for ip in addresses {
        if cancel.is_cancelled() {
            break;
        }
        match socket
            .send_to(request.as_bytes(), SocketAddr::new(*ip, 1900))
            .await
        {
            Ok(_) => sent += 1,
            Err(error) => warnings.push(format!("SSDP unicast send to {ip} failed: {error}")),
        }
    }
    if sent == 0 {
        return Err(SsdpError::Unavailable(warnings.join("; ")));
    }

    let window = timeout.max(Duration::from_millis(800));
    let deadline = Instant::now() + window;
    let mut locations: BTreeMap<String, (Option<String>, IpAddr)> = BTreeMap::new();
    let mut buffer = [0_u8; 8192];
    while !cancel.is_cancelled() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                let text = String::from_utf8_lossy(&buffer[..length]);
                let Some(location) = header_value(&text, "location") else {
                    continue;
                };
                let usn = header_value(&text, "usn");
                locations.entry(location).or_insert((usn, from.ip()));
            }
            Ok(Err(error)) => {
                warnings.push(format!("SSDP receive failed: {error}"));
                break;
            }
            Err(_) => break,
        }
    }

    let fetches = locations
        .into_iter()
        .map(|(location, (usn, source_ip))| async move {
            match fetch_description(&location, source_ip, timeout).await {
                Ok(mut device) => {
                    if device.udn.is_none() {
                        device.udn = usn.map(|value| {
                            value
                                .split("::")
                                .next()
                                .unwrap_or(value.as_str())
                                .to_string()
                        });
                    }
                    Ok(device)
                }
                Err(error) => Err(format!("{location}: {error}")),
            }
        });
    let results: Vec<Result<UpnpObservation, String>> = stream::iter(fetches)
        .buffer_unordered(DESCRIPTION_CONCURRENCY)
        .collect()
        .await;

    let mut devices = Vec::new();
    for result in results {
        match result {
            Ok(device) => devices.push(device),
            Err(error) => warnings.push(error),
        }
    }
    devices.sort_by(|left, right| left.location.cmp(&right.location));
    devices.dedup_by(|left, right| left.location == right.location);

    Ok(SsdpDiscovery { devices, warnings })
}

fn build_search_request(timeout: Duration) -> String {
    let mx = timeout.as_secs().clamp(1, 3);
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {mx}\r\n\
         ST: ssdp:all\r\n\
         USER-AGENT: NetAtlas/0.1\r\n\
         \r\n"
    )
}

async fn fetch_description(
    location: &str,
    source_ip: IpAddr,
    timeout: Duration,
) -> Result<UpnpObservation, SsdpError> {
    let url = HttpLocation::parse(location)?;
    let address = resolve(&url, timeout).await?;
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| SsdpError::Http(format!("connecting to {location} timed out")))?
        .map_err(|error| SsdpError::Http(format!("connecting to {location}: {error}")))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: NetAtlas/0.1\r\n\r\n",
        url.path, url.authority
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| SsdpError::Http(format!("sending request to {location}: {error}")))?;

    let mut bytes = Vec::new();
    let mut limited = stream.take(MAX_DESCRIPTION_BYTES as u64);
    let _ = tokio::time::timeout(timeout, limited.read_to_end(&mut bytes)).await;

    let response = parse_http_response(&bytes)?;
    if response.status != 200 {
        return Err(SsdpError::Http(format!(
            "{location} returned HTTP status {}",
            response.status
        )));
    }
    let body = String::from_utf8_lossy(&response.body);
    let fields = extract_device(&body)?;
    let hash = sha256_hex(response.body.as_slice());
    let key = fields.udn.clone().unwrap_or_else(|| location.to_string());
    Ok(UpnpObservation {
        udn: fields.udn,
        source_ip,
        location: location.to_string(),
        device_type: fields.device_type,
        friendly_name: fields.friendly_name,
        manufacturer: fields.manufacturer,
        model_name: fields.model_name,
        model_number: fields.model_number,
        model_description: fields.model_description,
        serial_number: fields.serial_number,
        source_unit: format!("ssdp:{key}:description:{hash}"),
    })
}

async fn resolve(url: &HttpLocation, timeout: Duration) -> Result<SocketAddr, SsdpError> {
    if let Ok(ip) = url.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, url.port));
    }
    let mut addresses = tokio::time::timeout(timeout, lookup_host((url.host.as_str(), url.port)))
        .await
        .map_err(|_| SsdpError::Http(format!("resolving {} timed out", url.host)))?
        .map_err(|error| SsdpError::Http(format!("resolving {}: {error}", url.host)))?;
    addresses
        .next()
        .ok_or_else(|| SsdpError::Http(format!("{} resolved to no addresses", url.host)))
}

#[derive(Debug, Clone)]
struct HttpLocation {
    authority: String,
    host: String,
    port: u16,
    path: String,
}

impl HttpLocation {
    fn parse(value: &str) -> Result<Self, SsdpError> {
        let rest = value.strip_prefix("http://").ok_or_else(|| {
            SsdpError::InvalidLocation(value.to_string(), "only http:// is supported".to_string())
        })?;
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(SsdpError::InvalidLocation(
                value.to_string(),
                "missing host".to_string(),
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port.parse::<u16>().map_err(|_| {
                    SsdpError::InvalidLocation(value.to_string(), "invalid port".to_string())
                })?;
                (host, port)
            }
            _ => (authority, 80),
        };
        Ok(Self {
            authority: authority.to_string(),
            host: host.to_string(),
            port,
            path: if path.is_empty() { "/" } else { path }.to_string(),
        })
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_http_response(bytes: &[u8]) -> Result<HttpResponse, SsdpError> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| SsdpError::Parse("HTTP response has no header terminator".to_string()))?;
    let header_text = String::from_utf8_lossy(&bytes[..split]);
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| SsdpError::Parse("HTTP response has no status line".to_string()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| SsdpError::Parse("HTTP response has an invalid status".to_string()))?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let body_start = split + 4;
    let mut body = bytes[body_start..].to_vec();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        body = decode_chunked(&body)?;
    } else if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        body.truncate(length);
    }
    Ok(HttpResponse { status, body })
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, SsdpError> {
    let mut decoded = Vec::new();
    let mut cursor = 0_usize;
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| SsdpError::Parse("chunked body has no size line".to_string()))?
            + cursor;
        let size_text = String::from_utf8_lossy(&body[cursor..line_end]);
        let size = usize::from_str_radix(size_text.trim(), 16)
            .map_err(|_| SsdpError::Parse("chunked body has an invalid size".to_string()))?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        let end = cursor
            .checked_add(size)
            .filter(|end| *end <= body.len())
            .ok_or_else(|| SsdpError::Parse("chunked body is truncated".to_string()))?;
        decoded.extend_from_slice(&body[cursor..end]);
        cursor = end + 2;
    }
    Ok(decoded)
}

fn header_value(message: &str, name: &str) -> Option<String> {
    message.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

#[derive(Debug, Default)]
struct DeviceFields {
    udn: Option<String>,
    device_type: Option<String>,
    friendly_name: Option<String>,
    manufacturer: Option<String>,
    model_name: Option<String>,
    model_number: Option<String>,
    model_description: Option<String>,
    serial_number: Option<String>,
}

fn extract_device(xml: &str) -> Result<DeviceFields, SsdpError> {
    let document =
        Document::parse(xml).map_err(|error| SsdpError::Parse(format!("invalid XML: {error}")))?;
    let device = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "device")
        .ok_or_else(|| SsdpError::Parse("description has no device element".to_string()))?;
    let field = |name: &str| {
        device
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == name)
            .and_then(|node| node.text())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    };
    Ok(DeviceFields {
        udn: field("UDN"),
        device_type: field("deviceType"),
        friendly_name: field("friendlyName"),
        manufacturer: field("manufacturer"),
        model_name: field("modelName"),
        model_number: field("modelNumber"),
        model_description: field("modelDescription"),
        serial_number: field("serialNumber"),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{HttpLocation, decode_chunked, extract_device, header_value, parse_http_response};

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room Speaker</friendlyName>
    <manufacturer>Example Audio</manufacturer>
    <modelName>SoundOne</modelName>
    <modelNumber>SO-100</modelNumber>
    <serialNumber>ABC123</serialNumber>
    <UDN>uuid:12345678-1234-1234-1234-123456789abc</UDN>
  </device>
</root>"#;

    #[test]
    fn extracts_device_fields_from_namespaced_xml() {
        let fields = extract_device(DESCRIPTION).unwrap();
        assert_eq!(
            fields.udn.as_deref(),
            Some("uuid:12345678-1234-1234-1234-123456789abc")
        );
        assert_eq!(
            fields.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(fields.manufacturer.as_deref(), Some("Example Audio"));
        assert_eq!(fields.model_name.as_deref(), Some("SoundOne"));
        assert_eq!(fields.model_number.as_deref(), Some("SO-100"));
    }

    #[test]
    fn rejects_xml_without_device_element() {
        assert!(extract_device("<root><service/></root>").is_err());
    }

    #[test]
    fn parses_http_content_length_and_chunked() {
        let response =
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyextra").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"body");

        let response = parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.body, b"body");
    }

    #[test]
    fn decodes_chunked_body() {
        assert_eq!(
            decode_chunked(b"4\r\ntest\r\n3\r\nabc\r\n0\r\n\r\n").unwrap(),
            b"testabc"
        );
    }

    #[test]
    fn finds_headers_case_insensitively() {
        let message = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2:80/desc.xml\r\n";
        assert_eq!(
            header_value(message, "location").as_deref(),
            Some("http://192.168.1.2:80/desc.xml")
        );
    }

    #[test]
    fn parses_http_location() {
        let url = HttpLocation::parse("http://192.168.1.2:49152/desc.xml").unwrap();
        assert_eq!(url.host, "192.168.1.2");
        assert_eq!(url.port, 49152);
        assert_eq!(url.path, "/desc.xml");
        assert!(HttpLocation::parse("https://example.test/desc.xml").is_err());
    }
}
