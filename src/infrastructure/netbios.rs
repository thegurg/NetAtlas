//! NetBIOS NBSTAT discovery.
//!
//! A wildcard NBSTAT query asks a host for its registered NetBIOS names. The
//! result is a naming claim, not a verified identity, and many modern hosts do
//! not answer at all. A timeout is not evidence that a host is absent.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use futures_util::{StreamExt, stream};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::domain::NetbiosObservation;

static NEXT_TRANSACTION_ID: AtomicU16 = AtomicU16::new(0x4e41);

#[derive(Debug, Error)]
pub enum NetbiosError {
    #[error("binding NetBIOS socket: {0}")]
    Bind(#[source] io::Error),
    #[error("sending NetBIOS query: {0}")]
    Send(#[source] io::Error),
    #[error("NetBIOS query timed out")]
    Timeout,
    #[error("receiving NetBIOS response: {0}")]
    Receive(#[source] io::Error),
    #[error("invalid NetBIOS response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Clone)]
pub struct NetbiosHost {
    pub ip: IpAddr,
    pub names: Vec<NetbiosObservation>,
}

#[derive(Debug, Clone, Default)]
pub struct NetbiosDiscovery {
    pub hosts: Vec<NetbiosHost>,
    pub warnings: Vec<String>,
}

/// Query each address for its NetBIOS name table.
pub async fn query_hosts(
    addresses: &[IpAddr],
    timeout: Duration,
    concurrency: usize,
    cancel: &CancellationToken,
) -> Result<NetbiosDiscovery, NetbiosError> {
    let results: Vec<Result<NetbiosHost, String>> = stream::iter(addresses.iter().copied())
        .map(|ip| {
            let cancel = cancel.clone();
            async move {
                if cancel.is_cancelled() {
                    return Err(format!("{ip}: cancelled"));
                }
                match query_one(ip, timeout).await {
                    Ok(names) if names.is_empty() => Err(format!("{ip}: no names returned")),
                    Ok(names) => Ok(NetbiosHost { ip, names }),
                    Err(error) => Err(format!("{ip}: {error}")),
                }
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut hosts = Vec::new();
    let mut warnings = Vec::new();
    for result in results {
        match result {
            Ok(host) => hosts.push(host),
            Err(warning) => warnings.push(warning),
        }
    }
    hosts.sort_by_key(|host| host.ip);
    Ok(NetbiosDiscovery { hosts, warnings })
}

async fn query_one(ip: IpAddr, timeout: Duration) -> Result<Vec<NetbiosObservation>, NetbiosError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(NetbiosError::Bind)?;
    let transaction_id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
    let request = build_query(transaction_id);
    socket
        .send_to(&request, SocketAddr::new(ip, 137))
        .await
        .map_err(NetbiosError::Send)?;

    let mut buffer = [0_u8; 1500];
    let (length, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buffer))
        .await
        .map_err(|_| NetbiosError::Timeout)?
        .map_err(NetbiosError::Receive)?;

    let source_unit = format!("netbios:{ip}:{transaction_id:04x}");
    parse_response(&buffer[..length], transaction_id, &source_unit)
        .map_err(NetbiosError::InvalidResponse)
}

fn build_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0000_u16.to_be_bytes()); // flags
    packet.extend_from_slice(&1_u16.to_be_bytes()); // questions
    packet.extend_from_slice(&0_u16.to_be_bytes()); // answers
    packet.extend_from_slice(&0_u16.to_be_bytes()); // authorities
    packet.extend_from_slice(&0_u16.to_be_bytes()); // additional
    packet.push(0x20); // encoded name length
    packet.extend_from_slice(b"CK");
    for _ in 0..15 {
        packet.extend_from_slice(b"AA");
    }
    packet.push(0x00); // root label
    packet.extend_from_slice(&0x0021_u16.to_be_bytes()); // NBSTAT
    packet.extend_from_slice(&0x0001_u16.to_be_bytes()); // IN
    packet
}

fn parse_response(
    packet: &[u8],
    expected_id: u16,
    source_unit: &str,
) -> Result<Vec<NetbiosObservation>, String> {
    if packet.len() < 12 {
        return Err("response is shorter than a DNS header".to_string());
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if id != expected_id {
        return Err("response transaction ID does not match".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return Err("response bit is not set".to_string());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("NetBIOS response code {rcode}"));
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut cursor = 12;
    for _ in 0..questions {
        cursor = skip_name(packet, cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| "truncated question".to_string())?;
    }

    let mut names = Vec::new();
    for _ in 0..answers {
        cursor = skip_name(packet, cursor)?;
        if cursor + 10 > packet.len() {
            return Err("truncated answer header".to_string());
        }
        let record_type = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        cursor += 8; // type, class, TTL
        let data_length = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]) as usize;
        cursor += 2;
        let end = cursor
            .checked_add(data_length)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| "truncated answer data".to_string())?;
        if record_type == 0x0021 && data_length >= 1 {
            let count = packet[cursor] as usize;
            let mut offset = cursor + 1;
            for _ in 0..count {
                if offset + 18 > end {
                    break;
                }
                let raw_name = &packet[offset..offset + 15];
                let name = String::from_utf8_lossy(raw_name)
                    .trim_end_matches([' ', '\0'])
                    .to_string();
                let suffix = packet[offset + 15];
                let name_flags = u16::from_be_bytes([packet[offset + 16], packet[offset + 17]]);
                if !name.is_empty() {
                    names.push(NetbiosObservation {
                        name,
                        suffix,
                        group: name_flags & 0x8000 != 0,
                        source_unit: source_unit.to_string(),
                    });
                }
                offset += 18;
            }
        }
        cursor = end;
    }
    Ok(names)
}

fn skip_name(packet: &[u8], mut cursor: usize) -> Result<usize, String> {
    loop {
        let length = *packet
            .get(cursor)
            .ok_or_else(|| "truncated DNS name".to_string())? as usize;
        if length == 0 {
            return Ok(cursor + 1);
        }
        if length & 0xc0 == 0xc0 {
            if cursor + 1 >= packet.len() {
                return Err("truncated DNS name pointer".to_string());
            }
            return Ok(cursor + 2);
        }
        cursor = cursor
            .checked_add(1 + length)
            .filter(|next| *next <= packet.len())
            .ok_or_else(|| "truncated DNS label".to_string())?;
    }
}

#[cfg(test)]
mod tests {
    use super::{build_query, parse_response, skip_name};

    fn response_packet() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x4e41_u16.to_be_bytes());
        packet.extend_from_slice(&0x8400_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes()); // questions
        packet.extend_from_slice(&1_u16.to_be_bytes()); // answers
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        packet.extend_from_slice(&0x0021_u16.to_be_bytes());
        packet.extend_from_slice(&0x0001_u16.to_be_bytes());
        packet.extend_from_slice(&0_u32.to_be_bytes());
        let mut data = Vec::new();
        data.push(2);
        data.extend_from_slice(b"WORKSTATION    ");
        data.push(0x00);
        data.extend_from_slice(&0x0400_u16.to_be_bytes());
        data.extend_from_slice(b"WORKGROUP      ");
        data.push(0x00);
        data.extend_from_slice(&0x8400_u16.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(&data);
        packet
    }

    #[test]
    fn builds_a_wildcard_nbstat_query() {
        let query = build_query(0x4e41);
        assert_eq!(&query[..2], &[0x4e, 0x41]);
        assert_eq!(query[12], 0x20);
        assert_eq!(&query[13..15], b"CK");
        assert_eq!(query[45], 0x00);
        assert_eq!(&query[46..48], &[0x00, 0x21]);
        assert_eq!(&query[48..50], &[0x00, 0x01]);
    }

    #[test]
    fn parses_names_and_group_bit() {
        let names = parse_response(&response_packet(), 0x4e41, "netbios:test").unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].name, "WORKSTATION");
        assert!(!names[0].group);
        assert_eq!(names[1].name, "WORKGROUP");
        assert!(names[1].group);
    }

    #[test]
    fn rejects_mismatched_transaction_id() {
        assert!(parse_response(&response_packet(), 0x1234, "netbios:test").is_err());
    }

    #[test]
    fn skips_compressed_names() {
        assert_eq!(skip_name(&[0xc0, 0x0c], 0).unwrap(), 2);
        assert_eq!(skip_name(&[0x03, b'a', b'b', b'c', 0x00], 0).unwrap(), 5);
    }
}
