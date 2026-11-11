//! Network context and link-layer address types.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::domain::DomainError;

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 6 {
            return None;
        }
        let mut octets = [0_u8; 6];
        octets.copy_from_slice(bytes);
        Some(Self(octets))
    }

    pub fn octets(self) -> [u8; 6] {
        self.0
    }

    /// True when the locally administered bit is set.
    ///
    /// This is not proof of MAC randomization: hypervisors and manually
    /// assigned addresses also set this bit.
    pub fn is_locally_administered(self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_multicast(self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Return the first `bits` bits as uppercase hex, for OUI lookup.
    ///
    /// IEEE registry prefixes are 24, 28, or 36 bits, all nibble-aligned.
    pub fn prefix_hex(self, bits: u8) -> Result<String, DomainError> {
        if !matches!(bits, 24 | 28 | 36) {
            return Err(DomainError::InvalidPrefixBits(bits));
        }
        let full = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]);
        Ok(full[..(bits as usize / 4)].to_string())
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(DomainError::InvalidMac(value.to_string()));
        }

        let hex_parts: Vec<String> = if trimmed.contains(':') || trimmed.contains('-') {
            let separator = if trimmed.contains(':') { ':' } else { '-' };
            let parts: Vec<&str> = trimmed.split(separator).collect();
            if parts.len() != 6 {
                return Err(DomainError::InvalidMac(value.to_string()));
            }
            parts
                .iter()
                .map(|part| {
                    if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                        Err(DomainError::InvalidMac(value.to_string()))
                    } else {
                        Ok(format!("{part:0>2}"))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if trimmed.contains('.') {
            let parts: Vec<&str> = trimmed.split('.').collect();
            if parts.len() != 3 || parts.iter().any(|part| part.len() != 4 || !part.chars().all(|c| c.is_ascii_hexdigit())) {
                return Err(DomainError::InvalidMac(value.to_string()));
            }
            let joined = parts.concat();
            (0..6)
                .map(|index| joined[index * 2..index * 2 + 2].to_string())
                .collect()
        } else if trimmed.len() == 12 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            (0..6)
                .map(|index| trimmed[index * 2..index * 2 + 2].to_string())
                .collect()
        } else {
            return Err(DomainError::InvalidMac(value.to_string()));
        };

        let mut octets = [0_u8; 6];
        for (index, part) in hex_parts.iter().enumerate() {
            octets[index] = u8::from_str_radix(part, 16)
                .map_err(|_| DomainError::InvalidMac(value.to_string()))?;
        }
        Ok(Self(octets))
    }
}

impl Serialize for MacAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
    pub family: u8,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub mac: Option<MacAddress>,
    pub mtu: Option<u32>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub oper_state: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
}

impl InterfaceInfo {
    pub fn ipv4_addresses(&self) -> impl Iterator<Item = &InterfaceAddress> {
        self.addresses.iter().filter(|address| address.address.is_ipv4())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteInfo {
    pub destination: Option<IpNet>,
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Noarp,
    Permanent,
    None,
    Other(u16),
}

impl NeighborState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Reachable => "reachable",
            Self::Stale => "stale",
            Self::Delay => "delay",
            Self::Probe => "probe",
            Self::Failed => "failed",
            Self::Noarp => "noarp",
            Self::Permanent => "permanent",
            Self::None => "none",
            Self::Other(_) => "other",
        }
    }

    /// Whether the state is compatible with having observed a live neighbour.
    pub fn is_present(self) -> bool {
        matches!(
            self,
            Self::Reachable | Self::Stale | Self::Delay | Self::Probe | Self::Permanent | Self::Noarp
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: IpAddr,
    pub mac: Option<MacAddress>,
    pub interface: Option<String>,
    pub state: NeighborState,
    pub is_router: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkSegment {
    pub interface: String,
    pub prefix: IpNet,
    pub gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub interfaces: Vec<InterfaceInfo>,
    pub routes: Vec<RouteInfo>,
    pub neighbors: Vec<NeighborEntry>,
    pub default_interface: Option<String>,
    pub default_gateway: Option<IpAddr>,
    pub warnings: Vec<String>,
    pub captured_at_ms: i64,
}

impl NetworkContext {
    pub fn interface_by_name(&self, name: &str) -> Option<&InterfaceInfo> {
        self.interfaces.iter().find(|interface| interface.name == name)
    }

    pub fn local_ips(&self) -> Vec<IpAddr> {
        self.interfaces
            .iter()
            .flat_map(|interface| interface.addresses.iter().map(|address| address.address))
            .collect()
    }

    pub fn interface_for_ip(&self, ip: IpAddr) -> Option<&InterfaceInfo> {
        self.interfaces.iter().find(|interface| {
            interface
                .addresses
                .iter()
                .any(|address| prefix_for_address(address).is_some_and(|prefix| prefix.contains(&ip)))
        })
    }

    pub fn segment_for_ip(&self, ip: IpAddr) -> Option<IpNet> {
        self.interfaces.iter().find_map(|interface| {
            interface.addresses.iter().find_map(|address| {
                let prefix = prefix_for_address(address)?;
                prefix.contains(&ip).then_some(prefix)
            })
        })
    }

    pub fn segments(&self) -> Vec<NetworkSegment> {
        let mut segments = Vec::new();
        for interface in &self.interfaces {
            for address in &interface.addresses {
                let Some(prefix) = prefix_for_address(address) else {
                    continue;
                };
                if segments.iter().any(|segment: &NetworkSegment| {
                    segment.interface == interface.name && segment.prefix == prefix
                }) {
                    continue;
                }
                let gateway = self.default_gateway.filter(|gateway| {
                    self.default_interface.as_deref() == Some(interface.name.as_str())
                        && prefix.contains(gateway)
                });
                segments.push(NetworkSegment {
                    interface: interface.name.clone(),
                    prefix,
                    gateway,
                });
            }
        }
        segments
    }

    pub fn neighbor_for_ip(&self, ip: IpAddr) -> Option<&NeighborEntry> {
        self.neighbors.iter().find(|neighbor| neighbor.ip == ip)
    }
}

pub fn prefix_for_address(address: &InterfaceAddress) -> Option<IpNet> {
    IpNet::new(address.address, address.prefix_len).ok()
}

/// Enumerate candidate IPv4 hosts in a prefix.
///
/// Network and broadcast addresses are excluded for prefixes shorter than /31.
/// The returned list never exceeds `max_hosts`; oversized scopes are rejected
/// before any probe is sent.
pub fn enumerate_ipv4_hosts(
    net: Ipv4Net,
    exclude: &[IpAddr],
    max_hosts: usize,
) -> Result<Vec<Ipv4Addr>, DomainError> {
    let prefix_len = net.prefix_len();
    let network = u32::from(net.network());
    let broadcast = u32::from(net.broadcast());

    let (start, end) = match prefix_len {
        32 => (network, network),
        31 => (network, broadcast),
        _ => (network.saturating_add(1), broadcast.saturating_sub(1)),
    };

    let count = u64::from(end).saturating_sub(u64::from(start)) + 1;
    if count > max_hosts as u64 {
        return Err(DomainError::PrefixTooLarge(format!(
            "{net} contains {count} candidate addresses (limit {max_hosts})"
        )));
    }

    let excluded: HashSet<Ipv4Addr> = exclude
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(*ip),
            IpAddr::V6(_) => None,
        })
        .collect();

    Ok((start..=end)
        .map(Ipv4Addr::from)
        .filter(|ip| !excluded.contains(ip))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use super::{MacAddress, enumerate_ipv4_hosts};

    #[test]
    fn parses_mac_formats() {
        let expected: MacAddress = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!("AA-BB-CC-DD-EE-FF".parse::<MacAddress>().unwrap(), expected);
        assert_eq!("aabb.ccdd.eeff".parse::<MacAddress>().unwrap(), expected);
        assert_eq!("aabbccddeeff".parse::<MacAddress>().unwrap(), expected);
        assert!("not-a-mac".parse::<MacAddress>().is_err());
        assert!("aa:bb:cc:dd:ee".parse::<MacAddress>().is_err());
    }

    #[test]
    fn detects_local_and_multicast_bits() {
        assert!("02:00:00:00:00:01".parse::<MacAddress>().unwrap().is_locally_administered());
        assert!(!"00:11:22:33:44:55".parse::<MacAddress>().unwrap().is_locally_administered());
        assert!("01:00:5e:00:00:01".parse::<MacAddress>().unwrap().is_multicast());
    }

    #[test]
    fn oui_prefixes_are_nibble_aligned() {
        let mac: MacAddress = "3c:cd:5d:11:22:33".parse().unwrap();
        assert_eq!(mac.prefix_hex(24).unwrap(), "3CCD5D");
        assert_eq!(mac.prefix_hex(28).unwrap(), "3CCD5D1");
        assert_eq!(mac.prefix_hex(36).unwrap(), "3CCD5D112");
    }

    #[test]
    fn enumerates_small_networks() {
        let net: Ipv4Net = "192.168.1.0/30".parse().unwrap();
        let hosts = enumerate_ipv4_hosts(net, &[], 100).unwrap();
        assert_eq!(hosts, vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]);
    }

    #[test]
    fn enumerates_point_to_point_and_host_prefixes() {
        let net: Ipv4Net = "10.0.0.0/31".parse().unwrap();
        assert_eq!(enumerate_ipv4_hosts(net, &[], 10).unwrap().len(), 2);

        let net: Ipv4Net = "10.0.0.7/32".parse().unwrap();
        assert_eq!(
            enumerate_ipv4_hosts(net, &[], 10).unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)]
        );
    }

    #[test]
    fn rejects_oversized_scopes() {
        let net: Ipv4Net = "10.0.0.0/16".parse().unwrap();
        assert!(enumerate_ipv4_hosts(net, &[], 100).is_err());
    }

    #[test]
    fn excludes_local_addresses() {
        let net: Ipv4Net = "192.168.1.0/29".parse().unwrap();
        let hosts = enumerate_ipv4_hosts(net, &["192.168.1.1".parse().unwrap()], 100).unwrap();
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 1)));
    }
}
