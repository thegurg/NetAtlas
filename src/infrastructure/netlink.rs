//! Linux network context via netlink.
//!
//! Read-only operations: links, addresses, routes, and the kernel neighbour
//! cache. These do not require elevated privileges.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlags, LinkMessage},
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourMessage,
        NeighbourState as KernelNeighbourState,
    },
    route::{RouteAddress, RouteAttribute, RouteMessage},
};
use rtnetlink::{Handle, RouteMessageBuilder, new_connection};
use thiserror::Error;

use crate::domain::{
    InterfaceAddress, InterfaceInfo, MacAddress, NeighborEntry, NeighborState, NetworkContext,
    RouteInfo, time::now_ms,
};

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("netlink connection failed: {0}")]
    Connect(String),
    #[error("netlink request failed: {0}")]
    Request(String),
}

/// Read the current network context.
pub async fn snapshot() -> Result<NetworkContext, NetlinkError> {
    let (connection, handle, _) =
        new_connection().map_err(|error| NetlinkError::Connect(error.to_string()))?;
    tokio::spawn(connection);

    let links = dump_links(&handle).await?;
    let addresses = dump_addresses(&handle).await?;

    let mut warnings = Vec::new();
    let routes = match dump_routes(&handle).await {
        Ok(routes) => routes,
        Err(error) => {
            warnings.push(format!("route table unavailable: {error}"));
            Vec::new()
        }
    };
    let neighbors = match dump_neighbors(&handle).await {
        Ok(neighbors) => neighbors,
        Err(error) => {
            warnings.push(format!("neighbour table unavailable: {error}"));
            Vec::new()
        }
    };

    let mut addresses_by_index: HashMap<u32, Vec<InterfaceAddress>> = HashMap::new();
    for message in addresses {
        let Some(ip) = address_ip(&message) else {
            continue;
        };
        let family = match message.header.family {
            AddressFamily::Inet => 4,
            AddressFamily::Inet6 => 6,
            _ => continue,
        };
        addresses_by_index
            .entry(message.header.index)
            .or_default()
            .push(InterfaceAddress {
                address: ip,
                prefix_len: message.header.prefix_len,
                family,
                scope: Some(message.header.scope.to_string()),
            });
    }

    let mut interfaces = Vec::new();
    for message in links {
        let Some(name) = link_name(&message) else {
            continue;
        };
        interfaces.push(InterfaceInfo {
            name,
            index: message.header.index,
            mac: link_mac(&message),
            mtu: link_mtu(&message),
            is_up: message.header.flags.contains(LinkFlags::Up),
            is_loopback: message.header.flags.contains(LinkFlags::Loopback),
            oper_state: link_oper_state(&message),
            addresses: addresses_by_index
                .remove(&message.header.index)
                .unwrap_or_default(),
        });
    }

    let index_to_name: HashMap<u32, String> = interfaces
        .iter()
        .map(|interface| (interface.index, interface.name.clone()))
        .collect();

    let mut parsed_routes = Vec::new();
    for message in routes {
        parsed_routes.push(parse_route(&message, &index_to_name));
    }

    let default_route = parsed_routes
        .iter()
        .filter(|route| route.is_default && route.gateway.is_some())
        .min_by_key(|route| route.metric.unwrap_or(u32::MAX));

    let default_gateway = default_route.and_then(|route| route.gateway);
    let default_interface = default_route
        .and_then(|route| route.interface.clone())
        .or_else(|| {
            interfaces
                .iter()
                .find(|interface| {
                    interface.is_up
                        && !interface.is_loopback
                        && interface
                            .addresses
                            .iter()
                            .any(|address| address.family == 4)
                })
                .map(|interface| interface.name.clone())
        });

    let parsed_neighbors = neighbors
        .iter()
        .filter_map(|message| parse_neighbor(message, &index_to_name))
        .collect();

    Ok(NetworkContext {
        interfaces,
        routes: parsed_routes,
        neighbors: parsed_neighbors,
        default_interface,
        default_gateway,
        warnings,
        captured_at_ms: now_ms(),
    })
}

async fn dump_links(handle: &Handle) -> Result<Vec<LinkMessage>, NetlinkError> {
    let mut stream = handle.link().get().execute();
    let mut links = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| NetlinkError::Request(error.to_string()))?
    {
        links.push(message);
    }
    Ok(links)
}

async fn dump_addresses(handle: &Handle) -> Result<Vec<AddressMessage>, NetlinkError> {
    let mut stream = handle.address().get().execute();
    let mut addresses = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| NetlinkError::Request(error.to_string()))?
    {
        addresses.push(message);
    }
    Ok(addresses)
}

async fn dump_routes(handle: &Handle) -> Result<Vec<RouteMessage>, NetlinkError> {
    let mut routes = Vec::new();

    let mut v4 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
        .execute();
    while let Some(message) = v4
        .try_next()
        .await
        .map_err(|error| NetlinkError::Request(error.to_string()))?
    {
        routes.push(message);
    }

    let mut v6 = handle
        .route()
        .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
        .execute();
    while let Some(message) = v6
        .try_next()
        .await
        .map_err(|error| NetlinkError::Request(error.to_string()))?
    {
        routes.push(message);
    }

    Ok(routes)
}

async fn dump_neighbors(handle: &Handle) -> Result<Vec<NeighbourMessage>, NetlinkError> {
    let mut neighbors = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut stream = handle
            .neighbours()
            .get()
            .set_address_family(family)
            .execute();
        while let Some(message) = stream
            .try_next()
            .await
            .map_err(|error| NetlinkError::Request(error.to_string()))?
        {
            neighbors.push(message);
        }
    }
    Ok(neighbors)
}

fn link_name(message: &LinkMessage) -> Option<String> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })
}

fn link_mac(message: &LinkMessage) -> Option<MacAddress> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Address(bytes) => MacAddress::from_bytes(bytes),
            _ => None,
        })
}

fn link_mtu(message: &LinkMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Mtu(mtu) => Some(*mtu),
            _ => None,
        })
}

fn link_oper_state(message: &LinkMessage) -> Option<String> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::OperState(state) => Some(format!("{state:?}").to_lowercase()),
            _ => None,
        })
}

fn address_ip(message: &AddressMessage) -> Option<IpAddr> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Address(ip) => Some(*ip),
            _ => None,
        })
}

fn parse_route(message: &RouteMessage, index_to_name: &HashMap<u32, String>) -> RouteInfo {
    let mut destination = None;
    let mut gateway = None;
    let mut interface = None;
    let mut metric = None;

    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(address) => {
                if let Some(ip) = route_address_ip(address) {
                    destination = IpNet::new(ip, message.header.destination_prefix_length).ok();
                }
            }
            RouteAttribute::Gateway(address) => {
                gateway = route_address_ip(address);
            }
            RouteAttribute::Oif(index) => {
                interface = index_to_name.get(index).cloned();
            }
            RouteAttribute::Priority(priority) => {
                metric = Some(*priority);
            }
            _ => {}
        }
    }

    RouteInfo {
        destination,
        gateway,
        interface,
        metric,
        is_default: message.header.destination_prefix_length == 0,
    }
}

fn route_address_ip(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

fn parse_neighbor(
    message: &NeighbourMessage,
    index_to_name: &HashMap<u32, String>,
) -> Option<NeighborEntry> {
    let mut ip = None;
    let mut mac = None;

    for attribute in &message.attributes {
        match attribute {
            NeighbourAttribute::Destination(address) => {
                ip = match address {
                    NeighbourAddress::Inet(address) => Some(IpAddr::V4(*address)),
                    NeighbourAddress::Inet6(address) => Some(IpAddr::V6(*address)),
                    NeighbourAddress::Other(_) => None,
                    _ => None,
                };
            }
            NeighbourAttribute::LinkLayerAddress(bytes) => {
                mac = MacAddress::from_bytes(bytes);
            }
            _ => {}
        }
    }

    Some(NeighborEntry {
        ip: ip?,
        mac,
        interface: index_to_name.get(&message.header.ifindex).cloned(),
        state: map_neighbor_state(message.header.state),
        is_router: message
            .header
            .flags
            .contains(rtnetlink::packet_route::neighbour::NeighbourFlags::Router),
    })
}

fn map_neighbor_state(state: KernelNeighbourState) -> NeighborState {
    match state {
        KernelNeighbourState::Incomplete => NeighborState::Incomplete,
        KernelNeighbourState::Reachable => NeighborState::Reachable,
        KernelNeighbourState::Stale => NeighborState::Stale,
        KernelNeighbourState::Delay => NeighborState::Delay,
        KernelNeighbourState::Probe => NeighborState::Probe,
        KernelNeighbourState::Failed => NeighborState::Failed,
        KernelNeighbourState::Noarp => NeighborState::Noarp,
        KernelNeighbourState::Permanent => NeighborState::Permanent,
        KernelNeighbourState::None => NeighborState::None,
        KernelNeighbourState::Other(value) => NeighborState::Other(value),
        _ => NeighborState::None,
    }
}
