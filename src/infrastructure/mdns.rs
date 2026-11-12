//! Bounded mDNS service discovery through `mdns-sd`.
//!
//! The adapter starts a short-lived mDNS daemon, browses a small set of service
//! types for a bounded window, and returns resolved service instances. It does
//! not decide device identity or properties; it reports what the device
//! published.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, TxtProperties};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::domain::MdnsServiceObservation;

/// Service types that commonly expose useful device metadata. The list is
/// intentionally small; browsing every DNS-SD type would add traffic without a
/// corresponding identification benefit.
pub const DEFAULT_SERVICE_TYPES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",
    "_matter._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
];

#[derive(Debug, Error)]
pub enum MdnsError {
    #[error("starting mDNS daemon: {0}")]
    Daemon(String),
}

#[derive(Debug, Clone, Default)]
pub struct MdnsDiscovery {
    pub services: Vec<MdnsServiceObservation>,
    pub warnings: Vec<String>,
}

/// Browse for mDNS services for at most `window`.
pub async fn discover(
    service_types: &[&str],
    window: Duration,
    cancel: &CancellationToken,
) -> Result<MdnsDiscovery, MdnsError> {
    let daemon = ServiceDaemon::new().map_err(|error| MdnsError::Daemon(error.to_string()))?;
    let mut warnings = Vec::new();
    let mut receivers = Vec::new();
    for service_type in service_types {
        match daemon.browse(service_type) {
            Ok(receiver) => receivers.push(receiver),
            Err(error) => warnings.push(format!("mDNS browse {service_type} failed: {error}")),
        }
    }
    if receivers.is_empty() {
        let _ = daemon.shutdown();
        let detail = if warnings.is_empty() {
            "no mDNS service types could be browsed".to_string()
        } else {
            warnings.join("; ")
        };
        return Err(MdnsError::Daemon(detail));
    }

    let (sender, mut receiver) = tokio::sync::mpsc::channel(128);
    let mut handles = Vec::new();
    for source in receivers {
        let sender = sender.clone();
        handles.push(tokio::spawn(async move {
            while let Ok(event) = source.recv_async().await {
                if sender.send(event).await.is_err() {
                    break;
                }
            }
        }));
    }
    drop(sender);

    let deadline = Instant::now() + window;
    let mut seen = HashSet::new();
    let mut services = Vec::new();
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let event = tokio::select! {
            _ = cancel.cancelled() => break,
            event = tokio::time::timeout(remaining, receiver.recv()) => match event {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => break,
            },
        };
        if let ServiceEvent::ServiceResolved(service) = event {
            let service = *service;
            if !service.is_valid() {
                continue;
            }
            if !seen.insert(service.fullname.clone()) {
                continue;
            }
            services.push(to_observation(&service));
        }
    }

    for handle in handles {
        handle.abort();
    }
    let _ = daemon.shutdown();

    services.sort_by(|left, right| left.fullname.cmp(&right.fullname));
    Ok(MdnsDiscovery { services, warnings })
}

fn to_observation(service: &ResolvedService) -> MdnsServiceObservation {
    let addresses: Vec<IpAddr> = service
        .addresses
        .iter()
        .map(mdns_sd::ScopedIp::to_ip_addr)
        .collect();
    MdnsServiceObservation {
        fullname: service.fullname.clone(),
        service_type: service.ty_domain.clone(),
        host: service.host.clone(),
        port: service.port,
        addresses,
        properties: properties_map(service.get_properties()),
        source_unit: format!("mdns:{}", service.fullname),
    }
}

fn properties_map(properties: &TxtProperties) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for property in properties.iter() {
        map.insert(
            property.key().to_ascii_lowercase(),
            property.val_str().to_string(),
        );
    }
    map
}

/// Map a DNS-SD service type to a conservative device category.
///
/// Only service types with an unambiguous category mapping are included. A
/// generic `_http._tcp` service is not enough to call a device a server.
pub fn category_for_service_type(service_type: &str) -> Option<&'static str> {
    let normalized = service_type.to_ascii_lowercase();
    if normalized.starts_with("_ipp.")
        || normalized.starts_with("_ipps.")
        || normalized.starts_with("_printer.")
        || normalized.starts_with("_pdl-datastream.")
    {
        Some("printer")
    } else if normalized.starts_with("_airplay.") || normalized.starts_with("_googlecast.") {
        Some("media_renderer")
    } else if normalized.starts_with("_raop.") {
        Some("speaker")
    } else if normalized.starts_with("_hap.") || normalized.starts_with("_matter.") {
        Some("iot")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use mdns_sd::TxtProperties;

    use super::{category_for_service_type, properties_map};

    #[test]
    fn maps_unambiguous_service_types() {
        assert_eq!(
            category_for_service_type("_ipp._tcp.local."),
            Some("printer")
        );
        assert_eq!(
            category_for_service_type("_airplay._tcp.local."),
            Some("media_renderer")
        );
        assert_eq!(
            category_for_service_type("_raop._tcp.local."),
            Some("speaker")
        );
        assert_eq!(category_for_service_type("_hap._tcp.local."), Some("iot"));
        assert_eq!(category_for_service_type("_http._tcp.local."), None);
        assert_eq!(category_for_service_type("_ssh._tcp.local."), None);
    }

    #[test]
    fn extracts_txt_properties_case_insensitively() {
        let properties = TxtProperties::from(&b"\x0bmodel=Test1\x0bvendor=ACME"[..]);
        let map = properties_map(&properties);
        assert_eq!(map.get("model").map(String::as_str), Some("Test1"));
        assert_eq!(map.get("vendor").map(String::as_str), Some("ACME"));
    }
}
