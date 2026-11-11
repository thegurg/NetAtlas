//! Discovery session orchestration.
//!
//! The orchestrator owns scope resolution, provider scheduling, aggregation,
//! identity resolution, identification, and persistence. Providers only report
//! what they observed.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::application::identify::{self, ProviderAvailability};
use crate::application::identity::{self, DEFAULT_MAC_WINDOW_MS};
use crate::application::model::{
    DiscoveryMethod, ProviderErrorInfo, ProviderErrorKind, ProviderReport, ProviderStatus,
    ResolvedDevice, ScanConfig, ScanResult, ScanScope, SessionStatus,
};
use crate::config::Config;
use crate::domain::{
    HostObservation, HostProbe, HostnameObservation, NetworkContext, ObservationRecord,
    ProtocolObservation, ServiceRecord, Source, SubjectType, TcpProbe, Transport, ids::new_id,
    network::enumerate_ipv4_hosts, time::now_ms,
};
use crate::infrastructure::{
    icmp, mdns, netbios, netlink, reverse_dns, service_probe, ssdp, storage::Store, tcp_probe,
};

/// Per-scan options, normally filled from the CLI with configuration defaults.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub interface: Option<String>,
    pub target: Option<String>,
    pub enable_icmp: bool,
    pub enable_tcp: bool,
    pub enable_dns: bool,
    pub enable_mdns: bool,
    pub enable_ssdp: bool,
    pub enable_netbios: bool,
    pub enable_services: bool,
    pub timeout_ms: u64,
    pub dns_timeout_ms: u64,
    pub mdns_window_ms: u64,
    pub concurrency: usize,
    pub max_hosts: usize,
    pub mac_window_ms: i64,
}

impl ScanOptions {
    pub fn from_config(config: &Config) -> Self {
        Self {
            interface: None,
            target: None,
            enable_icmp: true,
            enable_tcp: true,
            enable_dns: true,
            enable_mdns: true,
            enable_ssdp: true,
            enable_netbios: true,
            enable_services: true,
            timeout_ms: config.timeout_ms,
            dns_timeout_ms: config.dns_timeout_ms,
            mdns_window_ms: 3_000,
            concurrency: config.concurrency,
            max_hosts: config.max_hosts,
            mac_window_ms: DEFAULT_MAC_WINDOW_MS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=65_536).contains(&self.max_hosts) {
            bail!("max_hosts must be between 1 and 65536");
        }
        if !(1..=1_024).contains(&self.concurrency) {
            bail!("concurrency must be between 1 and 1024");
        }
        if !(100..=60_000).contains(&self.timeout_ms) {
            bail!("timeout_ms must be between 100 and 60000");
        }
        if !(100..=60_000).contains(&self.dns_timeout_ms) {
            bail!("dns_timeout_ms must be between 100 and 60000");
        }
        if !(500..=30_000).contains(&self.mdns_window_ms) {
            bail!("mdns_window_ms must be between 500 and 30000");
        }
        if !self.enable_icmp
            && !self.enable_tcp
            && !self.enable_dns
            && !self.enable_mdns
            && !self.enable_ssdp
            && !self.enable_netbios
            && !self.enable_services
        {
            bail!("at least one discovery method must be enabled");
        }
        if let Some(target) = &self.target {
            parse_target(target)?;
        }
        Ok(())
    }

    fn methods(&self) -> Vec<DiscoveryMethod> {
        let mut methods = vec![DiscoveryMethod::Neighbor];
        if self.enable_icmp {
            methods.push(DiscoveryMethod::Icmp);
        }
        if self.enable_tcp {
            methods.push(DiscoveryMethod::Tcp);
        }
        if self.enable_dns {
            methods.push(DiscoveryMethod::ReverseDns);
        }
        if self.enable_mdns {
            methods.push(DiscoveryMethod::Mdns);
        }
        if self.enable_ssdp {
            methods.push(DiscoveryMethod::Ssdp);
        }
        if self.enable_netbios {
            methods.push(DiscoveryMethod::Netbios);
        }
        if self.enable_services {
            methods.push(DiscoveryMethod::ServiceProbe);
        }
        methods
    }
}

/// Run one discovery session and persist it.
pub async fn run_scan(
    store: &mut Store,
    options: ScanOptions,
    cancel: CancellationToken,
) -> Result<ScanResult> {
    options.validate()?;
    let started_at_ms = now_ms();
    let session_id = new_id();

    let mut context = netlink::snapshot()
        .await
        .context("reading network context through netlink")?;

    let scope = resolve_scope(&context, &options)?;
    let candidate_set: HashSet<IpAddr> = scope.candidates.iter().copied().collect();

    let mut probes = Vec::new();
    let mut seen_neighbors = HashSet::new();
    let mut reports = Vec::new();

    // Passive neighbour table: facts the kernel already holds.
    let neighbour_started = now_ms();
    let initial_neighbors =
        collect_neighbor_probes(&context, &scope, &candidate_set, &mut seen_neighbors);
    probes.extend(initial_neighbors.iter().cloned());
    reports.push(provider_report(
        "neighbour_table",
        DiscoveryMethod::Neighbor,
        ProviderStatus::Ok,
        neighbour_started,
        now_ms(),
        initial_neighbors.len(),
        None,
    ));

    // ICMP echo sweep.
    let icmp_started = now_ms();
    if options.enable_icmp && !cancel.is_cancelled() {
        match icmp::sweep(
            &scope.candidates,
            Duration::from_millis(options.timeout_ms),
            options.concurrency,
            &cancel,
        )
        .await
        {
            Ok(sweep) => {
                for reply in &sweep.replies {
                    probes.push(HostProbe::icmp(reply.ip, reply.rtt_ms, now_ms()));
                }
                reports.push(provider_report(
                    "icmp_echo",
                    DiscoveryMethod::Icmp,
                    ProviderStatus::Ok,
                    icmp_started,
                    now_ms(),
                    sweep.replies.len(),
                    None,
                ));
            }
            Err(error) => {
                let message = error.to_string();
                let kind = match &error {
                    icmp::IcmpError::PermissionDenied(_) => ProviderErrorKind::PermissionDenied,
                    icmp::IcmpError::Unavailable(_) => ProviderErrorKind::Unavailable,
                };
                reports.push(provider_report(
                    "icmp_echo",
                    DiscoveryMethod::Icmp,
                    ProviderStatus::Failed,
                    icmp_started,
                    now_ms(),
                    0,
                    Some(ProviderErrorInfo { kind, message }),
                ));
            }
        }
    } else {
        reports.push(provider_report(
            "icmp_echo",
            DiscoveryMethod::Icmp,
            ProviderStatus::Skipped,
            icmp_started,
            now_ms(),
            0,
            None,
        ));
    }

    // mDNS/DNS-SD browse. The window is bounded so a scan cannot hang on a
    // silent multicast segment.
    let mdns_started = now_ms();
    if options.enable_mdns && !cancel.is_cancelled() {
        match mdns::discover(
            mdns::DEFAULT_SERVICE_TYPES,
            Duration::from_millis(options.mdns_window_ms),
            &cancel,
        )
        .await
        {
            Ok(discovery) => {
                let mut observed = 0_usize;
                for service in &discovery.services {
                    for address in &service.addresses {
                        if !candidate_set.contains(address) {
                            continue;
                        }
                        probes.push(HostProbe::mdns(*address, service.clone(), now_ms()));
                        observed += 1;
                    }
                }
                for warning in &discovery.warnings {
                    context.warnings.push(format!("mDNS: {warning}"));
                }
                reports.push(provider_report(
                    "mdns",
                    DiscoveryMethod::Mdns,
                    ProviderStatus::Ok,
                    mdns_started,
                    now_ms(),
                    observed,
                    None,
                ));
            }
            Err(error) => reports.push(provider_report(
                "mdns",
                DiscoveryMethod::Mdns,
                ProviderStatus::Failed,
                mdns_started,
                now_ms(),
                0,
                Some(ProviderErrorInfo {
                    kind: ProviderErrorKind::Unavailable,
                    message: error.to_string(),
                }),
            )),
        }
    } else {
        reports.push(provider_report(
            "mdns",
            DiscoveryMethod::Mdns,
            ProviderStatus::Skipped,
            mdns_started,
            now_ms(),
            0,
            None,
        ));
    }

    // SSDP/UPnP M-SEARCH plus a bounded description fetch.
    let ssdp_started = now_ms();
    if options.enable_ssdp && !cancel.is_cancelled() {
        match ssdp::discover(
            &scope.candidates,
            Duration::from_millis(options.timeout_ms),
            &cancel,
        )
        .await
        {
            Ok(discovery) => {
                let mut observed = 0_usize;
                for device in &discovery.devices {
                    if !candidate_set.contains(&device.source_ip) {
                        continue;
                    }
                    probes.push(HostProbe::upnp(device.source_ip, device.clone(), now_ms()));
                    observed += 1;
                }
                for warning in &discovery.warnings {
                    context.warnings.push(format!("SSDP: {warning}"));
                }
                reports.push(provider_report(
                    "ssdp",
                    DiscoveryMethod::Ssdp,
                    ProviderStatus::Ok,
                    ssdp_started,
                    now_ms(),
                    observed,
                    None,
                ));
            }
            Err(error) => reports.push(provider_report(
                "ssdp",
                DiscoveryMethod::Ssdp,
                ProviderStatus::Failed,
                ssdp_started,
                now_ms(),
                0,
                Some(ProviderErrorInfo {
                    kind: ProviderErrorKind::Unavailable,
                    message: error.to_string(),
                }),
            )),
        }
    } else {
        reports.push(provider_report(
            "ssdp",
            DiscoveryMethod::Ssdp,
            ProviderStatus::Skipped,
            ssdp_started,
            now_ms(),
            0,
            None,
        ));
    }

    // NetBIOS name-table queries. Names are naming claims, not verified
    // properties, but a response is positive evidence that the host exists.
    let netbios_started = now_ms();
    if options.enable_netbios && !cancel.is_cancelled() {
        match netbios::query_hosts(
            &scope.candidates,
            Duration::from_millis(options.timeout_ms),
            options.concurrency,
            &cancel,
        )
        .await
        {
            Ok(discovery) => {
                let mut observed = 0_usize;
                for host in &discovery.hosts {
                    for name in &host.names {
                        probes.push(HostProbe::netbios(host.ip, name.clone(), now_ms()));
                        observed += 1;
                    }
                }
                let mut silent = 0_usize;
                for warning in &discovery.warnings {
                    if warning.ends_with("NetBIOS query timed out") {
                        silent += 1;
                    } else {
                        context.warnings.push(format!("NetBIOS: {warning}"));
                    }
                }
                if silent > 0 {
                    context.warnings.push(format!(
                        "NetBIOS: {silent} host(s) did not answer; silence is not proof of absence"
                    ));
                }
                reports.push(provider_report(
                    "netbios",
                    DiscoveryMethod::Netbios,
                    ProviderStatus::Ok,
                    netbios_started,
                    now_ms(),
                    observed,
                    None,
                ));
            }
            Err(error) => reports.push(provider_report(
                "netbios",
                DiscoveryMethod::Netbios,
                ProviderStatus::Failed,
                netbios_started,
                now_ms(),
                0,
                Some(ProviderErrorInfo {
                    kind: ProviderErrorKind::Unavailable,
                    message: error.to_string(),
                }),
            )),
        }
    } else {
        reports.push(provider_report(
            "netbios",
            DiscoveryMethod::Netbios,
            ProviderStatus::Skipped,
            netbios_started,
            now_ms(),
            0,
            None,
        ));
    }

    // Active probes populate the kernel neighbour table. Re-read it before
    // deciding which hosts still need a TCP reachability probe.
    refresh_neighbors(
        &mut context,
        &scope,
        &candidate_set,
        &mut seen_neighbors,
        &mut probes,
    )
    .await;

    let discovered = discovered_addresses(&probes);

    // TCP connect fallback only for addresses that are still silent.
    let tcp_started = now_ms();
    if options.enable_tcp && !cancel.is_cancelled() {
        let remaining: Vec<IpAddr> = scope
            .candidates
            .iter()
            .copied()
            .filter(|ip| !discovered.contains(ip))
            .collect();
        let results = tcp_probe::probe_hosts(
            &remaining,
            tcp_probe::DEFAULT_TCP_PORTS,
            Duration::from_millis(options.timeout_ms),
            options.concurrency,
            &cancel,
        )
        .await;
        let mut observed = 0_usize;
        for result in results {
            if !result.outcome.is_presence() {
                continue;
            }
            observed += 1;
            probes.push(HostProbe::tcp(
                result.ip,
                result.port,
                result.outcome,
                result.rtt_ms,
                now_ms(),
            ));
        }
        reports.push(provider_report(
            "tcp_connect",
            DiscoveryMethod::Tcp,
            ProviderStatus::Ok,
            tcp_started,
            now_ms(),
            observed,
            None,
        ));
    } else {
        reports.push(provider_report(
            "tcp_connect",
            DiscoveryMethod::Tcp,
            ProviderStatus::Skipped,
            tcp_started,
            now_ms(),
            0,
            None,
        ));
    }

    refresh_neighbors(
        &mut context,
        &scope,
        &candidate_set,
        &mut seen_neighbors,
        &mut probes,
    )
    .await;

    let discovered = discovered_addresses(&probes);

    // Reverse DNS only for hosts that actually answered. A missing answer is
    // not evidence about the host.
    let dns_started = now_ms();
    if options.enable_dns && !cancel.is_cancelled() && !discovered.is_empty() {
        let addresses: Vec<IpAddr> = discovered.iter().copied().collect();
        match reverse_dns::lookup(
            &addresses,
            Duration::from_millis(options.dns_timeout_ms),
            options.concurrency,
            &cancel,
        )
        .await
        {
            Ok(answers) => {
                for answer in &answers {
                    probes.push(HostProbe::reverse_dns(
                        answer.ip,
                        answer.name.clone(),
                        now_ms(),
                    ));
                }
                reports.push(provider_report(
                    "reverse_dns",
                    DiscoveryMethod::ReverseDns,
                    ProviderStatus::Ok,
                    dns_started,
                    now_ms(),
                    answers.len(),
                    None,
                ));
            }
            Err(error) => {
                reports.push(provider_report(
                    "reverse_dns",
                    DiscoveryMethod::ReverseDns,
                    ProviderStatus::Failed,
                    dns_started,
                    now_ms(),
                    0,
                    Some(ProviderErrorInfo {
                        kind: ProviderErrorKind::Unavailable,
                        message: error.to_string(),
                    }),
                ));
            }
        }
    } else {
        reports.push(provider_report(
            "reverse_dns",
            DiscoveryMethod::ReverseDns,
            ProviderStatus::Skipped,
            dns_started,
            now_ms(),
            0,
            None,
        ));
    }

    // Safe service banners only for hosts that already answered. Probing every
    // candidate would turn a discovery scan into an unrequested port scan.
    let service_started = now_ms();
    if options.enable_services && !cancel.is_cancelled() {
        let addresses: Vec<IpAddr> = discovered.iter().copied().collect();
        if addresses.is_empty() {
            reports.push(provider_report(
                "service_banner",
                DiscoveryMethod::ServiceProbe,
                ProviderStatus::Ok,
                service_started,
                now_ms(),
                0,
                None,
            ));
        } else {
            let discovery = service_probe::probe_hosts(
                &addresses,
                service_probe::DEFAULT_SERVICE_PORTS,
                Duration::from_millis(options.timeout_ms),
                options.concurrency,
                &cancel,
            )
            .await;
            let mut observed = 0_usize;
            for host in &discovery.hosts {
                for service in &host.services {
                    probes.push(HostProbe::service(host.ip, service.clone(), now_ms()));
                    observed += 1;
                }
            }
            for warning in &discovery.warnings {
                context.warnings.push(format!("service probe: {warning}"));
            }
            reports.push(provider_report(
                "service_banner",
                DiscoveryMethod::ServiceProbe,
                ProviderStatus::Ok,
                service_started,
                now_ms(),
                observed,
                None,
            ));
        }
    } else {
        reports.push(provider_report(
            "service_banner",
            DiscoveryMethod::ServiceProbe,
            ProviderStatus::Skipped,
            service_started,
            now_ms(),
            0,
            None,
        ));
    }

    let hosts = aggregate_probes(&probes, &context);
    let existing = store
        .load_existing_devices(started_at_ms, options.mac_window_ms)
        .context("loading stored devices for identity resolution")?;
    let resolved = identity::resolve(&hosts, &existing, started_at_ms, options.mac_window_ms);

    let oui_entries = store.oui_entries().context("loading OUI prefixes")?;
    let oui_version = store
        .oui_source()
        .context("reading OUI source metadata")?
        .and_then(|source| source.version)
        .unwrap_or_else(|| "unknown".to_string());
    let providers = ProviderAvailability {
        oui: !oui_entries.is_empty(),
        mdns: provider_available(&reports, DiscoveryMethod::Mdns),
        ssdp: provider_available(&reports, DiscoveryMethod::Ssdp),
        netbios: provider_available(&reports, DiscoveryMethod::Netbios),
        service_banner: provider_available(&reports, DiscoveryMethod::ServiceProbe),
    };
    let mut identification = identify::identify(
        session_id,
        &resolved.devices,
        &oui_entries,
        &oui_version,
        &providers,
        started_at_ms,
    );

    for (device_id, probe) in &resolved.reuse_probes {
        identification.observations.push(ObservationRecord {
            id: new_id(),
            session_id: Some(session_id),
            subject_type: SubjectType::Device,
            subject_id: device_id.to_string(),
            kind: probe.kind,
            property: None,
            value: probe.value.clone(),
            source: probe.source,
            method: probe.method.clone(),
            observed_at_ms: probe.observed_at_ms,
            expires_at_ms: probe.expires_at_ms,
            details: probe.details.clone(),
        });
    }

    let status = if cancel.is_cancelled() {
        SessionStatus::Cancelled
    } else if reports
        .iter()
        .any(|report| report.status == ProviderStatus::Failed)
    {
        SessionStatus::Partial
    } else {
        SessionStatus::Completed
    };

    let services = build_services(&probes, &resolved.devices);

    let finished_at_ms = now_ms();
    let scan = ScanResult {
        session_id,
        started_at_ms,
        finished_at_ms,
        status,
        scope: ScanScope {
            interface: scope.interface.clone(),
            target: Some(scope.target.display()),
            candidate_count: scope.candidates.len(),
            discovered_count: hosts.len(),
        },
        config: ScanConfig {
            timeout_ms: options.timeout_ms,
            dns_timeout_ms: options.dns_timeout_ms,
            mdns_window_ms: options.mdns_window_ms,
            concurrency: options.concurrency,
            max_hosts: options.max_hosts,
            service_ports: service_probe::DEFAULT_SERVICE_PORTS.to_vec(),
            methods: options.methods(),
        },
        context,
        hosts,
        devices: resolved.devices,
        services,
        observations: identification.observations,
        evidence: identification.evidence,
        inferences: identification.inferences,
        identity_links: resolved.links,
        provider_reports: reports,
    };

    store.save_scan(&scan).context("persisting scan session")?;
    Ok(scan)
}

struct ResolvedScope {
    interface: Option<String>,
    target: ScopeTarget,
    candidates: Vec<IpAddr>,
}

enum ScopeTarget {
    Host(IpAddr),
    V4(Ipv4Net),
}

impl ScopeTarget {
    fn display(&self) -> String {
        match self {
            Self::Host(ip) => ip.to_string(),
            Self::V4(net) => net.to_string(),
        }
    }
}

fn resolve_scope(context: &NetworkContext, options: &ScanOptions) -> Result<ResolvedScope> {
    let requested_interface = match &options.interface {
        Some(name) => {
            let interface = context
                .interface_by_name(name)
                .with_context(|| format!("interface {name} was not found"))?;
            Some(interface.name.clone())
        }
        None => None,
    };

    let target = match &options.target {
        Some(value) => parse_target(value)?,
        None => {
            let interface = choose_interface(context, requested_interface.as_deref())?;
            let address = interface.ipv4_addresses().next().with_context(|| {
                format!(
                    "interface {} has no IPv4 address to sweep; pass --target explicitly",
                    interface.name
                )
            })?;
            let net = Ipv4Net::new(
                match address.address {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => unreachable!("filtered to IPv4"),
                },
                address.prefix_len,
            )
            .with_context(|| format!("invalid prefix on {}", interface.name))?;
            ScopeTarget::V4(net)
        }
    };

    let interface = requested_interface.or_else(|| match &target {
        ScopeTarget::Host(ip) => context
            .interface_for_ip(*ip)
            .map(|interface| interface.name.clone()),
        ScopeTarget::V4(net) => context
            .interface_for_ip(net.addr().into())
            .map(|interface| interface.name.clone()),
    });

    let candidates = match &target {
        ScopeTarget::Host(ip) => vec![*ip],
        ScopeTarget::V4(net) => enumerate_ipv4_hosts(*net, &context.local_ips(), options.max_hosts)
            .map_err(anyhow::Error::from)?
            .into_iter()
            .map(IpAddr::V4)
            .collect(),
    };

    Ok(ResolvedScope {
        interface,
        target,
        candidates,
    })
}

fn choose_interface<'a>(
    context: &'a NetworkContext,
    requested: Option<&str>,
) -> Result<&'a crate::domain::InterfaceInfo> {
    if let Some(name) = requested {
        return context
            .interface_by_name(name)
            .with_context(|| format!("interface {name} was not found"));
    }
    if let Some(default) = context.default_interface.as_deref()
        && let Some(interface) = context.interface_by_name(default)
        && interface.ipv4_addresses().next().is_some()
    {
        return Ok(interface);
    }
    context
        .interfaces
        .iter()
        .find(|interface| {
            interface.is_up && !interface.is_loopback && interface.ipv4_addresses().next().is_some()
        })
        .context("no active IPv4 interface was found; pass --interface or --target")
}

fn parse_target(value: &str) -> Result<ScopeTarget> {
    if value.contains('/') {
        let net: IpNet = value
            .parse()
            .with_context(|| format!("invalid target prefix {value:?}"))?;
        match net {
            IpNet::V4(net) => Ok(ScopeTarget::V4(net)),
            IpNet::V6(net) if net.prefix_len() == 128 => {
                Ok(ScopeTarget::Host(IpAddr::V6(net.addr())))
            }
            IpNet::V6(_) => {
                bail!("IPv6 sweeps are not supported; supply a single IPv6 address instead")
            }
        }
    } else {
        let ip: IpAddr = value
            .parse()
            .with_context(|| format!("invalid target address {value:?}"))?;
        Ok(ScopeTarget::Host(ip))
    }
}

fn collect_neighbor_probes(
    context: &NetworkContext,
    scope: &ResolvedScope,
    candidates: &HashSet<IpAddr>,
    seen: &mut HashSet<(IpAddr, Option<crate::domain::MacAddress>, String)>,
) -> Vec<HostProbe> {
    let mut probes = Vec::new();
    for neighbor in &context.neighbors {
        if !candidates.contains(&neighbor.ip) || !neighbor.state.is_present() {
            continue;
        }
        if let (Some(scope_interface), Some(neighbor_interface)) =
            (&scope.interface, &neighbor.interface)
            && scope_interface != neighbor_interface
        {
            continue;
        }
        let key = (
            neighbor.ip,
            neighbor.mac,
            neighbor.state.as_str().to_string(),
        );
        if !seen.insert(key) {
            continue;
        }
        probes.push(HostProbe::neighbor(
            neighbor.ip,
            neighbor.mac,
            Some(neighbor.state.as_str().to_string()),
            neighbor.interface.as_deref(),
            context.captured_at_ms,
        ));
    }
    probes
}

async fn refresh_neighbors(
    context: &mut NetworkContext,
    scope: &ResolvedScope,
    candidates: &HashSet<IpAddr>,
    seen: &mut HashSet<(IpAddr, Option<crate::domain::MacAddress>, String)>,
    probes: &mut Vec<HostProbe>,
) {
    match netlink::snapshot().await {
        Ok(fresh) => {
            context.neighbors = fresh.neighbors;
            context.captured_at_ms = fresh.captured_at_ms;
            probes.extend(collect_neighbor_probes(context, scope, candidates, seen));
        }
        Err(error) => {
            context
                .warnings
                .push(format!("neighbour table refresh failed: {error}"));
        }
    }
}

fn discovered_addresses(probes: &[HostProbe]) -> HashSet<IpAddr> {
    probes
        .iter()
        .filter(|probe| {
            probe.kind == crate::domain::ObservationKind::IcmpReply
                || matches!(
                    probe.kind,
                    crate::domain::ObservationKind::MdnsService
                        | crate::domain::ObservationKind::UpnpDescription
                        | crate::domain::ObservationKind::NetbiosName
                        | crate::domain::ObservationKind::ServiceBanner
                )
                || probe
                    .tcp_outcome
                    .is_some_and(crate::domain::TcpProbeOutcome::is_presence)
                || probe
                    .neighbor_state
                    .as_deref()
                    .is_some_and(neighbor_state_is_present)
        })
        .map(|probe| probe.ip)
        .collect()
}

fn neighbor_state_is_present(state: &str) -> bool {
    matches!(
        state,
        "reachable" | "stale" | "delay" | "probe" | "permanent" | "noarp"
    )
}

fn aggregate_probes(probes: &[HostProbe], context: &NetworkContext) -> Vec<HostObservation> {
    let mut hosts: BTreeMap<IpAddr, HostObservation> = BTreeMap::new();

    for probe in probes {
        let host = hosts.entry(probe.ip).or_insert_with(|| HostObservation {
            ip: probe.ip,
            interface: context
                .interface_for_ip(probe.ip)
                .map(|interface| interface.name.clone()),
            segment: context.segment_for_ip(probe.ip),
            mac: None,
            neighbor_state: None,
            icmp_rtt_ms: None,
            tcp: Vec::new(),
            hostname: None,
            first_seen_ms: probe.observed_at_ms,
            last_seen_ms: probe.observed_at_ms,
            sources: Vec::new(),
            probes: Vec::new(),
        });

        host.first_seen_ms = host.first_seen_ms.min(probe.observed_at_ms);
        host.last_seen_ms = host.last_seen_ms.max(probe.observed_at_ms);

        if host.interface.is_none() {
            host.interface = probe
                .value
                .get("interface")
                .and_then(|value| value.as_str())
                .map(ToString::to_string);
        }
        if probe.mac.is_some() {
            host.mac = probe.mac;
        }
        if probe.neighbor_state.is_some() {
            host.neighbor_state = probe.neighbor_state.clone();
        }
        if probe.kind == crate::domain::ObservationKind::IcmpReply {
            host.icmp_rtt_ms = probe.rtt_ms;
        }
        if let (Some(port), Some(outcome)) = (probe.tcp_port, probe.tcp_outcome) {
            host.tcp.push(TcpProbe {
                port,
                outcome,
                rtt_ms: probe.rtt_ms,
                observed_at_ms: probe.observed_at_ms,
            });
        }
        if let Some(name) = &probe.hostname {
            host.hostname = Some(HostnameObservation {
                name: name.clone(),
                source: probe.source,
                observed_at_ms: probe.observed_at_ms,
            });
        }
        if !host.sources.contains(&probe.source) {
            host.sources.push(probe.source);
        }
        host.probes.push(probe.clone());
    }

    hosts.into_values().collect()
}

fn build_services(probes: &[HostProbe], devices: &[ResolvedDevice]) -> Vec<ServiceRecord> {
    let mut ip_to_device: HashMap<IpAddr, Uuid> = HashMap::new();
    for device in devices {
        for host in &device.hosts {
            ip_to_device.insert(host.ip, device.id);
        }
    }

    let mut services = Vec::new();
    let mut seen = HashSet::new();
    for probe in probes {
        let Some(device_id) = ip_to_device.get(&probe.ip).copied() else {
            continue;
        };
        let service = match &probe.protocol {
            Some(ProtocolObservation::Service(service)) => ServiceRecord {
                id: new_id(),
                device_id,
                ip: probe.ip,
                port: service.port,
                transport: service.transport,
                protocol: service.protocol.clone(),
                product: service.product.clone(),
                version: service.version.clone(),
                banner: service.banner.clone(),
                source: Source::ServiceBanner,
                observed_at_ms: probe.observed_at_ms,
                details: json!({
                    "source_unit": service.source_unit,
                    "os_hint": service.os_hint,
                }),
            },
            Some(ProtocolObservation::Mdns(service)) => ServiceRecord {
                id: new_id(),
                device_id,
                ip: probe.ip,
                port: service.port,
                transport: Transport::Tcp,
                protocol: Some(service.service_type.clone()),
                product: service
                    .properties
                    .get("model")
                    .or_else(|| service.properties.get("product"))
                    .cloned(),
                version: service.properties.get("version").cloned(),
                banner: None,
                source: Source::Mdns,
                observed_at_ms: probe.observed_at_ms,
                details: json!({
                    "source_unit": service.source_unit,
                    "fullname": service.fullname,
                    "host": service.host,
                    "properties": service.properties,
                }),
            },
            Some(ProtocolObservation::Upnp(device)) => ServiceRecord {
                id: new_id(),
                device_id,
                ip: probe.ip,
                port: upnp_location_port(&device.location),
                transport: Transport::Tcp,
                protocol: Some("upnp".to_string()),
                product: device.model_name.clone(),
                version: None,
                banner: None,
                source: Source::Ssdp,
                observed_at_ms: probe.observed_at_ms,
                details: json!({
                    "source_unit": device.source_unit,
                    "location": device.location,
                    "udn": device.udn,
                    "device_type": device.device_type,
                    "friendly_name": device.friendly_name,
                }),
            },
            Some(ProtocolObservation::Netbios(_)) | None => continue,
        };

        let key = (
            service.device_id,
            service.ip,
            service.port,
            service.transport,
            service.protocol.clone(),
            service.source,
        );
        if seen.insert(key) {
            services.push(service);
        }
    }

    services.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.protocol.cmp(&right.protocol))
    });
    services
}

fn upnp_location_port(location: &str) -> u16 {
    let (rest, default_port) = if let Some(rest) = location.strip_prefix("http://") {
        (rest, 80)
    } else if let Some(rest) = location.strip_prefix("https://") {
        (rest, 443)
    } else {
        (location, 80)
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some((_, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return port;
    }
    default_port
}

fn provider_available(reports: &[ProviderReport], method: DiscoveryMethod) -> bool {
    reports
        .iter()
        .any(|report| report.method == method && report.status == ProviderStatus::Ok)
}

fn provider_report(
    name: &str,
    method: DiscoveryMethod,
    status: ProviderStatus,
    started_at_ms: i64,
    finished_at_ms: i64,
    observations: usize,
    error: Option<ProviderErrorInfo>,
) -> ProviderReport {
    ProviderReport {
        name: name.to_string(),
        method,
        status,
        started_at_ms,
        finished_at_ms,
        observations,
        error,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{ScopeTarget, aggregate_probes, parse_target};
    use crate::domain::{HostProbe, MacAddress, NetworkContext, Source, TcpProbeOutcome};

    fn context() -> NetworkContext {
        NetworkContext {
            interfaces: Vec::new(),
            routes: Vec::new(),
            neighbors: Vec::new(),
            default_interface: None,
            default_gateway: None,
            warnings: Vec::new(),
            captured_at_ms: 1_000,
        }
    }

    #[test]
    fn parses_host_and_prefix_targets() {
        assert!(matches!(
            parse_target("192.168.1.10").unwrap(),
            ScopeTarget::Host(_)
        ));
        assert!(matches!(
            parse_target("192.168.1.0/24").unwrap(),
            ScopeTarget::V4(_)
        ));
        assert!(parse_target("2001:db8::/64").is_err());
        assert!(matches!(
            parse_target("2001:db8::1/128").unwrap(),
            ScopeTarget::Host(_)
        ));
    }

    #[test]
    fn aggregates_icmp_tcp_and_neighbour_facts() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();
        let probes = vec![
            HostProbe::icmp(ip, 1.5, 1_000),
            HostProbe::tcp(ip, 443, TcpProbeOutcome::Open, Some(2.0), 1_001),
            HostProbe::neighbor(ip, Some(mac), Some("reachable".into()), Some("eth0"), 1_002),
            HostProbe::reverse_dns(ip, "host.lan".into(), 1_003),
        ];
        let hosts = aggregate_probes(&probes, &context());
        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!(host.mac, Some(mac));
        assert_eq!(host.icmp_rtt_ms, Some(1.5));
        assert_eq!(host.tcp.len(), 1);
        assert_eq!(host.hostname.as_ref().unwrap().name, "host.lan");
        assert_eq!(host.first_seen_ms, 1_000);
        assert_eq!(host.last_seen_ms, 1_003);
        assert_eq!(host.sources.len(), 4);
        assert_eq!(host.sources[0], Source::IcmpEcho);
    }

    #[test]
    fn tcp_timeout_is_not_presence() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let probe = HostProbe::tcp(ip, 80, TcpProbeOutcome::Timeout, None, 1_000);
        let discovered = super::discovered_addresses(std::slice::from_ref(&probe));
        assert!(discovered.is_empty());
    }

    #[test]
    fn refused_tcp_is_presence() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let probe = HostProbe::tcp(ip, 80, TcpProbeOutcome::Refused, Some(1.0), 1_000);
        let discovered = super::discovered_addresses(std::slice::from_ref(&probe));
        assert!(discovered.contains(&ip));
    }

    fn mdns_service(ip: IpAddr) -> crate::domain::MdnsServiceObservation {
        let mut properties = std::collections::BTreeMap::new();
        properties.insert("model".to_string(), "Laser 9000".to_string());
        crate::domain::MdnsServiceObservation {
            fullname: "Printer._ipp._tcp.local.".to_string(),
            service_type: "_ipp._tcp.local.".to_string(),
            host: "printer.local.".to_string(),
            port: 631,
            addresses: vec![ip],
            properties,
            source_unit: "mdns:Printer._ipp._tcp.local.".to_string(),
        }
    }

    fn upnp_device(ip: IpAddr) -> crate::domain::UpnpObservation {
        crate::domain::UpnpObservation {
            udn: Some("uuid:test".to_string()),
            source_ip: ip,
            location: format!("http://{ip}:49152/desc.xml"),
            device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".to_string()),
            friendly_name: Some("Living Room".to_string()),
            manufacturer: Some("Example Audio".to_string()),
            model_name: Some("SoundOne".to_string()),
            model_number: None,
            model_description: None,
            serial_number: None,
            source_unit: "ssdp:uuid:test:description:test".to_string(),
        }
    }

    fn service_observation(ip: IpAddr) -> crate::domain::ServiceObservation {
        crate::domain::ServiceObservation {
            port: 22,
            transport: crate::domain::Transport::Tcp,
            protocol: Some("ssh".to_string()),
            product: Some("OpenSSH".to_string()),
            version: Some("9.6".to_string()),
            banner: Some("SSH-2.0-OpenSSH_9.6".to_string()),
            os_hint: Some("Ubuntu".to_string()),
            source_unit: format!("service:{ip}:22"),
        }
    }

    fn netbios_name(ip: IpAddr) -> crate::domain::NetbiosObservation {
        crate::domain::NetbiosObservation {
            name: "WORKSTATION".to_string(),
            suffix: 0,
            group: false,
            source_unit: format!("netbios:{ip}:4e41"),
        }
    }

    fn device_for(ip: IpAddr) -> crate::application::model::ResolvedDevice {
        crate::application::model::ResolvedDevice {
            id: crate::domain::ids::new_id(),
            label: None,
            identifiers: Vec::new(),
            hosts: vec![crate::domain::HostObservation {
                ip,
                interface: Some("eth0".into()),
                segment: None,
                mac: None,
                neighbor_state: None,
                icmp_rtt_ms: None,
                tcp: Vec::new(),
                hostname: None,
                first_seen_ms: 1_000,
                last_seen_ms: 1_000,
                sources: Vec::new(),
                probes: Vec::new(),
            }],
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            is_new: true,
        }
    }

    #[test]
    fn protocol_responses_count_as_presence() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let probes = vec![
            HostProbe::mdns(ip, mdns_service(ip), 1_000),
            HostProbe::upnp(ip, upnp_device(ip), 1_001),
            HostProbe::netbios(ip, netbios_name(ip), 1_002),
            HostProbe::service(ip, service_observation(ip), 1_003),
        ];
        let discovered = super::discovered_addresses(&probes);
        assert!(discovered.contains(&ip));
    }

    #[test]
    fn builds_services_from_protocol_probes() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let device = device_for(ip);
        let probes = vec![
            HostProbe::service(ip, service_observation(ip), 1_000),
            HostProbe::mdns(ip, mdns_service(ip), 1_001),
            HostProbe::upnp(ip, upnp_device(ip), 1_002),
        ];
        let services = super::build_services(&probes, std::slice::from_ref(&device));
        assert_eq!(services.len(), 3);

        let ssh = services.iter().find(|service| service.port == 22).unwrap();
        assert_eq!(ssh.device_id, device.id);
        assert_eq!(ssh.protocol.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.source, Source::ServiceBanner);

        let mdns = services
            .iter()
            .find(|service| service.source == Source::Mdns)
            .unwrap();
        assert_eq!(mdns.protocol.as_deref(), Some("_ipp._tcp.local."));
        assert_eq!(mdns.port, 631);
        assert_eq!(mdns.product.as_deref(), Some("Laser 9000"));

        let upnp = services
            .iter()
            .find(|service| service.source == Source::Ssdp)
            .unwrap();
        assert_eq!(upnp.port, 49152);
        assert_eq!(upnp.product.as_deref(), Some("SoundOne"));
    }

    #[test]
    fn deduplicates_identical_service_observations() {
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let device = device_for(ip);
        let probes = vec![
            HostProbe::service(ip, service_observation(ip), 1_000),
            HostProbe::service(ip, service_observation(ip), 1_001),
        ];
        let services = super::build_services(&probes, std::slice::from_ref(&device));
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn parses_upnp_location_ports() {
        assert_eq!(
            super::upnp_location_port("http://192.168.1.10:49152/desc.xml"),
            49152
        );
        assert_eq!(
            super::upnp_location_port("http://192.168.1.10/desc.xml"),
            80
        );
        assert_eq!(
            super::upnp_location_port("https://192.168.1.10:8443/desc.xml"),
            8443
        );
        assert_eq!(
            super::upnp_location_port("https://192.168.1.10/desc.xml"),
            443
        );
    }
}
