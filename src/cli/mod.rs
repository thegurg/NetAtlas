//! Command-line interface.
//!
//! Presentation only: every command calls the same application services the
//! future TUI will use. No discovery, inference, or SQL lives here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::application::discovery::{self, ScanOptions};
use crate::application::dns::{
    self, DnsCompareReport, DnsHistoryFilter, DnsRunSummary, QueryOptions,
};
use crate::application::inventory::{self, ChangeReport, DeviceFilter, DeviceHistory, SegmentMap};
use crate::application::model::{ScanResult, SessionStatus};
use crate::config::Config;
use crate::domain::time::format_short;
use crate::domain::{
    DeviceDetail, DeviceSummary, DnsFlags, DnsMeasurement, DnsOutcome, DnsQuery, DnsRecordType,
    InferenceRecord, NetworkContext, Property, ResolverEndpoint, Transport,
};
use crate::infrastructure::{dns as dns_io, netlink, storage::Store};

pub const EXIT_OK: i32 = 0;
pub const EXIT_OPERATIONAL: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PARTIAL: i32 = 3;
pub const EXIT_NOT_FOUND: i32 = 4;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "netatlas",
    version,
    about = "Linux-first network discovery, identification, and diagnostics",
    long_about = None
)]
struct Cli {
    /// Override the SQLite database path.
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show interfaces, addresses, routes, and neighbour counts.
    Interfaces,
    /// Discover hosts on a local segment.
    Discover(DiscoverArgs),
    /// List known devices from the database.
    Devices(DevicesArgs),
    /// Show one device with identifiers, evidence, and inferences.
    Device {
        /// Device UUID.
        id: String,
    },
    /// Show a logical segment map derived from recorded IP prefixes.
    Map(MapArgs),
    /// Show changes between a scan and the previous comparable scan.
    Changes(ChangesArgs),
    /// Show one device's per-session inventory history.
    History {
        /// Device UUID.
        id: String,
    },
    /// Inspect or import IEEE OUI registry data.
    Oui {
        #[command(subcommand)]
        command: OuiCommand,
    },
    /// Query DNS, compare resolvers, or inspect DNS measurement history.
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
}

#[derive(Debug, Args)]
struct DiscoverArgs {
    /// Restrict the scan to one interface.
    #[arg(short, long)]
    interface: Option<String>,
    /// Explicit IPv4 prefix or single IP address.
    #[arg(short, long)]
    target: Option<String>,
    /// Per-probe timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
    /// Reverse DNS timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    dns_timeout_ms: Option<u64>,
    /// Maximum concurrent network operations.
    #[arg(short, long)]
    concurrency: Option<usize>,
    /// Maximum number of candidate addresses.
    #[arg(long)]
    max_hosts: Option<usize>,
    /// Disable ICMP echo probing.
    #[arg(long)]
    no_icmp: bool,
    /// Disable TCP connect fallback.
    #[arg(long)]
    no_tcp: bool,
    /// Disable reverse DNS.
    #[arg(long)]
    no_dns: bool,
    /// Disable mDNS/DNS-SD browsing.
    #[arg(long)]
    no_mdns: bool,
    /// Disable SSDP/UPnP discovery.
    #[arg(long)]
    no_ssdp: bool,
    /// Disable NetBIOS name queries.
    #[arg(long)]
    no_netbios: bool,
    /// Disable safe TCP service banner probes.
    #[arg(long)]
    no_services: bool,
    /// mDNS browse window in milliseconds.
    #[arg(long, value_name = "MS")]
    mdns_window_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct DevicesArgs {
    /// Case-insensitive substring search over addresses, names, and inferences.
    #[arg(long, value_name = "TEXT")]
    search: Option<String>,
    /// Restrict to devices whose most recent address is inside this prefix.
    #[arg(long, value_name = "CIDR")]
    segment: Option<String>,
    /// Show only devices older than the freshness threshold.
    #[arg(long)]
    stale: bool,
    /// Override the stale threshold in milliseconds.
    #[arg(long, value_name = "MS")]
    stale_after_ms: Option<i64>,
}

#[derive(Debug, Args)]
struct MapArgs {
    /// Restrict the map to one interface.
    #[arg(short, long)]
    interface: Option<String>,
}

#[derive(Debug, Args)]
struct ChangesArgs {
    /// Compare this session instead of the latest one.
    #[arg(long, value_name = "UUID")]
    session: Option<String>,
}

#[derive(Debug, Subcommand)]
enum OuiCommand {
    /// Show the active OUI source and record count.
    Status,
    /// Import an IEEE registry CSV file.
    Import {
        /// CSV file to import.
        file: PathBuf,
        /// Version label stored with the import.
        #[arg(long)]
        version: Option<String>,
    },
    /// Look up one MAC address.
    Lookup {
        /// MAC address in any common format.
        mac: String,
    },
}

#[derive(Debug, Subcommand)]
enum DnsCommand {
    /// Send one name to one or more resolvers and record the measurements.
    Query(DnsQueryArgs),
    /// Query two or more resolvers and compare their answers.
    Compare(DnsCompareArgs),
    /// List stored DNS measurements.
    History(DnsHistoryArgs),
}

#[derive(Debug, Args)]
struct DnsQueryArgs {
    /// Name to query. A trailing dot is optional.
    name: String,
    #[command(flatten)]
    options: DnsOptionsArgs,
    /// Do not persist the measurements.
    #[arg(long)]
    no_save: bool,
}

#[derive(Debug, Args)]
struct DnsCompareArgs {
    /// Name to query. A trailing dot is optional.
    name: String,
    #[command(flatten)]
    options: DnsOptionsArgs,
    /// Do not persist the measurements.
    #[arg(long)]
    no_save: bool,
}

#[derive(Debug, Args)]
struct DnsOptionsArgs {
    /// Record type to query; repeatable or comma-separated. Defaults to A,AAAA.
    #[arg(long = "type", value_name = "TYPE", value_delimiter = ',')]
    record_types: Vec<String>,
    /// Resolver: `system`, an IP address, `IP:PORT`, or `[IPv6]:PORT`. Repeatable.
    #[arg(long, value_name = "RESOLVER")]
    resolver: Vec<String>,
    /// Send the query over TCP instead of UDP.
    #[arg(long)]
    tcp: bool,
    /// Per-attempt timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
    /// Number of attempts per query.
    #[arg(long, value_name = "N")]
    attempts: Option<u32>,
    /// Maximum concurrent queries.
    #[arg(long)]
    concurrency: Option<usize>,
    /// Do not set the EDNS DNSSEC OK (DO) bit.
    #[arg(long)]
    no_dnssec_ok: bool,
}

#[derive(Debug, Args)]
struct DnsHistoryArgs {
    /// Restrict to one query name.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// Restrict to one record type.
    #[arg(long = "type", value_name = "TYPE")]
    record_type: Option<String>,
    /// Restrict to one resolver label or socket address.
    #[arg(long, value_name = "RESOLVER")]
    resolver: Option<String>,
    /// Maximum number of measurements to show.
    #[arg(long, default_value_t = 50, value_name = "N")]
    limit: usize,
}

/// Run the CLI and return a process exit code.
pub async fn run() -> i32 {
    let cli = Cli::parse();
    match execute(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            EXIT_OPERATIONAL
        }
    }
}

async fn execute(cli: Cli) -> Result<i32> {
    let config = Config::load(cli.db)?;
    let json_output = cli.json;

    match cli.command {
        Command::Interfaces => {
            let context = netlink::snapshot()
                .await
                .context("reading network context through netlink")?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "context": context,
                }))?;
            } else {
                print_interfaces(&context);
            }
            Ok(EXIT_OK)
        }
        Command::Discover(args) => {
            let mut store = Store::open(&config.db_path)?;
            let mut options = ScanOptions::from_config(&config);
            options.interface = args.interface;
            options.target = args.target;
            if let Some(timeout) = args.timeout_ms {
                options.timeout_ms = timeout;
            }
            if let Some(timeout) = args.dns_timeout_ms {
                options.dns_timeout_ms = timeout;
            }
            if let Some(concurrency) = args.concurrency {
                options.concurrency = concurrency;
            }
            if let Some(max_hosts) = args.max_hosts {
                options.max_hosts = max_hosts;
            }
            if let Some(window) = args.mdns_window_ms {
                options.mdns_window_ms = window;
            }
            options.enable_icmp = !args.no_icmp;
            options.enable_tcp = !args.no_tcp;
            options.enable_dns = !args.no_dns;
            options.enable_mdns = !args.no_mdns;
            options.enable_ssdp = !args.no_ssdp;
            options.enable_netbios = !args.no_netbios;
            options.enable_services = !args.no_services;

            if let Err(error) = options.validate() {
                eprintln!("error: {error}");
                return Ok(EXIT_USAGE);
            }

            let cancel = CancellationToken::new();
            install_cancel_handler(&cancel);
            let scan = discovery::run_scan(&mut store, options, cancel).await?;
            let changes = inventory::changes_for_session(&store, Some(scan.session_id))?;

            if json_output {
                let mut value = with_schema(&scan);
                if let Value::Object(map) = &mut value {
                    map.insert("changes".to_string(), serde_json::to_value(&changes)?);
                }
                print_json(&value)?;
            } else {
                print_scan(&scan);
                if let Some(report) = &changes {
                    print_change_summary(report);
                }
            }
            Ok(match scan.status {
                SessionStatus::Partial | SessionStatus::Cancelled => EXIT_PARTIAL,
                SessionStatus::Failed => EXIT_OPERATIONAL,
                _ => EXIT_OK,
            })
        }
        Command::Devices(args) => {
            let store = Store::open(&config.db_path)?;
            let mut filter = DeviceFilter {
                search: args.search,
                ..DeviceFilter::default()
            };
            if let Some(segment) = args.segment {
                match segment.parse::<IpNet>() {
                    Ok(prefix) => filter.segment = Some(prefix),
                    Err(error) => {
                        eprintln!("error: {segment:?} is not a valid CIDR prefix: {error}");
                        return Ok(EXIT_USAGE);
                    }
                }
            }
            if let Some(stale_after_ms) = args.stale_after_ms {
                if stale_after_ms <= 0 {
                    eprintln!("error: --stale-after-ms must be greater than zero");
                    return Ok(EXIT_USAGE);
                }
                filter.stale_after_ms = stale_after_ms;
            }
            filter.stale_only = args.stale;

            let now = crate::domain::time::now_ms();
            let devices = inventory::list_devices(&store, &filter, now)?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "devices": devices,
                    "filter": {
                        "search": filter.search,
                        "segment": filter.segment.map(|prefix| prefix.to_string()),
                        "stale_only": filter.stale_only,
                        "stale_after_ms": filter.stale_after_ms,
                    }
                }))?;
            } else {
                print_devices(&devices, filter.is_active());
            }
            Ok(EXIT_OK)
        }
        Command::Map(args) => {
            let store = Store::open(&config.db_path)?;
            let map = inventory::build_map(
                &store,
                args.interface.as_deref(),
                crate::domain::time::now_ms(),
            )?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "map": map,
                }))?;
            } else {
                print_map(&map);
            }
            Ok(EXIT_OK)
        }
        Command::Changes(args) => {
            let store = Store::open(&config.db_path)?;
            let session_id = match args.session {
                Some(value) => match Uuid::parse_str(&value) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        eprintln!("error: {value:?} is not a valid session UUID");
                        return Ok(EXIT_USAGE);
                    }
                },
                None => None,
            };
            let report = inventory::changes_for_session(&store, session_id)?;
            if session_id.is_some() && report.is_none() {
                eprintln!("session {} was not found", session_id.unwrap_or_default());
                return Ok(EXIT_NOT_FOUND);
            }
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "changes": report,
                    "note": report.is_none().then_some(
                        "No scan sessions have been recorded yet. Run `netatlas discover` first."
                    ),
                }))?;
            } else if let Some(report) = &report {
                print_changes(report);
            } else {
                println!("No scan sessions have been recorded yet. Run `netatlas discover` first.");
            }
            Ok(EXIT_OK)
        }
        Command::History { id } => {
            let Ok(id) = Uuid::parse_str(&id) else {
                eprintln!("error: {id:?} is not a valid device UUID");
                return Ok(EXIT_USAGE);
            };
            let store = Store::open(&config.db_path)?;
            let history = inventory::device_history(&store, id, crate::domain::time::now_ms())?;
            let Some(history) = history else {
                eprintln!("device {id} was not found");
                return Ok(EXIT_NOT_FOUND);
            };
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "history": history,
                }))?;
            } else {
                print_history(&history);
            }
            Ok(EXIT_OK)
        }
        Command::Device { id } => {
            let Ok(id) = Uuid::parse_str(&id) else {
                eprintln!("error: {id:?} is not a valid device UUID");
                return Ok(EXIT_USAGE);
            };
            let store = Store::open(&config.db_path)?;
            let Some(detail) = store.get_device(id)? else {
                eprintln!("device {id} was not found");
                return Ok(EXIT_NOT_FOUND);
            };
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "device": detail,
                }))?;
            } else {
                print_device(&detail);
            }
            Ok(EXIT_OK)
        }
        Command::Oui { command } => run_oui(command, &config, json_output),
        Command::Dns { command } => run_dns(command, &config, json_output).await,
    }
}

fn run_oui(command: OuiCommand, config: &Config, json_output: bool) -> Result<i32> {
    match command {
        OuiCommand::Status => {
            let store = Store::open(&config.db_path)?;
            let source = store.oui_source()?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "source": source,
                }))?;
            } else if let Some(source) = source {
                println!("OUI source: {}", source.name);
                println!(
                    "Version:    {}",
                    source.version.as_deref().unwrap_or("unknown")
                );
                println!("Records:    {}", source.record_count);
                println!("Imported:   {}", format_short(source.imported_at_ms));
                println!("SHA-256:    {}", source.content_sha256);
                if let Some(url) = source.source_url {
                    println!("Source:     {url}");
                }
            } else {
                println!("No OUI source is active.");
            }
            Ok(EXIT_OK)
        }
        OuiCommand::Import { file, version } => {
            let mut store = Store::open(&config.db_path)?;
            let contents = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let report = store.import_oui_csv(&contents, version.as_deref())?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "import": {
                        "source_id": report.source_id,
                        "record_count": report.record_count,
                        "skipped": report.skipped,
                        "version": report.version,
                        "content_sha256": report.content_sha256,
                    }
                }))?;
            } else {
                println!(
                    "Imported {} OUI records ({} skipped).",
                    report.record_count, report.skipped
                );
                println!("Version: {}", report.version);
                println!("SHA-256: {}", report.content_sha256);
            }
            Ok(EXIT_OK)
        }
        OuiCommand::Lookup { mac } => {
            let Ok(mac) = mac.parse::<crate::domain::MacAddress>() else {
                eprintln!("error: {mac:?} is not a valid MAC address");
                return Ok(EXIT_USAGE);
            };
            let store = Store::open(&config.db_path)?;
            let found = store.lookup_oui(mac)?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "mac": mac.to_string(),
                    "match": found,
                }))?;
            } else if let Some(found) = found {
                println!(
                    "{mac}  {}  ({}/{})",
                    found.organization, found.prefix_hex, found.prefix_bits
                );
            } else {
                println!(
                    "{mac}  no OUI association (locally administered addresses are never attributed)"
                );
            }
            Ok(EXIT_OK)
        }
    }
}

async fn run_dns(command: DnsCommand, config: &Config, json_output: bool) -> Result<i32> {
    match command {
        DnsCommand::Query(args) => {
            let options = match prepare_dns_options(&args.name, &args.options, config, false) {
                Ok(options) => options,
                Err(message) => {
                    eprintln!("error: {message}");
                    return Ok(EXIT_USAGE);
                }
            };
            run_dns_queries(options, !args.no_save, config, json_output, false).await
        }
        DnsCommand::Compare(args) => {
            let options = match prepare_dns_options(&args.name, &args.options, config, true) {
                Ok(options) => options,
                Err(message) => {
                    eprintln!("error: {message}");
                    return Ok(EXIT_USAGE);
                }
            };
            run_dns_queries(options, !args.no_save, config, json_output, true).await
        }
        DnsCommand::History(args) => run_dns_history(args, config, json_output),
    }
}

fn prepare_dns_options(
    name: &str,
    args: &DnsOptionsArgs,
    config: &Config,
    require_two_resolvers: bool,
) -> std::result::Result<QueryOptions, String> {
    let normalized = dns_io::normalize_name(name).map_err(|error| error.to_string())?;
    let record_types = parse_dns_record_types(&args.record_types)?;
    let queries = record_types
        .into_iter()
        .map(|record_type| DnsQuery {
            name: normalized.clone(),
            record_type,
        })
        .collect();
    let resolvers = resolve_dns_resolvers(&args.resolver)?;
    if require_two_resolvers && resolvers.len() < 2 {
        return Err(
            "compare requires at least two distinct resolvers; pass --resolver more than once"
                .to_string(),
        );
    }

    let timeout_ms = args.timeout_ms.unwrap_or(config.dns_timeout_ms);
    if timeout_ms == 0 {
        return Err("--timeout-ms must be greater than zero".to_string());
    }
    let attempts = args.attempts.unwrap_or(1);
    if attempts == 0 {
        return Err("--attempts must be at least 1".to_string());
    }
    let concurrency = args.concurrency.unwrap_or(config.concurrency);
    if concurrency == 0 {
        return Err("--concurrency must be greater than zero".to_string());
    }

    Ok(QueryOptions {
        queries,
        resolvers,
        transport: if args.tcp {
            Transport::Tcp
        } else {
            Transport::Udp
        },
        timeout: Duration::from_millis(timeout_ms),
        attempts,
        concurrency,
        dnssec_ok: !args.no_dnssec_ok,
    })
}

fn parse_dns_record_types(values: &[String]) -> std::result::Result<Vec<DnsRecordType>, String> {
    if values.is_empty() {
        return Ok(vec![DnsRecordType::A, DnsRecordType::Aaaa]);
    }
    let mut record_types = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let record_type = part
                .parse::<DnsRecordType>()
                .map_err(|error| error.to_string())?;
            if !record_types.contains(&record_type) {
                record_types.push(record_type);
            }
        }
    }
    if record_types.is_empty() {
        return Err("no DNS record type was provided".to_string());
    }
    Ok(record_types)
}

fn resolve_dns_resolvers(values: &[String]) -> std::result::Result<Vec<ResolverEndpoint>, String> {
    if values.is_empty() {
        return dns_io::system_resolvers().map_err(|error| error.to_string());
    }
    let mut resolvers: Vec<ResolverEndpoint> = Vec::new();
    for value in values {
        let resolver = dns_io::parse_resolver(value).map_err(|error| error.to_string())?;
        if !resolvers
            .iter()
            .any(|existing| existing.address == resolver.address)
        {
            resolvers.push(resolver);
        }
    }
    if resolvers.is_empty() {
        return Err("no resolver was provided".to_string());
    }
    Ok(resolvers)
}

async fn run_dns_queries(
    options: QueryOptions,
    save: bool,
    config: &Config,
    json_output: bool,
    compare: bool,
) -> Result<i32> {
    let cancel = CancellationToken::new();
    install_cancel_handler(&cancel);
    let measurements = dns::execute(&options, &cancel).await;
    let summary = dns::summarize(&measurements);
    let exit_code = dns_exit_code(&measurements);

    if save {
        let mut store = Store::open(&config.db_path)?;
        dns::persist(&mut store, &measurements)?;
    }

    if json_output {
        if compare {
            let report = dns::compare(&measurements);
            print_json(&json!({
                "schema_version": SCHEMA_VERSION,
                "comparison": report,
                "summary": summary,
                "saved": save,
            }))?;
        } else {
            print_json(&json!({
                "schema_version": SCHEMA_VERSION,
                "measurements": measurements,
                "summary": summary,
                "saved": save,
            }))?;
        }
    } else if compare {
        print_dns_comparison(&dns::compare(&measurements));
        print_dns_summary(&summary, save);
    } else {
        for measurement in &measurements {
            print_dns_measurement(measurement);
        }
        print_dns_summary(&summary, save);
    }

    Ok(exit_code)
}

fn run_dns_history(args: DnsHistoryArgs, config: &Config, json_output: bool) -> Result<i32> {
    let mut filter = DnsHistoryFilter {
        limit: args.limit,
        ..DnsHistoryFilter::default()
    };
    if let Some(name) = args.name {
        match dns_io::normalize_name(&name) {
            Ok(name) => filter.name = Some(name),
            Err(error) => {
                eprintln!("error: {error}");
                return Ok(EXIT_USAGE);
            }
        }
    }
    if let Some(record_type) = args.record_type {
        match record_type.parse::<DnsRecordType>() {
            Ok(record_type) => filter.record_type = Some(record_type),
            Err(error) => {
                eprintln!("error: {error}");
                return Ok(EXIT_USAGE);
            }
        }
    }
    filter.resolver = args.resolver;
    if filter.limit == 0 {
        eprintln!("error: --limit must be greater than zero");
        return Ok(EXIT_USAGE);
    }

    let store = Store::open(&config.db_path)?;
    let measurements = dns::history(&store, &filter)?;
    if json_output {
        print_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "history": measurements,
            "filter": {
                "name": filter.name,
                "record_type": filter.record_type.map(|value| value.as_str()),
                "resolver": filter.resolver,
                "limit": filter.limit,
            }
        }))?;
    } else if measurements.is_empty() {
        println!("No DNS measurements match this filter.");
    } else {
        print_dns_history(&measurements);
    }
    Ok(EXIT_OK)
}

fn dns_exit_code(measurements: &[DnsMeasurement]) -> i32 {
    if measurements.is_empty() {
        return EXIT_OPERATIONAL;
    }
    let failed = measurements
        .iter()
        .filter(|measurement| measurement.is_transport_failure())
        .count();
    let cancelled = measurements
        .iter()
        .filter(|measurement| measurement.outcome == DnsOutcome::Cancelled)
        .count();
    if failed + cancelled == measurements.len() {
        EXIT_OPERATIONAL
    } else if failed > 0 || cancelled > 0 {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

fn print_dns_measurement(measurement: &DnsMeasurement) {
    println!(
        "{} {}",
        measurement.query.name, measurement.query.record_type
    );
    println!(
        "  resolver {}  transport {}  {} ms  attempts {}",
        measurement.resolver,
        measurement.transport.as_str().to_ascii_uppercase(),
        measurement.elapsed_ms,
        measurement.attempts
    );
    match (&measurement.outcome, &measurement.response) {
        (DnsOutcome::Response, Some(response)) => {
            println!(
                "  outcome response  RCODE {}  flags {}",
                response.rcode,
                dns_flag_labels(&response.flags)
            );
            if response.answers.is_empty() {
                println!(
                    "  answers none (a negative answer or a referral is still a DNS response)"
                );
            } else {
                for record in &response.answers {
                    println!(
                        "  answer {} {} {} {}",
                        record.name,
                        record.record_type,
                        record.ttl,
                        record.value.display_value()
                    );
                }
            }
            if !response.authority.is_empty() {
                println!("  authority:");
                for record in &response.authority {
                    println!(
                        "    {} {} {} {}",
                        record.name,
                        record.record_type,
                        record.ttl,
                        record.value.display_value()
                    );
                }
            }
            println!(
                "  counts answer {} authority {} additional {}",
                response.answer_count, response.authority_count, response.additional_count
            );
        }
        (outcome, _) => {
            println!(
                "  outcome {}  {}",
                outcome.as_str(),
                measurement.error.as_deref().unwrap_or("no detail")
            );
        }
    }
    let dnssec = &measurement.dnssec;
    println!(
        "  DNSSEC validation {}  DO {}  AD {}  RRSIG {}  response EDNS {}",
        dnssec.validation.as_str(),
        yes_no(dnssec.do_bit),
        yes_no(dnssec.ad_flag),
        yes_no(dnssec.rrsig_present),
        yes_no(dnssec.response_edns)
    );
}

fn print_dns_comparison(report: &DnsCompareReport) {
    if report.comparisons.is_empty() {
        println!("No DNS comparison was produced.");
        return;
    }
    println!("DNS comparison for {}", report.name);
    println!("Resolvers:");
    for resolver in &report.resolvers {
        println!("  {resolver}");
    }
    for comparison in &report.comparisons {
        println!();
        println!("{} {}", comparison.query.name, comparison.query.record_type);
        println!(
            "  responded {}  failed {}  cancelled {}  comparable {}",
            comparison.responded,
            comparison.failed,
            comparison.cancelled,
            yes_no(comparison.comparable)
        );
        println!(
            "  RCODE consistent {}  answers consistent {}  TTL varied {}  DNSSEC varied {}",
            yes_no(comparison.rcode_consistent),
            yes_no(comparison.answers_consistent),
            yes_no(comparison.ttl_varied),
            yes_no(comparison.dnssec_varied)
        );
        for measurement in &comparison.measurements {
            match (&measurement.outcome, &measurement.response) {
                (DnsOutcome::Response, Some(response)) => {
                    let answers = response
                        .answers
                        .iter()
                        .map(|record| {
                            format!(
                                "{} {} {}",
                                record.record_type,
                                record.ttl,
                                record.value.display_value()
                            )
                        })
                        .collect::<Vec<_>>();
                    println!(
                        "  {}  {}  {} ms  {}",
                        measurement.resolver.label,
                        response.rcode,
                        measurement.elapsed_ms,
                        if answers.is_empty() {
                            "no answers".to_string()
                        } else {
                            answers.join("; ")
                        }
                    );
                }
                (outcome, _) => {
                    println!(
                        "  {}  {}  {} ms  {}",
                        measurement.resolver.label,
                        outcome.as_str(),
                        measurement.elapsed_ms,
                        measurement.error.as_deref().unwrap_or("no detail")
                    );
                }
            }
        }
        for note in &comparison.notes {
            println!("  note: {note}");
        }
    }
    println!();
    println!("Overall consistent: {}", yes_no(report.consistent));
    println!("Note: {}", report.note);
}

fn print_dns_summary(summary: &DnsRunSummary, saved: bool) {
    println!();
    println!(
        "Summary: {} queries, {} responses, {} transport failures, {} cancelled.{}",
        summary.total,
        summary.responded,
        summary.failed,
        summary.cancelled,
        if saved {
            " Measurements saved."
        } else {
            " Measurements not saved."
        }
    );
    println!("Note: {}", summary.note);
    println!(
        "DNSSEC: no cryptographic validation was performed; the AD flag and RRSIG presence are observations, not a validation result."
    );
}

fn print_dns_history(measurements: &[DnsMeasurement]) {
    let mut rows = Vec::new();
    for measurement in measurements {
        rows.push(vec![
            format_short(measurement.queried_at_ms),
            measurement.query.name.clone(),
            measurement.query.record_type.as_str().to_string(),
            measurement.resolver.label.clone(),
            measurement.resolver.address.to_string(),
            measurement.transport.as_str().to_string(),
            measurement.outcome.as_str().to_string(),
            measurement
                .rcode()
                .map(|code| code.name().to_string())
                .unwrap_or_else(|| "-".to_string()),
            measurement.elapsed_ms.to_string(),
        ]);
    }
    print_table(
        &[
            "TIME",
            "NAME",
            "TYPE",
            "RESOLVER",
            "ADDRESS",
            "TRANSPORT",
            "OUTCOME",
            "RCODE",
            "MS",
        ],
        rows,
    );
}

fn dns_flag_labels(flags: &DnsFlags) -> String {
    let mut labels = Vec::new();
    if flags.authoritative {
        labels.push("aa");
    }
    if flags.truncated {
        labels.push("tc");
    }
    if flags.recursion_desired {
        labels.push("rd");
    }
    if flags.recursion_available {
        labels.push("ra");
    }
    if flags.authentic_data {
        labels.push("ad");
    }
    if flags.checking_disabled {
        labels.push("cd");
    }
    if labels.is_empty() {
        "none".to_string()
    } else {
        labels.join(" ")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn install_cancel_handler(token: &CancellationToken) {
    let token = token.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            token.cancel();
        }
    });
}

fn with_schema<T: Serialize>(value: T) -> Value {
    match serde_json::to_value(value) {
        Ok(Value::Object(mut map)) => {
            map.insert("schema_version".to_string(), json!(SCHEMA_VERSION));
            Value::Object(map)
        }
        Ok(other) => json!({ "schema_version": SCHEMA_VERSION, "result": other }),
        Err(error) => {
            json!({ "schema_version": SCHEMA_VERSION, "serialization_error": error.to_string() })
        }
    }
}

fn print_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_interfaces(context: &NetworkContext) {
    let mut rows = Vec::new();
    for interface in &context.interfaces {
        let state = if interface.is_up { "up" } else { "down" };
        rows.push(vec![
            interface.name.clone(),
            interface.index.to_string(),
            state.to_string(),
            interface
                .mac
                .map(|mac| mac.to_string())
                .unwrap_or_else(|| "-".to_string()),
            interface
                .mtu
                .map(|mtu| mtu.to_string())
                .unwrap_or_else(|| "-".to_string()),
            interface
                .addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.prefix_len))
                .collect::<Vec<_>>()
                .join(", "),
        ]);
    }
    print_table(
        &["INTERFACE", "INDEX", "STATE", "MAC", "MTU", "ADDRESSES"],
        rows,
    );

    if let Some(gateway) = context.default_gateway {
        println!(
            "\nDefault gateway: {gateway}{}",
            context
                .default_interface
                .as_deref()
                .map(|name| format!(" via {name}"))
                .unwrap_or_default()
        );
    } else {
        println!("\nDefault gateway: none observed");
    }

    if !context.routes.is_empty() {
        println!("\nRoutes:");
        let mut rows = Vec::new();
        for route in &context.routes {
            rows.push(vec![
                route
                    .destination
                    .map(|destination| destination.to_string())
                    .unwrap_or_else(|| "default".to_string()),
                route
                    .gateway
                    .map(|gateway| gateway.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                route.interface.clone().unwrap_or_else(|| "-".to_string()),
                route
                    .metric
                    .map(|metric| metric.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ]);
        }
        print_table(&["DESTINATION", "GATEWAY", "INTERFACE", "METRIC"], rows);
    }

    println!("\nNeighbour entries: {}", context.neighbors.len());
    for warning in &context.warnings {
        println!("warning: {warning}");
    }
}

fn print_scan(scan: &ScanResult) {
    println!(
        "Scan {} {}",
        short_id(scan.session_id),
        scan.status.as_str()
    );
    println!(
        "Started {}  finished {}  ({} ms)",
        format_short(scan.started_at_ms),
        format_short(scan.finished_at_ms),
        scan.finished_at_ms.saturating_sub(scan.started_at_ms)
    );
    println!(
        "Scope: interface {}  target {}  {} candidates  {} hosts",
        scan.scope.interface.as_deref().unwrap_or("-"),
        scan.scope.target.as_deref().unwrap_or("-"),
        scan.scope.candidate_count,
        scan.scope.discovered_count
    );

    println!("\nProviders:");
    for report in &scan.provider_reports {
        let detail = match &report.error {
            Some(error) => format!("{}: {}", error.kind_str(), error.message),
            None => format!("{} observation(s)", report.observations),
        };
        println!(
            "  {:<16} {:<8} {}",
            report.name,
            report.status.as_str(),
            detail
        );
    }

    if !scan.devices.is_empty() {
        println!();
        print_scan_devices(scan);
    } else {
        println!("\nNo hosts were observed. This is not proof that the segment is empty.");
    }

    if !scan.services.is_empty() {
        println!("\nServices:");
        print_services(&scan.services);
    }

    for warning in &scan.context.warnings {
        println!("warning: {warning}");
    }
}

fn print_scan_devices(scan: &ScanResult) {
    let inferences = inference_map(scan);
    let mut rows = Vec::new();
    for device in &scan.devices {
        let ips = device
            .hosts
            .iter()
            .map(|host| host.ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let macs = device
            .identifiers
            .iter()
            .filter(|identifier| identifier.kind == crate::domain::IdentifierKind::Mac)
            .map(|identifier| identifier.value.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let hostname = device
            .hosts
            .iter()
            .find_map(|host| host.hostname.as_ref().map(|name| name.name.clone()))
            .unwrap_or_else(|| "-".to_string());
        let manufacturer = inference_value(&inferences, device.id, Property::Manufacturer);
        let category = inference_value(&inferences, device.id, Property::Category);
        let model = inference_value(&inferences, device.id, Property::Model);
        rows.push(vec![
            short_id(device.id),
            ips,
            if macs.is_empty() {
                "-".to_string()
            } else {
                macs
            },
            manufacturer,
            category,
            model,
            hostname,
            if device.is_new { "new" } else { "known" }.to_string(),
        ]);
    }
    print_table(
        &[
            "ID",
            "ADDRESSES",
            "MACS",
            "MANUFACTURER",
            "CATEGORY",
            "MODEL",
            "HOSTNAME",
            "STATUS",
        ],
        rows,
    );
}

fn print_services(services: &[crate::domain::ServiceRecord]) {
    let mut rows = Vec::new();
    for service in services {
        rows.push(vec![
            short_id(service.device_id),
            service.ip.to_string(),
            service.port.to_string(),
            service.transport.as_str().to_string(),
            service.protocol.clone().unwrap_or_else(|| "-".to_string()),
            service.product.clone().unwrap_or_else(|| "-".to_string()),
            service.version.clone().unwrap_or_else(|| "-".to_string()),
            service.source.as_str().to_string(),
        ]);
    }
    print_table(
        &[
            "DEVICE",
            "ADDRESS",
            "PORT",
            "TRANSPORT",
            "PROTOCOL",
            "PRODUCT",
            "VERSION",
            "SOURCE",
        ],
        rows,
    );
}

fn inference_map(scan: &ScanResult) -> HashMap<(Uuid, Property), &InferenceRecord> {
    scan.inferences
        .iter()
        .map(|inference| ((inference.device_id, inference.property), inference))
        .collect()
}

fn inference_value(
    inferences: &HashMap<(Uuid, Property), &InferenceRecord>,
    device_id: Uuid,
    property: Property,
) -> String {
    inferences
        .get(&(device_id, property))
        .map(|inference| inference.view().display_value())
        .unwrap_or_else(|| "unknown".to_string())
}

fn print_devices(devices: &[DeviceSummary], filtered: bool) {
    if devices.is_empty() {
        if filtered {
            println!("No devices matched the filter.");
        } else {
            println!("No devices have been recorded yet. Run `netatlas discover` first.");
        }
        return;
    }
    let mut rows = Vec::new();
    for device in devices {
        rows.push(vec![
            short_id(device.id),
            join_or_dash(&device.ips),
            join_or_dash(&device.macs),
            device.manufacturer.display_value(),
            join_or_dash(&device.hostnames),
            format_short(device.last_seen_ms),
            format_freshness(device.freshness),
        ]);
    }
    print_table(
        &[
            "ID",
            "ADDRESSES",
            "MACS",
            "MANUFACTURER",
            "HOSTNAMES",
            "LAST SEEN",
            "FRESHNESS",
        ],
        rows,
    );
    if devices.iter().any(|device| device.freshness.is_stale()) {
        println!(
            "\nStale records have not been observed recently. Staleness is not proof that a device is offline."
        );
    }
}

fn print_map(map: &SegmentMap) {
    if map.segments.is_empty() && map.unassigned.is_empty() {
        println!("No inventory has been recorded yet. Run `netatlas discover` first.");
        return;
    }

    for segment in &map.segments {
        println!(
            "Segment {}  interface {}  gateway {}  last seen {}  ({})",
            segment.prefix,
            segment.interface,
            segment
                .gateway
                .map(|gateway| gateway.to_string())
                .unwrap_or_else(|| "-".to_string()),
            format_short(segment.last_seen_ms),
            format_freshness(segment.freshness)
        );
        if segment.devices.is_empty() {
            println!("  No devices are currently associated with this prefix.\n");
            continue;
        }
        let rows = segment
            .devices
            .iter()
            .map(device_map_row)
            .collect::<Vec<_>>();
        print_table(
            &[
                "ID",
                "ADDRESS",
                "MAC",
                "MANUFACTURER",
                "CATEGORY",
                "HOSTNAMES",
                "LAST SEEN",
                "FRESHNESS",
            ],
            rows,
        );
        println!();
    }

    if !map.unassigned.is_empty() {
        println!("Unassigned devices (most recent address does not match a recorded segment):");
        let rows = map
            .unassigned
            .iter()
            .map(device_map_row)
            .collect::<Vec<_>>();
        print_table(
            &[
                "ID",
                "ADDRESS",
                "MAC",
                "MANUFACTURER",
                "CATEGORY",
                "HOSTNAMES",
                "LAST SEEN",
                "FRESHNESS",
            ],
            rows,
        );
        println!();
    }

    println!("{}", map.note);
}

fn device_map_row(device: &DeviceSummary) -> Vec<String> {
    vec![
        short_id(device.id),
        device
            .ips
            .first()
            .cloned()
            .unwrap_or_else(|| "-".to_string()),
        device
            .macs
            .first()
            .cloned()
            .unwrap_or_else(|| "-".to_string()),
        device.manufacturer.display_value(),
        device.category.display_value(),
        join_or_dash(&device.hostnames),
        format_short(device.last_seen_ms),
        format_freshness(device.freshness),
    ]
}

fn print_changes(report: &ChangeReport) {
    println!(
        "Scan {} {}",
        short_id(report.current.id),
        report.current.status.as_str()
    );
    println!(
        "Scope: interface {}  target {}",
        report.current.scope.interface.as_deref().unwrap_or("-"),
        report.current.scope.target.as_deref().unwrap_or("-")
    );
    if let Some(previous) = &report.previous {
        println!(
            "Compared with scan {} ({} device(s))",
            short_id(previous.id),
            previous.device_count
        );
    }
    if let Some(note) = &report.note {
        println!("{note}");
    }
    if !report.comparable {
        return;
    }
    if report.events.is_empty() {
        println!("\nNo changes were detected between the comparable scans.");
        return;
    }

    let rows = report
        .events
        .iter()
        .map(|event| {
            vec![
                short_id(event.device_id),
                event.kind.as_str().to_string(),
                event.summary.clone(),
                format_short(event.observed_at_ms),
            ]
        })
        .collect::<Vec<_>>();
    println!();
    print_table(&["DEVICE", "CHANGE", "SUMMARY", "OBSERVED"], rows);
    println!(
        "\n'not_observed' means the device was absent from this scan, not that it is offline."
    );
}

fn print_change_summary(report: &ChangeReport) {
    println!("\nChanges since the previous comparable scan:");
    if let Some(note) = &report.note {
        println!("  {note}");
    }
    if !report.comparable {
        return;
    }
    if report.events.is_empty() {
        println!("  No changes detected.");
        return;
    }
    for event in &report.events {
        println!(
            "  {:<16} {}  {}",
            event.kind.as_str(),
            short_id(event.device_id),
            event.summary
        );
    }
}

fn print_history(history: &DeviceHistory) {
    let summary = &history.summary;
    println!(
        "Device {}  {}",
        summary.id,
        summary.label.as_deref().unwrap_or("(no label)")
    );
    println!(
        "First seen {}  last seen {}  ({})",
        format_short(summary.first_seen_ms),
        format_short(summary.last_seen_ms),
        format_freshness(summary.freshness)
    );
    println!("Addresses: {}", join_or_dash(&summary.ips));
    println!("MACs:      {}", join_or_dash(&summary.macs));
    println!("Hostnames: {}", join_or_dash(&summary.hostnames));

    if !history.sessions.is_empty() {
        println!("\nRecorded sessions:");
        let rows = history
            .sessions
            .iter()
            .map(|entry| {
                vec![
                    short_id(entry.session.id),
                    format_short(entry.session.started_at_ms),
                    entry.session.status.as_str().to_string(),
                    join_or_dash(&entry.snapshot.ips),
                    join_or_dash(&entry.snapshot.macs),
                    join_or_dash(&entry.snapshot.hostnames),
                    snapshot_inference(&entry.snapshot, Property::Manufacturer),
                    snapshot_inference(&entry.snapshot, Property::Category),
                    snapshot_inference(&entry.snapshot, Property::Os),
                    snapshot_inference(&entry.snapshot, Property::Model),
                ]
            })
            .collect::<Vec<_>>();
        print_table(
            &[
                "SESSION",
                "STARTED",
                "STATUS",
                "ADDRESSES",
                "MACS",
                "HOSTNAMES",
                "MANUFACTURER",
                "CATEGORY",
                "OS",
                "MODEL",
            ],
            rows,
        );
    }

    if !history.changes.is_empty() {
        println!("\nChanges between recorded sessions:");
        let rows = history
            .changes
            .iter()
            .map(|event| {
                vec![
                    short_id(event.session_id),
                    event.kind.as_str().to_string(),
                    event.summary.clone(),
                ]
            })
            .collect::<Vec<_>>();
        print_table(&["SESSION", "CHANGE", "SUMMARY"], rows);
    }

    if let Some(note) = &history.note {
        println!("\n{note}");
    }
}

fn snapshot_inference(
    snapshot: &crate::domain::DeviceSessionSnapshot,
    property: Property,
) -> String {
    snapshot
        .inferences
        .iter()
        .find(|inference| inference.property == property)
        .map(
            |inference| match (inference.status, &inference.value, inference.unknown_reason) {
                (crate::domain::InferenceStatus::Conflicted, _, _) => "conflicted".to_string(),
                (_, Some(Value::String(value)), _) => value.clone(),
                (_, Some(value), _) => value.to_string(),
                (_, None, Some(reason)) => format!("unknown ({})", reason.as_str()),
                (_, None, None) => "unknown".to_string(),
            },
        )
        .unwrap_or_else(|| "unknown".to_string())
}

fn format_freshness(freshness: crate::domain::Freshness) -> String {
    format!(
        "{} ({})",
        freshness.state.as_str(),
        format_age(freshness.age_ms)
    )
}

fn format_age(ms: i64) -> String {
    let seconds = ms.max(0) / 1_000;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn print_device(detail: &DeviceDetail) {
    let summary = &detail.summary;
    println!(
        "Device {}  {}",
        summary.id,
        summary.label.as_deref().unwrap_or("(no label)")
    );
    println!(
        "First seen {}  last seen {}  ({})",
        format_short(summary.first_seen_ms),
        format_short(summary.last_seen_ms),
        format_freshness(summary.freshness)
    );
    println!("Addresses: {}", join_or_dash(&summary.ips));
    println!("MACs:      {}", join_or_dash(&summary.macs));
    println!("Hostnames: {}", join_or_dash(&summary.hostnames));

    println!("\nInferences:");
    for (name, view) in [
        ("manufacturer", &summary.manufacturer),
        ("category", &summary.category),
        ("os", &summary.os),
        ("model", &summary.model),
    ] {
        println!(
            "  {name:<14} {:<28} {:<8} {}",
            view.display_value(),
            view.confidence.as_str(),
            view.status.as_str()
        );
        println!("    {}", view.rationale);
    }

    if !detail.identifiers.is_empty() {
        println!("\nIdentifiers:");
        let mut rows = Vec::new();
        for identifier in &detail.identifiers {
            rows.push(vec![
                identifier.kind.as_str().to_string(),
                identifier.value.clone(),
                identifier.source.as_str().to_string(),
                identifier.confidence.as_str().to_string(),
                format_short(identifier.last_seen_ms),
            ]);
        }
        print_table(
            &["KIND", "VALUE", "SOURCE", "CONFIDENCE", "LAST SEEN"],
            rows,
        );
    }

    if !detail.evidence.is_empty() {
        println!("\nEvidence:");
        let mut rows = Vec::new();
        for evidence in &detail.evidence {
            rows.push(vec![
                evidence.property.as_str().to_string(),
                display_json(&evidence.candidate),
                evidence.source.as_str().to_string(),
                evidence.source_unit.clone(),
                evidence.confidence.as_str().to_string(),
                evidence.rationale.clone(),
            ]);
        }
        print_table(
            &[
                "PROPERTY",
                "CANDIDATE",
                "SOURCE",
                "SOURCE UNIT",
                "CONFIDENCE",
                "RATIONALE",
            ],
            rows,
        );
    }

    if !detail.services.is_empty() {
        println!("\nServices:");
        print_services(&detail.services);
    }

    if !detail.links.is_empty() {
        println!("\nIdentity links:");
        for link in &detail.links {
            println!(
                "  {} -> {}  {}  {}  {}",
                short_id(link.from_device_id),
                short_id(link.to_device_id),
                link.basis,
                link.status.as_str(),
                link.rationale
            );
        }
    }

    if !detail.observations.is_empty() {
        println!("\nRecent observations:");
        let mut rows = Vec::new();
        for observation in detail.observations.iter().take(20) {
            rows.push(vec![
                observation.kind.as_str().to_string(),
                observation.source.as_str().to_string(),
                observation.method.clone(),
                display_json(&observation.value),
                format_short(observation.observed_at_ms),
            ]);
        }
        print_table(&["KIND", "SOURCE", "METHOD", "VALUE", "OBSERVED"], rows);
    }
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            if index < widths.len() {
                widths[index] = widths[index].max(cell.chars().count());
            }
        }
    }

    let header_line = headers
        .iter()
        .enumerate()
        .map(|(index, header)| format!("{header:<width$}", width = widths[index]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{header_line}");
    println!(
        "{}",
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in rows {
        let line = row
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                format!(
                    "{cell:<width$}",
                    width = widths.get(index).copied().unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", line.trim_end());
    }
}

fn short_id(id: Uuid) -> String {
    let full = id.to_string();
    full.chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn display_json(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

trait ProviderErrorKindLabel {
    fn kind_str(&self) -> &'static str;
}

impl ProviderErrorKindLabel for crate::application::model::ProviderErrorInfo {
    fn kind_str(&self) -> &'static str {
        match self.kind {
            crate::application::model::ProviderErrorKind::PermissionDenied => "permission_denied",
            crate::application::model::ProviderErrorKind::Unavailable => "unavailable",
            crate::application::model::ProviderErrorKind::Timeout => "timeout",
            crate::application::model::ProviderErrorKind::Io => "io",
            crate::application::model::ProviderErrorKind::Parse => "parse",
            crate::application::model::ProviderErrorKind::Cancelled => "cancelled",
        }
    }
}
