//! Command-line interface.
//!
//! Presentation only: every command calls the same application services the
//! future TUI will use. No discovery, inference, or SQL lives here.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::application::discovery::{self, ScanOptions};
use crate::application::model::{ScanResult, SessionStatus};
use crate::config::Config;
use crate::domain::time::format_short;
use crate::domain::{DeviceDetail, DeviceSummary, InferenceRecord, NetworkContext, Property};
use crate::infrastructure::{netlink, storage::Store};

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
    Devices,
    /// Show one device with identifiers, evidence, and inferences.
    Device {
        /// Device UUID.
        id: String,
    },
    /// Inspect or import IEEE OUI registry data.
    Oui {
        #[command(subcommand)]
        command: OuiCommand,
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
            options.enable_icmp = !args.no_icmp;
            options.enable_tcp = !args.no_tcp;
            options.enable_dns = !args.no_dns;

            if let Err(error) = options.validate() {
                eprintln!("error: {error}");
                return Ok(EXIT_USAGE);
            }

            let cancel = CancellationToken::new();
            install_cancel_handler(&cancel);
            let scan = discovery::run_scan(&mut store, options, cancel).await?;

            if json_output {
                print_json(&with_schema(&scan))?;
            } else {
                print_scan(&scan);
            }
            Ok(match scan.status {
                SessionStatus::Partial | SessionStatus::Cancelled => EXIT_PARTIAL,
                SessionStatus::Failed => EXIT_OPERATIONAL,
                _ => EXIT_OK,
            })
        }
        Command::Devices => {
            let store = Store::open(&config.db_path)?;
            let devices = store.list_devices(None)?;
            if json_output {
                print_json(&json!({
                    "schema_version": SCHEMA_VERSION,
                    "devices": devices,
                }))?;
            } else {
                print_devices(&devices);
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
        rows.push(vec![
            short_id(device.id),
            ips,
            if macs.is_empty() {
                "-".to_string()
            } else {
                macs
            },
            manufacturer,
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
            "HOSTNAME",
            "STATUS",
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

fn print_devices(devices: &[DeviceSummary]) {
    if devices.is_empty() {
        println!("No devices have been recorded yet. Run `netatlas discover` first.");
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
        ],
        rows,
    );
}

fn print_device(detail: &DeviceDetail) {
    let summary = &detail.summary;
    println!(
        "Device {}  {}",
        summary.id,
        summary.label.as_deref().unwrap_or("(no label)")
    );
    println!(
        "First seen {}  last seen {}",
        format_short(summary.first_seen_ms),
        format_short(summary.last_seen_ms)
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
