# NetAtlas development guide

Status: Phase 5 complete, Phase 6 in progress (route explorer done; export/backup/restore
slice implemented). Validated transactional import with dry-run, scheduled
monitoring/change-detection jobs, the TUI, and cryptographic DNSSEC validation are not
implemented yet.

## 1. Environment baseline

Inspected on 2026-11-11:

| Item | Value |
| --- | --- |
| OS | Arch Linux, kernel 7.2.14 |
| Rust | 1.99.1 (stable) |
| Cargo | 1.99.1 |
| SQLite CLI | 3.54.1 |
| Interface | `wlo1`, `172.20.10.6/28`, gateway `172.20.10.1` (at the last live check) |
| Unprivileged ICMP | allowed (`net.ipv4.ping_group_range = 0 2147483647`) |
| Current process capabilities | no `CAP_NET_RAW`; ordinary user |

The last two rows are why the implementation uses ICMP datagram sockets and the kernel
neighbour table instead of raw sockets. The environment is a development aid, not a
product requirement; the code degrades cleanly when these differ.

## 2. Toolchain and commands

```bash
rustup show
cargo fmt
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run -- --help
```

Useful manual checks:

```bash
cargo run -- interfaces
cargo run -- discover --target 192.168.1.0/24 --timeout-ms 500 --no-dns
cargo run -- discover --target 192.168.1.0/24 --mdns-window-ms 1500 --json
cargo run -- devices --segment 192.168.1.0/24 --stale
cargo run -- map --json
cargo run -- changes --json
cargo run -- history <device-uuid> --json
cargo run -- discover --target 192.168.1.0/24 --no-mdns --no-ssdp --no-netbios --no-services
cargo run -- devices
cargo run -- device <uuid>
cargo run -- oui status
cargo run -- oui lookup 3c:cd:5d:11:22:33
cargo run -- dns query example.com --type A,AAAA --json
cargo run -- dns compare example.com --type A --resolver system --resolver 1.1.1.1
cargo run -- dns history --name example.com --limit 10
cargo run -- route trace example.com
cargo run -- route trace 1.1.1.1 --method icmp --max-hops 20 --probes 2 --timeout-ms 1000
cargo run -- route history --json
cargo run -- route compare example.com --method udp --json
cargo run -- export json --output ./netatlas-export.json
cargo run -- export csv --output ./devices.csv
cargo run -- db integrity
cargo run -- db backup --output ./netatlas-backup.db
cargo run -- db restore --input ./netatlas-backup.db --to ./netatlas-restored.db
```

Live-network checks are opt-in and must never run during ordinary `cargo test`. The
project still does not ship a live test target; add one only when it states its interface and
scope, never scans broadly, and is marked `#[ignore]`.

No test may depend on the user's real Wi-Fi network, a public DNS resolver, or Internet
access. Fixtures and local sockets are the default.

## 3. Dependency policy

Rules:

- Add a dependency only when the standard library or an existing dependency cannot do
  the job cleanly.
- Check maintenance status, license, MSRV, feature flags, and transitive weight.
- Pin versions in `Cargo.toml`; commit `Cargo.lock`.
- Avoid crates with unmaintained core dependencies.
- Isolate each dependency behind an adapter so it can be replaced.

### Implemented dependencies

Versions verified against crates.io on 2026-11-11.

| Crate | Version | Why |
| --- | --- | --- |
| `clap` | 4.6.7 | CLI parsing, help, usage errors |
| `tokio` | 1.54.1 | Async runtime; required by rtnetlink, hickory, surge-ping |
| `tokio-util` | 0.7.20 | `CancellationToken` for scans and DNS queries |
| `tracing` / `tracing-subscriber` | 0.1.44 / 0.3.23 | Structured logging on stderr |
| `thiserror` | 2.0.21 | Typed domain/provider/storage errors |
| `anyhow` | 1.0.104 | Context at application/CLI boundaries |
| `serde` / `serde_json` | 1.0.229 / 1.0.154 | JSON output, evidence details, persistence payloads |
| `toml` | 1.2.1 | Config file |
| `chrono` | 0.4.45 | UTC timestamps and formatting |
| `uuid` | 1.29.2 | UUIDv7 identifiers |
| `ipnet` | 2.12.2 | Prefix/subnet math |
| `rusqlite` | 0.42.0 | SQLite with `bundled` for reproducibility |
| `rtnetlink` | 0.24.0 | Links, addresses, routes, neighbour table |
| `surge-ping` | 0.9.1 | Unprivileged ICMP echo |
| `hickory-resolver` | 0.26.3 | Reverse DNS, system resolver configuration, and DNS protocol types |
| `libc` | 0.2.191 | Linux socket options, `IP_RECVERR`, and error-queue parsing for route probes |
| `socket2` | 0.6.5 | Typed socket creation/configuration for route probes |
| `mdns-sd` | 0.21.7 | Bounded mDNS/DNS-SD browse and service resolution |
| `roxmltree` | 0.21.2 | Bounded UPnP device-description XML parsing |
| `futures-util` | 0.3.31 | Bounded `buffer_unordered` probe scheduling |
| `csv` | 1.4.0 | IEEE OUI registry parsing |
| `sha2` | 0.10.9 | OUI provenance hash |

Dev dependencies: `tempfile` 3.27, `assert_cmd` 2.2, `predicates` 3.1.

### Explicitly not chosen

- `reqwest`/`ureq`: SSDP descriptions use a small bounded plain-HTTP client.
- `pnet`: packet construction is not needed. Add `etherparse` only if a real
  packet-parsing requirement appears.
- `oui` / `mac_oui`: see architecture decision D6. NetAtlas parses the IEEE registry
  itself and stores provenance.
- `macaddr`: the domain has a small tested `MacAddress` type, which avoids an
  unnecessary dependency and keeps local-admin handling explicit.
- `directories`: XDG resolution is a few lines.
- `refinery` or another migration framework: a small ordered SQL runner is sufficient.
- `async-trait`: providers are called directly. A provider trait will be introduced only
  when more providers need uniform scheduling. Route probing uses `socket2` and `libc`
  for unprivileged Linux `IP_RECVERR` hop discovery.

### Deferred dependencies

`ratatui` and `crossterm` are planned for the TUI phase and are not in `Cargo.toml` yet.
`hickory-proto` is used through the `hickory_resolver::proto` re-export rather than as a
direct dependency. TLS inspection would require an explicit TLS dependency and a separate
design review.

## 4. Code organization and standards

```
src/
  main.rs                 binary entry point and tracing setup
  lib.rs                  public crate surface
  config/                 XDG paths, config.toml, defaults, validation
  domain/                 pure types and rules
    ids.rs                UUIDv7 creation
    time.rs               UTC millisecond helpers
    network.rs            MAC, interfaces, segments, host enumeration
    device.rs             devices, identifiers, links, presentation views
    observation.rs        observed facts and normalized host probes
    service.rs            transport and persisted service records
    evidence.rs           evidence records and properties
    inference.rs          aggregation, conflict, unknown reasons
    dns.rs                DNS queries, response codes, measurements, comparison
    route.rs              route probes, hops, runs, aggregation, comparison
    confidence.rs         qualitative confidence rubric
    error.rs              domain errors
  application/
    model.rs              session/scan result types
    discovery.rs          scope resolution, provider scheduling, persistence
    identity.rs           identity resolution v1
    identify.rs           evidence extraction and inference
    route.rs              trace/history/compare/persist orchestration
  infrastructure/
    netlink.rs            links, addresses, routes, neighbour table
    icmp.rs               ICMP echo provider
    tcp_probe.rs          bounded TCP connect fallback
    reverse_dns.rs        PTR lookup adapter
    dns.rs                raw UDP/TCP DNS client with RCODE/flags/TTL capture
    route.rs              unprivileged ICMP/UDP/TCP hop probing via IP_RECVERR
    mdns.rs               bounded mDNS/DNS-SD browse adapter
    ssdp.rs               SSDP M-SEARCH and bounded UPnP description fetch
    netbios.rs            wildcard NBSTAT name queries
    service_probe.rs      bounded HTTP/SSH/FTP/SMTP banner probes
    oui.rs                IEEE CSV parser, embedded snapshot, lookup
    storage/              SQLite store, migrations, repositories
  cli/                    clap definitions, human/JSON output, exit codes
```

Standards:

- Domain code is pure: no Tokio, rusqlite, or sockets.
- Protocol parsing accepts bytes/strings and returns typed values; adapters own sockets.
- Use `Result` and typed errors. No `unwrap()`/`expect()` in production paths without a
  documented invariant.
- Bound every queue, response body, probe set, and concurrency limit.
- Log with `tracing`; include session/device IDs where relevant. Never log secrets.
- No `unsafe`.
- Keep CLI output stable and documented. JSON output has a top-level `schema_version`.
- Do not suppress Clippy warnings without a comment explaining why.

## 5. Testing strategy

### Deterministic by default

| Area | Test approach | Location |
| --- | --- | --- |
| Subnet/host enumeration | Pure unit tests, including /31, /32, oversized prefixes | `src/domain/network.rs` |
| MAC/OUI | Parser tests, longest-prefix match, local-admin detection, malformed input | `src/domain/network.rs`, `src/infrastructure/oui.rs` |
| Identity resolution | Same MAC/new IP, same IP/new MAC, local MAC, IP-only, expiry | `src/application/identity.rs` |
| Evidence/inference | Agreement, conflict, correlated units, expiry, OUI, protocol evidence, unknown reasons | `src/domain/inference.rs`, `src/application/identify.rs` |
| Probe aggregation | ICMP/TCP/neighbour/reverse-DNS facts, protocol responses as presence, timeout is not presence | `src/application/discovery.rs` |
| mDNS | TXT property parsing, service-type category mapping | `src/infrastructure/mdns.rs` |
| SSDP/UPnP | Header parsing, bounded HTTP body, XML fields, malformed XML rejection | `src/infrastructure/ssdp.rs` |
| NetBIOS | NBSTAT query layout, name-table parsing, group bit, compressed names | `src/infrastructure/netbios.rs` |
| Service probes | HTTP/SSH/FTP/SMTP banner parsing, local SSH banner, cancellation | `src/infrastructure/service_probe.rs` |
| TCP probe outcomes | Local listener open/refused, cancellation | `src/infrastructure/tcp_probe.rs` |
| Inventory | Freshness, new/not-observed events, partial caveat, address/MAC/hostname/inference changes, unchanged devices | `src/domain/inventory.rs` |
| Inventory views | Scope matching, history, search/filter, longest-prefix segment grouping, unassigned devices | `src/application/inventory.rs` |
| DNS domain | Record-type/RCODE parsing, DNSSEC states, TTL/case-insensitive comparison, transport-failure handling | `src/domain/dns.rs` |
| DNS transport | Local mock UDP/TCP servers, RCODE/TTL/flags capture, truncation fallback, timeout, cancellation, resolver/name parsing | `src/infrastructure/dns.rs` |
| DNS application | Grouping by record type, comparison summary, history filter defaults | `src/application/dns.rs` |
| Route domain | Probe/method/status parsing, hop aggregation, sample/loss accounting, comparison rules | `src/domain/route.rs` |
| Route transport | Unprivileged loopback ICMP/UDP traces, `IP_RECVERR` layout assumptions, option construction | `src/infrastructure/route.rs` |
| Route application | History filter defaults and run summaries | `src/application/route.rs` |
| SQLite | `:memory:` migrations, OUI import/lookup, scan/service/snapshot/DNS/route round-trip, strong identifiers | `src/infrastructure/storage/mod.rs` |
| CLI | `assert_cmd` with a temp data dir; help, JSON, exit codes, filters, map/changes/history, OUI import/lookup, DNS query/compare/history, route trace/history/compare | `tests/cli.rs` |

### Fixtures

Keep fixtures small and reviewable. Each protocol fixture should record how it was
captured (tool, date, sanitized fields) without unrelated personal data. The OUI tests
use a small inline CSV fixture; the production snapshot lives under `data/oui/`.

## 6. OUI data policy

- Source: IEEE registration authority CSV (MA-L, MA-M, MA-S). Attribution and source
  URL are stored with the import.
- The repository includes a snapshot under `data/oui/` with its version/date and
  SHA-256 recorded in `data/oui/README.md`.
- The binary embeds that snapshot and imports it on first open. `netatlas oui import`
  adds a newer source; lookups use the most recent source.
- Import is validated (prefix length, hex digits, duplicates) and transactional.
- The active source is shown by `netatlas oui status` and stored in `oui_sources`.
- Lookup is longest-prefix match (36, then 28, then 24 bits). Results are labeled as an
  address-block association.
- Locally administered MACs are never attributed. A missing OUI entry is not evidence
  about the device.

## 7. Roadmap and acceptance criteria

Each phase ends with `cargo fmt`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test`, documentation updates, and an honest limitations report.

### Phase 0 — architecture (done)

Deliverables: architecture, data model, identification strategy, roadmap, dependency
decisions.

### Phase 1 — shared core and discovery (done)

Deliverables implemented:

- Cargo crate (library + binary), config/XDG paths, tracing.
- Domain types: IDs, time, interface/segment, device/identifier, observation, evidence,
  inference, confidence, errors.
- Netlink network context: interfaces, addresses, routes, default gateway, neighbour
  table.
- Discovery orchestration with bounded concurrency and cancellation.
- Providers: passive neighbour table, ICMP sweep, bounded TCP connect fallback, reverse
  DNS.
- Identity resolution v1: MAC linking, no IP-only merge, local-MAC separation, address
  reuse links.
- OUI loader/lookup with a versioned embedded snapshot.
- Evidence extraction for manufacturer; category/OS/model explicitly unknown with
  reasons.
- SQLite migration 0001 and repositories; session/observation/evidence persistence.
- CLI: `interfaces`, `discover`, `devices`, `device`, `oui status/import/lookup`,
  `--json`, documented exit codes.
- Deterministic tests for pure logic, migrations, storage round-trip, TCP probes, and
  CLI behavior.

Phase 2 limitations are listed in the README and in `docs/identification.md`.

### Phase 2 — identification (done)

Deliverables implemented:

- mDNS/DNS-SD provider with a bounded browse window and conservative service-type
  category mapping.
- SSDP M-SEARCH plus unicast discovery, bounded plain-HTTP UPnP description fetch, and
  `roxmltree` parsing.
- NetBIOS wildcard NBSTAT queries; names are recorded as identifiers, not verified
  properties.
- Safe TCP service probes for HTTP, SSH, FTP, and SMTP with bounded connects, request
  size, response size, and timeouts.
- Evidence extraction for manufacturer, category, OS family, and model from OUI, UPnP,
  mDNS, and banner OS hints; correlated fields share one source unit.
- Strong-identifier linking by UPnP UDN and mDNS instance, including conflict links
  against MAC matches.
- Provider-aware unknown reasons (`provider_unavailable` vs `no_evidence`).
- Service observations persisted in the existing `services` table and shown by
  `discover` and `device`.
- CLI flags `--no-mdns`, `--no-ssdp`, `--no-netbios`, `--no-services`, and
  `--mdns-window-ms`.
- Deterministic parser, inference, identity, storage, and aggregation tests.

Phase 2 limitations: no TLS inspection, SSH host keys, or certificate fingerprints;
service probes cover a small plain-text port set and only hosts that answered discovery;
mDNS/SSDP/NetBIOS results depend on multicast and firewall conditions; exact OS versions
and specific device models are not invented.

### Phase 3 — LAN inventory and map (done)

Deliverables implemented:

- Migration `0002_inventory` with per-session device snapshots.
- Device history across recorded sessions.
- Logical segment grouping from recorded IP prefixes, with longest-prefix matching.
- Derived `new_device`, `not_observed`, `ip_changed`, `mac_changed`,
  `hostname_changed`, and `inference_changed` events.
- Scope-aware comparison: same interface and target, completed or partial sessions only.
- `not_observed` wording and partial-scan caveats; absence is never reported as offline.
- Search/filter by text, segment, and staleness; overridable stale threshold.
- Stale indicators for devices and segments with an explicit non-offline note.
- CLI commands `map`, `changes`, and `history`, plus `devices` filters.
- Deterministic tests for snapshots, comparison, filtering, grouping, and CLI behavior.

Phase 3 limitations: history begins with the first scan after migration `0002_inventory`;
the map is logical subnet grouping, not physical topology; stale data is not an offline
determination; change events are derived on read rather than stored. Stale `running`
scan sessions are marked `interrupted` on database open so crashed scans do not remain
indefinitely active.

### Phase 4 — DNS analysis (done)

Deliverables implemented:

- Migration `0003_dns` with `dns_measurements`, including transport failures.
- Raw UDP/TCP DNS client over hickory protocol types, with RCODE, flags, TTLs, EDNS,
  AD, and RRSIG capture, bounded timeouts/retries, cancellation, and UDP truncation
  fallback to TCP.
- A/AAAA/CNAME/MX/NS/TXT/SOA queries, custom resolver syntax, and system resolver
  discovery.
- Resolver comparison with RCODE and answer-set agreement, TTL variation, DNSSEC-field
  variation, and explicit transport-failure notes.
- Explicit DNSSEC state: `not_performed` plus DO/AD/RRSIG/EDNS observations. No
  cryptographic validation is claimed.
- CLI commands `dns query`, `dns compare`, and `dns history`, with text/JSON output and
  documented exit codes.
- Deterministic tests using local mock UDP/TCP servers; no live network required.

Phase 4 limitations: no cryptographic DNSSEC validation, DoT/DoH, CNAME-chain walking,
scheduled DNS monitoring, or retention job; only seven record types are modelled; DNS
results are point-in-time and resolver-specific.

### Phase 5 — route explorer (done)

Deliverables implemented:

- Migration `0004_route` with `route_runs` and `route_hops` (including serialized
  per-probe samples).
- Unprivileged ICMP datagram, UDP, and TCP route probing using per-hop TTL and
  `IP_RECVERR` error-queue hop discovery (no raw sockets, no `CAP_NET_RAW`).
- Configurable target, method, port, max hops, probes per hop, timeout, and concurrency,
  with cancellation and bounded execution.
- Per-hop responder address, reverse-DNS hostname hint, reply/timeout/error counts,
  best/average RTT, loss ratio, and preserved sample counts.
- Route history and derived comparison of runs with the same target IP, method, and port.
- CLI commands `route trace`, `route history`, and `route compare`, with text/JSON
  output and documented exit codes.
- Deterministic domain/storage/CLI tests plus loopback transport tests.

Phase 5 limitations: IPv4 only; no raw-socket mode, MPLS/ICMP extension parsing, path MTU
discovery, AS/geo enrichment, or continuous route monitoring. Hop discovery depends on
`IP_RECVERR` and environment ICMP permissions. Non-responsive hops and route variability
are reported as measurements, never as proof of a broken route.

### Phase 6 — monitoring and import/export (in progress)

Implemented in this slice:

- Versioned JSON export (`export json`) of sessions (with snapshots), device summaries/details
  (including evidence, inferences, observations, services when available), DNS measurements,
  and route runs.
- Lossy CSV export (`export csv`) of current device summaries with documented omissions.
- SQLite maintenance commands: `db integrity`, `db backup` (online backup API + integrity
  verification), and `db restore` (validated backup, schema check, destination copy, stale
  WAL/SHM cleanup).
- JSON import with dry-run (`import json --dry-run`) and transactional apply for
  non-conflicting DNS measurements and route runs by stable ID, with conflict reporting
  and no overwrites. Sessions/devices/identity-graph records are reported as unsupported
  in this slice (no silent merges).
- Migration `0005_monitoring` with `monitor_runs` and `network_events`.
- `monitor scan` runs an opt-in discovery check (one-shot or `--interval-seconds` loop),
  persists monitor runs, and records derived network events from scan change comparison.
- `monitor runs` and `monitor events` list persisted monitoring history.
- Stale `running` scan sessions and monitor runs are marked `interrupted` on database open.
- Deterministic application/storage/CLI coverage for export, import, backup/restore, and
  monitoring history/listing flows.

Remaining Phase 6 work:

- Full conflict-aware, transactional import with dry-run for sessions, devices, identifiers,
  evidence, inferences, observations, and services (duplicate detection/conflict reporting,
  no silent merge).
- Scheduled DNS monitoring checks, richer event taxonomy/jobs, and additional
  change-detection automation beyond scan-derived events.

### Phase 7 — TUI

Deliverables: dashboard, map, devices, device details/evidence, DNS, route, monitoring,
history, import/export, settings; background tasks, progress, cancellation, terminal
restoration.

### Phase 8 — hardening

Performance, resource limits, packaging, installation, documentation, security review.

## 8. Definition of done

A feature is done only when:

- Its behavior is implemented, not mocked or TODO-shaped.
- Deterministic tests cover success, failure, partial failure, and malformed input.
- Evidence and provenance are preserved where the feature produces conclusions.
- CLI/TUI and persisted data agree.
- Documentation states what works and what remains limited.
- Formatting, Clippy, and tests were actually run and reported honestly.
