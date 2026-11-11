# NetAtlas development guide

Status: Phase 1 (shared core and discovery) implemented. Phase 2 identification
providers are not implemented yet.

## 1. Environment baseline

Inspected on 2026-11-11:

| Item | Value |
| --- | --- |
| OS | Arch Linux, kernel 7.2.14 |
| Rust | 1.99.1 (stable) |
| Cargo | 1.99.1 |
| SQLite CLI | 3.54.1 |
| Interface | `wlo1`, `192.168.1.4/24`, gateway `192.168.1.1` |
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
cargo run -- devices
cargo run -- oui status
cargo run -- oui lookup 3c:cd:5d:11:22:33
```

Live-network checks are opt-in and must never run during ordinary `cargo test`. Phase 1
does not ship a live test target yet; add one only when it states its interface and
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
| `tokio-util` | 0.7.20 | `CancellationToken` for scans |
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
| `hickory-resolver` | 0.26.3 | Reverse DNS through the system resolver |
| `futures-util` | 0.3.31 | Bounded `buffer_unordered` probe scheduling |
| `csv` | 1.4.0 | IEEE OUI registry parsing |
| `sha2` | 0.10.9 | OUI provenance hash |

Dev dependencies: `tempfile` 3.27, `assert_cmd` 2.2, `predicates` 3.1.

### Explicitly not chosen

- `pnet`: packet construction is not needed. Add `etherparse` only if a real
  packet-parsing requirement appears.
- `reqwest`/`ureq`: SSDP descriptions will use a small bounded plain-HTTP client.
- `oui` / `mac_oui`: see architecture decision D6. NetAtlas parses the IEEE registry
  itself and stores provenance.
- `macaddr`: the domain has a small tested `MacAddress` type, which avoids an
  unnecessary dependency and keeps local-admin handling explicit.
- `directories`: XDG resolution is a few lines.
- `refinery` or another migration framework: a small ordered SQL runner is sufficient.
- `async-trait` and `socket2`: Phase 1 calls adapters directly and uses Tokio's TCP
  timeouts. A provider trait will be introduced only when more providers need uniform
  scheduling.

### Deferred dependencies

`mdns-sd`, `hickory-proto`, `ratatui`, and `crossterm` are planned for later phases and
are not in `Cargo.toml` yet.

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
    evidence.rs           evidence records and properties
    inference.rs          aggregation, conflict, unknown reasons
    confidence.rs         qualitative confidence rubric
    error.rs              domain errors
  application/
    model.rs              session/scan result types
    discovery.rs          scope resolution, provider scheduling, persistence
    identity.rs           identity resolution v1
    identify.rs           evidence extraction and inference
  infrastructure/
    netlink.rs            links, addresses, routes, neighbour table
    icmp.rs               ICMP echo provider
    tcp_probe.rs          bounded TCP connect fallback
    reverse_dns.rs        PTR lookup adapter
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
| Evidence/inference | Agreement, conflict, correlated units, expiry, OUI, unknown reasons | `src/domain/inference.rs`, `src/application/identify.rs` |
| Probe aggregation | ICMP/TCP/neighbour/reverse-DNS facts, timeout is not presence | `src/application/discovery.rs` |
| TCP probe outcomes | Local listener open/refused, cancellation | `src/infrastructure/tcp_probe.rs` |
| SQLite | `:memory:` migrations, OUI import/lookup, scan round-trip | `src/infrastructure/storage/mod.rs` |
| CLI | `assert_cmd` with a temp data dir; help, JSON, exit codes, OUI import/lookup | `tests/cli.rs` |

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

Phase 1 limitations are listed in the README and in `docs/identification.md`.

### Phase 2 — identification (next)

Deliverables: mDNS, SSDP/UPnP descriptions, NetBIOS, safe TCP service probes; full
evidence fusion, conflict handling, independence units; device category/OS/model rules;
profile explanations; fixture suite from `docs/identification.md` section 9.

Acceptance: the identification acceptance scenarios pass; multiple independent sources
can contribute; conflicts are preserved; model/OS are not invented.

### Phase 3 — LAN inventory and map

Deliverables: device history, segments, new/disappeared/changed events, search/filter,
segment-based map representation, stale data indicators.

### Phase 4 — DNS analysis

Deliverables: A/AAAA/CNAME/MX/NS/TXT/SOA queries, custom resolvers, timing, RCODE, TTL,
resolver comparison, explicit DNSSEC validation state, DNS history.

### Phase 5 — route explorer

Deliverables: ICMP/UDP/TCP traceroute, configurable hops/timeouts/probes, RTT and loss
with sample counts, reverse DNS, route comparison.

### Phase 6 — monitoring and import/export

Deliverables: opt-in scheduled scans/DNS checks, change detection, JSON/CSV export,
SQLite backup/restore, validated transactional import with dry-run.

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
