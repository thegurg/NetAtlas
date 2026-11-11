# NetAtlas development guide

Status: Phase 0. The repository contains documentation only. Commands below are the
intended workflow once the crate exists.

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

The last two rows are the reason the design uses ICMP datagram sockets and the kernel
neighbour table instead of raw sockets. The environment is a development aid, not a
product requirement; the code must degrade cleanly when these differ.

## 2. Toolchain and commands

```bash
rustup show                 # confirm stable toolchain
cargo fmt
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run -- --help
```

Live-network checks are opt-in and must never run during ordinary `cargo test`:

```bash
NETATLAS_LIVE_TESTS=1 cargo test --test live_discovery -- --ignored --nocapture
```

No test may depend on the user's real Wi-Fi network, a public DNS resolver, or Internet
access. Fixtures and fakes are the default.

## 3. Dependency policy

Rules:

- Add a dependency only when the standard library or an existing dependency cannot do
  the job cleanly.
- Check maintenance status, license, MSRV, feature flags, and transitive weight.
- Pin versions in `Cargo.toml`; commit `Cargo.lock`.
- Avoid crates with unmaintained core dependencies (for example, the `oui` crate pulls
  in the deprecated `failure` crate).
- Isolate each dependency behind an adapter so it can be replaced.

### Selected dependencies

Versions verified against crates.io on 2026-11-11.

| Crate | Version | Phase | Why |
| --- | --- | --- | --- |
| `clap` | 4.6.7 | 1 | CLI parsing with derive, help, exit codes |
| `tokio` | 1.54.1 | 1 | Async runtime; required by rtnetlink, hickory, surge-ping |
| `tokio-util` | 0.7.20 | 1 | `CancellationToken` for scans |
| `tracing` | 0.1.44 | 1 | Structured logging |
| `tracing-subscriber` | 0.3.23 | 1 | Log formatting and env filter |
| `thiserror` | 2.0.21 | 1 | Typed domain/provider errors |
| `anyhow` | 1.0.104 | 1 | Context at application/CLI boundary |
| `serde` / `serde_json` | 1.0.229 / 1.0.154 | 1 | JSON output, evidence details, exports |
| `toml` | 1.2.1 | 1 | Config file |
| `chrono` | 0.4.45 | 1 | UTC timestamps and formatting |
| `uuid` | 1.29.2 | 1 | UUIDv7 identifiers |
| `ipnet` | 2.12.2 | 1 | Prefix/subnet math |
| `macaddr` | 1.0.1 | 1 | MAC parsing, formatting, local-admin bit |
| `rusqlite` | 0.42.0 | 1 | SQLite, `bundled` for reproducibility |
| `rtnetlink` | 0.24.0 | 1 | Links, addresses, routes, neighbour table |
| `surge-ping` | 0.9.1 | 1 | Unprivileged ICMP echo (SOCK_DGRAM on Linux) |
| `socket2` | 0.6.5 | 1 | TCP connect timeouts, multicast/SSDP sockets |
| `hickory-resolver` | 0.26.3 | 1/4 | Reverse DNS now; DNS diagnostics and DNSSEC later |
| `hickory-proto` | 0.26.3 | 4 | Explicit DNSSEC validation state |
| `async-trait` | 0.1.92 | 1 | Dyn-compatible async provider port |
| `mdns-sd` | 0.21.7 | 2 | mDNS browse/resolve daemon |
| `ratatui` / `crossterm` | 0.30.2 / 0.29.0 | 7 | TUI |
| `csv` | 1.4.0 | 6 | CSV export/import |

Dev dependencies: `tempfile` 3.27, `assert_cmd` 2.2, `predicates` 3.1.

Explicitly not chosen:

- `pnet`: packet construction is not needed for the initial providers. Add
  `etherparse` only if a real packet-parsing requirement appears.
- `reqwest`/`ureq`: SSDP descriptions are plain HTTP with a small bounded client.
- `oui` / `mac_oui`: see architecture decision D6. NetAtlas loads the IEEE registry
  itself.
- `directories`: XDG resolution is a few lines.
- `refinery` or another migration framework: a small ordered SQL runner is sufficient.

## 4. Code organization and standards

- Domain code is pure: no `tokio`, `rusqlite`, `ratatui`, or `std::net` sockets in
  `domain`.
- Protocol parsing functions accept bytes and return typed values; they do not open
  sockets. Socket adapters call them.
- One responsibility per module. Do not create empty modules for future phases.
- Use `Result` and typed errors. No `unwrap()`/`expect()` in production paths without a
  documented invariant.
- Bound every queue, channel, response body, and probe set.
- Prefer owned, explicit data at boundaries; avoid `Arc<Mutex<_>>` as a default.
- Log with `tracing`; include session/device IDs where relevant. Never log secrets or
  full packet payloads at info level.
- No `unsafe` unless required for a Linux interface; isolate, document invariants, and
  test the boundary.
- Keep CLI output stable and documented. JSON output is versioned by a top-level
  `schema_version` field.
- Do not suppress Clippy warnings without a comment explaining why.

## 5. Testing strategy

### Deterministic by default

| Area | Test approach |
| --- | --- |
| Subnet/host enumeration | Pure unit tests, including /31, /32, IPv6, huge prefixes rejected |
| MAC/OUI | Parser tests, longest-prefix match, local-admin detection, malformed input |
| Neighbour snapshot normalization | Fixture structs -> domain observations |
| ICMP/TCP probe aggregation | Fake probe results, timeouts, partial loss |
| mDNS/SSDP/NetBIOS parsing | Captured byte/JSON fixtures, malformed and truncated inputs |
| Identity resolution | Same MAC/new IP, same IP/new MAC, randomized MAC, ambiguous match |
| Evidence aggregation | Agreement, conflict, correlated source units, expiry, caps |
| SQLite | `:memory:` migrations, constraints, transaction rollback, session finalization |
| CLI | `assert_cmd` against a temp data dir and fixture database |
| DNS | Fixture responses: record types, RCODE, TTL, DNSSEC states |
| Route | Synthetic hop samples: timeouts, filtered hops, loss windows |
| Import/export | Round-trip, duplicate, version mismatch, dry-run |

### Live tests

Only with `NETATLAS_LIVE_TESTS=1` and `#[ignore]`. They must state the interface and
scope, never scan broadly, and must not be required for CI.

### Fixtures

Keep fixtures small and reviewable under `tests/fixtures/`. Each protocol fixture
records how it was captured (tool, date, sanitized fields) without including unrelated
personal data.

## 6. OUI data policy

- Source: IEEE registration authority CSV (MA-L, MA-M, MA-S). Attribution and source
  URL are stored with the import.
- The repository may include a snapshot under `data/oui/` with its version/date and
  SHA-256 recorded. The binary can also load a user-updated file from the XDG data
  directory.
- Import is validated (prefix length, hex digits, duplicates) and transactional.
- The active database version is shown by `netatlas oui status` and stored in
  `oui_sources`.
- Lookup is longest-prefix match. Results are labeled as an address-block association.
- Never treat a missing OUI entry as evidence about the device.

## 7. Roadmap and acceptance criteria

Each phase ends with `cargo fmt`, `cargo clippy --all-targets --all-features -D
warnings`, `cargo test`, documentation updates, and a report of limitations.

### Phase 0 — architecture (current)

Deliverables: this document set, dependency decisions, data model, identification
strategy, roadmap.

Acceptance: architecture, shared data model, and identification strategy are reviewed
and approved before code starts.

### Phase 1 — shared core and discovery

Deliverables:

- Cargo crate (library + binary), config/XDG paths, tracing.
- Domain types: IDs, time, interface/segment, device/identifier, observation, evidence,
  inference, confidence, service, errors.
- Netlink network context: interfaces, addresses, routes, default gateway, neighbour
  table.
- Discovery session orchestrator with bounded concurrency and cancellation.
- Providers: passive neighbour table, ICMP sweep, bounded TCP connect fallback,
  reverse DNS; basic mDNS hostname resolution if it fits the slice.
- Identity resolution v1 (no merge on IP; MAC reuse handling).
- OUI loader/lookup with a versioned snapshot.
- Evidence extraction for manufacturer; category/OS/model explicitly unknown with
  reasons.
- SQLite migration 0001 and repositories; session/observation persistence.
- CLI: `interfaces`, `discover`, `devices`, `device`, `oui status`, `--json`,
  documented exit codes.
- Tests for all pure logic, migrations, and CLI behavior.

Acceptance:

- On an authorized LAN, `discover` returns hosts with source, timestamp, identifiers,
  and manufacturer association where OUI applies.
- Unknown fields show a reason; no invented category/OS/model.
- A provider failure leaves other results intact and marks the session partial.
- Deterministic `cargo test` passes without network access.
- A non-response is reported as no response, not "offline".

### Phase 2 — identification

Deliverables: mDNS, SSDP/UPnP descriptions, NetBIOS, safe TCP service probes; full
evidence fusion, conflict handling, independence units; device category/OS/model rules;
profile explanations; fixture suite from `docs/identification.md` section 9.

Acceptance: the identification acceptance scenarios pass; multiple independent sources
can contribute; conflicts are preserved; model/OS are not invented.

### Phase 3 — LAN inventory and map

Deliverables: device history, segments, new/disappeared/changed events, search/filter,
segment-based map representation, stale data indicators.

Acceptance: IP/MAC changes are tracked without false merges; the map never claims
unobserved physical topology.

### Phase 4 — DNS analysis

Deliverables: A/AAAA/CNAME/MX/NS/TXT/SOA queries, custom resolvers, timing, RCODE, TTL,
resolver comparison, explicit DNSSEC validation state, DNS history.

Acceptance: DNSSEC record presence is never reported as validation success; resolver
differences and failures are visible.

### Phase 5 — route explorer

Deliverables: ICMP/UDP/TCP traceroute, configurable hops/timeouts/probes, RTT and loss
with sample counts, reverse DNS, route comparison.

Acceptance: non-responsive hops are not declared broken; measurement windows and sample
counts are visible.

### Phase 6 — monitoring and import/export

Deliverables: opt-in scheduled scans/DNS checks, change detection, JSON/CSV export,
SQLite backup/restore, validated transactional import with dry-run.

Acceptance: imports are transactional and report conflicts; CSV limitations are
documented; monitoring has limits and stop controls.

### Phase 7 — TUI

Deliverables: dashboard, map, devices, device details/evidence, DNS, route, monitoring,
history, import/export, settings; background tasks, progress, cancellation, terminal
restoration.

Acceptance: network work never blocks rendering; unknown/conflict/stale states are
visible; terminal is restored on error/panic.

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
