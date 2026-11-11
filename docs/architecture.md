# NetAtlas architecture

Status: Phase 0 design. Nothing in this document is implemented yet.

## 1. Goals and non-goals

### Goals

- One engine, two presentation layers (CLI and TUI).
- Evidence-based device identification with inspectable provenance.
- Deterministic, testable protocol and inference logic that does not depend on the
  user's live network.
- Bounded, cancellable network operations that work unprivileged where possible.
- Persistent observations and history in SQLite, with schema migrations.
- Linux-first implementation using kernel-provided network context.

### Non-goals for the first milestones

- Packet-capture-style passive monitoring.
- Claiming physical topology (switch/AP attachment) that was not observed.
- Aggressive service/OS fingerprinting or exploitation.
- Cross-platform support. Linux is the only target for now.
- A plugin framework. Modules are compiled in and use shared domain types.

## 2. Layers and dependency direction

```
            +---------------------------+
            |        CLI / TUI          |   presentation only
            +-------------+-------------+
                          |
            +-------------v-------------+
            |     Application services  |   use-case orchestration
            |  discovery, identify,     |
            |  inventory, dns, route,   |
            |  monitor, import/export   |
            +-------------+-------------+
                          |
            +-------------v-------------+
            |          Domain           |   pure rules and types
            |  device, identity,        |
            |  observation, evidence,   |
            |  inference, confidence,   |
            |  dns, route, events       |
            +-------------+-------------+
                          ^
                          | implements ports declared by app/domain
            +-------------+-------------+
            |     Infrastructure        |   I/O adapters
            |  netlink, ICMP, mDNS,     |
            |  SSDP, NetBIOS, probes,   |
            |  DNS transport, SQLite    |
            +---------------------------+
```

Rules:

- `domain` depends only on `std`, `serde`, `ipnet`, `macaddr`, `chrono`, `uuid`,
  `thiserror`. No sockets, no SQLite, no terminal, no async runtime.
- `application` depends on `domain` and on narrow port traits for I/O. It never opens
  a socket or writes SQL directly.
- `infrastructure` implements those ports. Protocol parsers are separate from socket
  operations so they can be tested from fixtures.
- `cli` and `tui` depend on application services and domain types. Neither contains
  discovery, protocol, fingerprinting, or database logic.
- Dependencies point inward. `domain` never imports an adapter.

## 3. Planned module map

```
src/
  main.rs                 binary entry point, runtime setup, exit-code mapping
  lib.rs                  public crate surface for integration tests
  config/                 XDG paths, config.toml, defaults, validation
  domain/
    ids.rs                typed IDs (DeviceId, SessionId, ...)
    time.rs               UTC millisecond timestamps
    network.rs            interface, address, segment, gateway
    device.rs             device profile and identifiers
    observation.rs        observed facts and measurements
    evidence.rs           evidence, source units, independence keys
    inference.rs          candidate conclusions and conflicts
    confidence.rs         confidence enum and aggregation rubric
    service.rs            service observations
    dns.rs                DNS records, measurements, validation state
    route.rs              route measurements and hops
    event.rs              derived change events
    error.rs              domain errors
  application/
    ports.rs              provider, resolver, probe, clock ports
    context.rs            gather local network context
    discovery.rs          orchestrate providers into one session
    identify.rs           run inference over observations
    inventory.rs          device/segment queries and history
    dns.rs                query/compare use cases (later)
    route.rs              trace/compare use cases (later)
    monitor.rs            change detection (later)
    export.rs             import/export (later)
  infrastructure/
    netlink/              links, addresses, routes, neighbour table
    icmp/                 ICMP echo provider (surge-ping)
    probe/                bounded TCP connect probes
    mdns/                 mDNS browse/resolve adapter
    ssdp/                 SSDP discovery + description fetch
    netbios/              NBSTAT query + parser
    service/              safe protocol-specific banner collection
    oui/                  IEEE registry loader and lookup
    dns/                  hickory transport and DNSSEC validation
    route/                ICMP/UDP/TCP traceroute probes
    storage/              SQLite store, migrations, repositories
  cli/                    clap definitions, handlers, table/JSON output
  tui/                    ratatui state and views
```

Feature modules (`discovery`, `identification`, `lan`, `dns`, `route`, `monitoring`)
are realized as application services plus infrastructure adapters, not as separate
applications. Names may evolve during implementation; the layer boundaries may not.

## 4. Data flow

### Discovery and identification

```
network context (netlink)
        |
        v
scan session scope: interface and/or target prefix, methods, limits
        |
        v
providers run concurrently, each emitting normalized observations
  neighbour table | ICMP echo | reverse DNS | mDNS | SSDP | NetBIOS | TCP probes
        |
        v
observation stream (facts only, with source, method, timestamp, details)
        |
        v
identity resolution: link identifiers to logical devices
        |
        v
evidence extraction: each observation may support a property candidate
        |
        v
inference: aggregate independent evidence, detect conflicts, assign confidence
        |
        v
persist session + observations + evidence + inferences in transactions
        |
        v
CLI table/JSON or TUI views (both read the same application services)
```

A provider never decides final device identity. A provider reports what it observed.
The identification layer consumes observations and produces explainable candidates.

### DNS and route

DNS and route measurements follow the same shape: a measurement is recorded with its
method, target, resolver/probe parameters, timing, and result. Comparison is a pure
domain operation over stored measurements.

## 5. Provider contract

Each discovery provider implements one port:

```rust
#[async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn methods(&self) -> &'static [DiscoveryMethod];

    async fn run(
        &self,
        context: &ScanContext,
        sink: &ObservationSink,
        cancel: &CancellationToken,
    ) -> ProviderReport;
}
```

- `ObservationSink` is a bounded channel sender. Providers emit observations as they
  are made; they do not accumulate an unbounded result set.
- `ProviderReport` contains counts, duration, and typed errors. A provider failure is
  recorded in the session and does not cancel other providers.
- `ScanContext` carries the explicit interface/target scope, timeouts, concurrency
  limit, and rate limit. Providers must not invent their own scope.
- `CancellationToken` is checked between probe batches and used to abort in-flight
  sockets.

Fake providers in tests implement the same trait and emit fixture observations.

## 6. Concurrency and cancellation

- Tokio multi-thread runtime. Blocking work (SQLite writes) runs on a dedicated
  blocking thread or is serialized in one writer task; it never blocks the async
  workers or the TUI render loop.
- Every scan has a `JoinSet` of provider tasks and a global `Semaphore` for network
  operations. Default network concurrency is 64, configurable. No unbounded spawning.
- Per-provider timeout and per-operation timeout are separate. A slow provider cannot
  extend the whole scan indefinitely.
- `Ctrl-C` (CLI) or a cancel action (TUI) triggers the cancellation token; the session
  is finalized as `cancelled` with whatever observations were already recorded.
- Progress is reported through a bounded event channel (`SessionEvent`), consumed by
  the CLI progress renderer or the TUI. The TUI never performs network I/O itself.

## 7. Error model and exit codes

- Domain errors use `thiserror` and are typed (`InvalidMac`, `InvalidPrefix`,
  `IdentityAmbiguity`, ...).
- Application boundaries may use `anyhow` to add context, but provider errors are
  preserved as structured values in the session, not flattened into strings.
- Recoverable provider failures (permission denied, timeout, malformed response,
  interface down) are recorded and surfaced; they do not erase other results.
- No `unwrap()`/`expect()` in production paths without a documented invariant.

CLI exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Operation completed. Zero discovered hosts is still a completed result. |
| 1 | Operational failure (database, configuration, unrecoverable I/O). |
| 2 | Invalid usage (clap default). |
| 3 | Partial result: at least one requested method failed, results are incomplete. |
| 4 | Requested object not found (device, session, measurement). |

`--json` output always includes a `status` field and any provider errors, so automation
can distinguish complete from partial results.

## 8. Permission model

- Default operation is unprivileged.
- Interface, address, route, and neighbour data come from netlink read operations,
  which do not require elevated privileges.
- ICMP echo uses Linux ICMP datagram ("ping") sockets. If the kernel's
  `net.ipv4.ping_group_range` does not allow the user, the provider records
  `insufficient_permissions` and the scan falls back to TCP connect probes plus the
  neighbour table. It does not fail the whole scan.
- Raw sockets are not used in the initial milestones. If a later method genuinely needs
  `CAP_NET_RAW`, the command will explain why and the fallback; NetAtlas will never
  silently relaunch as root.
- DNS, TCP connect, mDNS, SSDP, and NetBIOS queries are ordinary unprivileged sockets.

## 9. Storage boundary

- Application services call repository methods; they do not execute SQL.
- SQLite runs with foreign keys enabled, WAL journaling, and explicit transactions.
- Schema changes are versioned migrations applied in order, recorded in
  `schema_migrations` and guarded by `PRAGMA user_version`.
- Observation history is append-oriented. Current device profiles are derived, not
  overwritten.
- A scan writes its session, observations, evidence, and inferences in bounded
  transaction batches; a crash leaves a `running` session that can be finalized as
  `interrupted` on next startup rather than corrupting prior history.

## 10. Decision log

### D1 — Rust, Tokio, single binary with library crate

Use stable Rust (environment: 1.99.1) and Tokio. The library crate exists so integration
tests and future front ends use the same application surface as the binary.

Alternatives: async-std (smaller ecosystem for DNS/netlink), no async (blocking TUI and
parallel probes become awkward). Tokio wins because rtnetlink, hickory, and surge-ping
all support it.

### D2 — Layered modules instead of one module per feature

The specification's feature names are preserved as services/adapters, but code is
organized by layer so domain rules cannot accidentally depend on sockets or SQLite.

Alternative: `src/dns/`, `src/route/` each containing domain + I/O. Rejected because it
duplicates boundaries and invites protocol logic into presentation.

### D3 — Netlink for network context, not shelling out to `ip`

Use `rtnetlink` for links, addresses, routes, and the neighbour table. This avoids
parsing localized command output and gives structured attributes.

Alternative: `ip -j` subprocess. Rejected as a primary path; it may remain a diagnostic
fallback only if a kernel/netlink incompatibility is found.

### D4 — ICMP via unprivileged ping sockets

Use `surge-ping` (SOCK_DGRAM ICMP on Linux). The current environment permits it
(`ping_group_range = 0 2147483647`). No raw socket or setuid helper is required.

Alternative: raw ICMP with `CAP_NET_RAW`. Rejected as a default because it would make
ordinary discovery privileged.

### D5 — Neighbour table plus traffic-based ARP resolution

ARP facts come from the kernel neighbour table (netlink `RTM_GETNEIGH`). To populate it,
send bounded ICMP/TCP probes to candidate addresses, then re-read the table. NetAtlas
does not hand-craft ARP frames in the initial milestones.

Rationale: the kernel already owns ARP/NDP state; reading it avoids duplicate protocol
logic and permission requirements. A crafted-ARP provider can be added later if a real
need is demonstrated.

### D6 — OUI data is loaded from the IEEE registry, not a lookup crate

The `oui` crate depends on the unmaintained `failure` crate; `mac_oui` embeds data with
unclear licensing. NetAtlas will ship a versioned IEEE MA-L/MA-M/MA-S CSV snapshot,
load it into SQLite, and record source, version, import time, and content hash.

OUI lookup is longest-prefix match and is always reported as manufacturer association,
not model or ownership.

### D7 — DNS through hickory, with explicit validation state

Use `hickory-resolver` 0.26 for queries and `Lookup::message()` for RCODE, flags, and
per-record TTL. Enable `dnssec-ring` and use hickory-proto validation primitives to
produce an explicit state: `secure`, `insecure`, `bogus`, `indeterminate`, `unsupported`.
Presence of DNSKEY/DS/RRSIG records is never reported as successful validation.

Alternative: a hand-written DNS client. Rejected: too much protocol surface for the value.

### D8 — mDNS via `mdns-sd`, bounded to the scan window

`mdns-sd` owns a daemon thread. Each scan creates it, browses the required service
types for a bounded window, resolves what it finds, then shuts it down. The adapter
normalizes events into observations; the rest of the system does not see the daemon.

Alternative: `hickory-proto` mDNS directly. More control, significantly more code; revisit
only if `mdns-sd` cannot expose needed metadata.

### D9 — Plain bounded HTTP for SSDP descriptions

SSDP descriptions are fetched over plain HTTP with a hand-written, size- and
time-bounded client (headers plus a small body limit). No TLS or general HTTP stack is
needed, and this avoids a large dependency.

### D10 — No `pnet` dependency initially

Packet parsing is not needed for the first milestones: netlink supplies ARP/NDP facts,
surge-ping supplies ICMP, and SSDP/NetBIOS are ordinary UDP/TCP payloads. If a later
provider needs packet-level parsing, add `etherparse` for parsing and keep packet
construction isolated and tested.

### D11 — SQLite via rusqlite with bundled SQLite

Use `rusqlite` 0.42 with the `bundled` feature for a reproducible SQLite version.
Migrations are plain SQL applied by a small in-crate runner; no migration framework is
needed at this scale.

### D12 — XDG paths without a directories crate

Resolve `$XDG_CONFIG_HOME`/`$XDG_DATA_HOME` (falling back to `~/.config` and
`~/.local/share`) in `config/`. This is a few lines and avoids a dependency whose
platform matrix NetAtlas does not use.

## 11. Known limitations to design around

- Wi-Fi client isolation, hotspot mode, VLANs, firewalls, and multicast filtering can
  hide peers and evidence. Results must say so rather than implying absence.
- Mobile devices sleep, randomize MACs, and expose little metadata.
- OUI data maps address blocks, not devices. Virtual machines and hypervisors use
  locally administered addresses.
- Hostnames are claims, not verified identities.
- Service banners and UPnP/mDNS descriptions are self-reported and can be stale or
  misleading.
- Exact phone/PC model identification is usually impossible from LAN observations.
- Netlink neighbour entries do not carry a kernel timestamp; `observed_at` records when
  NetAtlas read the entry, and the neighbour state (`REACHABLE`, `STALE`, ...) is kept.
- The local resolver may cache answers; DNS diagnostics must record the resolver and
  cannot claim authoritative freshness.

## 12. Security and safety posture

- Explicit target scope; refuse accidentally huge ranges unless the user passes an
  explicit `--max-hosts` override.
- Bounded timeouts, concurrency, and response sizes.
- No disruptive probes, no authentication attempts, no exploitation, no deauth.
- No secrets in logs or exports. DHCP/AP credentials are not part of inventory.
- Database and exports contain network observations; documentation will state that they
  may be sensitive.
