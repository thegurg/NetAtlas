# NetAtlas architecture

Status: Phase 2 implemented (identification providers and evidence fusion). Later-phase
modules are described where they affect the current boundaries, but they do not exist yet.

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

- `domain` depends only on `std`, `serde`, `serde_json`, `ipnet`, `chrono`, `uuid`,
  `thiserror`. No sockets, no SQLite, no terminal, no async runtime.
- `application` depends on `domain` and on concrete infrastructure adapters. It
  orchestrates I/O but contains no socket setup and no SQL. A port trait layer will be
  introduced only when it genuinely simplifies dispatch.
- `infrastructure` contains the adapters. Protocol parsing is separated from socket
  operations so it can be tested from fixtures (OUI parsing is the current example).
- `cli` depends on application services and domain types. It contains no discovery,
  protocol, fingerprinting, or database logic.
- Dependencies point inward. `domain` never imports an adapter.

## 3. Implemented module map

```
src/
  main.rs                 binary entry point, tracing setup, exit code
  lib.rs                  public crate surface for integration tests
  config/                 XDG paths, config.toml, defaults, validation
  domain/
    ids.rs                UUIDv7 identifier creation
    time.rs               UTC millisecond timestamps and formatting
    network.rs            MAC, interface, address, segment, gateway, host enumeration
    device.rs             devices, identifiers, identity links, presentation views
    observation.rs        observed facts, host probes, normalized host observations
    service.rs            transport and persisted service records
    evidence.rs           evidence, properties, source units
    inference.rs          candidate conclusions, conflicts, unknown reasons
    confidence.rs         confidence enum and aggregation rubric
    error.rs              domain errors
  application/
    model.rs              scan/session result types
    discovery.rs          scope resolution, provider scheduling, persistence
    identity.rs           identity resolution v1
    identify.rs           evidence extraction and inference
  infrastructure/
    netlink.rs            links, addresses, routes, neighbour table
    icmp.rs               ICMP echo provider (surge-ping)
    tcp_probe.rs          bounded TCP connect fallback
    reverse_dns.rs        PTR lookup through hickory
    mdns.rs               bounded mDNS/DNS-SD browse adapter
    ssdp.rs               SSDP M-SEARCH plus bounded UPnP description fetch
    netbios.rs            wildcard NBSTAT name-table queries
    service_probe.rs      bounded HTTP/SSH/FTP/SMTP banner probes
    oui.rs                IEEE registry parser, embedded snapshot, lookup
    storage/              SQLite store, migrations, repositories
  cli/                    clap definitions, handlers, table/JSON output
```

Planned later modules: `application/inventory.rs`, `application/dns.rs`,
`application/route.rs`, `application/monitor.rs`, `application/export.rs`, and `tui/`.
They are not created as empty placeholders.

Feature modules (`discovery`, `identification`, `lan`, `dns`, `route`, `monitoring`)
are realized as application services plus infrastructure adapters, not as separate
applications. Names may evolve; the layer boundaries may not.

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
  Phase 2: neighbour table | ICMP echo | TCP connect | reverse DNS
           mDNS | SSDP/UPnP | NetBIOS | service banners
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

## 5. Provider contract in Phase 2

Phase 2 still uses concrete adapters with narrow async functions rather than a
dyn-compatible trait:

```rust
icmp::sweep(&addresses, timeout, concurrency, &cancel).await
tcp_probe::probe_hosts(&addresses, ports, timeout, concurrency, &cancel).await
reverse_dns::lookup(&addresses, timeout, concurrency, &cancel).await
mdns::discover(&service_types, window, &cancel).await
ssdp::discover(&addresses, timeout, &cancel).await
netbios::query_hosts(&addresses, timeout, concurrency, &cancel).await
service_probe::probe_hosts(&addresses, ports, timeout, concurrency, &cancel).await
netlink::snapshot().await
```

The orchestrator, not the adapter, decides scope and builds `HostProbe` values. Each
adapter returns typed results and errors:

- A provider failure is recorded in `ProviderReport` and does not cancel other
  providers. The session becomes `partial`.
- `ScanOptions` carries the explicit interface/target scope, timeouts, concurrency
  limit, `max_hosts`, the mDNS window, and per-provider enable flags. Adapters must not
  invent their own scope.
- `CancellationToken` is checked before each probe; in-flight probes are bounded by the
  per-operation timeout and, for mDNS, the browse window.
- mDNS, SSDP, and NetBIOS are only sent to the resolved candidate set. Service probes run
  only against addresses that already answered discovery.
- The identification layer receives a `ProviderAvailability` snapshot derived from the
  provider reports, so `unknown` can distinguish `no_evidence` from
  `provider_unavailable`.

A provider trait is still deferred. The adapters have different result shapes (host
lists, service lists, name lists), so a single trait would add dispatch without removing
meaningful orchestration. Test doubles are not needed because parsing and aggregation are
tested directly from fixture bytes and observations.

## 6. Concurrency and cancellation

- Tokio multi-thread runtime. SQLite writes happen synchronously after network work, on
  the scan task, inside one transaction. The current CLI has no render loop to block; a
  future TUI will move persistence to a dedicated writer task.
- Probes use `futures_util::buffer_unordered` with the configured concurrency (default
  64). There is no unbounded spawning. `max_hosts` bounds the candidate set before any
  probe is sent.
- Per-operation timeouts are explicit (`--timeout-ms`, `--dns-timeout-ms`). The mDNS
  browse is additionally capped by `--mdns-window-ms` (default 3 s). SSDP sends are
  bounded by the per-operation timeout and each description fetch is individually
  timed out and size-limited. There is no separate whole-provider deadline beyond these
  bounds, so a scan's total work remains finite.
- `Ctrl-C` (CLI) triggers a `CancellationToken`. The session is finalized as
  `cancelled` with whatever observations were already recorded. The CLI exits with code
  3 because the result is incomplete.
- Progress is not streamed yet. The CLI prints a final report. Phase 7 will add a
  bounded event channel for the TUI.

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
| 1 | Operational failure (database, configuration, netlink, unrecoverable I/O). |
| 2 | Invalid usage: clap errors, invalid target syntax, MAC, UUID, or scan limits. |
| 3 | Partial or cancelled result: at least one requested method failed, or Ctrl-C interrupted the scan. |
| 4 | Requested object not found (device). An OUI miss is a normal result and exits 0. |

`--json` output always includes `schema_version` and the session `status`, and provider
reports carry typed errors, so automation can distinguish complete from partial results.

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

- Application services call `Store` methods; the CLI does not execute SQL.
- SQLite runs with foreign keys enabled, WAL journaling, and explicit transactions.
- Schema changes are versioned SQL migrations applied in order, recorded in
  `schema_migrations` and guarded by `PRAGMA user_version`. A newer database version is
  rejected rather than opened.
- Observation history is append-oriented. Current device profiles are derived from
  identifiers and the latest inference per property.
- One scan writes its session, devices, identifiers, observations, evidence,
  inferences, identity links, and service observations in one transaction. A failure
  rolls the whole scan back. A crash can leave a `running` session; finalizing it as
  `interrupted` on next startup is not implemented yet.
- The `services` table stores mDNS, UPnP, and TCP banner observations. It is the same
  service inventory surfaced by `discover` and `device`; it is not a second, unrelated
  data path.
- `Store::open` imports the embedded OUI snapshot on first use. `Store::open_in_memory`
  is used by tests and does not import it automatically.

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
unclear licensing. NetAtlas ships a versioned IEEE MA-L/MA-M/MA-S CSV snapshot, loads
it into SQLite, and records source, version, import time, and content hash.

OUI lookup is longest-prefix match and is always reported as manufacturer association,
not model or ownership.

### D7 — DNS through hickory, with explicit validation state

Use `hickory-resolver` 0.26 for queries and `Lookup::message()` for RCODE, flags, and
per-record TTL. Enable `dnssec-ring` and use hickory-proto validation primitives to
produce an explicit state: `secure`, `insecure`, `bogus`, `indeterminate`, `unsupported`.
Presence of DNSKEY/DS/RRSIG records is never reported as successful validation.

Phase 2 uses hickory only for reverse-DNS PTR lookups in discovery. The validation
states belong to the DNS diagnostics phase and are not reported by `discover`.

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

### D13 — Custom `MacAddress` instead of a crate

The domain owns a 48-bit `MacAddress` with parsing for colon, hyphen, Cisco dotted, and
plain hex forms, plus explicit local-admin and multicast checks. This keeps the
local-admin rule visible at the type boundary and avoids a dependency whose API and
license would need separate review.

### D14 — Direct provider adapters in Phase 2

Phase 2 has eight provider families and no third-party provider plugins. Direct async
functions keep scheduling, cancellation, and error mapping in one readable orchestrator.
The planned `DiscoveryProvider` trait remains deferred because the adapters return
different shapes and the orchestration still needs provider-specific ordering (for
example, service probes must run after discovery has found answering hosts).

### D15 — Neighbour table re-read after active probes

The kernel owns ARP/NDP state. After ICMP and TCP probes, the orchestrator reads the
neighbour table again and merges new entries. This yields MACs for hosts that answered
without hand-crafting ARP frames. Duplicate entries are deduplicated by address, MAC, and
state.

### D16 — One SQLite source per OUI import, latest wins

An OUI import is a new `oui_sources` row with its own hash and record set. Lookups use
`oui_prefixes` rows from the most recent source (ordered by import time and UUIDv7 ID).
Old sources remain for provenance instead of being destructively replaced. The
in-memory `oui_entries()` loader reads only the latest source.

### D17 — SQLite writes stay on the scan task for now

The current CLI has no render loop, so one transaction at the end of a scan is simpler
and safer than a writer task. When the TUI arrives, persistence will move behind a
writer task or a blocking pool so rendering is never blocked.

### D18 — Strong identifiers link before MAC

UPnP UDNs and mDNS instance names are self-reported, but they are intended to survive
address and randomized-MAC changes. They are therefore matched before MAC addresses. A
strong identifier that conflicts with a MAC match wins, and the competing MAC match is
preserved as an `uncertain` link rather than discarded. A locally administered MAC still
never merges on its own.

### D19 — Service probes only run against hosts that answered

Probing every candidate on the service port list would turn discovery into an
unrequested port scan. The orchestrator therefore runs service probes only for
addresses that already produced a positive discovery observation. The port set is
small, plain-text only, and does not include TLS handshakes or authentication.

## 11. Known limitations to design around

- Wi-Fi client isolation, hotspot mode, VLANs, firewalls, and multicast filtering can
  hide peers and evidence. Results must say so rather than implying absence.
- Mobile devices sleep, randomize MACs, and expose little metadata.
- OUI data maps address blocks, not devices. Virtual machines and hypervisors use
  locally administered addresses.
- A locally administered MAC still cannot merge on its own, so privacy-randomized clients
  without a matching UDN or mDNS instance create a new logical device per scan plus an
  uncertain link. Strong identifiers reduce this when the device publishes them.
- A host seen only through ICMP, with no MAC and no strong identifier, also creates a new
  logical device per scan because IP alone never merges.
- Hostnames and NetBIOS names are claims, not verified identities.
- Service banners and UPnP/mDNS descriptions are self-reported and can be stale or
  misleading.
- Exact phone/PC model identification is usually impossible from LAN observations.
- Netlink neighbour entries do not carry a kernel timestamp; `observed_at` records when
  NetAtlas read the entry, and the neighbour state (`REACHABLE`, `STALE`, ...) is kept.
- The local resolver may cache answers; reverse DNS is a naming hint, not a verified
  identity. DNS diagnostics must record the resolver and cannot claim authoritative
  freshness.
- mDNS results depend on multicast reachability and the platform daemon; SSDP depends on
  plain HTTP descriptions being reachable; NetBIOS is often disabled or filtered. A
  provider that ran and found nothing is `no_evidence`, not proof of absence.
- Service probing covers a small plain-text port set. TLS-only services, SSH host keys,
  and TLS certificate fingerprints are not captured yet.
- A provider failure makes the session `partial`; it does not imply that the failed
  method found nothing.

## 12. Security and safety posture

- Explicit target scope; refuse accidentally huge ranges unless the user passes an
  explicit `--max-hosts` override.
- Bounded timeouts, concurrency, and response sizes.
- No disruptive probes, no authentication attempts, no exploitation, no deauth.
- No secrets in logs or exports. DHCP/AP credentials are not part of inventory.
- Database and exports contain network observations; documentation will state that they
  may be sensitive.
