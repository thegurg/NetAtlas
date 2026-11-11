# NetAtlas

Linux-first network exploration and diagnostics in Rust, with a CLI and a TUI over one
shared engine and SQLite history.

> **Status: Phase 1 — shared core and discovery.** The CLI, discovery providers,
> identity resolution, OUI lookup, evidence/inference pipeline, and SQLite persistence
> are implemented. The TUI, DNS diagnostics, route exploration, monitoring, and
> mDNS/SSDP/NetBIOS/service probing are not implemented yet. This README describes what
> works now and what remains limited; it is not a claim that later-phase features exist.

## What works now

```bash
netatlas interfaces
netatlas discover [--interface wlo1] [--target 192.168.1.0/24]
netatlas devices
netatlas device <uuid>
netatlas oui status
netatlas oui import path/to/oui.csv --version 2026-11
netatlas oui lookup 3c:cd:5d:11:22:33
```

Every command supports `--json`, `--help`, and the documented exit codes. A global
`--db <path>` overrides the SQLite database location.

### Discovery

Phase 1 uses four sources:

1. The kernel neighbour table (netlink `RTM_GETNEIGH`), including a re-read after active
   probes so ARP/NDP entries learned during the scan are visible.
2. ICMP echo through unprivileged Linux ICMP datagram sockets (`surge-ping`).
3. A bounded TCP connect fallback on a small fixed port set when ICMP is unavailable or
   silent. A refusal counts as a response; a timeout does not.
4. Reverse DNS (PTR) for hosts that actually answered.

Scans are explicit in scope, bounded by `--max-hosts` and `--concurrency`, and
cancellable with Ctrl-C. A provider failure is recorded and does not erase other
results; the session becomes `partial`.

### Identification

The only property with real evidence in Phase 1 is **manufacturer**, from the IEEE OUI
registry. It is reported as an address-block association at `medium` confidence, never
as proof of model, ownership, or OS. Locally administered MAC addresses are never
OUI-attributed; the reason is shown as `locally_administered_mac`.

Category, OS, and model are always `unknown` with an explicit reason
(`no_evidence`) because no Phase 1 provider observes protocol fields that could support
them. NetAtlas does not guess.

### Identity

- A globally administered MAC within the freshness window links to the device that last
  held it.
- A locally administered MAC is weak evidence and never merges devices on its own; an
  `uncertain` link is recorded instead.
- An IP address never merges devices. Address reuse creates a separate device, an
  `address_reuse_suspected` observation, and an `uncertain` link.
- Hostnames never merge devices on their own.
- A device that changes IP keeps its identity when the MAC links it.

### Persistence

SQLite schema migration `0001_discovery` stores interfaces, addresses, segments, scan
sessions, devices, identifiers, observations, evidence, inferences, identity links, and
OUI sources/prefixes. Foreign keys and WAL are enabled. The IEEE MA-L/MA-M/MA-S snapshot
under `data/oui/` is embedded in the binary and imported on first open.

## Current limitations

- No mDNS, SSDP/UPnP, NetBIOS, or service/banner probing yet. Those are Phase 2 and are
  what would supply category/OS/model evidence.
- Locally administered MACs (including many virtual machines and privacy-randomized
  clients) produce a new logical device per scan plus an uncertain link. This is
  intentional until stronger identifiers exist.
- A host observed only through ICMP with no MAC also produces a new device per scan; IP
  alone is never used to merge.
- Wi-Fi client isolation, firewalls, sleeping devices, and multicast filtering can hide
  peers and evidence. A scan with no result is not proof that a segment is empty.
- The local resolver may cache PTR answers; reverse DNS is a naming hint, not identity.
- No TUI, DNS query/comparison, traceroute, monitoring, import/export, or map yet.
- No live-network tests run during `cargo test`; they are opt-in only.

## Build and test

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo run -- --help
```

Deterministic tests cover domain rules, OUI parsing/lookup, identity resolution,
inference, SQLite migration/round-trip, TCP probe outcomes, and CLI behavior. They do not
require a live network.

## Principles

- Facts, inferences, and measurements are stored separately.
- Evidence is preserved; conflicting evidence is shown, not overwritten.
- Unknown is never replaced by a guess to make output look complete.
- IP addresses are not device identities; MAC addresses are not assumed permanent.
- A non-response is not proof that a host is offline.
- No root requirement for ordinary use. Elevated capability is requested only for the
  specific operation that needs it, never by silently relaunching as root.
- Discovery is bounded, explicit in scope, rate-limited, and cancellable.

## Documents

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Layers, module map, data flow, concurrency, errors, permissions, decision log |
| [docs/data-model.md](docs/data-model.md) | Domain entities, identity rules, evidence model, SQLite schema and migrations |
| [docs/identification.md](docs/identification.md) | Identification pipeline, evidence reliability, confidence rubric, acceptance tests |
| [docs/development.md](docs/development.md) | Toolchain, dependencies, testing policy, coding standards, roadmap |

## Safety

NetAtlas is intended for networks the user owns or is authorized to inspect. It does not
implement deauthentication, credential attacks, exploitation, or stealth behavior.

## License

Declared as `MIT OR Apache-2.0` in `Cargo.toml`.
