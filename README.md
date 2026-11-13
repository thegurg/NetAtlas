# NetAtlas

Linux-first network exploration and diagnostics in Rust, with a CLI and a TUI over one
shared engine and SQLite history.

> **Status: Phase 4 — DNS diagnostics.** The CLI, discovery providers, identity
> resolution, OUI lookup, evidence/inference pipeline, mDNS, SSDP/UPnP, NetBIOS, safe
> TCP service probes, SQLite persistence, per-session inventory snapshots, device
> history, change detection, segment grouping, filtering, stale-data indicators, raw DNS
> queries, resolver comparison, DNS measurement history, and explicit DNSSEC observation
> state are implemented. The TUI, route exploration, monitoring, import/export, and
> cryptographic DNSSEC validation are not implemented yet. This README describes what
> works now and what remains limited; it is not a claim that later-phase features exist.

## What works now

```bash
netatlas interfaces
netatlas discover [--interface wlo1] [--target 192.168.1.0/24]
netatlas discover --target 192.168.1.0/24 --no-mdns --no-ssdp --no-netbios --no-services
netatlas devices [--search TEXT] [--segment 192.168.1.0/24] [--stale]
netatlas device <uuid>
netatlas map [--interface wlo1]
netatlas changes [--session <uuid>]
netatlas history <uuid>
netatlas oui status
netatlas oui import path/to/oui.csv --version 2026-11
netatlas oui lookup 3c:cd:5d:11:22:33
netatlas dns query example.com [--type A,AAAA] [--resolver 1.1.1.1]
netatlas dns compare example.com --resolver system --resolver 1.1.1.1
netatlas dns history [--name example.com] [--type A] [--resolver system]
```

Every command supports `--json`, `--help`, and the documented exit codes. A global
`--db <path>` overrides the SQLite database location.

### Discovery

The current provider set uses these sources:

1. The kernel neighbour table (netlink `RTM_GETNEIGH`), including a re-read after active
   probes so ARP/NDP entries learned during the scan are visible.
2. ICMP echo through unprivileged Linux ICMP datagram sockets (`surge-ping`).
3. A bounded TCP connect fallback on a small fixed port set when ICMP is unavailable or
   silent. A refusal counts as a response; a timeout does not.
4. Reverse DNS (PTR) for hosts that actually answered.
5. mDNS/DNS-SD browsing for a bounded window (`--mdns-window-ms`, default 3 s).
6. SSDP M-SEARCH plus unicast probes, with a bounded plain-HTTP UPnP description fetch.
7. NetBIOS wildcard NBSTAT queries; names are claims, not verified identities.
8. Safe TCP service probes (HTTP `HEAD`, SSH/FTP/SMTP banners) on ports 21, 22, 25, 80,
   and 8080, only for hosts that already answered.

Each provider can be disabled with `--no-icmp`, `--no-tcp`, `--no-dns`, `--no-mdns`,
`--no-ssdp`, `--no-netbios`, or `--no-services`. Scans are explicit in scope, bounded by
`--max-hosts` and `--concurrency`, and cancellable with Ctrl-C. A provider failure is
recorded and does not erase other results; the session becomes `partial`.

### Identification

The identification pipeline extracts evidence for four properties:

- **Manufacturer** from the IEEE OUI registry (`medium`, an address-block association),
  an explicit UPnP `manufacturer` field (`medium`), or mDNS TXT
  `manufacturer`/`vendor` (`low`). Locally administered MAC addresses are never
  OUI-attributed; the reason is shown as `locally_administered_mac`.
- **Category** from unambiguous UPnP device types and mDNS service types (`medium`).
  Open ports alone never establish a category.
- **OS family** from explicit SSH/FTP/SMTP/HTTP banner hints and mDNS TXT fields
  (`low`). Families are canonicalized (`Linux`, `Windows`, `macOS`, ...); TTL is never
  used.
- **Model** from explicit UPnP `modelName`/`modelNumber` (`medium`) or mDNS TXT model
  fields (`low`).

Agreement between independent sources can raise confidence to `high`; disagreement
produces `conflicted` with both candidates preserved. When relevant providers were
disabled or failed, the property is `unknown` with `provider_unavailable`; when they ran
and found nothing, the reason is `no_evidence`. NetAtlas does not guess.

Service observations (port, transport, protocol, product, version, banner) are persisted
and shown separately. Product/version strings are self-reported service metadata and are
not promoted to device manufacturer or model evidence.

### Identity

- A UPnP UDN or mDNS instance name links devices ahead of MAC. A conflict between a
  strong identifier and a MAC match is preserved as an `uncertain` link.
- A globally administered MAC within the freshness window links to the device that last
  held it.
- A locally administered MAC is weak evidence and never merges devices on its own; an
  `uncertain` link is recorded instead.
- An IP address never merges devices. Address reuse creates a separate device, an
  `address_reuse_suspected` observation, and an `uncertain` link.
- Hostnames and NetBIOS names never merge devices on their own.
- A device that changes IP keeps its identity when the MAC or a strong identifier links
  it.

### Inventory, history, and map

Every scan records a compact per-device inventory snapshot: the addresses, MACs,
hostnames, and four inferred properties observed in that session. `netatlas changes`
compares the latest session with the most recent earlier scan of the same interface and
target. `netatlas history <uuid>` shows one device across sessions and the changes
between them. `netatlas map` groups devices by the recorded IP segment containing their
most recent address.

Change kinds are `new_device`, `not_observed`, `ip_changed`, `mac_changed`,
`hostname_changed`, and `inference_changed`. `not_observed` means the device was absent
from that scan; it is never a claim that the device is offline. Comparisons are only made
when the interface and target match, and partial scans are labelled because a failed
provider can hide devices.

`netatlas devices` supports case-insensitive `--search` across addresses, names, and
inferences, a `--segment` filter, and `--stale`. Stale means older than the 24-hour
inventory threshold (overridable with `--stale-after-ms`); it is a data-freshness
indicator, not an online/offline determination. Segment grouping is logical (IP prefix),
not physical switch or access-point topology.

### DNS diagnostics

`netatlas dns query` sends A, AAAA, CNAME, MX, NS, TXT, or SOA queries (default
`A,AAAA`) to one or more resolvers and records a measurement per query. Each measurement
includes the resolver, transport, timing, attempts, RCODE, header flags, TTLs, answer and
authority records, and section counts. Transport failures are stored as measurements too.

`--resolver` accepts `system`, an IP address, `IP:PORT`, or `[IPv6]:PORT`; it is
repeatable. With no `--resolver`, the system resolver list is read from the system
configuration. `netatlas dns compare` requires at least two distinct resolvers and reports
RCODE agreement, answer-set agreement, TTL variation, and DNSSEC-related field variation.
Answer-set equality ignores TTL and DNS name case; TTL differences are reported
separately because caching is expected.

DNSSEC is reported honestly: the client can set the EDNS DO bit and records the AD flag,
RRSIG presence, and EDNS presence, but the validation state is always `not_performed`.
No cryptographic validation, trust-anchor management, or chain-of-trust claim is made.
See [docs/dns.md](docs/dns.md).

Exit codes for DNS commands: `0` when every query produced a DNS response (including
NXDOMAIN/SERVFAIL/REFUSED), `1` when every query failed at the transport level, `3` for
partial transport failure or cancellation, and `2` for usage errors.

### Persistence

SQLite migration `0001_discovery` stores interfaces, addresses, segments, scan sessions,
devices, identifiers, observations, evidence, inferences, identity links, services, and
OUI sources/prefixes. Migration `0002_inventory` adds per-session device snapshots used
for history and change detection. Migration `0003_dns` adds `dns_measurements` for raw
DNS query results, timing, RCODEs, and explicit DNSSEC observation state. Foreign keys
and WAL are enabled. The IEEE MA-L/MA-M/MA-S snapshot under `data/oui/` is embedded in
the binary and imported on first open.

## Current limitations

- mDNS results depend on multicast reachability and the platform daemon; SSDP depends on
  plain HTTP descriptions being reachable; NetBIOS is often disabled or filtered. A
  provider that ran and found nothing is `no_evidence`, not proof of absence.
- Service probes cover a small plain-text port set and only hosts that already answered
  discovery. TLS-only services, SSH host keys, and TLS certificate fingerprints are not
  captured yet.
- Banners and UPnP/mDNS descriptions are self-reported and can be stale or misleading.
  They are evidence, not verified facts.
- Locally administered MACs without a matching UDN or mDNS instance still produce a new
  logical device per scan plus an uncertain link. Strong identifiers reduce this when
  the device publishes them.
- A host observed only through ICMP with no MAC and no strong identifier also produces a
  new device per scan; IP alone is never used to merge.
- Wi-Fi client isolation, firewalls, sleeping devices, and multicast filtering can hide
  peers and evidence. A scan with no result is not proof that a segment is empty.
- The local resolver may cache PTR answers; reverse DNS is a naming hint, not identity.
- Inventory history begins with the first scan recorded after migration `0002_inventory`.
  Earlier sessions have raw observations but no compact snapshot, so they cannot be
  compared by `changes` or shown in per-session `history`.
- DNS history begins with the first measurement recorded after migration `0003_dns`.
- DNS results are point-in-time measurements from one resolver. Cached answers and
  split-horizon DNS can legitimately differ; a match is not proof of correct
  configuration. Only the seven listed record types are modelled.
- DNSSEC validation is not implemented. The AD flag and RRSIG presence are observations,
  not a local validation result.
- No DNS-over-TLS, DNS-over-HTTPS, scheduled DNS monitoring, or CNAME-chain walking yet.
- Segment grouping uses the most recently seen address for each device and the prefixes
  recorded from network context. It does not infer physical topology, VLANs, or
  switch/AP attachment.
- Stale records are not offline devices. A device can be present but unobserved because
  of sleep, firewall rules, client isolation, or scope limits.
- No TUI, traceroute, monitoring, or import/export yet.
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
inference, protocol parsers (mDNS/SSDP/NetBIOS/service banners), DNS name/resolver
parsing, DNS transport behavior against local mock servers, DNS comparison, inventory
change detection and filtering, SQLite migration/round-trip, TCP probe outcomes, and CLI
behavior. They do not require a live network.

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
| [docs/inventory.md](docs/inventory.md) | Inventory snapshots, history, change semantics, segment map, freshness |
| [docs/dns.md](docs/dns.md) | DNS queries, resolver selection, comparison, exit codes, DNSSEC honesty, history |
| [docs/development.md](docs/development.md) | Toolchain, dependencies, testing policy, coding standards, roadmap |

## Safety

NetAtlas is intended for networks the user owns or is authorized to inspect. It does not
implement deauthentication, credential attacks, exploitation, or stealth behavior.

## License

Declared as `MIT OR Apache-2.0` in `Cargo.toml`.
