# NetAtlas

Linux-first network exploration and diagnostics in Rust, with a CLI and a TUI over one
shared engine and SQLite history.

> **Status: Phase 0 — architecture only.** No implementation code exists yet. This
> README and the documents under `docs/` describe the proposed design and the planned
> implementation order. They are not claims that features already work.

## What NetAtlas is for

NetAtlas combines five capabilities in one application:

1. LAN discovery and evidence-based device identification.
2. LAN inventory and topology representation.
3. DNS analysis and resolver comparison.
4. Route exploration and path measurements.
5. Historical monitoring and change detection.

The primary objective is **honest device identification**: every displayed conclusion
must be traceable to observations, confidence must be explainable, and `Unknown` is a
valid result. A scan that only prints IP/MAC pairs is not a successful identification
result.

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

## Planned CLI surface

Commands are added only when the behavior behind them is implemented. The intended
shape is:

```bash
netatlas interfaces
netatlas discover --interface wlan0
netatlas devices
netatlas device <id>

netatlas map
netatlas dns query example.com
netatlas dns compare example.com
netatlas route example.com --method tcp
netatlas monitor
netatlas changes
netatlas export --format json
netatlas import backup.json
netatlas tui
```

All commands will support `--help`, non-interactive execution, meaningful exit codes,
and machine-readable JSON where useful.

## Safety

NetAtlas is intended for networks the user owns or is authorized to inspect. It does not
implement deauthentication, credential attacks, exploitation, or stealth behavior.

## License

Not yet chosen.
