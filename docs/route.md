# Route exploration

Status: implemented in Phase 5 as a CLI and shared-engine feature. No TUI route view exists yet.

## What a route run means

A route run is a point-in-time measurement, not a device property and not proof that a
path is healthy or broken.

For each TTL (hop), NetAtlas sends one or more probes and records:

- the responder address, if any router or the target answered within the probe window
- an optional reverse-DNS hostname hint for that responder
- per-probe outcomes: reply, ICMP error, timeout, transport error, or cancelled
- best and average RTT for probes that produced a timing sample
- loss as `timeouts / samples` for that hop
- the exact sample count and timeout count used to compute those numbers

A hop that does not answer is recorded as `no_response` data for that hop. It does **not**
mean the route is broken; routers often rate-limit or drop TTL-expired replies.

## Probe methods

NetAtlas uses unprivileged Linux probing:

| Method | How it works | Notes |
| --- | --- | --- |
| `icmp` | ICMP datagram echo socket (`IPPROTO_ICMP`) with per-hop TTL | Requires unprivileged ICMP permission (`net.ipv4.ping_group_range` or equivalent). |
| `udp` | UDP datagram with per-hop TTL (default port 33434) | Default method. Hop addresses are learned from `IP_RECVERR` ICMP errors. |
| `tcp` | TCP connect attempt with per-hop TTL (default port 33434 unless set) | A connect/refusal from the target is treated as target reached. |

Hop responders are collected from the socket error queue (`IP_RECVERR`, `MSG_ERRQUEUE`).
No raw socket or `CAP_NET_RAW` is required for this implementation. If a method is not
permitted by the environment, the run records a transport/setup failure honestly.

## CLI

```bash
# Trace (default: UDP, 30 hops, 3 probes/hop)
netatlas route trace example.com
netatlas route trace 1.1.1.1 --method icmp --max-hops 20 --probes 2 --timeout-ms 1000
netatlas route trace example.com --method tcp --port 443 --no-save
netatlas route trace example.com --json

# History
netatlas route history
netatlas route history --target 1.1.1.1 --method udp --limit 20 --json

# Compare the latest two comparable runs, or the latest against a specific run
netatlas route compare example.com --method udp
netatlas route compare 1.1.1.1 --method icmp --against-run <run-uuid> --json
```

## Comparison

Comparisons are derived, point-in-time, and only performed for runs with the same target
IP, probe method, and port. They report:

- whether the responder sequence changed (including unknown/non-responsive hops)
- hop-count and target-reachability changes
- material RTT changes for hops that answered in both runs, ignoring small jitter
- material loss changes, always in the context of sample counts

Comparisons never claim that a change is a fault; they describe what changed between two
measurements.

## Storage

Migration `0004_route` adds:

- `route_runs`: target, resolved target IP, method, port, timestamps, bounds, status,
  reachability, and error
- `route_hops`: per-run TTL rows with responder, hostname hint, aggregate metrics, and
  serialized per-probe samples

## Limitations

- IPv4 only. IPv6 targets are rejected explicitly.
- No raw-socket traceroute mode; behavior depends on `IP_RECVERR` and unprivileged ICMP
  availability in the running environment.
- No MPLS/ICMP extension parsing, path MTU discovery, AS/geo enrichment, or continuous
  route monitoring.
- Reverse DNS is a best-effort hint and may be absent or stale relative to the responder.
- Firewalls, rate limiting, ECMP, and asymmetric routing can make routes appear incomplete
  or variable without indicating a problem.
- Run status is a measurement outcome (`completed`, `partial`, `no_response`, `failed`,
  `cancelled`), not a network health verdict.
