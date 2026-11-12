# NetAtlas inventory, history, and change detection

Status: Phase 3 implemented. This document describes what the inventory layer records,
how comparisons are scoped, and what the output does not claim.

## 1. What is recorded

Each scan writes one `device_sessions` row per observed logical device. The row is a
compact snapshot, not a replacement for raw observations:

- session and device IDs;
- device first/last seen timestamps;
- the addresses, MAC addresses, and hostnames observed for that device in that session;
- the four inferred properties (`manufacturer`, `category`, `os`, `model`) with their
  value, confidence, status, and unknown reason.

Raw observations, evidence, and inference history remain in their existing append-only
tables. The snapshot exists so inventory reads and change comparisons do not need to
replay every observation.

Migration `0002_inventory` creates the table. History therefore starts with the first
scan recorded after that migration. Older sessions still contain raw observations, but
they have no compact snapshot and cannot be compared by `changes` or listed in
per-session `history`.

## 2. Change detection

`netatlas changes` compares a session with the most recent earlier session that:

1. has the same interface and target string;
2. has status `completed` or `partial`;
3. is earlier than the current session.

If no such session exists, the report says comparison is unavailable. It does not compare
scans of different segments or scans with different provider sets merely because they are
adjacent in time.

The current session must also be `completed` or `partial`. A cancelled or failed scan is
reported as not comparable rather than treated as a complete observation of the segment.

### 2.1 Event kinds

| Kind | Meaning |
| --- | --- |
| `new_device` | A device profile in this session was not in the compared earlier session. |
| `not_observed` | A device in the earlier session was absent from this session. This is not proof that it is offline. |
| `ip_changed` | The set of addresses recorded for the device changed. |
| `mac_changed` | The set of MAC addresses recorded for the device changed. |
| `hostname_changed` | The set of hostnames recorded for the device changed. |
| `inference_changed` | One of the four inferred properties changed in value, status, unknown reason, or confidence. |

A partial scan can miss devices because a provider failed. The report carries a note and
`not_observed` summaries say so explicitly. `netatlas changes` never emits an "offline"
event.

Device identity can legitimately change between scans when only an IP address or a
randomized MAC is available. Such a device may appear as one `not_observed` profile plus
one `new_device` profile. This is a consequence of the conservative identity rules, not
an assertion that two physical devices exist.

## 3. Device history

`netatlas history <uuid>` shows:

- the current device summary and freshness;
- every recorded session snapshot for the device, in chronological order;
- changes between consecutive snapshots (addresses, MACs, hostnames, and inferences);
- a note when no snapshots exist yet.

History is per logical device. If identity resolution could not safely link two
observations, they remain separate histories.

## 4. Segment map

`netatlas map` groups devices by the recorded IP prefix containing each device's most
recently seen address. The longest matching prefix wins. Devices with no address, or with
an address outside every recorded prefix, are listed as unassigned.

The map is logical inventory:

- it does not prove physical switch, access-point, or VLAN topology;
- a shared subnet does not prove that two devices share a link;
- stale segment records remain visible with a freshness indicator;
- only the most recent address per device is used for grouping, so a device that changed
  segments appears under its current segment.

## 5. Filtering and freshness

`netatlas devices` supports:

- `--search TEXT`: case-insensitive substring match over label, addresses, MACs,
  hostnames, manufacturer, category, OS, and model;
- `--segment CIDR`: devices whose most recent address is inside the prefix;
- `--stale`: only devices older than the freshness threshold;
- `--stale-after-ms MS`: override the default 24-hour threshold.

Freshness is a presentation threshold. A stale device has not been observed recently; it
may still be present. The CLI prints that caveat whenever stale records are shown.

## 6. Acceptance checks

Deterministic tests cover:

- snapshot round-trip through SQLite;
- session listing, latest-session selection, and device history;
- new/not-observed events and the partial-scan caveat;
- address, MAC, hostname, and inference changes;
- scope matching that ignores scans of other targets;
- search and stale filtering;
- segment grouping by longest matching prefix and the unassigned fallback;
- CLI help, empty-map, empty-changes, invalid-segment, and missing-device behavior.

Live checks use a temporary database and local discovery only. `cargo test` never scans
the user's real network.
