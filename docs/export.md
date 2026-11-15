# Export and backup

Status: Phase 6 slice in progress (JSON/CSV export, SQLite backup/restore/integrity, and
validated JSON import with dry-run for measurement records). Scheduled monitoring and
full conflict-aware session/device identity import are not implemented yet.

## JSON export

`netatlas export json --output <path>` writes a versioned JSON snapshot of the current
database state:

- `schema_version`: export document version
- `exported_at_ms`: export timestamp
- `sessions`: scan session records with their per-device inventory snapshots (for history/change context)
- `devices`: for each known device, the current summary and full detail when available
  (identifiers, links, evidence, inferences, observations, services)
- `dns_measurements`: stored DNS measurements (including transport failures)
- `route_runs`: stored route runs with hops and probe samples

JSON export is intended to preserve records with evidence, inference rationale, and
timestamps. Consumers should treat it as a point-in-time snapshot, not a live view.

## CSV export

`netatlas export csv --output <path>` writes a **lossy** table of current device summaries.

Columns: `id, first_seen_ms, last_seen_ms, ips, macs, hostnames, manufacturer, category, os, model, confidence_note`.

Omitted by design: the evidence graph, observations, per-identifier history, DNS
measurements, route runs, raw details, and provenance needed to explain conclusions.
Use JSON export when those fields matter.

## Database backup and restore

```bash
netatlas db integrity [--json]
netatlas db backup --output <backup.db> [--json]
netatlas db restore --input <backup.db> [--to <destination.db>] [--json]
```

- `backup` uses the SQLite online backup API and verifies the backup with `PRAGMA integrity_check`.
- `restore` validates the backup file (integrity and schema presence) before copying it to
  the destination and removes stale `-wal`/`-shm` sidecars for the restored file.
- Restore is a file-level replacement operation; do not run it concurrently with active writers.

## JSON import

```bash
netatlas import json --input <export.json> --dry-run [--json]
netatlas import json --input <export.json> [--json]
```

- Validates the export schema version and reports a per-section summary (total, importable,
  imported, skipped existing, conflicts, unsupported) plus conflict details and notes.
- Import is transactional for applied writes; conflicting records are never overwritten.
- **Current scope:** non-conflicting DNS measurements and route runs are imported by stable
  ID. Identical existing records are skipped; same ID with different content is reported as
  a conflict.
- **Not yet merged automatically:** sessions/snapshots and device/identifier/evidence/
  inference/observation identity-graph records are reported as unsupported in this slice to
  avoid silent merges or identity corruption. Use `db backup/restore` for full-fidelity
  database restoration.

## Limitations

- No full conflict-aware import of sessions, devices, identifiers, evidence, inferences,
  observations, or services yet (no dry-run merge of identity graphs).
- CSV import is not implemented.
- Exports/imports contain network observations and inferred properties; treat files as
  sensitive operational data.
- CSV cannot represent evidence, conflicts, or measurement history.
- Scheduled monitoring, monitor-run/event storage, and automatic change-detection jobs are
  not implemented yet.
