# Export and backup

Status: Phase 6 slice implemented (JSON/CSV export and SQLite backup/restore/integrity). 
Validated transactional import with dry-run and scheduled monitoring are not implemented yet.

## JSON export

`netatlas export json --output <path>` writes a versioned JSON snapshot of the current
database state:

- `schema_version`: export document version
- `exported_at_ms`: export timestamp
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

## Limitations

- No validated transactional import of exported JSON/CSV bundles yet (no dry-run merge or
  conflict-reporting import workflow).
- Exports contain network observations and inferred properties; treat export files as
  sensitive operational data.
- CSV cannot represent evidence, conflicts, or measurement history.
- Scheduled monitoring, monitor-run/event storage, and automatic change-detection jobs are
  not implemented yet.
