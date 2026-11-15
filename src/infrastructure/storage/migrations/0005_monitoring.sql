-- Phase 6 schema: monitoring runs and recorded network events.

CREATE TABLE monitor_runs (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('scan','dns')),
    status          TEXT NOT NULL CHECK (status IN ('running','completed','partial','failed','cancelled','interrupted')),
    started_at_ms   INTEGER NOT NULL,
    finished_at_ms  INTEGER,
    target          TEXT,
    config_json     TEXT NOT NULL,
    summary_json    TEXT,
    error           TEXT
);
CREATE INDEX idx_monitor_runs_kind_time ON monitor_runs(kind, started_at_ms DESC);

CREATE TABLE network_events (
    id              TEXT PRIMARY KEY,
    run_id          TEXT REFERENCES monitor_runs(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info','warning','change','error')),
    subject_type    TEXT,
    subject_id      TEXT,
    message         TEXT NOT NULL,
    details_json    TEXT NOT NULL,
    observed_at_ms  INTEGER NOT NULL
);
CREATE INDEX idx_network_events_time ON network_events(observed_at_ms DESC);
CREATE INDEX idx_network_events_run ON network_events(run_id, observed_at_ms DESC);

-- Phase 7: import provenance tracking

CREATE TABLE session_provenance (
    session_id      TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,
    recorded_at_ms  INTEGER NOT NULL
);
CREATE INDEX idx_session_provenance_source ON session_provenance(source, recorded_at_ms DESC);

CREATE TABLE device_provenance (
    device_id       TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,
    recorded_at_ms  INTEGER NOT NULL
);
CREATE INDEX idx_device_provenance_source ON device_provenance(source, recorded_at_ms DESC);

CREATE TABLE import_reports (
    id              TEXT PRIMARY KEY,
    ran_at_ms       INTEGER NOT NULL,
    dry_run         INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL,
    total_records   INTEGER NOT NULL,
    imported_count  INTEGER NOT NULL,
    conflict_count  INTEGER NOT NULL,
    notes_json      TEXT NOT NULL
);
