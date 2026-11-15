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
