-- Phase 5 schema: route exploration measurements.
-- Runs are point-in-time measurements. A non-responsive hop is a recorded fact,
-- not a route-failure claim.

CREATE TABLE route_runs (
    id               TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    target_ip        TEXT NOT NULL,
    method           TEXT NOT NULL CHECK (method IN ('icmp','udp','tcp')),
    port             INTEGER,
    started_at_ms    INTEGER NOT NULL,
    finished_at_ms   INTEGER NOT NULL,
    max_hops         INTEGER NOT NULL,
    probes_per_hop   INTEGER NOT NULL,
    status           TEXT NOT NULL
                     CHECK (status IN ('completed','partial','no_response','failed','cancelled')),
    target_reached   INTEGER NOT NULL CHECK (target_reached IN (0,1)),
    error            TEXT
);
CREATE INDEX idx_route_runs_time ON route_runs(started_at_ms DESC);
CREATE INDEX idx_route_runs_target ON route_runs(target_ip, method, port, started_at_ms DESC);

CREATE TABLE route_hops (
    run_id           TEXT NOT NULL REFERENCES route_runs(id) ON DELETE CASCADE,
    ttl              INTEGER NOT NULL,
    responder        TEXT,
    hostname         TEXT,
    samples_json     TEXT NOT NULL,
    reply_count      INTEGER NOT NULL,
    timeout_count    INTEGER NOT NULL,
    error_count      INTEGER NOT NULL,
    best_rtt_ms      REAL,
    avg_rtt_ms       REAL,
    loss_ratio       REAL NOT NULL,
    PRIMARY KEY (run_id, ttl)
);
CREATE INDEX idx_route_hops_run ON route_hops(run_id, ttl);
