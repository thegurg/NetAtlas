-- Per-session inventory snapshots.
--
-- The snapshot is a compact, derived record of what one scan observed for one
-- device. It supports device history, change detection, and fast inventory
-- reads without replaying every raw observation. It does not replace the
-- append-oriented observations, evidence, or inference tables.

CREATE TABLE device_sessions (
    session_id     TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    first_seen_ms  INTEGER NOT NULL,
    last_seen_ms   INTEGER NOT NULL,
    ips_json       TEXT NOT NULL DEFAULT '[]',
    macs_json      TEXT NOT NULL DEFAULT '[]',
    hostnames_json TEXT NOT NULL DEFAULT '[]',
    inferences_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (session_id, device_id)
);

CREATE INDEX idx_device_sessions_device ON device_sessions(device_id, session_id);
CREATE INDEX idx_device_sessions_session ON device_sessions(session_id);
