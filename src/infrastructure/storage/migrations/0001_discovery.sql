-- Phase 1 schema: network context, discovery, identity, evidence, and OUI.
-- All timestamps are UTC milliseconds since the Unix epoch.

CREATE TABLE interfaces (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    index_no      INTEGER,
    mac           TEXT,
    mtu           INTEGER,
    is_up         INTEGER NOT NULL,
    is_loopback   INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);

CREATE TABLE interface_addresses (
    id            TEXT PRIMARY KEY,
    interface_id  TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    address       TEXT NOT NULL,
    prefix_len    INTEGER NOT NULL,
    family        INTEGER NOT NULL,
    scope         TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);
CREATE INDEX idx_ifaddr_interface ON interface_addresses(interface_id);

CREATE TABLE network_segments (
    id            TEXT PRIMARY KEY,
    interface_id  TEXT NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    prefix        TEXT NOT NULL,
    gateway       TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    UNIQUE(interface_id, prefix)
);

CREATE TABLE scan_sessions (
    id            TEXT PRIMARY KEY,
    scope_json    TEXT NOT NULL,
    methods_json  TEXT NOT NULL,
    config_json   TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER,
    status        TEXT NOT NULL
                  CHECK (status IN ('running','completed','partial','cancelled','failed','interrupted')),
    errors_json   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_sessions_started ON scan_sessions(started_at_ms);

CREATE TABLE devices (
    id            TEXT PRIMARY KEY,
    label         TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    merged_into   TEXT REFERENCES devices(id)
);

CREATE TABLE device_identifiers (
    id            TEXT PRIMARY KEY,
    device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    value         TEXT NOT NULL,
    normalized    TEXT NOT NULL,
    source        TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    confidence    TEXT NOT NULL CHECK (confidence IN ('high','medium','low','unknown')),
    details_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_ident_lookup ON device_identifiers(kind, normalized, last_seen_ms);
CREATE INDEX idx_ident_device ON device_identifiers(device_id, last_seen_ms);

CREATE TABLE identity_links (
    id             TEXT PRIMARY KEY,
    from_device_id TEXT NOT NULL REFERENCES devices(id),
    to_device_id   TEXT NOT NULL REFERENCES devices(id),
    basis          TEXT NOT NULL,
    confidence     TEXT NOT NULL CHECK (confidence IN ('high','medium','low','unknown')),
    status         TEXT NOT NULL CHECK (status IN ('accepted','rejected','uncertain')),
    rationale      TEXT NOT NULL,
    created_at_ms  INTEGER NOT NULL,
    CHECK (from_device_id <> to_device_id)
);

CREATE TABLE observations (
    id             TEXT PRIMARY KEY,
    session_id     TEXT REFERENCES scan_sessions(id),
    subject_type   TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    property       TEXT,
    value_json     TEXT NOT NULL,
    source         TEXT NOT NULL,
    method         TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    expires_at_ms  INTEGER,
    details_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_obs_subject ON observations(subject_type, subject_id, observed_at_ms);
CREATE INDEX idx_obs_session ON observations(session_id);

CREATE TABLE evidence (
    id             TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    property       TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    source         TEXT NOT NULL,
    source_unit    TEXT NOT NULL,
    confidence     TEXT NOT NULL CHECK (confidence IN ('high','medium','low','unknown')),
    rationale      TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    expires_at_ms  INTEGER
);
CREATE INDEX idx_evidence_device_prop ON evidence(device_id, property, observed_at_ms);
CREATE INDEX idx_evidence_unit ON evidence(source_unit);

CREATE TABLE inferences (
    id                TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    property          TEXT NOT NULL,
    value_json        TEXT,
    confidence        TEXT NOT NULL CHECK (confidence IN ('high','medium','low','unknown')),
    status            TEXT NOT NULL CHECK (status IN ('supported','conflicted','unknown')),
    rationale         TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    unknown_reason    TEXT,
    computed_at_ms    INTEGER NOT NULL
);
CREATE INDEX idx_inference_device ON inferences(device_id, property, computed_at_ms);

CREATE TABLE services (
    id             TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL,
    port           INTEGER NOT NULL,
    transport      TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
    protocol       TEXT,
    product        TEXT,
    version        TEXT,
    banner         TEXT,
    tls_json       TEXT,
    source         TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    details_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_services_device ON services(device_id, observed_at_ms);

CREATE TABLE oui_sources (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    version        TEXT,
    source_url     TEXT,
    content_sha256 TEXT NOT NULL,
    imported_at_ms INTEGER NOT NULL,
    record_count   INTEGER NOT NULL
);

CREATE TABLE oui_prefixes (
    prefix_hex   TEXT NOT NULL,
    prefix_bits  INTEGER NOT NULL,
    organization TEXT NOT NULL,
    source_id    TEXT NOT NULL REFERENCES oui_sources(id) ON DELETE CASCADE,
    PRIMARY KEY (prefix_hex, prefix_bits, source_id)
);
CREATE INDEX idx_oui_lookup ON oui_prefixes(prefix_bits, prefix_hex);
