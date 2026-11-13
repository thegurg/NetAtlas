-- Phase 4 schema: DNS measurements.
-- Each row is one query to one resolver. Transport failures are recorded too.
-- DNSSEC validation state is explicit; the current client only emits not_performed.

CREATE TABLE dns_measurements (
    id               TEXT PRIMARY KEY,
    queried_at_ms    INTEGER NOT NULL,
    resolver_label   TEXT NOT NULL,
    resolver_address TEXT NOT NULL,
    query_name       TEXT NOT NULL,
    record_type      TEXT NOT NULL,
    transport        TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
    outcome          TEXT NOT NULL
                     CHECK (outcome IN ('response','timeout','transport_error','cancelled')),
    rcode            INTEGER,
    elapsed_ms       INTEGER NOT NULL,
    attempts         INTEGER NOT NULL,
    response_json    TEXT,
    dnssec_json      TEXT NOT NULL,
    error            TEXT
);
CREATE INDEX idx_dns_measurements_time ON dns_measurements(queried_at_ms DESC);
CREATE INDEX idx_dns_measurements_query ON dns_measurements(query_name, record_type);
CREATE INDEX idx_dns_measurements_resolver ON dns_measurements(resolver_label, resolver_address);
