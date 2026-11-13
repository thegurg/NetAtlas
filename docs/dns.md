# NetAtlas DNS diagnostics

Status: Phase 4 implemented (raw queries, resolver comparison, and measurement
history). Cryptographic DNSSEC validation is **not** implemented; see section 5.

## 1. What a DNS measurement is

A DNS measurement is one query of one name and record type sent to one resolver at one
time. It records:

- the normalized query name and record type;
- the resolver label and socket address;
- the transport actually used (`udp`, or `tcp` after a truncated UDP response);
- the outcome (`response`, `timeout`, `transport_error`, `cancelled`);
- elapsed milliseconds and the number of attempts;
- the RCODE, header flags, answer and authority records, and section counts;
- TTLs for every supported record;
- explicit DNSSEC-related observations (DO bit, AD flag, RRSIG presence, EDNS presence).

A DNS response is a measurement, not a claim that a name is correct or that a device is
reachable. Cached answers, split-horizon DNS, and resolver policy can all produce
different but legitimate results.

## 2. Commands

```bash
# Query the first system resolver for A and AAAA (the default).
netatlas dns query example.com

# Query selected types against one explicit resolver.
netatlas dns query example.com --type A,AAAA --resolver 1.1.1.1

# Query a non-default port over TCP.
netatlas dns query example.com --type MX --resolver 192.0.2.53:5353 --tcp

# Compare two resolvers for the same name and record types.
netatlas dns compare example.com --type A --resolver system --resolver 1.1.1.1

# Inspect stored measurements.
netatlas dns history --name example.com --type A --limit 20
```

Every command supports `--json`. `--no-save` prevents a query or comparison from being
written to the database.

### Record types

`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, and `SOA`. The default is `A,AAAA`. The
`--type` option is repeatable and accepts comma-separated values; duplicate types are
queried once.

### Resolver syntax

`--resolver` accepts:

- `system` — use the first resolver from the system configuration;
- an IPv4 or IPv6 address (port 53);
- `IP:PORT`;
- `[IPv6]:PORT`.

When `--resolver` is omitted, the resolver list is read from the system configuration
(`/etc/resolv.conf` through hickory). Multiple system resolvers are queried in order and
labelled `system`, `system[1]`, and so on. Duplicate socket addresses are removed.

`compare` requires at least two distinct resolvers. It does not silently fall back to
two public resolvers.

### Bounds and cancellation

- `--timeout-ms` sets the per-attempt timeout (default from configuration, 1500 ms).
- `--attempts` sets the number of exchange attempts per query (default 1).
- `--concurrency` bounds concurrent queries (default from configuration).
- Ctrl-C cancels outstanding queries; in-flight queries are reported as `cancelled`.
- A truncated UDP response triggers one bounded TCP retry.

## 3. Output

Text output shows, per measurement:

- the query name and type;
- resolver, transport, elapsed time, and attempts;
- the RCODE and header flags (`aa`, `tc`, `rd`, `ra`, `ad`, `cd`);
- answer records with type, TTL, and value;
- authority records when present;
- the DNSSEC observation state.

`dns compare` additionally reports, per record type:

- how many resolvers responded, failed, or were cancelled;
- whether the comparison is available (at least two responses);
- whether RCODEs agree;
- whether answer sets agree;
- whether TTLs varied;
- whether DNSSEC-related response fields varied;
- notes explaining every difference.

Answer-set equality ignores TTL and DNS name case. TTL variation is reported separately
because caching legitimately changes TTLs.

`dns history` prints one row per stored measurement with time, name, type, resolver
label, resolver address, transport, outcome, RCODE, and elapsed time.

## 4. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every query produced a DNS response. NXDOMAIN, SERVFAIL, and REFUSED are valid responses. |
| 1 | Every query failed at the transport level (timeout, socket/framing error, or cancellation). |
| 2 | Usage error: invalid name, record type, resolver, timeout, attempts, or too few resolvers for `compare`. |
| 3 | Some queries produced a DNS response and some failed or were cancelled. |
| 4 | Reserved for not-found results in other commands. |

A DNS response is never treated as a transport failure merely because its RCODE is an
error code.

## 5. DNSSEC state

The current client sets the EDNS DNSSEC OK (DO) bit by default (`--no-dnssec-ok`
disables it) and records:

- `do_bit` — whether this client requested DNSSEC records;
- `ad_flag` — the resolver's Authentic Data claim;
- `rrsig_present` — whether an RRSIG record appeared in the response;
- `response_edns` — whether the response contained an EDNS OPT record;
- `validation` — always `not_performed` today.

**No cryptographic validation is performed.** The AD bit and the presence of RRSIG
records are observations about the response, not a local chain-of-trust validation. The
`secure`, `insecure`, `bogus`, and `indeterminate` states are reserved for a future
validator and are never inferred from the response.

## 6. Persistence

Migration `0003_dns` adds `dns_measurements`. Each row stores the query, resolver,
transport, outcome, RCODE, timing, attempts, response JSON, DNSSEC observation JSON, and
error text. Transport failures are stored too, so a timeout is visible in history.

History begins with the first measurement recorded after migration `0003_dns`. There is
no retention or pruning job yet.

## 7. Limitations

- No DNSSEC cryptographic validation, trust-anchor management, or chain-of-trust
  reporting.
- No DNS-over-TLS, DNS-over-HTTPS, or proxy support.
- No recursive walk of CNAME chains; the response is reported as received.
- Only the record types listed above are modelled. Other record types are counted in the
  section totals but not displayed.
- `system` uses the first configured resolver for `--resolver system`; use repeated
  `--resolver` values to compare multiple system resolvers.
- No scheduled or continuous DNS monitoring yet.
- Measurements reflect one moment and one resolver. A difference is not automatically a
  misconfiguration; a match is not proof of correctness.
- No live-network tests run during `cargo test`; tests use local mock UDP/TCP servers.
