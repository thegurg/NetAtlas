# NetAtlas device identification strategy

Status: Phase 2 implements identity resolution plus evidence and inference for
manufacturer, category, OS family, and model from the IEEE OUI registry, mDNS,
SSDP/UPnP descriptions, NetBIOS names, and bounded TCP service banners. It does not
implement TLS inspection, SSH host-key capture, TCP/IP stack fingerprinting, or exact OS
version identification.

## 1. Objective

Produce an honest, inspectable device profile from LAN evidence. The measure of success
is not how many fields are filled in, but whether each filled field is justified and
each empty field explains why it is empty.

A device that is discovered but remains unidentified is **not** a successful
identification result. It is a correctly reported limitation.

## 2. Pipeline

```
observations (facts)
   |
   v
identity resolution  -> which logical device does this observation belong to?
   |
   v
evidence extraction  -> which property does this observation support?
   |
   v
independence grouping -> collapse correlated fields from one exchange
   |
   v
aggregation          -> candidate value, confidence, status
   |
   v
conflict detection   -> keep competing candidates, mark conflicted
   |
   v
profile + explanation -> CLI/TUI fields with evidence links and unknown reasons
```

The identification engine is a pure function over observations, a clock, an OUI index,
and a provider-availability snapshot. It performs no I/O and is tested entirely from
fixtures. The discovery orchestrator decides which providers run and passes the result
to the pure identification layer.

## 3. Evidence classes and reliability

Base strengths are deliberately conservative. `—` means the source is not used for that
property.

| Source | Manufacturer | Category | OS | Model | Implementation |
| --- | --- | --- | --- | --- | --- |
| Neighbour table / ARP | — | — | — | — | Identity and presence only |
| ICMP echo reply | — | — | — | — | Presence and RTT only; TTL is not an OS signal |
| Reverse DNS PTR | — | — | — | — | Naming hint only; may be stale or user-controlled |
| mDNS service type | — | medium | — | — | `_ipp._tcp` suggests a printer, but the device controls the claim |
| mDNS TXT records | low | — | low | low | Only explicit fields (`manufacturer=`, `model=`, `os=`, `osxvers=`) count |
| mDNS instance/host name | — | — | — | — | Naming hint; strong as an *identifier*, weak as a property |
| SSDP/UPnP description | medium | medium | — | medium | Self-reported; all fields from one description are one source unit |
| NetBIOS name/workgroup | — | — | — | — | Naming claim; recorded as an identifier, never property evidence |
| Open TCP port | — | — | — | — | A port is not proof of a product or category |
| HTTP `Server` header | — | — | low | — | Product/version stored as service metadata; only explicit OS hints become evidence |
| SSH banner | — | — | low | — | OS family only, never exact version |
| FTP/SMTP banner | — | — | low | — | OS family only; product/version stored as service metadata |
| TLS certificate subject/SAN | — | — | — | — | Not implemented; reserved as a future identity fingerprint |
| OUI registry | medium | — | — | — | Address-block association, not device ownership or model |
| TCP/IP stack fingerprint | — | — | — | — | Not implemented; never inferred from TTL alone |

`high` is never assigned from a single self-reported field. See the aggregation rubric.

**Phase 2 implementation:** OUI, mDNS, SSDP/UPnP, and service-banner OS hints are active.
Service product and version strings are persisted as service metadata but are not promoted
to manufacturer or model evidence. NetBIOS names are identifiers only.

## 4. Property rules

### 4.1 Manufacturer / vendor

- OUI lookup yields a **manufacturer association** with `medium` confidence. The UI
  labels it as an OUI association; it is not proof of the device's manufacturer or
  owner.
- If the MAC is locally administered, no OUI claim is made. The device detail shows
  `locally_administered_mac` and manufacturer stays `unknown` unless independent
  evidence (e.g. an explicit UPnP manufacturer field) exists.
- An explicit UPnP `manufacturer` field is `medium` evidence. An mDNS TXT
  `manufacturer`/`vendor` field is `low` evidence.
- If OUI association and an explicit protocol field agree after normalization,
  confidence becomes `high` and the rationale lists both source units.
- If they disagree, both values are preserved and the property is `conflicted`.
- Manufacturer candidates are normalized for case, punctuation, and common corporate
  suffixes (`Inc`, `Ltd`, `LLC`, `GmbH`, ...) so `Example Networks, Inc.` and
  `example networks` do not produce a false conflict.
- A model is never derived from OUI data.

### 4.2 Device category

Category evidence is supplied by UPnP `deviceType` and by a small set of unambiguous
mDNS service types:

- UPnP: `MediaRenderer` -> `media_renderer`, `MediaServer` -> `media_server`,
  `InternetGatewayDevice`/`WANDevice` -> `router`, `Printer` -> `printer`,
  `Scanner` -> `scanner`, `DigitalSecurityCamera` -> `camera`,
  `BinaryLight`/`DimmableLight` -> `smart_light`, `Thermostat` -> `thermostat`,
  `ZonePlayer` -> `speaker`, `MediaPlayer` -> `media_player`,
  `Television` -> `television`.
- mDNS: `_ipp`/`_ipps`/`_printer`/`_pdl-datastream` -> `printer`,
  `_airplay`/`_googlecast` -> `media_renderer`, `_raop` -> `speaker`,
  `_hap`/`_matter` -> `iot`.

Rules:

- Both mappings are `medium` confidence because the device controls the claim.
- Open ports alone never establish a category. A host with port 22 is not classified as
  a server.
- Hostname keywords ("iphone", "printer") are not used at all.
- Two independent sources that agree may raise confidence to `high`.
- Conflicting categories remain conflicting; NetAtlas does not pick the more flattering
  one.

### 4.3 Operating system

- OS is `unknown` by default.
- SSH, FTP, SMTP, and HTTP banners can support an OS *family* at `low` confidence when
  the string is explicit (`OpenSSH ... Ubuntu`, `Apache/2.4.58 (Ubuntu)`).
- mDNS TXT `os`/`osversion` can support a family at `low`; `osxvers` is treated as a
  macOS hint.
- OS candidates are canonicalized to broad families (`Linux`, `Windows`, `macOS`,
  `FreeBSD`, `OpenBSD`, `NetBSD`) so `Ubuntu` and `Linux` do not appear as a false
  conflict.
- TTL is never used as an OS signal.
- TCP/IP stack fingerprinting is deferred. If added, it must be validated against a
  controlled fixture set and may only report a family with `medium` confidence.
- Exact OS versions are reported only as service/banner metadata, not as a verified OS
  version.

### 4.4 Model

- The model is `unknown` unless a protocol explicitly exposes it: UPnP `modelName` /
  `modelNumber`, or mDNS TXT `model`/`modelName`/`modelNumber`.
- An explicit model is `medium` from UPnP and `low` from mDNS because it is
  self-reported.
- It becomes `high` only when an independent identifier or manufacturer association
  agrees with the claimed manufacturer.
- NetAtlas never infers a phone or PC model from a MAC address, OUI, port set, hostname,
  or service product string.

### 4.5 Services

Service observations are recorded as their own records (port, transport, protocol,
product, version, banner, source, timestamp, details). A service observation can support
a device property, but service identity and device identity remain separate concepts.

- Probes are bounded and plain-text only: HTTP `HEAD`, and server-first banners for SSH,
  FTP, and SMTP. Ports: 21, 22, 25, 80, 8080.
- Service probes run only against hosts that already answered discovery. Discovery does
  not become an unrequested full port scan.
- HTTP redirects are not followed, credentials are never sent, and TLS-only services are
  not probed because a useful banner cannot be obtained without a TLS stack.
- Product/version strings and raw banners are self-reported service metadata. They are
  not used to assert device manufacturer or model.
- mDNS resolved services and UPnP descriptions are also persisted as service records so
  the service inventory and the evidence graph agree.

## 5. Independence and aggregation

### 5.1 Source units

Each evidence row has a `source_unit`. Examples:

- One SSDP description: `ssdp:<udn>:description:<sha256>` — all fields from it are one
  unit, even if they support different properties.
- One mDNS response: `mdns:<instance-fullname>`.
- One service exchange: `service:<ip>:<port>`.
- One OUI database version: `oui:<prefix>:<db-version>`.
- One ICMP exchange: `icmp:<address>:<session>`.

Agreement between two fields from the same unit does not raise confidence. The
implementation reuses the exchange's base `source_unit` for every field it extracts.

### 5.2 Rubric

1. Compute the strongest base strength among fresh, non-conflicting evidence.
2. If at least two **independent** units agree, raise one level (maximum `high`).
3. If independent units disagree, keep all candidates, set status `conflicted`, and
   lower the displayed confidence one level.
4. Weak-only evidence yields at most `low`.
5. Expired evidence yields `unknown` with reason `stale_evidence`.
6. A property with no evidence yields `unknown` with a reason from section 7.

No numeric score is shown. Confidence is a qualitative label with a rationale.

## 6. Identity resolution (summary)

Full rules are in `docs/data-model.md` section 3. Key points:

- Strong identifiers (UPnP UDN, mDNS instance name) link devices ahead of MAC. A UDN or
  mDNS instance observed on two addresses in one scan is one device.
- If a strong identifier matches one stored device and the MAC matches another, the
  strong identifier wins and the MAC conflict is preserved as an `uncertain` link with
  basis `strong_identifier_conflict`.
- Global MAC links within a freshness window.
- IP alone never merges; address reuse creates a separate device and an event.
- Hostname and NetBIOS name alone never merge.
- Ambiguous matches create an `uncertain` link, not a merge.
- Locally administered MACs are weak identity evidence and never OUI evidence.
- SSH host keys and TLS certificate fingerprints are reserved identifier kinds but are
  not captured yet.

## 7. Unknown reasons

Every `unknown` property carries one of:

| Reason | Meaning |
| --- | --- |
| `no_evidence` | At least one relevant provider ran, but no observation supports the property |
| `provider_unavailable` | Every provider that could supply evidence for this property was disabled or failed |
| `insufficient_permissions` | The method requires a capability the process lacks |
| `client_isolation_suspected` | Peer discovery returned almost nothing; network may isolate clients |
| `device_sleeping` | Device responded earlier but not in this window |
| `conflicting_evidence` | Sources disagree; values are preserved separately |
| `unsupported_protocol` | Device exposes no protocol NetAtlas can interpret |
| `model_not_exposed` | Category/OS known, but no model-specific field exists |
| `locally_administered_mac` | OUI cannot be applied to this address |
| `stale_evidence` | Prior evidence exists but is outside its freshness window |

Phase 2 distinguishes `provider_unavailable` from `no_evidence` using the scan's provider
reports. A disabled or failed mDNS/SSDP provider produces `provider_unavailable` for
category and model; a provider that ran and found nothing produces `no_evidence`. The UI
shows the reason and, where useful, what authorized data source could improve
identification. It does not imply that the source is available or permitted.

## 8. Profile output contract

A device detail view/JSON object includes:

```text
id, label, first_seen, last_seen
identifiers[]        kind, value, source, first/last seen
addresses[]          ip, segment, first/last seen
manufacturer         value, confidence, status, evidence[], unknown_reason?
category             value, confidence, status, evidence[], unknown_reason?
os                   value, confidence, status, evidence[], unknown_reason?
model                value, confidence, status, evidence[], unknown_reason?
services[]           port, transport, protocol, product, version, banner, source, observed_at
evidence[]           property, candidate, source, source_unit, confidence, rationale, observed_at
conflicts[]          property, candidates[], sources[]
sessions[]           scan session references
```

Every conclusion is expandable to the evidence rows that produced it. Evidence rows
link back to observations with their raw/normalized values. A scan result also carries
`services[]` and per-provider reports so the same data is visible before and after
persistence.

## 9. Acceptance tests (fixtures, no live network)

The identification milestone is complete only when these scenarios pass deterministically.
The status column records what Phase 2 covers; `deferred` scenarios are not claimed as
working functionality.

| # | Scenario | Expected | Phase 2 status |
| --- | --- | --- | --- |
| 1 | ARP/neighbour entry only, globally administered MAC | Device exists; manufacturer from OUI `medium`; category/OS/model `unknown` with `no_evidence` | Implemented |
| 2 | UPnP media-renderer fixture with manufacturer + model + deviceType | Manufacturer/model/category supported with source units and rationale | Implemented and tested |
| 3 | UPnP says media renderer, mDNS says printer | Category `conflicted`; both candidates retained; confidence lowered | Implemented by aggregation; covered by conflict tests |
| 4 | Locally administered MAC | No OUI manufacturer; reason `locally_administered_mac` | Implemented |
| 5 | Same IP, different MAC across sessions | Two devices; `address_reuse_suspected` event; no merge | Implemented |
| 6 | Same MAC, new IP | Same device; new IP identifier; history preserved | Implemented |
| 7 | Two fields from one SSDP description agree | Counted as one source unit; no confidence bump | Implemented by shared `source_unit` |
| 8 | OUI + explicit UPnP manufacturer agree | Manufacturer `high`, both units listed | Implemented and tested |
| 9 | OUI says vendor A, UPnP says vendor B | Manufacturer `conflicted`, both preserved | Implemented and tested |
| 10 | mDNS provider disabled | Other evidence still produces a profile; reason `provider_unavailable` | Implemented and tested |
| 11 | Evidence older than freshness window | Property `unknown` with `stale_evidence` | Implemented in inference aggregation |
| 12 | Hostname "iPhone" with no other evidence | Category at most `low`, not a confirmed smartphone | Implemented by absence: hostnames are not category evidence |
| 13 | TTL value only | OS stays `unknown`; TTL is not used as OS evidence | Implemented by absence: TTL is not collected |
| 14 | Duplicate hostname on two MACs | No merge; hostname identifier shared with conflict note | No-merge rule implemented; conflict note not yet surfaced |
| 15 | Malformed SSDP/mDNS fixture | Provider error recorded; no panic; other providers unaffected | Implemented for parsers; provider failures are isolated |

Additional property tests:

- Confidence aggregation is monotonic and capped; conflicting evidence never increases
  confidence. — implemented in `domain::inference` tests.
- `source_unit` grouping is stable and deterministic. — implemented in
  `domain::inference` tests.
- Every non-unknown inference has at least one evidence ID. — holds for the implemented
  paths.
- Every unknown inference has a reason. — implemented.
- Service observations survive a SQLite save/load round trip. — implemented in
  `infrastructure::storage` tests.
- Protocol responses count as host presence. — implemented in `application::discovery`
  tests.

## 10. Explicit non-goals

- Claiming a specific phone/PC model from OUI, open ports, or service product strings.
- Treating an open ADB-related port as proof of an Android phone.
- Reporting an OS from TTL alone.
- Merging devices because they share an IP, a hostname, a NetBIOS name, or a subnet.
- Presenting UPnP/mDNS self-descriptions as verified facts.
- Probing TLS-only services without a TLS stack or sending credentials.
- Hiding a conflict behind one "best" answer.
