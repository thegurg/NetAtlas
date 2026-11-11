# NetAtlas device identification strategy

Status: Phase 0 design. Not implemented yet.

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

The identification engine is a pure function over observations, a clock, and the OUI
index. It performs no I/O and is tested entirely from fixtures.

## 3. Evidence classes and reliability

Base strengths are deliberately conservative. `—` means the source must not be used
for that property.

| Source | Manufacturer | Category | OS | Model | Notes |
| --- | --- | --- | --- | --- | --- |
| Neighbour table / ARP | — | — | — | — | Identity and presence only |
| ICMP echo reply | — | — | — | — | Presence and RTT only; TTL is not an OS signal |
| Reverse DNS PTR | — | low | — | — | Naming hint only; may be stale or user-controlled |
| mDNS service type | — | medium | low | — | `_ipp._tcp` suggests a printer, but the device controls the claim |
| mDNS TXT records | medium | low | low | medium | Only explicit fields (`model=`, `manufacturer=`) count |
| mDNS instance/host name | — | low | — | — | Naming hint; strong as an *identifier*, weak as a property |
| SSDP/UPnP description | medium | medium | low | medium | Self-reported; fields from one description are one source unit |
| NetBIOS name/workgroup | — | low | low | — | Legacy naming hints; easily spoofed or stale |
| Open TCP port | — | low | — | — | A port is not proof of a product or category |
| HTTP `Server` header | low | low | low | low | Product/version claim; often stripped or wrong |
| SSH banner | low | low | medium | — | Banner is self-reported; OS family only, never exact version |
| TLS certificate subject/SAN | low | — | — | — | Useful as an identity fingerprint, not a category |
| OUI registry | medium | — | — | — | Address-block association, not device ownership or model |
| TCP/IP stack fingerprint | — | — | medium* | — | *Only after validation; never from TTL alone |

`high` is never assigned from a single self-reported field. See the aggregation rubric.

## 4. Property rules

### 4.1 Manufacturer / vendor

- OUI lookup yields a **manufacturer association** with `medium` confidence. The UI
  labels it as an OUI association; it is not proof of the device's manufacturer or
  owner.
- If the MAC is locally administered, no OUI claim is made. The device detail shows
  `locally_administered_mac` and manufacturer stays `unknown` unless independent
  evidence (e.g. an explicit UPnP manufacturer field) exists.
- If OUI association and an explicit protocol field agree, confidence becomes `high`
  and the rationale lists both source units.
- If they disagree, both values are preserved and the property is `conflicted`.
- A model is never derived from OUI data.

### 4.2 Device category

Candidate categories:

`smartphone`, `tablet`, `laptop`, `desktop`, `server`, `router`, `access_point`,
`printer`, `smart_tv`, `media_renderer`, `speaker`, `camera`, `iot`,
`network_equipment`, `virtual_machine`, `unknown`.

Rules:

- UPnP `deviceType` maps to a category only when the mapping is unambiguous
  (`MediaRenderer` -> `media_renderer`, `Printer` -> `printer`,
  `InternetGatewayDevice` -> `router`).
- mDNS service types can support a category (`_ipp._tcp` -> printer) at `medium`.
- Open ports alone never establish a category. A host with port 22 is not classified as
  a server.
- Hostname keywords ("iphone", "printer") are at most `low`, and only alongside another
  hint.
- Two independent sources that agree may raise confidence to `high`.
- Conflicting categories remain conflicting; NetAtlas does not pick the more flattering
  one.

### 4.3 Operating system

- OS is `unknown` by default.
- SSH/HTTP banners can support an OS *family* at `medium` when the string is explicit
  (`OpenSSH ... Ubuntu`, `Server: Microsoft-IIS`).
- UPnP `modelDescription` or mDNS TXT may support a family at `low`.
- TTL is never used as an OS signal. It is recorded as a measurement of hop distance at
  most.
- TCP/IP stack fingerprinting is deferred. If added, it must be validated against a
  controlled fixture set and may only report a family with `medium` confidence.
- Exact OS versions are reported only as service/banner metadata, not as a verified OS
  version.

### 4.4 Model

- The model is `unknown` unless a protocol explicitly exposes it: UPnP `modelName` /
  `modelNumber`, mDNS TXT `model`, or a product string in a service description.
- An explicit model is `medium` by default because it is self-reported.
- It becomes `high` only when an independent identifier or manufacturer association
  agrees with the claimed manufacturer.
- NetAtlas never infers a phone model from a MAC address, OUI, port set, or hostname.

### 4.5 Services

Services are recorded as their own observations (port, transport, protocol, product,
version, banner, TLS metadata, source, timestamp). A service observation can support a
device property, but service identity and device identity remain separate concepts.

## 5. Independence and aggregation

### 5.1 Source units

Each evidence row has a `source_unit`. Examples:

- One SSDP description: `ssdp:<udn>:description:<sha256>` — all fields from it are one
  unit, even if they support different properties.
- One mDNS response: `mdns:<instance>:<record-type>`.
- One OUI database version: `oui:<prefix>:<db-version>`.
- One ICMP exchange: `icmp:<address>:<session>`.

Agreement between two fields from the same unit does not raise confidence.

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

- Strong identifiers (UPnP UDN, host key, certificate fingerprint, mDNS instance) link
  directly.
- Global MAC links within a freshness window.
- IP alone never merges; address reuse creates a separate device and an event.
- Hostname alone never merges.
- Ambiguous matches create an `uncertain` link, not a merge.
- Locally administered MACs are weak identity evidence and never OUI evidence.

## 7. Unknown reasons

Every `unknown` property carries one of:

| Reason | Meaning |
| --- | --- |
| `no_evidence` | No observation supports the property |
| `provider_unavailable` | The method that could supply evidence did not run or failed |
| `insufficient_permissions` | The method requires a capability the process lacks |
| `client_isolation_suspected` | Peer discovery returned almost nothing; network may isolate clients |
| `device_sleeping` | Device responded earlier but not in this window |
| `conflicting_evidence` | Sources disagree; values are preserved separately |
| `unsupported_protocol` | Device exposes no protocol NetAtlas can interpret |
| `model_not_exposed` | Category/OS known, but no model-specific field exists |
| `locally_administered_mac` | OUI cannot be applied to this address |
| `stale_evidence` | Prior evidence exists but is outside its freshness window |

The UI shows the reason and, where useful, what authorized data source could improve
identification (for example: "UPnP description not available; enabling SSDP may help").
It does not imply that the source is available or permitted.

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
link back to observations with their raw/normalized values.

## 9. Acceptance tests (fixtures, no live network)

The identification milestone is complete only when these scenarios pass deterministically.

| # | Scenario | Expected |
| --- | --- | --- |
| 1 | ARP/neighbour entry only, globally administered MAC | Device exists; manufacturer from OUI `medium`; category/OS/model `unknown` with `no_evidence` |
| 2 | UPnP media-renderer fixture with manufacturer + model + deviceType | Manufacturer/model/category supported with source units and rationale |
| 3 | UPnP says media renderer, mDNS says printer | Category `conflicted`; both candidates retained; confidence lowered |
| 4 | Locally administered MAC | No OUI manufacturer; reason `locally_administered_mac` |
| 5 | Same IP, different MAC across sessions | Two devices; `address_reuse_suspected` event; no merge |
| 6 | Same MAC, new IP | Same device; new IP identifier; history preserved |
| 7 | Two fields from one SSDP description agree | Counted as one source unit; no confidence bump |
| 8 | OUI + explicit UPnP manufacturer agree | Manufacturer `high`, both units listed |
| 9 | OUI says vendor A, UPnP says vendor B | Manufacturer `conflicted`, both preserved |
| 10 | mDNS provider disabled | Other evidence still produces a profile; session `partial`; reason `provider_unavailable` |
| 11 | Evidence older than freshness window | Property `unknown` with `stale_evidence` |
| 12 | Hostname "iPhone" with no other evidence | Category at most `low`, not a confirmed smartphone |
| 13 | TTL value only | OS stays `unknown`; TTL is not used as OS evidence |
| 14 | Duplicate hostname on two MACs | No merge; hostname identifier shared with conflict note |
| 15 | Malformed SSDP/mDNS fixture | Provider error recorded; no panic; other providers unaffected |

Additional property tests:

- Confidence aggregation is monotonic and capped; conflicting evidence never increases
  confidence.
- `source_unit` grouping is stable and deterministic.
- Every non-unknown inference has at least one evidence ID.
- Every unknown inference has a reason.
- Serialization round-trip preserves evidence and status.

## 10. Explicit non-goals

- Claiming a specific phone/PC model from OUI or open ports.
- Treating an open ADB-related port as proof of an Android phone.
- Reporting an OS from TTL alone.
- Merging devices because they share an IP, a hostname, or a subnet.
- Presenting UPnP/mDNS self-descriptions as verified facts.
- Hiding a conflict behind one "best" answer.
