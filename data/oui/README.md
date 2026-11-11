# Vendored IEEE OUI registry snapshot

Retrieved on 2026-11-11 from the IEEE Registration Authority:

| File | Registry | Prefix bits | Source | SHA-256 |
| --- | --- | --- | --- | --- |
| `oui.csv` | MA-L | 24 | https://standards-oui.ieee.org/oui/oui.csv | `43c2346afbbbe824cb02c58815a8ba23cae95b9153ae849ef29a97cdf6f271da` |
| `mam.csv` | MA-M | 28 | https://standards-oui.ieee.org/oui28/mam.csv | `161e9a5f51bac5463d0a8e41c9789f4926b8f0fd64232eac14d2e86f22294388` |
| `oui36.csv` | MA-S | 36 | https://standards-oui.ieee.org/oui36/oui36.csv | `898bfc0a6e10405e0030b824c73bd5dd01103fca64d82cb8b02a10e8179ea483` |

These files are embedded into the binary as a fallback snapshot. NetAtlas records the
source name, retrieval version, import time, and content hash in the `oui_sources`
table. `netatlas oui import <file>` can replace the active database from a newer IEEE
file.

The CSV columns are `Registry,Assignment,Organization Name,Organization Address`.
Lookup is longest-prefix match (36, then 28, then 24 bits).

Attribution: the registry data is published by the IEEE Registration Authority. OUI
data identifies address-block assignments; it does not identify a device model, owner,
or necessarily the manufacturer of the finished product.
