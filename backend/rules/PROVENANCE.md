# Rule Set Provenance

This directory vendors third-party Suricata rule sets so the application can
import them **offline**. The files below were copied verbatim from shallow
upstream clones; no content was reformatted, re-encoded, or re-wrapped, and
line endings are byte-identical to upstream.

**Provenance recorded on:** 2026-10-11

## Summary

| Source | Upstream | Commit | License | `.rules` files | Bytes | Rule lines |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `daffainfo/` | https://github.com/daffainfo/suricata-rules | `23bfba7e688fdf5fadd8e378f070dae843e14263` | Apache-2.0 | 252 | 506,213 | 1,167 |
| `oisf/` | https://github.com/OISF/suricata | `4badfd13f43e112dd61c5cbab5718765512ed5ad` | GPL-2.0 | 32 | 108,872 | 448 |
| **Total** | | | | **284** | **615,085** | **1,615** |

"Bytes" is the summed size of the copied `.rules` files only; it excludes the
license files. "Rule lines" counts lines matching
`^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s` across those files
(header/blank lines within a multi-line rule body are not counted separately).

## daffainfo/suricata-rules — Apache-2.0

- **Upstream:** https://github.com/daffainfo/suricata-rules
- **Commit SHA:** `23bfba7e688fdf5fadd8e378f070dae843e14263`
- **License:** Apache License 2.0 — see `daffainfo/LICENSE`
- **Files copied:** 252 `.rules` files, 506,213 bytes, 1,167 rule lines
- **Structure:** relative subdirectory layout preserved from upstream, e.g.
  - `http/cves/<year>/CVE-<year>.rules` (years 2000, 2002, 2004–2026)
  - `http/cnvd/<year>/CNVD-<year>.rules` (2017–2024)
  - `http/default-logins/` (127 files)
  - `http/web-attacks/` (14 files)
  - `http/vulnerabilities/<product>/`
  - `http/tools/`, `http/miscellaneous/`
- Only `*.rules` files and `LICENSE` were copied. Upstream's `main.py`,
  `README.md` and `.github/` were intentionally **not** vendored.

## OISF/suricata — GPL-2.0

- **Upstream:** https://github.com/OISF/suricata
- **Commit SHA:** `4badfd13f43e112dd61c5cbab5718765512ed5ad`
- **License:** GNU General Public License v2 — see `oisf/COPYING` and
  `oisf/LICENSE` (both present upstream and both copied; they are identical
  files, 18,431 bytes each)
- **Files copied:** 32 `.rules` files, 108,872 bytes, 448 rule lines
- **Structure:** flattened — upstream's `rules/` directory was copied directly
  into `oisf/` with no nesting. These are the engine's own app-layer and
  decoder event rules (`app-layer-events.rules`, `decoder-events.rules`,
  `http-events.rules`, `stream-events.rules`, `tls-events.rules`, etc.), with
  SIDs in the `22xxxxx` range.

## Local corrections (not vendored)

`local/` is **ShadowPackets's own rule layer**, not upstream data. It is excluded from
the vendored counts above and carries no third-party licence.

It exists so a defective vendored rule can be corrected without editing the
vendored file: a correction is written under the **same SID**, and the importer's
upsert makes it supersede the vendored text at seed time. The vendored files
therefore remain byte-identical to the commits recorded above, and the counts in
this document stay true.

| Added | File | SIDs | Rule lines | Supersedes |
| --- | --- | --- | ---: | --- |
| 2026-10-11 | `local/linux-structures.rules` | 50200001–50200016 | 16 | `daffainfo/http/web-attacks/linux-structures.rules` |
| 2026-10-11 | `local/path-traversal.rules` | 50500002 | 1 | `daffainfo/http/web-attacks/path-traversal.rules` |

With the local layer present, one seed imports **286 files / 1,632 rule lines**
into **1,615 distinct SIDs** — the same SID inventory as the vendored set alone,
because every local rule replaces a vendored rule rather than adding one. The
audit behind these corrections, the packet-level evidence and the before/after
test results are in `RULE-AUDIT.md`.

## Licensing notes

- The two rule sets carry **different, incompatible-in-detail licenses**
  (Apache-2.0 vs GPL-2.0). Each license text is kept next to the rules it
  covers, in its own source directory. If these files are redistributed or
  bundled into a release artifact, keep both license texts alongside them.
- Rule text originates from third parties and is reproduced unmodified.
  Any local edit should be made in the application's rule store, not here.

## Vendored data — offline import only

These files are vendored **data**, not code. They exist so the application can
seed its rule inventory without network access.

> **The application must never fetch rules from the network at runtime.**
> There is no runtime download, update check, or remote sync of rule content.
> Imported rule text is read from this directory (or supplied by the user);
> everything else — editing, disabling, deleting, severity overrides — happens
> locally in the application database.
