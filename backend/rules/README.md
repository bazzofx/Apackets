# Vendored Suricata Rules

Bundled, offline rule sets for the built-in Suricata-compatible detection
engine. See `PROVENANCE.md` for upstream URLs, commit SHAs, licenses, counts.

## What is here

- `daffainfo/` — community CVE / CNVD / default-login / web-attack rules from
  [daffainfo/suricata-rules](https://github.com/daffainfo/suricata-rules)
  (Apache-2.0), upstream layout preserved (`http/cves/<year>/`, `http/cnvd/...`).
- `oisf/` — the Suricata engine's own app-layer and decoder event rules from
  [OISF/suricata](https://github.com/OISF/suricata) (GPL-2.0), copied flat.
- `local/` — **not vendored**: rules ShinboShark maintains itself. See
  [`local/` — the locally maintained correction layer](#local--the-locally-maintained-correction-layer).

The two vendored directories are **data files**, copied verbatim for offline
install; nothing here is fetched at runtime.

## How they are imported

Rule text is loaded from this directory into the `suricata_rules` table. The
backend seeds it automatically on first use, and seeding can also be triggered
explicitly with `POST /api/suricata/rules/seed`. Neither path contacts the
network.

## How rules are stored and managed

- Each rule is kept **verbatim** in its `raw` form alongside its parsed fields,
  keyed by Suricata `sid`; re-importing updates that SID, it does not duplicate.
- Every rule can be edited, disabled, or deleted individually in the UI. Local
  changes belong in the database, not in these files.
- Options the built-in matcher cannot evaluate are recorded as unsupported, so
  a rule is never silently half-matched.

## `local/` — the locally maintained correction layer

`local/` holds rules that ShinboShark maintains itself. It is the only place a
correction to a vendored rule belongs, and the only place that survives a
re-seed.

Corrections are written as **the same SID with corrected text**. The importer
upserts by SID, so a local rule supersedes the vendored rule it names — the
vendored file stays byte-identical to upstream and the provenance record stays
true, while the rule that actually runs is the corrected one. A local rule's
`source` is `bundled:local`, which is how the rules list shows that a rule is
locally maintained rather than vendored.

Each corrected rule carries a comment block naming the defect, the evidence and
why the replacement is safe; the full audit is in `RULE-AUDIT.md`.

Current contents:

| File | SIDs | Supersedes |
| --- | --- | --- |
| `local/linux-structures.rules` | 50200001–50200016 | `daffainfo/http/web-attacks/linux-structures.rules` |
| `local/path-traversal.rules` | 50500002 | `daffainfo/http/web-attacks/path-traversal.rules` |

## Adding your own rules

1. Drop a `.rules` file here (e.g. `backend/rules/local/my-rules.rules`) or
   anywhere on disk, with a unique `sid` per rule; duplicate SIDs overwrite.
2. Run `POST /api/suricata/rules/seed` again, then enable what you want in the
   rules list.
3. Do not edit the vendored upstream files in place — the next import would
   overwrite the change and break the provenance record. Put the correction in
   `local/` under the same SID instead.
