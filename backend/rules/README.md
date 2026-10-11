# Vendored Suricata Rules

Bundled, offline rule sets for the built-in Suricata-compatible detection
engine. See `PROVENANCE.md` for upstream URLs, commit SHAs, licenses, counts.

## What is here

- `daffainfo/` — community CVE / CNVD / default-login / web-attack rules from
  [daffainfo/suricata-rules](https://github.com/daffainfo/suricata-rules)
  (Apache-2.0), upstream layout preserved (`http/cves/<year>/`, `http/cnvd/...`).
- `oisf/` — the Suricata engine's own app-layer and decoder event rules from
  [OISF/suricata](https://github.com/OISF/suricata) (GPL-2.0), copied flat.

These are **data files**, vendored for offline install; nothing here is fetched
at runtime.

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

## Adding your own rules

1. Drop a `.rules` file here (e.g. `backend/rules/local/my-rules.rules`) or
   anywhere on disk, with a unique `sid` per rule; duplicate SIDs overwrite.
2. Run `POST /api/suricata/rules/seed` again, then enable what you want in the
   rules list.
3. Do not edit the vendored upstream files in place — the next import would
   overwrite the change and break the provenance record.
