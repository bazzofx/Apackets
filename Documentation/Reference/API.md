# Reference — the REST API

A map of APackets' HTTP surface: which router module owns which prefix, the
envelopes and conventions every endpoint shares, and where CSV and file exports
live. The normative shapes are in [`docs/CONTRACT.md`](../../docs/CONTRACT.md) —
this page summarises and links, it does not define.

Everything is served by the FastAPI application in `backend/app/main.py` under
the single prefix `/api`, as JSON in UTF-8. Interactive documentation is at
`/api/docs`, and the OpenAPI document at `/api/openapi.json`.

---

## 1. Conventions

### Router discovery

Routers are not auto-discovered by scanning directories. `main.py` holds an
explicit ordered tuple:

```python
ROUTER_SPECS: tuple[tuple[str, str], ...] = (
    ("app.api.routes_analyses", "router"),
    ...
)
```

`register_routers()` imports each module with `importlib.import_module` and does
`app.include_router(router)`. A module that cannot be imported, or that has no
`router` attribute, is logged as a warning and **skipped** rather than crashing
the process, so a partially built checkout still serves a working API with those
sections missing. The list of missing modules is what `GET /api/capabilities`
reports: it re-imports each module in `ROUTER_SPECS` and returns a
`features` map of `routes_analyses` → true/false (the key is the module name with
`routes_` removed), alongside the version and whether TShark is usable.

Order matters in one place only: the catch-all route that serves the built SPA is
added after `register_routers()`, and it answers `404 not_found` for any `/api/…`
path it would otherwise swallow.

### Envelopes

| Shape | Body | Used by |
|---|---|---|
| Paginated list | `{ "items": [...], "total": 0, "page": 1, "page_size": 100, "pages": 1 }` | every list endpoint that takes `page`/`page_size` |
| Non-paginated list | `{ "items": [...] }` | `GET /api/analyses/{id}/jobs` |
| Single resource | the object itself | `GET /api/analyses/{id}`, `.../packets/{n}`, `.../http/{id}`, … |
| Action result | `{ "ok": true, … }` | cancel, delete, rule import, Suricata re-run, object extract |

A few endpoints add fields beside the envelope:
`GET /api/analyses/{id}/packets` adds `filter`, `filter_valid` and
`filter_error` so a filter bar can tell zero results from a broken filter, and
`GET /api/analyses/{id}/objects` adds a `totals` object.

### Pagination and sorting

`pagination()` in `backend/app/api/deps.py` is the shared dependency:
`page` (default 1, min 1), `page_size` (default 100, min 1, **max 1000** —
`MAX_PAGE_SIZE`). It exposes `offset`/`limit` and builds the envelope above,
including `pages`.

Sorting is allow-listed per endpoint and never interpolated: `resolve_sort()`
maps a client key onto a stored SQL expression and raises
`400 invalid_sort` (with the `allowed` list in `details`) for anything else;
`resolve_order()` accepts only `asc`/`desc`. A leading `-` on the sort key is
tolerated and stripped.

### Error envelope

Every non-2xx response has exactly this body, produced by the handlers in
`backend/app/core/errors.py`:

```json
{ "error": { "code": "invalid_filter", "message": "human readable", "details": {} } }
```

`ApiError(status_code, code, message, details)` is raised anywhere in the request
path. `RequestValidationError` (a FastAPI/Pydantic query or body failure, e.g. an
out-of-range `window`) becomes `422 validation_error` with a compact
`details.problems` list of `{location, message, type}`. A bare Starlette
`HTTPException` is normalised through a status→code map (`400 bad_request`,
`404 not_found`, `405 method_not_allowed`, `413 file_too_large`,
`415 unsupported_file_type`, …), and anything unhandled becomes
`500 internal_error` with no internals leaked. Status codes and their meanings
are in [`docs/CONTRACT.md`](../../docs/CONTRACT.md) §2.

### Analysis gating

Two dependencies in `backend/app/api/deps.py` are applied across the routers:

* `get_analysis(analysis_id)` — validates the id shape first
  (`^[0-9a-f]{32}$`, else `400 invalid_analysis_id`) and returns the row, or
  `404 analysis_not_found`.
* `get_ready_analysis(analysis_id)` — the same, plus `409 analysis_not_ready`
  when `status != 'completed'`, with the current `status`, `stage` and `progress`
  in `details`. Every data endpoint uses this, which is why an analysis that is
  still processing cannot return a half-filled page.

`capture_path(row)` additionally raises `410 capture_missing` when the retained
upload is gone (`APACKETS_RETAIN_UPLOADS=false`, or the file was deleted), and
`analysis_ready_row()` combines both for the endpoints that must re-read the
capture.

---

## 2. Routers, prefixes and purpose

| Module | Prefix | Tag | What it serves |
|---|---|---|---|
| `routes_analyses.py` | `/api` | `analyses` | Upload (`POST /analyses`, 202), list, detail, `/summary` (dashboard aggregates), `/jobs`, cancel, delete, and `/health`. Two meta routes live here: `/health` and, in `main.py`, `/capabilities`. |
| `routes_packets.py` | `/api/analyses/{analysis_id}` | `packets` | `GET /packets` (filters, sort, pagination), `GET /packets/{number}` (layer tree + hex dump), `GET /packets/{number}/neighbors`, `POST /filter` (validate a display filter without erroring), `GET /packets/export.csv`. |
| `routes_conversations.py` | `/api/analyses/{analysis_id}` | `conversations` | `GET /conversations`, `GET /streams/{stream_id}`, `/streams/{stream_id}/search`, `/streams/{stream_id}/export`. |
| `routes_http.py` | `/api/analyses/{analysis_id}` | `http` | `GET /http` (transactions, with lead flags), `GET /http/{transaction_id}`. |
| `routes_dns.py` | `/api/analyses/{analysis_id}` | `dns` | `GET /dns`, `GET /dns/domains`, `GET /dns/{row_id}`. |
| `routes_tls.py` | `/api/analyses/{analysis_id}` | `tls` | `GET /tls`, `GET /tls/fingerprints`, `GET /tls/{session_id}`. |
| `routes_protocols.py` | `/api/analyses/{analysis_id}` | `protocols` | The five protocol-session sections: `GET /protocols` (one family's sessions, with lead flags), `GET /protocols/summary` (per-family totals) and `GET /protocols/{session_id}` (one session, with its `detail`, links and frame numbers), plus `POST /protocols/rescan` to re-run the extraction on an already-indexed capture. See [PROTOCOLS.md](../../docs/PROTOCOLS.md). |
| `routes_hosts.py` | `/api/analyses/{analysis_id}` | `hosts` | `GET /hosts`, `GET /hosts/graph`, `GET /hosts/{ip}`. |
| `routes_findings.py` | `/api/analyses` | `findings` | `GET /{analysis_id}/findings`, `/findings/rules`, `/findings/{finding_id}`, `/findings/{finding_id}/context`, `POST /{analysis_id}/findings/rescan`, `GET /{analysis_id}/alerts/conversations`. Note the prefix stops at `/analyses`, so the analysis id is a path segment of each route. |
| `routes_objects.py` | `/api/analyses` | `objects` | `GET /{analysis_id}/objects`, `GET /{analysis_id}/objects/{object_id}/export`, `POST /{analysis_id}/objects/extract` (re-run extraction). Same prefix shape as findings. |
| `routes_threat_hunt.py` | `/api/analyses/{analysis_id}` | `threat-hunt` | `GET /threat-hunt` — the seventeen indicators. See [Threat-Hunt.md](../Threat-Hunt.md). |
| `routes_profile.py` | `/api/analyses/{analysis_id}` | `profile` | `GET /profile?q=&limit=` (resolve a query to the entities this capture contains) and `GET /profile/{kind}/{entity}` (every question of §4 for one of them). An entity the capture never recorded answers `200` with every question `not_applicable`, so no lookup 404s on a stale link. See [Investigate.md](../Investigate.md). |
| `routes_settings.py` | `/api` | `settings` | `GET|PUT /settings`, `GET|POST /indicators`, `DELETE /indicators/{id}`. |
| `routes_suricata.py` | `/api` | `suricata` | Rule CRUD and listing under `/suricata/rules…`, `/suricata/rules/stats`, `/suricata/config` (`GET|PUT`), import and seed, plus the per-analysis `/analyses/{analysis_id}/suricata/alerts` and `/analyses/{analysis_id}/suricata/run`. |

Two meta endpoints come from `main.py` rather than a feature router:
`GET /api/capabilities` and the OpenAPI document itself.

---

## 3. Shapes: go to the contract

The exact request and response shapes — parameter lists and bounds, sort
allow-lists, the packet summary vs detail split, the `/summary` dashboard
payload, the error codes and the schema columns — are frozen in
[`docs/CONTRACT.md`](../../docs/CONTRACT.md):

| Contract section | What it fixes |
|---|---|
| §2 Common API conventions | Envelopes, error envelope, status codes, pagination/sort rules, analysis gating |
| §3 Database schema | Every table and column the responses are built from |
| §4 Backend module contracts | What each service module owns and how it is called |
| §5 API endpoint contract | Per-endpoint parameters, shapes and error codes |
| §6 `/summary` response shape | The dashboard aggregates, including `traffic_extremes`, `top_domains` and `top_domains_note` |
| §7 Packet summary vs detail | The two packet shapes, including `hex_dump` and `raw_hex` |
| §8 Detection rules | Finding ids and their configurable thresholds |
| §9 Frontend contract | What the pages are allowed to expect |

The Threat Map section additionally has its own normative document,
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md), which fixes the indicator
envelope, the six visual shapes, the caps and the only link parameters that may
be used.

---

## 4. Exports

| Endpoint | Format | Notes |
|---|---|---|
| `GET /api/analyses/{id}/packets/export.csv` | `text/csv; charset=utf-8` | Same filters and sort parameters as `GET /packets`, but no pagination: it emits the whole filtered result up to `APACKETS_MAX_EXPORT_ROWS` (200000 by default). Columns exactly `number,time,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info`; `time` is an ISO-8601 UTC stamp with microseconds, and newlines inside `info` are replaced with spaces so a row is always one line. |
| `GET /api/analyses/{id}/streams/{stream_id}/export` | `txt`, `hex`, `csv` or `raw` (`?format=`) | Per-chunk CSV (`index,direction,byte_len,hex`), hex text, ASCII text, or the byte-exact payload in capture order as `application/octet-stream`. An unknown format is `400 invalid_format` with the allowed list. |
| `GET /api/analyses/{id}/objects/{object_id}/export` | whatever the object is | One recovery from the capture, as a download. Served with `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`, under a sanitised filename; the file on disk is named after the server-generated object id. |

All three send `Content-Disposition: attachment` with a generated filename
(`packets-<first 8 chars of analysis id>.csv`, `stream-<transport>-<id>.<ext>`,
or the object's own name).

The packets CSV adds three headers so a truncated export is never mistaken for a
complete one:

| Header | Meaning |
|---|---|
| `X-Total-Rows` | How many rows matched the filter |
| `X-Exported-Rows` | How many rows are actually in the body |
| `X-Truncated` | Present (`true`) only when `X-Total-Rows` exceeds `X-Exported-Rows` |

The stream export instead reports `X-Stream-Id`, `X-Stream-Mode` and
`X-Stream-Format`. These and `Content-Disposition` are the headers the CORS
configuration exposes to the browser (`expose_headers` in `main.py`).

---

## 5. How the front end uses it

`frontend/src/services/api.ts` is the single client. It builds every URL from
`API_PREFIX = '/api'` plus an optional `VITE_API_BASE` origin (empty by default,
meaning same-origin — either the Vite dev proxy or the backend-served bundle),
drops `undefined`/`null`/empty query values in `buildQuery`, unwraps the error
envelope into a typed `ApiError` (`status`, `code`, `message`, `details`, with
`code: 'network_error'` and `status: 0` for a transport failure), and exposes one
small object per area — `analysesApi`, `packetsApi`, `conversationsApi`,
`httpApi`, `dnsApi`, `tlsApi`, `hostsApi`, `findingsApi`, `objectsApi`,
`settingsApi`, `suricataApi`, `alertsApi`, `threatHuntApi`. Uploads go through
`XMLHttpRequest` in `uploadAnalysis()` so the progress bar has real byte counts.

The Vite dev server proxies `/api` to `http://127.0.0.1:8000` (override with
`APACKETS_BACKEND_URL`), so no CORS negotiation happens in development; the
backend's `APACKETS_CORS_ORIGINS` default only matters if you point a browser at
the API from another origin.

---

## Related

[README.md](../README.md) · [Getting-Started.md](../Getting-Started.md) ·
[Architecture.md](../Architecture.md) · [Threat-Hunt.md](../Threat-Hunt.md) ·
[Findings.md](../Findings.md) · [Packets.md](../Packets.md) ·
[Settings.md](../Settings.md) · [docs/CONTRACT.md](../../docs/CONTRACT.md) ·
[docs/THREAT_HUNT.md](../../docs/THREAT_HUNT.md)
