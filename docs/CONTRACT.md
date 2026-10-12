# APackets — Frozen Interface Contract

This document is **normative**. Every module in this repository must conform to it.
Do not change this file to match your code; change your code to match this file.
If you believe the contract is wrong, implement to the contract and note the concern
in your report.

---

## 0. Ground rules

* Backend: Python 3.12, FastAPI, pydantic v2, SQLite (stdlib `sqlite3`).
* Frontend: React 18 + TypeScript + Vite + Tailwind CSS.
* **All processing is local.** No network calls at runtime. No telemetry.
* **Never fabricate data.** Every number returned by the API must be derived from
  real TShark output or real packet bytes. If a value is unknown, return `null` —
  never a placeholder, guess, or sample value.
* Treat all capture content as untrusted strings. Never interpolate capture-derived
  values into a shell command, a filesystem path, or raw HTML.
* Packet numbers always map to the original capture (`frame.number`, 1-based).

### TShark facts verified in this environment

Binary: `C:\Program Files\Wireshark\tshark.exe` (TShark 4.6.8). Also `capinfos.exe`
in the same directory. Resolution order is `settings.tshark_path` → `PATH` → `tshark`.

```
# field extraction (streaming, one line per packet)
tshark -r <file> -n -T fields -E separator=<TAB> -E occurrence=f -e <fields...>

# packet detail tree as nested JSON: obj[0]["_source"]["layers"]
tshark -r <file> -n -Y "frame.number==3" -T json

# hex + ascii dump (classic tshark dump format, parseable)
tshark -r <file> -n -Y "frame.number==3" -x

# capture metadata
capinfos -M -T <file>            # -T => tab separated key/value

# TCP stream reassembly (authoritative, handles seq/retrans/ooo)
tshark -r <file> -q -z follow,tcp,ascii,<stream_id>
tshark -r <file> -q -z follow,tcp,raw,<stream_id>
tshark -r <file> -q -z follow,tcp,hex,<stream_id>

# conversations
tshark -r <file> -q -z conv,tcp
tshark -r <file> -q -z conv,udp

# protocol hierarchy
tshark -r <file> -q -z io,phs

# object export
tshark -r <file> --export-objects http,<dir>
```

**Filter validation rule (critical):**
* exit code `0` → filter is valid. Zero matching rows means "valid, no results".
* exit code `4` (or stderr matching `is not a valid protocol or protocol field`,
  `Unexpected end of filter expression`, `was unexpected`, `syntax error`) → invalid.
* Never conflate the two. The UI must show a distinct message for each.

`-z follow,tcp,ascii,N` output shape (verbatim):

```
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 192.168.1.10:51000
Node 1: 93.184.216.34:80
70
GET /index.html HTTP/1.1<CR><LF>...
	68
HTTP/1.1 200 OK...
===================================================================
```

Lines are prefixed with a decimal **byte length** to indicate a chunk boundary;
a leading TAB before the number means direction `Node 1 -> Node 0`. Payload text
follows. `<CR><LF>` are real CR/LF bytes in the output.

---

## 1. Repository layout and file ownership

```
docs/CONTRACT.md                  (this file — read-only)
backend/
  requirements.txt
  app/
    main.py                       core owner
    core/{config,paths,errors,logging}.py      core owner
    db/{database.py,schema.sql}                core owner
    schemas/*.py                               core owner
    services/tshark.py                         core owner
    services/storage.py                        core owner
    services/jobs.py                           core owner
    services/capture_parser.py                 core owner
    services/packet_indexer.py                 core owner
    services/pipeline.py                       core owner
    services/conversation_analyzer.py          agent C
    services/stream_analyzer.py                agent C
    services/host_analyzer.py                  agent C
    services/http_analyzer.py                  agent B
    services/dns_analyzer.py                   agent B
    services/tls_analyzer.py                   agent B
    services/detection_engine.py               agent D
    services/object_extractor.py               agent D
    api/routes_analyses.py                     core owner
    api/routes_packets.py                      core owner
    api/routes_conversations.py                agent C
    api/routes_hosts.py                        agent C
    api/routes_http.py                         agent B
    api/routes_dns.py                          agent B
    api/routes_tls.py                          agent B
    api/routes_findings.py                     agent D
    api/routes_objects.py                      agent D
    api/routes_settings.py                     core owner
  tests/                                       core owner
frontend/                                       frontend agents
data/{uploads,analyses,exports}/                runtime, gitignored
```

**Only edit files you own.** If you need a change in a core-owned file, implement
your side and report the required change instead of editing it.

---

## 2. Common API conventions

All endpoints are prefixed `/api`. All responses are JSON, UTF-8.

### Success envelopes

* Paginated list:
  ```json
  { "items": [], "total": 0, "page": 1, "page_size": 100 }
  ```
* Non-paginated list: `{ "items": [] }`
* Single resource: the object itself, e.g. `{ "id": "...", "status": "completed", ... }`
* Action result: `{ "ok": true, ... }`

### Error envelope

Every non-2xx response body is exactly:

```json
{ "error": { "code": "invalid_filter", "message": "human readable", "details": {} } }
```

`details` is optional (default `{}`). Status codes:

| status | when |
|---|---|
| 400 | bad request / malformed input |
| 404 | unknown analysis, packet, stream, object |
| 409 | action conflicts with current state (e.g. analysis not completed) |
| 413 | upload exceeds max size |
| 415 | unsupported file type |
| 422 | request validates as JSON but semantically rejected (e.g. invalid display filter) |
| 500 | unexpected server error |
| 504 | TShark subprocess timeout |

Use `app.core.errors.ApiError(status_code, code, message, details)` and raise it.
Never return a bare `{"detail": ...}` — an exception handler normalises those.

### Pagination, sorting, filtering query params

Every paginated list endpoint accepts:

* `page` (int, default 1, min 1)
* `page_size` (int, default 100, min 1, max 1000)
* `sort` (str, one of the endpoint's allow-listed columns)
* `order` (`asc` | `desc`, default depends on endpoint)

Unknown `sort` values must return `400 invalid_sort`, never be passed to SQL.
Build SQL by selecting from an allow-list dict, **never** by interpolating raw
input. Use `?` placeholders for all values.

### Analysis state gating

Endpoints under `/api/analyses/{analysis_id}/...` return
`404 analysis_not_found` if the id is unknown.
Data endpoints return `409 analysis_not_ready` if `status != 'completed'`,
except `GET /api/analyses/{id}` and `GET /api/analyses` which always work.

`analysis_id` must match `^[0-9a-f]{32}$`. Reject anything else with
`400 invalid_analysis_id` before touching the filesystem.

---

## 3. Database schema (frozen)

Defined in `backend/app/db/schema.sql`. Column names below are authoritative.
All timestamps are Unix epoch **seconds as REAL** unless the column name says
`_text`. All JSON columns are TEXT holding a compact JSON array/object.

Three tables are defined by later contracts rather than here, because they belong to
features added after this document was frozen: `protocol_sessions` (the five protocol
session sections — Email, SSH, FTP, VoIP, SMB) in `docs/PROTOCOLS.md` §2, and the
address-to-country dataset of `docs/GEOGRAPHY.md` §4, which is a file under `data/geoip/`
rather than a table, and the
entity-profile and threat-map read paths, which store no tables of their own. Where a
later contract and this one touch, this one wins for everything defined above.

### analyses
`id TEXT PK`, `original_filename TEXT`, `stored_path TEXT`, `file_size INTEGER`,
`file_sha256 TEXT`, `file_type TEXT`, `encapsulation TEXT`,
`status TEXT` (`pending|processing|completed|failed|cancelled`),
`progress REAL`, `stage TEXT`, `error TEXT`, `packet_count INTEGER`,
`bytes_total INTEGER`, `capture_start REAL`, `capture_end REAL`, `duration REAL`,
`src_ip_count INTEGER`, `dst_ip_count INTEGER`, `tcp_count INTEGER`,
`udp_count INTEGER`, `dns_count INTEGER`, `http_count INTEGER`, `tls_count INTEGER`,
`created_at REAL`, `updated_at REAL`, `started_at REAL`, `finished_at REAL`

### jobs
`id TEXT PK`, `analysis_id TEXT`, `kind TEXT`, `status TEXT`
(`queued|running|completed|failed|cancelled`), `stage TEXT`, `progress REAL`,
`message TEXT`, `error TEXT`, `cancel_requested INTEGER`,
`created_at REAL`, `started_at REAL`, `finished_at REAL`

### packets  (PK `analysis_id, number`)
`analysis_id`, `number INTEGER`, `time_epoch REAL`, `time_relative REAL`,
`frame_len INTEGER`, `cap_len INTEGER`, `protocols TEXT`, `protocol TEXT`,
`info TEXT`, `eth_src TEXT`, `eth_dst TEXT`, `vlan_id INTEGER`,
`ip_version INTEGER`, `src_ip TEXT`, `dst_ip TEXT`, `src_port INTEGER`,
`dst_port INTEGER`, `transport TEXT`, `tcp_flags TEXT`, `tcp_flags_raw TEXT`,
`tcp_stream INTEGER`, `udp_stream INTEGER`, `ttl INTEGER`, `ip_id INTEGER`,
`tcp_seq INTEGER`, `tcp_ack INTEGER`, `tcp_window INTEGER`, `tcp_len INTEGER`,
`udp_len INTEGER`, `dns_query TEXT`, `dns_qtype TEXT`, `dns_rcode TEXT`,
`http_method TEXT`, `http_host TEXT`, `http_uri TEXT`, `http_status INTEGER`,
`tls_sni TEXT`, `tls_version TEXT`

`protocol` is the display protocol (`_ws.col.Protocol`, e.g. `TCP`, `HTTP`, `DNS`).
`protocols` is the colon-separated dissection chain (`frame.protocols`).

### conversations  (PK `analysis_id, conv_id`)
`analysis_id`, `conv_id TEXT`, `transport TEXT` (`tcp|udp`), `stream_id INTEGER`,
`endpoint_a TEXT`, `endpoint_b TEXT`, `ip_a TEXT`, `port_a INTEGER`, `ip_b TEXT`,
`port_b INTEGER`, `packets_a_to_b INTEGER`, `bytes_a_to_b INTEGER`,
`packets_b_to_a INTEGER`, `bytes_b_to_a INTEGER`, `packets_total INTEGER`,
`bytes_total INTEGER`, `start_time REAL`, `end_time REAL`, `duration REAL`,
`state TEXT`, `protocols TEXT`

`endpoint_a` is the endpoint whose SYN (TCP) or first packet (UDP) was seen first.
`conv_id` = `"{transport}:{ip_a}:{port_a}-{ip_b}:{port_b}"`.
`protocols` = comma-separated app protocols observed in that stream (e.g. `http,tls`).
`state` ∈ `established|reset|half_open|closed|unknown` (`unknown` when no TCP flags seen).

### streams
`analysis_id`, `stream_id INTEGER`, `transport TEXT`, `client_ip TEXT`,
`client_port INTEGER`, `server_ip TEXT`, `server_port INTEGER`,
`payload_bytes_client INTEGER`, `payload_bytes_server INTEGER`,
`packets INTEGER`, `start_time REAL`, `end_time REAL`, PK `(analysis_id, transport, stream_id)`

### http_transactions (PK `id INTEGER AUTOINCREMENT`)
`analysis_id`, `stream_id INTEGER`, `request_packet INTEGER`,
`response_packet INTEGER`, `time_epoch REAL`, `response_time REAL`,
`client_ip TEXT`, `client_port INTEGER`, `server_ip TEXT`, `server_port INTEGER`,
`method TEXT`, `host TEXT`, `uri TEXT`, `full_uri TEXT`, `version TEXT`,
`status_code INTEGER`, `status_text TEXT`, `user_agent TEXT`, `referer TEXT`,
`content_type TEXT`, `server_header TEXT`, `request_len INTEGER`,
`response_len INTEGER`, `request_headers TEXT`, `response_headers TEXT`
(JSON objects), `request_body TEXT`, `response_body TEXT` (decoded preview,
may be NULL), `request_body_size INTEGER`, `response_body_size INTEGER`,
`response_body_truncated INTEGER`, `flags TEXT` (JSON array of lead strings)

`full_uri` = `http://{host}{uri}` when host is known.

### dns_queries (PK `id INTEGER AUTOINCREMENT`)
`analysis_id`, `dns_id INTEGER`, `time_epoch REAL`, `packet_number INTEGER`,
`response_packet INTEGER`, `response_time REAL`, `response_delay REAL`,
`client_ip TEXT`, `server_ip TEXT`, `query_name TEXT`, `query_type TEXT`,
`is_response INTEGER`, `rcode INTEGER`, `rcode_name TEXT`, `answers TEXT` (JSON),
`answer_ips TEXT` (comma separated), `cnames TEXT` (comma separated),
`min_ttl INTEGER`, `authoritative INTEGER`, `truncated INTEGER`,
`name_length INTEGER`, `label_count INTEGER`, `longest_label INTEGER`,
`entropy REAL`, `flags TEXT` (JSON array)

One row **per query**, with the matching response merged into the same row
(matched by `dns.id`, transaction id, plus client/server pair, preferring the
first response after the query). Unanswered queries keep `response_packet` NULL.

### tls_sessions (PK `id INTEGER AUTOINCREMENT`)
`analysis_id`, `stream_id INTEGER`, `client_ip TEXT`, `client_port INTEGER`,
`server_ip TEXT`, `server_port INTEGER`, `client_packet INTEGER`,
`server_packet INTEGER`, `time_epoch REAL`, `client_version TEXT`,
`server_version TEXT`, `version TEXT`, `sni TEXT`, `alpn TEXT` (comma separated),
`selected_alpn TEXT`, `cipher_suite TEXT`, `ja3 TEXT`, `ja3_full TEXT`,
`ja3s TEXT`, `ja4 TEXT`, `cert_subject TEXT`, `cert_issuer TEXT`,
`cert_not_before TEXT`, `cert_not_after TEXT`, `cert_serial TEXT`,
`handshake_status TEXT`, `alert TEXT`, `record_count INTEGER`, `flags TEXT` (JSON)

`handshake_status` ∈ `complete|client_hello_only|server_hello_only|alert|unknown`.
Never invent a version, SNI, or certificate value: leave NULL.

### hosts (PK `analysis_id, ip`)
`analysis_id`, `ip TEXT`, `mac TEXT`, `first_seen REAL`, `last_seen REAL`,
`packets_sent INTEGER`, `packets_received INTEGER`, `bytes_sent INTEGER`,
`bytes_received INTEGER`, `ports TEXT` (JSON `[{"port":80,"count":3,"direction":"dst"}]`),
`protocols TEXT` (JSON `{"HTTP":2}`), `dns_names TEXT` (JSON `["a.example"]`),
`tls_sni TEXT` (JSON `["host.example"]`), `is_private INTEGER`,
`ip_version INTEGER`, `peer_count INTEGER`, `peers TEXT` (JSON `["10.0.0.2"]`)

### findings (PK `id TEXT`)
`analysis_id`, `rule_id TEXT`, `severity TEXT`
(`informational|low|medium|high`), `title TEXT`, `description TEXT`,
`reason TEXT`, `evidence TEXT` (JSON), `packet_numbers TEXT` (JSON int array),
`entities TEXT` (JSON `{"ips":[],"hostnames":[],"ports":[],"uris":[]}`),
`recommendation TEXT`, `created_at REAL`

`id` must be deterministic: `f"{rule_id}:{sha1(canonical_key)[:12]}"` so reruns
are idempotent.

### objects (PK `id TEXT`)
`analysis_id`, `filename TEXT` (sanitised), `original_filename TEXT`,
`stored_path TEXT` (relative to the analysis directory, always under `objects/`),
`protocol TEXT`, `content_type TEXT`, `size INTEGER`, `sha256 TEXT`, `sha1 TEXT`,
`md5 TEXT`, `src_ip TEXT`, `dst_ip TEXT`, `src_port INTEGER`, `dst_port INTEGER`,
`stream_id INTEGER`, `packet_numbers TEXT` (JSON), `status TEXT`
(`complete|partial|failed`), `note TEXT`, `created_at REAL`

### indicators (PK `id INTEGER AUTOINCREMENT`)
`analysis_id TEXT` (NULL = global), `type TEXT` (`ip|domain|port|ja3|ja4|ua|sha256`),
`value TEXT`, `note TEXT`, `created_at REAL`

### settings (PK `key`)
`key TEXT`, `value TEXT` (JSON), `updated_at REAL`

---

## 4. Backend module contracts

### `app.core.config.Settings`
pydantic-settings, env prefix `APACKETS_`, reads `.env`. Fields:

`data_dir: Path` (default `<repo>/data`), `max_upload_mb: int = 512`,
`tshark_path: str = "tshark"` (resolved), `capinfos_path: str = ""` (resolved),
`tshark_timeout_s: int = 300`, `max_packet_rows: int = 0` (0 = unlimited),
`max_object_bytes: int = 52428800`, `body_preview_bytes: int = 262144`,
`host: str = "127.0.0.1"`, `port: int = 8000`, `cors_origins: list[str]`,
`worker_threads: int = 2`, `retain_uploads: bool = True`,
`max_dns_rows: int = 200000`, `log_level: str = "INFO"`.
Import as `from app.core.config import settings`. Exposes derived properties
`uploads_dir`, `analyses_dir`, `exports_dir`, `db_path`.

### `app.db.database`
* `connect() -> sqlite3.Connection` — row_factory `sqlite3.Row`, `PRAGMA journal_mode=WAL`,
  `foreign_keys=ON`, `busy_timeout=10000`.
* `get_conn()` — contextmanager yielding a connection, commits on success.
* `init_db()` — creates schema (`CREATE TABLE IF NOT EXISTS`) and indexes.
* `query_all(sql, params) -> list[sqlite3.Row]`, `query_one(...)`, `execute(...)`.
Thread-safe: one connection per call, WAL allows concurrent readers.

### `app.services.tshark`
An `class TsharkRunner` plus a module-level `tshark` singleton.

```python
def resolve_binary(name: str = "tshark") -> str | None
def version() -> dict            # {"tshark": "4.6.8", "path": "...", "available": True}

def run(args: list[str], *, timeout: float | None = None,
        cancel_event: threading.Event | None = None,
        allow_exit_codes: tuple[int, ...] = (0,)) -> TsharkResult

@dataclass
class TsharkResult:
    args: list[str]; returncode: int; stdout: str; stderr: str
    duration: float; timed_out: bool; cancelled: bool

def stream_fields(path, fields: list[str], *, display_filter: str | None = None,
                  cancel_event=None, extra_args: list[str] | None = None
                  ) -> Iterator[list[str]]        # yields rows, validates filter first

def validate_filter(expr: str) -> tuple[bool, str | None]
    # (True, None) valid; (False, "reason") invalid. Empty/blank -> (True, None)

def follow_stream(path, stream_id: int, mode: str = "ascii") -> FollowStream
@dataclass
class FollowStream:
    node0: str | None; node1: str | None
    chunks: list[StreamChunk]        # in capture order
    raw: str                         # verbatim tshark block, '' if unavailable
@dataclass
class StreamChunk:
    direction: int   # 0 = node0->node1, 1 = node1->node0
    byte_len: int
    data: str        # decoded text (ascii mode)
    hex: str         # lowercase hex of the chunk bytes
```

**Security:** every invocation is `subprocess.run(argv_list, shell=False)`.
Never build a command string. The display filter is passed as a single argv
element after `-Y`. Arguments derived from capture content are never used to
select files or paths — only `analysis_id` (validated hex) and integer stream ids.

### `app.services.storage`
```python
def new_analysis_id() -> str                      # uuid4().hex
def analysis_dir(analysis_id: str) -> Path        # data/analyses/<id>/
def upload_path(analysis_id: str, filename: str) -> Path
def objects_dir(analysis_id: str) -> Path
def safe_filename(name: str) -> str               # basename, strip traversal/control chars
def sha256_file(path: Path, chunk: int = 1 << 20) -> str
def delete_analysis(analysis_id: str) -> None     # removes dir, guarded by hex check
def dir_size(path: Path) -> int
def ensure_within(base: Path, candidate: Path) -> Path   # raises on traversal
```

### `app.services.jobs`
In-process thread-pool worker (POC). `JobManager` singleton `jobs`.
```python
def submit(analysis_id: str, fn: Callable[[JobContext], None]) -> str   # job id
def cancel(job_id: str) -> bool
class JobContext:
    job_id: str; analysis_id: str
    def check_cancelled(self) -> None    # raises JobCancelled
    @property cancel_event -> threading.Event
    def set_stage(self, stage: str, progress: float | None = None) -> None
```
`set_stage` writes `jobs.stage/progress/message` and mirrors to `analyses.stage/progress`.
On completion sets `analyses.status='completed'`; on `JobCancelled` → `cancelled`;
on any other exception → `failed` with `analyses.error = repr(exc)` (truncated).

### Analyzer function signature (all analyzers)

Every service module in `services/` exposes exactly one entry point:

```python
def analyze(ctx: JobContext, analysis_id: str, capture_path: Path) -> dict:
    """Read the capture with TShark, persist derived rows, return a stats dict."""
```

Rules:
* Read `capture_path` only via `app.services.tshark`. Never load the whole capture
  into memory: consume `stream_fields` row by row, batching inserts.
* Call `ctx.set_stage(...)` and `ctx.check_cancelled()` periodically (at least
  every 5000 rows) so jobs stay cancellable.
* Persist with `app.db.database.get_conn()`, deleting existing rows for the
  analysis first (`DELETE FROM <table> WHERE analysis_id = ?`) so re-runs are
  idempotent.
* Return a dict of simple counters (ints/strings/None) for logging.
* Insert in batches of 500–2000 rows inside one transaction.
* Never raise for missing/unsupported fields — skip and continue. A malformed
  packet must never abort the analysis.

`pipeline.py` calls them in this order, each inside its own progress band, and
records per-stage timing. A failure in an optional analyser must be logged and
skipped; only extraction failure of packets fails the whole analysis.

---

## 5. API endpoint contract

`GET /api/health` → `{"status":"ok","tshark":{"available":true,"version":"4.6.8","path":"..."},"version":"0.1.0"}`

### Analyses (`routes_analyses.py`)
* `POST /api/analyses` — multipart `file` (required). Streams to disk, validates
  extension (`.pcap .pcapng .cap`) and magic bytes, enforces `max_upload_mb`,
  creates the row (`status='pending'`), submits the job, returns **202** with the
  analysis object. `415 unsupported_file_type`, `413 file_too_large`,
  `400 empty_file`.
* `GET /api/analyses` — paginated, newest first. Items include all `analyses`
  columns plus `job_status`.
* `GET /api/analyses/{id}` — analysis object plus `job` (latest job row) plus
  `progress`, `stage`.
* `GET /api/analyses/{id}/summary` — see §6. Accepts `?domain_limit=N`
  (default 5, 1–50) controlling how many entries `top_domains` returns.
* `DELETE /api/analyses/{id}` — requires `?confirm=true`, else `400 confirmation_required`.
  Deletes DB rows (cascade) and the analysis directory. Returns `{"ok":true,"id":...}`.
* `POST /api/analyses/{id}/cancel` — requests cancellation; `409 not_cancellable`
  if the job already finished.
* `GET /api/analyses/{id}/jobs` — `{"items":[...]}` job history.

### Packets (`routes_packets.py`)
* `GET /api/analyses/{id}/packets` — paginated. Filters (all optional):
  `filter` (Wireshark display filter, validated), `ip`, `src_ip`, `dst_ip`,
  `port`, `src_port`, `dst_port`, `protocol`, `transport` (`tcp|udp`),
  `tcp_flags` (substring match on TShark's 12-character `tcp.flags.str`, whose letters are `F S R P A U E C` - so `S` is SYN and `SA` is SYN+ACK; the Wireshark spelling `SYN` matches nothing here),
  `min_length`, `max_length`, `start_time`, `end_time` (epoch seconds or ISO),
  `search` (substring over `info`).
  Sort allow-list: `number, time_epoch, src_ip, dst_ip, src_port, dst_port,
  protocol, frame_len`. Default `number asc`.
  Response items are packet summary rows (§7) — **never payloads**.
  Also returns `"filter_valid": true, "filter_error": null` so the UI can
  distinguish zero-results from an invalid filter. An invalid filter returns
  `422 invalid_filter` with `details={"reason": "..."}`.
* `GET /api/analyses/{id}/packets/{number}` — packet detail (§7), including
  `layers` (nested dict from `-T json`), `hex_dump` (list of
  `{"offset":int,"hex":str,"ascii":str,"bytes":int}`), and `raw_hex` (str).
* `GET /api/analyses/{id}/packets/{number}/neighbors?filter=...&direction=next|prev`
  → `{"packet_number": int|null}` — next/previous packet matching the filter.
* `POST /api/analyses/{id}/filter` — body `{"filter": "...", "page":1, "page_size":50}`.
  Returns `{"valid": bool, "reason": str|null, "total": int, "items": [...]}`.
  Never 422s for an invalid filter: returns `valid=false` with the reason.
* `GET /api/analyses/{id}/packets/export.csv` — streams `text/csv` of the
  current filter (same params as the list endpoint), capped at 200000 rows.
  Columns exactly: `number,time,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info`.

### Conversations (`routes_conversations.py`)
* `GET /api/analyses/{id}/conversations` — paginated; filters `transport`, `ip`,
  `port`, `search`; sort allow-list `packets_total, bytes_total, start_time,
  duration, endpoint_a`. Includes `total_bytes` in the response as well as items.
* `GET /api/analyses/{id}/streams/{stream_id}` — `{"stream": stream_row,
  "follow": {"node0":..., "node1":..., "client_to_server":{"bytes":n,"text":...,
  "hex":...}, "server_to_client":{...}, "chunks":[...]}}`.
  Query param `mode` (`ascii|hex|raw`, default `ascii`).
  The reconstruction must come from TShark's `follow` reassembly, not naive payload
  concatenation.

### HTTP (`routes_http.py`)
* `GET /api/analyses/{id}/http` — paginated transactions. Filters `method`,
  `host`, `uri`, `status` (exact or class like `4xx`), `client_ip`, `server_ip`,
  `user_agent`, `search`, `interesting` (bool → only rows with non-empty `flags`).
  Sort allow-list `time_epoch, method, host, uri, status_code, response_len`.
  Response also carries `"methods": [...]`, `"hosts": [...]`,
  `"status_classes": {"2xx": n, ...}` for filter dropdowns (computed from the DB).
* `GET /api/analyses/{id}/http/{transaction_id}` — full transaction including
  headers objects and body previews.

### DNS (`routes_dns.py`)
* `GET /api/analyses/{id}/dns` — paginated queries. Filters `domain`, `client_ip`,
  `server_ip`, `qtype`, `rcode`, `unanswered` (bool), `nxdomain` (bool),
  `suspicious` (bool → flags non-empty), `search`.
  Sort allow-list `time_epoch, query_name, query_type, rcode_name, response_delay`.
  Response also carries `"qtypes": [...]`, `"rcodes": [...]`,
  `"top_clients": [{"client_ip":...,"count":n}]` (top 10).
* `GET /api/analyses/{id}/dns/{row_id}` — single row with parsed answers.
* `GET /api/analyses/{id}/dns/domains` — aggregated per-domain view:
  `{"items":[{"query_name":...,"queries":n,"clients":n,"rcodes":{...},
  "ips":[...],"first_seen":...,"last_seen":...}]}`.

### TLS (`routes_tls.py`)
* `GET /api/analyses/{id}/tls` — paginated sessions. Filters `sni`, `version`,
  `ip`, `port`, `alpn`, `ja3`, `has_cert` (bool). Sort allow-list
  `time_epoch, sni, version, server_port, cipher_suite`.
  Response also carries `"snis":[...]`, `"versions":[...]`.
* `GET /api/analyses/{id}/tls/{session_id}` — single session.
* `GET /api/analyses/{id}/tls/fingerprints` — `{"items":[{"fingerprint":...,
  "type":"ja3|ja3s|ja4","sessions":n,"snis":[...],"clients":[...]}]}`.

### Hosts (`routes_hosts.py`)
* `GET /api/analyses/{id}/hosts` — paginated. Filters `ip`, `search`,
  `is_private` (bool), `protocol`. Sort allow-list `ip, packets_sent,
  bytes_sent, bytes_received, first_seen, last_seen, peer_count`.
  Response carries `"total_bytes"`.
* `GET /api/analyses/{id}/hosts/{ip}` — host detail plus
  `conversations`, `dns_queries`, `http_transactions`, `tls_sessions` (each a
  small capped list, ≤50) and `packet_count`.
* `GET /api/analyses/{id}/hosts/graph` — `{"nodes":[{"id":ip,"label":ip,"mac":...,
  "packets":n,"bytes":n,"is_private":bool}],"edges":[{"source":ip,"target":ip,
  "packets":n,"bytes":n,"protocols":"tcp","ports":[...]}]}` built from observed
  conversations only.

### Findings (`routes_findings.py`)
* `GET /api/analyses/{id}/findings` — paginated. Filters `severity`, `rule_id`,
  `search`. Sort allow-list `severity, rule_id, title`. Default ordering is
  severity (high→informational) then rule id.
  Response carries `"counts": {"high":n,"medium":n,"low":n,"informational":n}`.
* `GET /api/analyses/{id}/findings/{finding_id}` — full finding.
* `GET /api/analyses/{id}/findings/rules` — `{"items":[{rule metadata}]}` listing
  every rule with id, title, severity, description, enabled, and hit count.
* `GET /api/analyses/{id}/alerts/conversations` — alerts above a severity, resolved to the
  conversations they belong to (feeds the Conversations flow highlight layer).
  Params: `min_severity` (`informational|low|medium|high`, default `medium`; invalid →
  `400 invalid_min_severity`) and `source` (`suricata|all`, **default `all`**; invalid → 422).
  `source=all` covers the imported Suricata rules **and** the built-in detection engine, so the
  overlay agrees with the Findings page — defaulting to Suricata alone reported zero medium
  alerts on a capture whose medium findings were all built-in. Pass `source=suricata` to isolate
  the imported rules; each alert's `rule_id` states its origin (`suricata:<sid>` vs a built-in
  rule name).
  Returns `counts` (at/above the threshold), `all_counts` (every severity, so a UI can disclose
  what is hidden), `alerts[]` (each with `conversations`, `packet_numbers`,
  `linked_by` ∈ `packets|none`), `by_conversation` keyed by the flow's own conversation key
  `transport:stream_id` with value `{severity, finding_ids, rules, titles}`, `by_ip`, plus
  `linked_conversations`, `unlinked_findings`, `packets_scanned`, `packets_truncated` and `note`.
  A conversation's severity is the **most urgent** among its alerts.

  The link is exact, never similarity-based: a finding's recorded frame numbers are looked up in
  the packet index, and their TCP/UDP stream id names the conversation. A finding with no
  frames, frames absent from the index, or frames carrying no stream id cannot be placed on the
  diagram and is counted in `unlinked_findings` rather than guessed at.

### Objects (`routes_objects.py`)
* `GET /api/analyses/{id}/objects` — `{"items":[...]}` (non-paginated is fine, but
  support `page`/`page_size` with the standard envelope).
* `GET /api/analyses/{id}/objects/{object_id}/export` — `FileResponse` with
  `Content-Disposition: attachment` using the sanitised filename. Must reject
  any `object_id` that is unknown and any stored path that escapes the analysis
  directory (`403 path_traversal`).
* `POST /api/analyses/{id}/objects/extract` — re-runs extraction, returns
  `{"ok":true,"extracted":n}`.

### Protocol sessions (`routes_protocols.py`)

`GET /analyses/{id}/protocols` (filters, paging, sort), `/protocols/summary` (per-family
totals and whether the analysis was ever extracted) and `/protocols/{session_id}` (one
session with its per-protocol `detail`), plus `POST /analyses/{id}/protocols/rescan` (202
and a job id). The five pages — Email, SSH, FTP, VoIP, SMB — read one table and one
extractor; the shape, the per-protocol `detail` keys, the lead flags and the caps are
fixed by `docs/PROTOCOLS.md`.

### Threat Hunt (`routes_threat_hunt.py`)
* `GET /api/analyses/{id}/threat-hunt` — the Threat Hunt indicator engine: 17
  indicators in the order fixed by `docs/THREAT_HUNT.md` §1, computed as SQL
  aggregates over the indexed tables only (no capture is re-read, so it still
  works after the upload has been purged). Query params `window` (seconds per
  time-series bucket, 5–3600, default 60) and `top` (rows per ranked visual,
  1–50, default 12); out-of-range values are `422 validation_error`, an unknown
  analysis is 404 `analysis_not_found` and an unfinished one 409
  `analysis_not_ready`.
  Each indicator reports `availability`: `ok` (computed, something matched),
  `empty` (computable, nothing crossed the threshold — which `availability_reason`
  states) or `not_applicable` (the capture cannot answer it, `availability_reason`
  says why). `headline.value` is 0 only when the availability is not `ok`, so a
  zero on screen always means "nothing matched". `visuals[]` entries are tagged
  by `kind` (`bars`, `timeline`, `histogram`, `scatter`, `heatmap`, `table`) and
  capped — bars/heatmap at `top`, timeline at 240 buckets, table at 50 rows,
  scatter at 200 points — with a cap that bit reported in `note` as `top N of M`.
  Every indicator carries the `caveat` naming what its pattern does *not*
  establish, and every link uses only the query parameters of
  `docs/THREAT_HUNT.md` §5.

### Settings (`routes_settings.py`)
* `GET /api/settings` — effective settings (safe subset) plus `data_dir`,
  `max_upload_mb`, `tshark` version/path, `retain_uploads`.
* `PUT /api/settings` — accept mutable keys (`max_upload_mb`, `retain_uploads`,
  `max_object_bytes`, `body_preview_bytes`, `tshark_timeout_s`); persists to the
  `settings` table. Returns the new effective settings.
* `GET /api/indicators`, `POST /api/indicators`, `DELETE /api/indicators/{id}` —
  analyst-supplied indicators for detection rule 10.

---

## 6. `/summary` response shape (Dashboard)

Built from the `analyses` row plus real aggregates. Every value must be `None`
when not derivable.

```json
{
  "analysis": { "...all analyses columns...", "job_status": "completed" },
  "totals": {
    "packets": 1234, "bytes": 987654, "duration": 12.5,
    "unique_src_ips": 4, "unique_dst_ips": 6,
    "tcp_packets": 800, "udp_packets": 400,
    "dns_queries": 20, "http_requests": 12, "tls_connections": 5,
    "conversations": 9, "hosts": 7, "findings": 3,
    "start_time": 1700000000.0, "end_time": 1700000012.5
  },
  "protocol_distribution": [{"protocol":"TCP","packets":800,"bytes":120000}],
  "traffic_series": [{"t":1700000000.0,"packets":12,"bytes":1440}],
  "series_interval": 0.5,
  "top_talkers": [{"ip":"10.0.0.5","direction":"source","packets":50,"bytes":5000}],
  "top_ports": [{"port":443,"protocol":"TCP","packets":40,"service":"https"}],
  "top_conversations": [{"conv_id":"...","endpoint_a":"...","endpoint_b":"...",
                          "transport":"tcp","bytes_total":1234,"packets_total":10}],
  "top_domains": [{"domain":"example.com","ips":["93.184.216.34"],"address_count":1,
                    "clients":["10.0.0.5"],"client_count":1,"bytes_sent":1200,
                    "bytes_received":8400,"bytes_total":9600,"packets":42}],
  "top_domains_note": "attribution caveat shown to the analyst",
  "traffic_extremes": {
    "max_sender": {"ip":"10.0.0.5","mac":"...","bytes":5000,"packets":50,
                    "bytes_sent":5000,"bytes_received":10,"is_private":1,
                    "ip_version":4,"hostnames":["example.com"]},
    "max_receiver": {"...same shape...": null}
  },
  "findings_summary": [{"id":"...","severity":"high","title":"...","rule_id":"..."}],
  "protocol_hierarchy": [{"protocol":"frame","frames":5,"bytes":425,"depth":0}],
  "severity_counts": {"high":1,"medium":0,"low":2,"informational":1},
  "notes": ["human readable caveat strings"]
}
```

* `traffic_series` uses at most **240 buckets**; `series_interval` is the bucket
  width in seconds (`max(duration,0) / buckets`, from 1 ms to the capture length).
* `protocol_distribution` comes from the `packets` table grouped by `protocol`,
  ordered by packet count desc, top 15.
* `protocol_hierarchy` comes from parsing `-z io,phs` (cached at analysis time
  into the `settings`-style cache is **not** required — recompute on request is
  acceptable only if it is fast; prefer storing it as JSON in a `stats_cache`
  table). Simplest acceptable approach: parse `-z io,phs` during analysis and
  persist the parsed tree as a single JSON row in `analyses`-adjacent storage.
  Use the `stats_cache` table (`analysis_id`, `kind`, `json`, `created_at`).
* `notes` must state real limitations, e.g. `"HTTPS payloads are not decrypted"`
  when TLS sessions exist and no keys were supplied.
* `traffic_extremes` reports the single busiest sender and receiver from the
  `hosts` table, ordered by `bytes_sent` / `bytes_received` respectively. Either
  member is `null` when nothing was sent/received. `bytes`/`packets` mirror the
  relevant direction; `bytes_sent`/`bytes_received` carry both.
* `top_domains` attributes bytes to a domain by taking the addresses observed in
  that domain's captured DNS answers and summing the conversations involving
  those addresses. **Direction must come from the conversation**, not be
  assumed: bytes arriving from a matched address are `bytes_received` and bytes
  sent to it are `bytes_sent`. Ranked by `bytes_total` desc, capped at
  `domain_limit`. A domain whose addresses never exchanged traffic is omitted —
  an empty list is the correct answer for a DNS-only capture.
* `top_domains_note` must be returned alongside `top_domains` and displayed
  wherever those numbers are shown: it states that attribution depends on
  captured DNS answers, that CNAME chains are not followed, and that a shared or
  CDN address can legitimately carry several names.

---

## 7. Packet summary vs detail shapes

**Summary** (list endpoints):
```json
{"number":3,"time_epoch":1700000000.5,"time_relative":1.2,
 "src_ip":"10.0.0.1","src_port":51000,"dst_ip":"10.0.0.2","dst_port":80,
 "protocol":"HTTP","transport":"tcp","length":124,"tcp_flags":"·······AP···",
 "info":"GET /index.html HTTP/1.1","protocols":"eth:ip:tcp:http",
 "src_mac":"...","dst_mac":"...","vlan_id":null,"ttl":64,
 "dns_query":null,"http_method":"GET","http_host":"example.com",
 "http_uri":"/index.html","http_status":null,"tls_sni":null}
```
Fields are `null` when absent. `src_port`/`dst_port` are `null` for non-TCP/UDP.

**Detail** = summary plus:
```json
{"layers": {"frame": {...}, "eth": {...}, "ip": {...}, "tcp": {...}, "http": {...}},
 "layer_order": ["frame","eth","ip","tcp","http"],
 "hex_dump": [{"offset":0,"hex":"94 83 c4 ...","ascii":"...0.#HK..E.","bytes":16}],
 "raw_hex": "9483c49a1190...",
 "raw_text": "GET /index.html HTTP/1.1\r\n...",
 "raw_len": 124,
 "raw_truncated": false}
```

`layers` is the raw `layers` object from `-T json`, with keys `*_tree` removed
(flatten `*_tree` children into the parent under their own field names).
`layer_order` follows the dissection order from `frame.protocols`.
`raw_text` is the ASCII rendering of the captured bytes (non-printables → `.`),
truncated at 8192 chars with `raw_truncated=true`.

---

## 8. Detection rules (fixed ids, configurable thresholds)

Rules live in `detection_engine.py` as data + a function per rule. Config is read
from the `settings` table under key `detection_config` (JSON), with defaults:

| rule_id | severity | default threshold |
|---|---|---|
| `tcp_syn_scan` | high | ≥20 distinct dst ports from one src within 10 s, ≥80% SYN-only |
| `dns_nxdomain_burst` | medium | ≥5 NXDOMAIN from one client |
| `dns_high_volume` | low | ≥100 queries from one client |
| `dns_long_labels` | medium | label ≥40 chars or name ≥100 chars |
| `http_suspicious_path` | medium | pattern list match |
| `http_cleartext_credentials` | high | sensitive field name in plaintext HTTP body/URI |
| `outbound_volume` | medium | single host sends ≥50 MB or ≥10× the median sender |
| `rare_destination_port` | informational | dst port seen once across the capture, outside a known-common list |
| `repeated_failed_connections` | medium | ≥10 TCP SYN with no SYN/ACK per destination |
| `indicator_match` | high | traffic matches an analyst-supplied indicator |

Every finding must include a human-readable `reason` stating the observed numbers
and the threshold, and `recommendation` with concrete next steps.
Language must be investigative ("consistent with", "worth reviewing"), never a
verdict ("is malware", "attack confirmed").

---

## 9. Frontend contract

* Vite dev server proxies `/api` → `http://127.0.0.1:8000`.
* `src/services/api.ts` exposes typed functions per endpoint and unwraps the
  error envelope into `ApiError { status, code, message, details }`.
* Types in `src/types/index.ts` mirror §3/§6/§7 exactly.
* Nav routes, in sidebar order: `/` dashboard, `/info`, `/conversations`, `/hosts`,
  `/findings`, `/objects`, `/packets`, then the **Protocols** subsection `/http`,
  `/dns`, `/tls`, then `/files` (PCAP Files) and `/settings`.
* Dark theme only. Palette (Tailwind theme extension):
  `bg` `#0b1120`, `surface` `#111a2e`, `surface2` `#16203a`, `border` `#22304d`,
  `accent` `#3b82f6`, `text` `#e2e8f0`, `muted` `#8296b4`,
  severity: informational `#64748b`, low `#38bdf8`, medium `#f59e0b`, high `#ef4444`.
* Monospace for all packet/IP/hex data.
* Every page must render a real empty state and a real error state; no fake rows.
* Never use `dangerouslySetInnerHTML` for capture-derived strings.

---

## 10. Definition of "done" for any module

1. It runs against a real capture without raising (including a capture that lacks
   the protocol entirely → zero rows, no error).
2. Its endpoint returns the documented shape.
3. It does not read a whole capture into memory.
4. It is covered by at least one test in `backend/tests/` (core owner may add).
5. `python -m pytest backend/tests -q` passes.
