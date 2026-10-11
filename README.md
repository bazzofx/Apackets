# APackets — Local PCAP Analyzer

A locally hosted web application for network traffic analysis and digital
forensics. Upload a PCAP or PCAPNG capture, and inspect packets, conversations,
reconstructed TCP streams, HTTP/DNS/TLS metadata, host activity and explainable
security findings through a dark, dense, Wireshark-adjacent web interface.

**Everything runs on this machine.** All dissection is performed by TShark
running as a local subprocess. There is no telemetry, no analytics, no cloud
service and no external threat-intelligence lookup. The application is fully
functional with networking disabled.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start with Docker Compose](#quick-start-with-docker-compose)
- [Local development](#local-development)
- [Configuration](#configuration)
- [Using the application](#using-the-application)
- [HTTP API](#http-api)
- [Security model](#security-model)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Project layout](#project-layout)
- [Implementation status](#implementation-status)

---

## How it works

```
        browser
           │  HTTP (loopback only)
           ▼
   ┌───────────────────┐        ┌──────────────────────────────┐
   │  React frontend   │  /api  │  FastAPI backend             │
   │  Vite + TS        │ ─────► │  • upload + validation       │
   │  Tailwind         │        │  • background job worker     │
   └───────────────────┘        │  • analyzers (HTTP/DNS/TLS…) │
                                │  • detection engine          │
                                └───────────┬──────────────────┘
                                            │ argv, shell=False
                                            ▼
                                    ┌───────────────┐
                                    │    TShark     │
                                    │  (dissection) │
                                    └───────┬───────┘
                                            │
                        ┌───────────────────┴────────────────────┐
                        ▼                                        ▼
              SQLite index (data/apackets.db)          original capture
              packets, conversations, streams,         (data/uploads/)
              http, dns, tls, hosts, findings,         extracted objects
              objects, indicators                      (data/analyses/<id>/)
```

Design decisions worth knowing:

- **TShark is the only packet decoder.** No protocol parsing is reimplemented.
  Wireshark display-filter syntax is supported by passing the expression to
  TShark itself.
- **The packet table stores summaries, not payloads.** `GET /packets` never
  transfers payload bytes; the detail view re-runs TShark against the retained
  capture so what you see always matches the original bytes.
- **TCP stream reconstruction uses TShark's own reassembly**
  (`-z follow,tcp,raw,<id>`), so sequence numbers, retransmissions and
  out-of-order segments are handled by Wireshark, not by concatenating payloads.
- **The worker runs in the API process** for this proof of concept (a bounded
  thread pool plus a `jobs` table). Uploads return `202` immediately and the
  client polls for progress. `JobManager` is the single scheduling seam, so
  moving to a separate worker process is a contained change.

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| TShark | 4.2+ recommended | **Required.** The decoder. 4.6.8 is what this was developed against. JA3/JA3S/JA4 fingerprint fields need 4.2+. |
| Python | 3.12+ | Backend. |
| Node.js | 20+ | Frontend build only. |
| Docker | optional | Docker Compose v2 for the containerised deployment. |

TShark is not bundled. Install Wireshark (which includes `tshark` and
`capinfos`) from <https://www.wireshark.org/download.html>, or via your package
manager:

```powershell
# Windows
winget install Wireshark.Wireshark
```

```bash
# Debian / Ubuntu
sudo apt-get install tshark
# Fedora / RHEL
sudo dnf install wireshark-cli
# macOS
brew install --cask wireshark
```

The application auto-detects the binaries on `PATH` and in the usual Windows
install locations. If yours live elsewhere, set `APACKETS_TSHARK_PATH`.

> Live capture is deliberately not supported, so TShark does **not** need
> capture privileges / `CAP_NET_RAW`. Only file reading is used.

---

## Quick start with Docker Compose

```bash
docker compose up --build
```

Then open **<http://127.0.0.1:8080>**.

Both containers publish only on loopback. Analysis data is kept in the
`apackets-data` named volume.

To keep captures in a directory you control instead, set
`APACKETS_DATA_HOST` in `.env` and use the bind mount commented in
`docker-compose.yml`.

Stop and remove everything, including the stored analyses:

```bash
docker compose down          # keep data
docker compose down -v       # also delete the data volume
```

---

## Local development

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```bash
# Linux / macOS
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Interactive API documentation: <http://127.0.0.1:8000/api/docs>

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. The Vite dev server proxies `/api` to
`http://127.0.0.1:8000`.

### Single-process production-style run

`npm run build` emits `frontend/dist`, and the backend serves that directory
automatically when it exists. So:

```bash
cd frontend && npm run build
cd ../backend && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

…serves the whole application from <http://127.0.0.1:8000>.

### Monitoring progress

`GET /api/analyses/{id}` reports `status`, `progress` and `stage`. The PCAP Files
page shows the same information inline and polls while work is in flight.

---

## Configuration

Copy `.env.example` to `.env`; every value is optional. Environment variables use
the `APACKETS_` prefix.

| Variable | Default | Meaning |
|---|---|---|
| `APACKETS_DATA_DIR` | `./data` | Uploads, analyses, exports and the SQLite database. |
| `APACKETS_MAX_UPLOAD_MB` | `512` | Upload size ceiling. |
| `APACKETS_TSHARK_PATH` | auto | Explicit path to `tshark`. |
| `APACKETS_CAPINFOS_PATH` | auto | Explicit path to `capinfos`. |
| `APACKETS_TSHARK_TIMEOUT_S` | `300` | Per-invocation wall-clock budget. |
| `APACKETS_MAX_OBJECT_BYTES` | `52428800` | Largest file that may be extracted from a capture. |
| `APACKETS_BODY_PREVIEW_BYTES` | `262144` | How much HTTP body is retained for display. |
| `APACKETS_MAX_EXPORT_ROWS` | `200000` | Row cap for a single CSV export. |
| `APACKETS_RETAIN_UPLOADS` | `true` | Keep the source capture. **Required** for packet detail and stream views. |
| `APACKETS_WORKER_THREADS` | `2` | Concurrent analysis jobs. |
| `APACKETS_HOST` | `127.0.0.1` | Bind address. |
| `APACKETS_PORT` | `8000` | Bind port. |
| `APACKETS_CORS_ORIGINS` | loopback dev ports | Comma-separated or JSON array. |
| `APACKETS_LOG_LEVEL` | `INFO` | `DEBUG`…`ERROR`. |

These can also be changed at runtime from the **Settings** page (upload limit,
object size limit, body preview size, TShark timeout, upload retention); runtime
changes are stored in the database and take effect without a restart.

### Exposing it on a LAN

Binding to anything other than loopback exposes unauthenticated capture data and
upload endpoints. **There is no authentication in this proof of concept.** If you
need remote access, put it behind an authenticating reverse proxy or an SSH
tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@analyst-workstation
```

---

## Using the application

| Page | What it does |
|---|---|
| **Dashboard** | Summary cards, protocol distribution, traffic over time, top talkers, top ports, findings summary, protocol hierarchy, and an explicit list of what the analysis *cannot* show. |
| **PCAP Files** | Drag-and-drop upload with live progress; table of analyses with status, packet count, capture window, open/delete/cancel actions. |
| **Packets** | The core explorer: dense sortable table, basic filters, advanced Wireshark display-filter mode, next/previous match navigation, CSV export, per-packet detail tree and hex/ASCII viewer. |
| **Conversations** | Unique conversations with per-direction packet/byte counts, TCP state, and a *Follow stream* viewer with ASCII/hex modes, in-stream search and local export. |
| **HTTP** | Request/response transactions with methods, hosts, URIs, status codes, user agents, headers and body previews; filters plus investigative lead flags (4xx/5xx, unusual methods, suspicious paths, plaintext credentials, IP-literal hosts, unusual user agents). |
| **DNS** | Queries and answers, response codes, returned addresses and TTLs; filters by domain, client, type; flags for long/encoded-looking names, repeated NXDOMAIN, unanswered queries and multi-IP answers. |
| **TLS** | Handshake metadata only: versions, SNI, ALPN, cipher suites, JA3/JA3S/JA4 fingerprints, and certificate subject/issuer/validity where the capture contains them. |
| **Hosts** | Every observed endpoint with MAC, first/last seen, bytes in and out, top ports, protocols, associated DNS names and TLS SNI, plus a relationship graph built strictly from observed connections. |
| **Files and Objects** | Content recoverable with supported dissectors (HTTP object export), with hashes, size, extraction status and a download action. |
| **Findings** | Explainable, rule-based observations with severity, the exact reason and observed numbers, supporting packet numbers, associated entities, and recommended next steps. |
| **Settings** | Effective configuration, runtime-editable limits, and analyst-supplied indicators for the indicator-match rule. |

### Packet filters

The basic filter bar covers IP, source/destination IP, port, protocol, transport,
TCP flags, packet length, time range and free-text search.

Advanced mode accepts Wireshark display-filter syntax, evaluated by TShark:

```
ip.addr == 192.168.1.10
tcp.port == 443
dns
http
tls.handshake.type == 1
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

A valid filter that matches nothing is reported as **0 results**. A filter that
does not compile is reported as **invalid**, with TShark's reason. These two
states are never conflated.

---

## HTTP API

All endpoints are under `/api` and return JSON. Full interactive documentation is
served at `/api/docs`.

Errors always use one envelope:

```json
{ "error": { "code": "invalid_filter", "message": "…", "details": {} } }
```

Paginated lists return `{ "items": [], "total": 0, "page": 1, "page_size": 100 }`.

### Analysis management

| Method | Path |
|---|---|
| `POST` | `/api/analyses` — multipart `file`; returns `202` with the analysis |
| `GET` | `/api/analyses` |
| `GET` | `/api/analyses/{id}` |
| `GET` | `/api/analyses/{id}/summary` |
| `GET` | `/api/analyses/{id}/jobs` |
| `POST` | `/api/analyses/{id}/cancel` |
| `DELETE` | `/api/analyses/{id}?confirm=true` |

### Packets

| Method | Path |
|---|---|
| `GET` | `/api/analyses/{id}/packets` — `filter`, `ip`, `src_ip`, `dst_ip`, `port`, `src_port`, `dst_port`, `protocol`, `transport`, `tcp_flags`, `min_length`, `max_length`, `start_time`, `end_time`, `search`, `stream_id`, `sort`, `order`, `page`, `page_size` |
| `GET` | `/api/analyses/{id}/packets/{number}` — detail incl. protocol layers and hex dump |
| `GET` | `/api/analyses/{id}/packets/{number}/neighbors?filter=…&direction=next\|prev` |
| `POST` | `/api/analyses/{id}/filter` — validate a display filter without erroring |
| `GET` | `/api/analyses/{id}/packets/export.csv` — same filters as the list |

### Protocol views

`GET /api/analyses/{id}/` + `conversations`, `streams/{stream_id}`,
`streams/{stream_id}/search`, `streams/{stream_id}/export`, `http`,
`http/{transaction_id}`, `dns`, `dns/{row_id}`, `dns/domains`, `tls`,
`tls/{session_id}`, `tls/fingerprints`, `hosts`, `hosts/{ip}`, `hosts/graph`,
`findings`, `findings/{finding_id}`, `findings/rules`, `objects`,
`objects/{object_id}/export`.

### Settings and indicators

`GET|PUT /api/settings`, plus `GET|POST /api/indicators` and
`DELETE /api/indicators/{id}`.

### Meta

`GET /api/health`, `GET /api/capabilities` (which feature areas are present in
this build), `GET /api/openapi.json`.

---

## Security model

This application parses **hostile input by design**. The following are
implemented:

- **Local-only defaults.** Services bind to `127.0.0.1` unless explicitly changed.
- **No shell.** Every TShark invocation is an argument vector with
  `shell=False`; no command string is ever constructed from user input.
- **Controlled filter execution.** Display filters are validated before use and
  are passed as a single argv element.
- **Input validation.** Extension allow-list, magic-byte sniffing, size limits,
  and a TShark readability check before an analysis is created.
- **Randomised server-side identifiers.** Upload paths are
  `data/uploads/<uuid4-hex>.<ext>`; the user-supplied filename is sanitised and
  kept only as a display label.
- **Path-traversal protection.** Every path derived from capture content or a
  database row is resolved and asserted to be inside its permitted directory.
- **Untrusted extracted files.** Objects are stored under
  `data/analyses/<id>/objects/`, are never executed, and are only served through
  an explicit download endpoint with `X-Content-Type-Options: nosniff`.
- **Resource limits.** Subprocess timeouts, upload ceilings, object-size limits,
  row caps on exports, and a bounded worker pool.
- **Safe deletion.** Removing an analysis validates the id, cancels any running
  job, deletes rows, then removes the directory.
- **Unprivileged runtime.** The container runs as a non-root user with
  `no-new-privileges` and all capabilities dropped; TShark needs no capture
  privileges for file analysis.
- **Pinned dependencies** in `requirements.txt` and `package.json`.
- **No telemetry.** Nothing is sent anywhere.

Capture-derived strings (hostnames, HTTP headers, file names, packet info) are
never interpreted as HTML and never used to build a path or a command. The
frontend does not use `dangerouslySetInnerHTML`.

---

## Testing

```bash
# from the repository root
cd backend
.venv/bin/python -m pytest tests -q            # Linux / macOS
.\.venv\Scripts\python.exe -m pytest tests -q  # Windows
```

The suite builds its own captures with Scapy and asserts against real TShark
output, so it needs **no internet access**. Slow large-capture tests are opt-in:

```bash
python -m pytest tests -q --run-slow
```

Environment note: Scapy writes a cache directory. Set `XDG_CACHE_HOME` to a
writable location if your environment restricts writes to the home directory:

```powershell
$env:XDG_CACHE_HOME = "$PWD\.cache"
```

---

## Troubleshooting

**"TShark/capinfos is not available on this host" / uploads rejected with 503**

TShark is not on `PATH`. Check:

```bash
tshark --version
```

Windows installs to `C:\Program Files\Wireshark\` and does not add itself to
`PATH`. Either add that directory to `PATH` or set an explicit path:

```
APACKETS_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
APACKETS_CAPINFOS_PATH=C:\Program Files\Wireshark\capinfos.exe
```

**`GET /api/health` reports `"status": "degraded"`**

TShark could not be executed. The `tshark` object in the response contains the
resolved `path` and `error`.

**Upload returns 415 `unsupported_file_type`**

The file's magic bytes are not PCAP/PCAPNG. Truncated or renamed files are
rejected here deliberately. `.pcap`, `.pcapng` and `.cap` extensions are
accepted; the content is what actually decides.

**Upload returns 400 `invalid_capture`**

The file has a valid header but TShark cannot read it — usually a truncated
capture. Re-export the capture from your capture tool.

**Dashboard shows "No transport conversations could be reconstructed"**

The capture has no TCP/UDP frames, or only non-IP traffic. This is a statement
about the capture, not an error.

**TLS page shows no SNI or certificates**

Expected in several real situations: the capture may be missing the handshake,
the client may not send SNI, or Encrypted ClientHello may conceal it. Unavailable
fields are left empty rather than guessed.

**HTTP page shows nothing for HTTPS traffic**

Correct and intentional. TLS payloads are not decrypted, so there are no HTTP
requests inside them. Only cleartext HTTP (typically port 80) is decodable.

**Followers of TCP streams show odd `\r` characters on Windows**

Windows' C runtime expands every LF that TShark writes into CRLF. The backend
inverts this expansion when reassembling streams, so the byte view and hex view
match the capture exactly. If you see stray CRs, you are on an older build.

**A very large capture takes a long time**

Processing time is dominated by TShark indexing every frame. The UI stays
responsive and reports progress and stage throughout. Packet detail, stream
reassembly, display filters and object export are the most expensive individual
operations because they re-read the capture.

**Analysis fails and the error column is filled in**

Other analyses are unaffected — each job is independent, and a failure in an
optional stage (HTTP, DNS, TLS, hosts, objects, detection) is recorded as a
warning while the rest of the analysis still completes.

---

## Known limitations

These are real and intentional for a proof of concept:

1. **HTTPS is not decrypted.** The TLS page reports handshake metadata only.
   HTTP paths, headers and bodies inside TLS are not available and are not
   invented. Supplying TLS session keys is not implemented.
2. **No authentication.** Anyone who can reach the port can read every capture
   and upload files. Keep it on loopback.
3. **Worker runs in-process.** A crash of the API process loses in-flight jobs
   (they are marked failed on next start, not resumed). There is no external
   queue.
4. **SQLite, single node.** Fine for a workstation; not for concurrent multi-user
   use or very large corpora.
5. **Display filters re-read the capture.** Each advanced filter runs TShark over
   the whole file, which is correct but not instant on multi-gigabyte captures.
6. **Object extraction covers HTTP only.** Other protocols' dissectors are not
   wired up yet.
7. **Detection is heuristic and rule-based.** It surfaces investigative leads with
   their reasons. It does not identify malware, does not claim to detect all
   attacks, and deliberately requires no internet or threat-intelligence feed.
8. **No live capture.** File analysis only.
9. **Packet-detail byte-range highlighting** in the hex viewer is not
   implemented; the hex/ASCII dump itself is.
10. **Certificate metadata depends on the capture.** TLS 1.3 certificates are
    usually encrypted and therefore unavailable.
11. **`APACKETS_RETAIN_UPLOADS=false`** makes packet detail, stream views and
    object export unavailable, because those features re-read the original file.

---

## Project layout

```
backend/
  app/
    main.py                 FastAPI application, router wiring, static SPA serving
    core/                   config, runtime-overridable settings, errors, logging
    db/                     SQLite access layer + schema.sql
    schemas/                request/response models
    services/
      tshark.py             the ONLY place a subprocess is spawned
      capture_parser.py     upload validation + capture metadata
      packet_indexer.py     streamed field extraction into SQLite
      conversation_analyzer.py
      stream_analyzer.py    TCP stream reassembly + search + export
      host_analyzer.py
      http_analyzer.py
      dns_analyzer.py
      tls_analyzer.py
      detection_engine.py   explainable rules
      object_extractor.py   file recovery with path-traversal protection
      pipeline.py           stage orchestration, progress, cancellation
      jobs.py               background worker + job records
      storage.py            layout, hashing, safe filenames, deletion
    api/                    one router per feature area + shared deps
  tests/                    pytest suite (Scapy-generated captures)
frontend/
  src/
    components/  pages/  layouts/  hooks/  services/  types/  utils/
docs/
  CONTRACT.md               the frozen interface contract
data/                       runtime: uploads, analyses, database  (gitignored)
docker-compose.yml  .env.example  README.md
```

---

## Implementation status

Verified working end to end (upload → background processing → dashboard →
packet explorer → protocol views → findings → export) against real captures.
See the report accompanying this build for the exact verification evidence, and
`GET /api/capabilities` for which feature areas are compiled into a given build.

`docs/CONTRACT.md` is the normative interface specification: database schema,
API shapes, analyzer conventions and security rules. It is written first and the
code conforms to it, so it doubles as the map for extending the application.
#   A p a c k e t s  
 