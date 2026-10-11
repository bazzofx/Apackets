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
- [Suricata rule based detection](#suricata-rule-based-detection)
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
| **Dashboard** | The at-a-glance visual overview: KPI tiles (DNS requests, conversations, hosts, findings by severity, packets, bytes, duration), a central **network map** of the endpoints this capture actually talked to, most-data-sent / most-data-received cards, the top 5 domains with direction-split sent/received bars, a protocol mix donut and a traffic sparkline. |
| **Info** | The reference view: the full summary cards, capture window, protocol distribution, traffic over time, top talkers, top ports, top conversations, protocol hierarchy, findings and the analysis limitations list. |
| **Conversations** | Unique conversations with per-direction packet/byte counts and TCP state, shown three ways: a **Flow** alluvial diagram (thickness = bytes), an **Info** table with the full detail pane, and a **Timeline** tab that lays one conversation out over time - the protocol events it carried, every indexed frame, and the reassembled stream's chunk timeline. The *Follow stream* viewer offers ASCII/hex modes, in-stream search and local export; the Alerts filter narrows either tab to the conversations tied to a finding. |
| **Hosts** | Every observed endpoint with MAC, first/last seen, bytes in and out, top ports, protocols, associated DNS names and TLS SNI, plus a relationship graph built strictly from observed connections. |
| **Findings** | Explainable, rule-based observations with severity, the exact reason and observed numbers, supporting packet numbers, associated entities, and recommended next steps. |
| **Threat Hunt** | Seventeen behavioural detections, grouped into tabs by phase of an investigation (recon and movement, C2 and name resolution, exfiltration and staging, web and alerts) with an Overview tab listing every headline number at a glance. Each detection carries the visual that suits it - interval histograms for beaconing, a source x destination-port heatmap for scanning, ranked bars, scatter plots, timelines and severity-ranked tables - plus what the pattern may indicate and, on every card, what it does **not** prove. Every figure is a real measurement from the analysis index, and each card links into the page that holds the underlying rows. |
| **Files and Objects** | Content recoverable with supported dissectors (HTTP object export), with hashes, size, extraction status and a download action. |
| **Packets** | The core explorer: dense sortable table, basic filters, advanced Wireshark display-filter mode, next/previous match navigation, CSV export, per-packet detail tree and hex/ASCII viewer. |
| **HTTP** | Request/response transactions with methods, hosts, URIs, status codes, user agents, headers and body previews; filters plus investigative lead flags (4xx/5xx, unusual methods, suspicious paths, plaintext credentials, IP-literal hosts, unusual user agents). |
| **DNS** | Queries and answers, response codes, returned addresses and TTLs; filters by domain, client, type; flags for long/encoded-looking names, repeated NXDOMAIN, unanswered queries and multi-IP answers. |
| **TLS** | Handshake metadata only: versions, SNI, ALPN, cipher suites, JA3/JA3S/JA4 fingerprints, and certificate subject/issuer/validity where the capture contains them. |
| **PCAP Files** | Drag-and-drop upload with live progress; table of analyses with status, packet count, capture window, open/delete/cancel actions. |
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

## Suricata rule based detection

APackets can evaluate Suricata rules. Two rule sets are vendored with the
application and an analyst can upload more; matches become ordinary findings,
alongside the ones the built-in rules produce.

**This is not Suricata.** No Suricata binary is installed and none is required.
`backend/app/services/suricata_engine.py` is a native Python matcher over the
fields TShark has already extracted during the packet, HTTP, DNS and TLS stages;
`backend/app/services/suricata_rules.py` is the parser and storage layer. Rule
semantics are implemented conservatively - an option that cannot be honoured
exactly causes the whole rule to be skipped rather than approximated. A rule
firing here means "this rule's pattern was present in the extracted fields", not
"Suricata would fire".

### Rule sources (vendored, offline)

| Set | Files | Rules | Licence | Upstream |
|---|---|---|---|---|
| `backend/rules/daffainfo/` | 252 | 1,167 | Apache-2.0 | <https://github.com/daffainfo/suricata-rules> at commit `23bfba7e688fdf5fadd8e378f070dae843e14263` |
| `backend/rules/oisf/` | 32 | 448 | GPL-2.0 | <https://github.com/OISF/suricata> (`rules/` directory) at commit `4badfd13f43e112dd61c5cbab5718765512ed5ad` |

Combined: 284 `.rules` files, 1,615 rules, about 615 KB. The upstream directory
layout is preserved, so rules keep their context (`http/cves/<year>/`,
`http/cnvd/<year>/`, `http/default-logins/`, `http/web-attacks/`, ...).
`backend/rules/PROVENANCE.md` records the upstream URLs and commit SHAs;
`backend/rules/README.md` describes the import flow.

**The application never downloads rules at runtime.** There is no network access
by design, for rule updates or for anything else. Rules arrive either from the
vendored tree or from analyst uploads.

Rules parse into `suricata_rules`, a table defined in `backend/app/db/schema.sql`
and keyed by SID. The verbatim rule text is stored, so a rule can be shown,
edited and re-imported unchanged. Of the 1,615 vendored rules, **1,114 are
evaluable** by the matcher and **501 are skipped** because they need engine
features APackets cannot honour. A skipped rule is stored, listed and clearly
flagged in the UI; it is never partially matched.

### What is evaluated

The rule header is evaluated in full: action, protocol, source and destination
addresses and ports (including `!` negation, CIDR, `[...]` lists, ranges,
`$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS` and the other standard variables),
and the `->` and `<>` directions.

Options evaluated: `flow`, `flags`, `dsize`, `ttl`, `content` (with `nocase`,
`startswith`, `endswith`, `offset`, `depth`, `fast_pattern`, hex escapes such as
`|3a|`, and negated content) and `pcre`, which is evaluated with Python's regex
engine with the `i`, `s`, `m` and `x` flags.

Content is matched against named inspection buffers taken from the reassembled
HTTP transactions and the packet index: `http.uri`, `http.raw_uri`, `http.host`,
`http.method`, `http.request_body`, `http.response_body`, `http.header`,
`http.request_header`, `http.response_header`, `http.user_agent`, `http.cookie`,
`http.referer`, `http.protocol`, `http.status_code`, `dns.query` and `tls.sni`.
Both the sticky-buffer form (`http.uri; content:"..."`) and the legacy modifier
form (`content:"..."; http_uri;`) are handled.

### What is skipped

A rule is skipped, and flagged as skipped in the UI, when it uses `flowbits`,
`xbits`, `threshold`, `detection_filter`, `byte_test` / `byte_jump` /
`byte_extract`, engine / app-layer / decode / stream events, content that has no
buffer selector and needs raw packet payload bytes, PCRE-only flags, or a
protocol APackets does not dissect (`smb`, `smtp`, `ike`, `mqtt`, `mdns`, `dnp3`,
`modbus`, `http2`, `pkthdr`).

### Findings and the pipeline

Matches become ordinary findings with `rule_id` set to `suricata:<sid>`, so they
appear in `GET /api/analyses/{id}/findings`, in the dashboard severity counts and
in the findings summary, next to the built-in rules. Each finding records the
sid, rev, classtype, action, rule source, the matched buffers, up to 10 example
matches with packet numbers, and states the evaluation basis. Findings are
grouped per rule and per peer pair / URI, capped at 25 grouped findings per rule
per capture (configurable).

Analysis runs an optional `suricata` stage after `detection`, in the 97-99%
progress band. Rules can also be re-run on demand for an existing analysis.

### Workflow

1. **Import.** The **Upload .rules** control on the Settings page accepts one or
   more `.rules` files (multipart, `.rules` only). **Import bundled** imports the
   vendored sets; it is idempotent, so re-importing refreshes rule text while
   keeping the enabled/disabled choice.
2. **Review.** The **Suricata rules** panel shows totals by severity and source,
   search plus severity / enabled / matcher-support / source filters, and a
   paginated table of SID, severity, protocol, action, message, category, source,
   hits and state.
3. **Enable or disable.** Every rule has an enabled/disabled toggle.
4. **Edit.** The **Edit** dialog edits the stored signature text. The SID must
   not change.
5. **Delete.** Removing a rule asks for confirmation.
6. **Run.** **Run on capture** re-evaluates every enabled rule against the
   selected analysis, reports matches per severity and links to the findings.

### Verified behaviour

Running the whole vendored set against `sf19us-MTA-lab-02.pcap` (398 packets, 6
HTTP transactions) evaluates the 1,114 evaluable rules (577 packet scope, 537
HTTP scope) in about 0.15 s and produces two high-severity findings:

| Finding | Message | Matched buffer |
|---|---|---|
| `suricata:50300004` | Possible SQL Injection attack (Contains singlequote POST data) | `http.request_body` |
| `suricata:51000006` | Possible JNDI Injection attack (Log4Shell) | `http.header` |

Both appear in the findings endpoint next to the built-in rules' findings. They
are leads, not verdicts: a signature match reports that a known pattern was
present in the extracted fields, and does not establish that the traffic was
malicious.

### Honest limitations

- There is no Suricata binary behind this, so rule behaviour is only as complete
  as the evaluated options listed above.
- Rules that need raw packet payload bytes are skipped, never matched against
  something else.
- Skipped options and undissected protocols are listed under *What is skipped*; a
  skipped rule never contributes a finding.
- PCRE-only flags are not supported.
- Matching is signature-based and does not prove maliciousness. See
  [Known limitations](#known-limitations).

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
| `GET` | `/api/analyses/{id}/summary` — accepts `?domain_limit=N` (default 5); returns the dashboard aggregates, `traffic_extremes` (`max_sender` / `max_receiver`), `top_domains` and the `top_domains_note` attribution caveat |
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

### Suricata rules

| Method | Path |
|---|---|
| `GET` | `/api/suricata/rules` - list rules (filters: `enabled`, `supported`, `severity`, `protocol`, `source`, `category`, `action`, `search`, `analysis_id`, `sort`, `order`; paginated) |
| `GET` | `/api/suricata/rules/stats` - totals by severity, source and category |
| `GET` | `/api/suricata/rules/{sid}` - one rule with its parsed options |
| `POST` | `/api/suricata/rules` - create one rule from its signature text |
| `PUT` | `/api/suricata/rules/{sid}` - edit the text and/or enable/disable |
| `DELETE` | `/api/suricata/rules/{sid}` - remove a rule |
| `POST` | `/api/suricata/rules/import` - upload one or more `.rules` files (multipart, field `file`) |
| `POST` | `/api/suricata/rules/seed` - import the vendored rule sets |
| `GET` | `/api/suricata/config` - matcher configuration |
| `PUT` | `/api/suricata/config` - update `HOME_NET`, variable overrides, finding cap |
| `GET` | `/api/analyses/{id}/suricata/alerts` - Suricata findings for one analysis |
| `POST` | `/api/analyses/{id}/suricata/run` - re-evaluate the enabled rules for one analysis |

Configuration defaults: `home_net` is RFC1918 plus loopback, link-local and IPv6
ULAs; `max_findings_per_rule` is `25`; `include_unsupported` is `false`;
`variables` holds overrides for `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_PORTS` and
the other rule variables (`*_SERVERS` default to `$HOME_NET`).

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
8. **The Suricata matcher is not Suricata.** No Suricata binary is installed or
   required; rules are evaluated by a native Python matcher against the fields
   TShark already extracted. Rules whose content needs raw packet payload bytes
   are skipped rather than approximated, and `flowbits`, `xbits`, `threshold`,
   `detection_filter`, `byte_test` / `byte_jump` / `byte_extract`, engine /
   app-layer / decode / stream events and PCRE-only flags are not evaluated. Of
   the 1,615 vendored rules, 501 are skipped for these reasons; a skipped rule is
   stored, listed and flagged, and never partially matched.
9. **No live capture.** File analysis only.
10. **Packet-detail byte-range highlighting** in the hex viewer is not
    implemented; the hex/ASCII dump itself is.
11. **Certificate metadata depends on the capture.** TLS 1.3 certificates are
    usually encrypted and therefore unavailable.
12. **`APACKETS_RETAIN_UPLOADS=false`** makes packet detail, stream views and
    object export unavailable, because those features re-read the original file.
13. **A signature match is not a verdict.** A Suricata rule that fires records
    that a known pattern was present in the extracted fields. It does not prove
    that the traffic was malicious, and a rule that does not fire does not prove
    that it was not.
14. **Per-domain byte figures are attribution, not ownership.** The dashboard's
    top-domains panel sums conversations involving the addresses this capture saw
    in that domain's DNS answers. Names that never appeared in a captured answer
    are absent, CNAME chains are not followed, and a shared or CDN address can
    legitimately carry several names. The caveat is returned with the data
    (`top_domains_note`) and shown under the panel. A DNS-only capture therefore
    legitimately shows **no** domains — names resolved, but nothing was exchanged
    with them.
15. **Certificate subject and issuer are often unavailable.** TShark's
    `x509af.subject` / `x509af.issuer` fields are ASN.1 CHOICE indices rather
    than distinguished names on the tested build, so the backend stores `NULL`
    instead of a misleading number. Certificate presence is therefore derived
    from the serial and validity columns, and a session can legitimately show a
    certificate with no subject or issuer.
16. **The host graph is not a topology.** Nodes and edges come only from
    conversations observed in the capture, and nodes are built from conversation
    endpoints, so a host that appears solely in non-TCP/UDP frames will not be
    drawn. The UI states this; nothing is inferred about physical or logical
    network layout.
17. **Very large captures are untested at scale.** A 20,000-packet generated
    capture is covered by an opt-in test, but the practical ceiling depends on
    the host's disk and CPU. No fixed maximum file size or processing time is
    promised.

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
      suricata_rules.py     Suricata rule parsing, storage and vendored import
      suricata_engine.py    native header/option/buffer matcher
      object_extractor.py   file recovery with path-traversal protection
      pipeline.py           stage orchestration, progress, cancellation
      jobs.py               background worker + job records
      storage.py            layout, hashing, safe filenames, deletion
    api/                    one router per feature area + shared deps
                            (routes_suricata.py for the rule endpoints)
  rules/                    vendored Suricata rule sets (daffainfo, oisf)
                            + PROVENANCE.md and import notes
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

The product path is implemented and verified end to end: **upload → background
processing → dashboard → packet explorer → conversations and TCP streams →
HTTP/DNS/TLS → hosts and graph → files and objects → findings → CSV and object
export**, with `DELETE`/cancel lifecycle handling throughout.

`GET /api/capabilities` reports which feature areas are compiled into a given
build, and `GET /api/health` reports whether TShark is usable.

### What was verified, and how

- **Backend test suite:** `python -m pytest backend/tests -q` — see the
  [Testing](#testing) section. The suite builds its own captures with Scapy and
  asserts against real TShark output, so it needs no network.
- **Real captures:** three real 2019 malware-traffic-analysis captures
  (398 / 164 / 32 packets) were uploaded through the HTTP API and processed to
  completion. For the 398-packet capture the run produced 37 conversations
  (22 established, 4 reset, 3 closed), 6 HTTP transactions, 4 DNS queries
  (2 NXDOMAIN), 7 hosts, 6 extracted HTTP objects and 6 findings — all derived
  from the capture, with no fabricated values.
- **Stream reconstruction:** byte-exact against an independent TShark path
  (`tcp.payload`) for text and binary payloads, including a real SMB2 stream
  (4,301 B client→server, 1,306 B server→client) and a synthetic stream carrying
  a retransmission plus an out-of-order segment, where the retransmitted bytes
  are deduplicated and the out-of-order segment is reordered.
- **Display-filter semantics:** a valid filter matching nothing returns 0
  results; an unparsable filter returns `422 invalid_filter` with TShark's
  reason. The two are never conflated, and unknown sort keys are rejected with
  `400` rather than reaching SQL.
- **Extraction and isolation:** extracted objects are stored under
  `data/analyses/<id>/objects/` under a server-generated identifier; a tampered
  `stored_path` of `../../evil.txt` yields `403 path_traversal`, and an object
  larger than the configured limit is recorded as `failed` with an explanatory
  note instead of being silently dropped.
- **Static serving:** the built SPA is served by the backend with client-route
  fallback; encoded traversal probes (`/%2e%2e/…`, `/..%2f…`) return `403`/`404`
  and never leak a file outside `frontend/dist`.

### Not verified in the build environment

- **Docker.** `docker compose config -q` passes and every `COPY` source in both
  Dockerfiles was checked against the build context, but the images were **not
  built or started** here: this machine's Docker engine requires elevated
  privileges / WSL access that the build sandbox denies
  (`open //./pipe/docker_engine: Access is denied`). Run
  `docker compose up --build` and confirm the health checks on a normal host.
- **Rendered UI.** The frontend was type-checked clean (`tsc` with
  `noUnusedLocals`/`noUnusedParameters`) and bundled successfully with Vite, and
  every endpoint each page consumes was verified against the live API — but the
  pages were never opened in a browser during this build, so visual layout and
  interactive behaviour have not been observed.

`docs/CONTRACT.md` is the normative interface specification: database schema,
API shapes, analyzer conventions and security rules. It is written first and the
code conforms to it, so it doubles as the map for extending the application.

### Suricata rule based detection

The vendored rule sets import, list, filter and evaluate; matches surface as
findings through `/api/analyses/{id}/findings` and
`/api/analyses/{id}/suricata/alerts`, and the whole enabled set runs against a
capture in well under a second (see
[Suricata rule based detection](#suricata-rule-based-detection)). The matcher is
native Python over TShark-extracted fields — it is **not** Suricata — and rules
it cannot evaluate are stored, listed and flagged rather than approximated.
