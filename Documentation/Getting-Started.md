# Getting Started

Install ShadowPackets on one machine, run it, upload a first capture and know what the
processing stages are doing while you wait.

ShadowPackets is a **locally hosted** workbench: TShark dissects the capture on this
host, the result is indexed into SQLite, and a React front end serves it over
loopback. Nothing is uploaded anywhere and there is no telemetry — see
[Architecture.md](Architecture.md) for why that holds.

---

## 1. Prerequisites

| Component | Version | Why |
|---|---|---|
| TShark | 4.2+ recommended; 4.6.8 is what this build was developed against | **Required.** It is the only packet decoder in the application. JA3/JA3S/JA4 fields need 4.2+. |
| Python | 3.12+ | Backend. |
| Node.js | 20+ | Frontend build and dev server only. |
| Docker | optional (Compose v2) | Only for the containerised route in §2.3. |

TShark is not bundled. Install Wireshark (which ships `tshark` and `capinfos`)
from <https://www.wireshark.org/download.html>, or:

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

The application resolves the binaries from `SHADOWPACKETS_TSHARK_PATH` /
`SHADOWPACKETS_CAPINFOS_PATH` first, then `PATH`, then the usual Wireshark install
directories (`C:\Program Files\Wireshark`, `C:\Program Files (x86)\Wireshark`,
`/usr/bin`, `/usr/local/bin`) — see `resolve_binary()` in
`backend/app/services/tshark.py`. Live capture is deliberately not supported, so
TShark needs no capture privileges.

---

## 2. Running it

### 2.1 Docker Compose

```bash
docker compose up --build
```

Then open **<http://127.0.0.1:8080>**. Both containers publish on loopback only
(`127.0.0.1:8080:80` for the frontend, `127.0.0.1:8000:8000` for the backend), and
analysis data lives in the `shadowpackets-data` named volume mounted at `/data`.

```bash
docker compose down        # stop, keep the stored analyses
docker compose down -v     # stop and delete the data volume
```

To keep captures in a directory you control, set `SHADOWPACKETS_DATA_HOST` in `.env`
and use the bind mount that is commented out in `docker-compose.yml`. The
containers run with `no-new-privileges:true` and all capabilities dropped (the
frontend's nginx adds back only `CHOWN`, `SETGID`, `SETUID`,
`NET_BIND_SERVICE`); memory and CPU are capped.

### 2.2 Local development (two processes)

Backend, from the repository root:

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

Frontend, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. The Vite dev server listens on `127.0.0.1:5173`
and proxies `/api` to `http://127.0.0.1:8000` (`frontend/vite.config.ts`); the
proxy target is overridable with `SHADOWPACKETS_BACKEND_URL`. The front end builds
every request URL from `API_PREFIX = '/api'` in `frontend/src/services/api.ts`,
so the same code works behind the proxy and behind the backend-served bundle.

Interactive API documentation is at <http://127.0.0.1:8000/api/docs>, and the
OpenAPI document at `/api/openapi.json`.

### 2.3 Single-process, production-style

`npm run build` emits `frontend/dist`, and the backend serves that directory
automatically when it exists:

```bash
cd frontend && npm run build
cd ../backend && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The whole application is then served from <http://127.0.0.1:8000>, with a
client-route fallback for SPA paths.

### 2.4 Configuration

Copy `.env.example` to `.env`; every value is optional and uses the `SHADOWPACKETS_`
prefix. For a local run, `python backend/tools/init_env.py` fills the default
TShark and Capinfos paths for the current OS (Windows `C:\Program Files\Wireshark`,
Linux `/usr/bin`) and keeps any value already present. The ones that matter on a
first run are `SHADOWPACKETS_DATA_DIR` (default
`./data`, resolved against the repository root), `SHADOWPACKETS_MAX_UPLOAD_MB` (512),
`SHADOWPACKETS_WORKER_THREADS` (2), `SHADOWPACKETS_HOST` (127.0.0.1) and
`SHADOWPACKETS_RETAIN_UPLOADS` (true). Upload limit, object-size limit, body-preview
size, TShark timeout and upload retention can also be changed at runtime from
`/settings`.

Binding anything other than loopback exposes unauthenticated capture data, so
there is one rule worth repeating: **there is no authentication**. Remote access
belongs behind an authenticating proxy or an SSH tunnel
(`ssh -L <host-port>:127.0.0.1:<host-port> user@workstation`).

---

## 3. What the first run does

On startup the application's lifespan handler runs five things, in this order
(`backend/app/main.py`):

1. `setup_logging(settings.log_level)` — logging at `INFO` unless changed.
2. `settings.ensure_dirs()` — creates `data/`, `data/uploads/`, `data/analyses/`
   and `data/exports/` (and the data directory if `SHADOWPACKETS_DATA_DIR` points
   somewhere that does not exist yet).
3. `db.init_db()` — opens `data/shadowpackets.db` and executes
   `backend/app/db/schema.sql`. The schema is written with
   `CREATE TABLE IF NOT EXISTS`, so this is idempotent: on a fresh checkout it
   creates all fifteen tables, on a later start it leaves them alone. No sample
   data, no seeded analysis, no migration step.
4. `tshark.version()` — resolves and executes TShark once and logs the result. A
   missing binary is logged as a warning (`"TShark is not available; uploads will
   be rejected until it is installed"`); it does not stop the server, and
   `GET /api/health` then reports `"status": "degraded"` with the resolved
   `path` and `error` under `tshark`.
5. `suricata_rules.seed_bundled_rules_if_empty()` — on a fresh database, imports
   the rule sets vendored under `backend/rules/`. It is skipped when the rule
   table already holds any rule, so an analyst's edits or uploads are never
   overwritten on restart.

It then logs the version, the data directory and the bind address, including
whether that address is local-only. Two things it deliberately does **not** do:

* **Re-import Suricata rules on every start.** The bundled sets are imported only
  while the store is empty; **Import bundled** on `/settings`
  (`POST /api/suricata/rules/seed`, idempotent) refreshes them on demand.
* **Queue an analysis.** Nothing is processed until you upload something.

`GET /api/capabilities` reports which feature areas this build actually has, by
trying to import each router module, plus whether TShark is available.

---

## 4. Your first capture

1. Open `/files` (PCAP Files) and drag a `.pcap`, `.pcapng` or `.cap` file onto
   the drop zone, or use the file picker. The same upload is
   `POST /api/analyses` with a multipart `file` field, and it returns **202**
   immediately with the analysis row.
2. The upload is validated before any analysis is created:
   * **extension** must be one of `.pcap`, `.pcapng`, `.cap` (the default of
     `allowed_extensions`, env `SHADOWPACKETS_ALLOWED_EXTENSIONS`, in
     `backend/app/core/config.py`), else `415 unsupported_file_type`;
   * **size** is streamed to disk and checked against the upload ceiling
     (512 MB by default), else `413 file_too_large`;
   * **magic bytes** are sniffed (`storage.sniff_capture_format`), so a renamed
     file is rejected rather than mis-parsed;
   * **TShark must be able to read it** (`capture_parser.inspect`), else
     `400 invalid_capture`.
3. The file is stored as `data/uploads/<32-hex-analysis-id><ext>`; your filename
   is sanitised and kept only as a display label. A `jobs` row is created and the
   job is queued on the in-process worker pool.
4. Watch it on `/files`, which shows status, progress and stage and polls while
   work is in flight; the same values are in `GET /api/analyses/{id}`
   (`status`, `progress`, `stage`, plus `warnings`).
5. When `status` is `completed`, select the analysis in the top bar. The
   dashboard (`/`), `/info`, `/threat-hunt` and the protocol pages are all gated
   on a finished analysis: an unfinished one is `409 analysis_not_ready`, an
   unknown one is `404 analysis_not_found`.

A capture with an encrypted-only, filtered or truncated payload is not an error:
the analytics pages say what could not be measured rather than inventing it.

---

## 5. The processing stages

`run_analysis()` in `backend/app/services/pipeline.py` is the whole pipeline. The
stage order below is the order the code performs it, with the progress band each
stage owns (`BANDS` in the same file) and what the stage writes.

| # | Stage | Progress band | Implemented in | Writes |
|---|---|---|---|---|
| 1 | `metadata` | 0–5% | `capture_parser.inspect` | `analyses.file_type`, `encapsulation`, `file_size`, `file_sha256`, `packet_count` |
| 2 | `packets` | 5–50% | `packet_indexer.index_packets` | `packets` rows (one per frame, streamed), then the capture aggregates back onto `analyses` (`bytes_total`, `capture_start`, `capture_end`, `duration`, `src_ip_count`, `dst_ip_count`, `tcp_count`, `udp_count`, `dns_count`, `http_count`, `tls_count`) |
| 3 | `conversations` | 50–58% | `conversation_analyzer.analyze` | `conversations`, `streams` |
| 4 | `http` | 58–68% | `http_analyzer.analyze` | `http_transactions` |
| 5 | `dns` | 68–76% | `dns_analyzer.analyze` | `dns_queries` |
| 6 | `tls` | 76–83% | `tls_analyzer.analyze` | `tls_sessions` |
| 7 | `hosts` | 83–90% | `host_analyzer.analyze` | `hosts` |
| 8 | `objects` | 90–94% | `object_extractor.analyze` | `objects` (rows plus the files under `data/analyses/<id>/objects/`) |
| 9 | `detection` | 94–97% | `detection_engine.analyze` | `findings` |
| 10 | `suricata` | 97–99% | `suricata_engine.analyze` | `findings` (`rule_id = suricata:<sid>`) |
| 11 | `finalise` | 99–100% | `pipeline._cache_protocol_hierarchy`, `_store_warnings`, `_refresh_counts` | `stats_cache` (`protocol_hierarchy`, `warnings`) and the DNS/HTTP/TLS counters on `analyses` |

Stage 1 and 2 are required: a failure there fails the job. Stages 3–10 are
**optional and independent** — each is imported by name, called through its
`analyze(ctx, analysis_id, capture_path)` entry point, and if it raises, the
exception is logged, recorded as a warning and the analysis still completes.
Losing an entire capture's metadata over one dissector would be worse than a
partial result, so a partly-analysed capture is a normal outcome; the warnings
are returned by `GET /api/analyses/{id}` and shown on `/info` and `/files`.

Cancellation is cooperative: `ctx.check_cancelled()` is called between stages and
inside the long packet loop, so **Cancel** on `/files` stops the job at the next
checkpoint rather than mid-write.

### How long it takes

Wall clock is dominated by stage 2, because TShark has to walk every frame.
Measured on this machine from `jobs.started_at` → `jobs.finished_at` in
`data/shadowpackets.db`:

| Capture | Packets indexed | Wall clock |
|---|---|---|
| `sf19us-MTA-lab-01.pcap` | 4,500 | 23.66 s |
| `sf19us-MTA-lab-03.pcap` | 4,093 | 35.60 s |
| `sf19us-MTA-lab-09.pcap` | 4,003 | 8.56 s |
| `sf19us-MTA-lab-07.pcap` | 1,933 | 6.29 s |
| `SpaceX_111025.pcapng` | 1,849 | 4.40 s |
| `nmap_sn_livehosts.pcapng` | 572 | 2.94 s |
| `sf19us-MTA-lab-02.pcap` | 398 | 5.49 s (a second run of the same file: 4.88 s) |
| `tls.pcap` | 29 | 2.98 s |
| `sf19us-MTA-lab-12.pcap` | 32 | 4.72 s (a second run: 2.98 s) |

Two things are worth reading off that table. First, small captures are not
instant: there is a fixed cost of a few seconds across the stages, because every
stage spawns TShark at least once — measured, a 5-packet `_probe.pcap` took 0.99 s
to 3.88 s across runs and the 29-packet `tls.pcap` took 2.98 s. Second, the spread
at similar packet counts — 4,003 packets in 8.56 s versus 4,093 in 35.60 s — is
real and comes from what the capture _contains_ (streams to reassemble, HTTP
bodies to preview, objects to extract), not from packet count alone. The README's
guidance holds: the practical ceiling depends on the host's disk and CPU, and no
fixed maximum processing time is promised.

### What a finished analysis typically holds

Indexed row counts from the same library, per capture:

| Capture | packets | conversations | http | dns | tls | hosts | findings | objects |
|---|---|---|---|---|---|---|---|---|
| `sf19us-MTA-lab-01.pcap` | 4,500 | 195 | 102 | 136 | 41 | 67 | 50 | 71 |
| `sf19us-MTA-lab-02.pcap` | 398 | 37 | 6 | 4 | 0 | 7 | 8 | 6 |
| `sf19us-MTA-lab-09.pcap` | 4,003 | 90 | 8 | 39 | 1 | 12 | 40 | 8 |
| `SpaceX_111025.pcapng` | 1,849 | 49 | 0 | 14 | 20 | 27 | 21 | 0 |
| `nmap_sn_livehosts.pcapng` | 572 | 14 | 0 | 8 | 4 | 13 | 9 | 0 |
| `tls.pcap` | 29 | 3 | 0 | 0 | 3 | 2 | 0 | 0 |

Zeroes there are results, not failures. `SpaceX_111025.pcapng` contains no
cleartext HTTP, so it has no HTTP transactions and no extractable objects;
`nmap_sn_livehosts.pcapng` is a scan, so it has conversations and hosts but no
HTTP. What is _absent_ is stated on `/info` and by the Threat Map cards rather
than being shown as a measured zero.

The library in `data/` currently holds **22** rows in `analyses` and 19 rows in
`jobs` (measured with an immutable read-only connection to
`data/shadowpackets.db`), not the 21 the surrounding brief mentions; the extra row is
`ef79e0d702094c53a2ee3e823d072dec` / `nmap_sn_livehosts.pcapng`, the most
recently created. Two of the 22 (`dddd…`, `eeee…`) are 32-character ids used as
test fixtures.

---

## 6. Running the tests

The suite builds its own captures with Scapy and asserts against real TShark
output, so it needs no internet access.

```powershell
# Windows, from the repository root
cd backend
.\.venv\Scripts\python.exe -m pytest tests -q
```

```bash
# Linux / macOS
cd backend
.venv/bin/python -m pytest tests -q
```

Slow tests are opt-in:

```bash
python -m pytest tests -q --run-slow
```

`backend/tests/conftest.py` registers `--run-slow` and skips anything marked
`slow` without it (one test in `test_api_and_pipeline.py`). It also does three
things worth knowing before you debug a failure:

* sets `XDG_CACHE_HOME` to `<repo>/.cache` and `XDG_CONFIG_HOME` to
  `<repo>/.config` **before** Scapy or the application is imported, because
  Scapy wants a writable cache directory;
* redirects `SHADOWPACKETS_DATA_DIR` to a throwaway `<repo>/.tmp/pytest-data-<pid>`
  directory, so the suite never touches `data/shadowpackets.db` or your uploads, and
  deletes it when the session ends;
* gives every test a `fresh_db` fixture that empties the per-analysis tables and
  removes uploaded files, plus a `client` (FastAPI `TestClient`) and a
  `run_analysis` helper that uploads through the real API and waits for
  completion.

If your environment restricts writes to the home directory, set the cache
directory yourself:

```powershell
$env:XDG_CACHE_HOME = "$PWD\.cache"
```

The seven test modules under `backend/tests/` define 177 `def test_…` functions
between them, distributed as: `test_api_and_pipeline.py` 68,
`test_tshark_runner.py` 36, `test_storage_and_validation.py` 31,
`test_suricata_rules.py` 18, `test_threat_hunt.py` 11,
`test_alert_linkage.py` 10, `test_findings_context.py` 3.

Front end type checking is a separate command, and it is strict
(`noUnusedLocals` / `noUnusedParameters`):

```bash
cd frontend
npx tsc --noEmit
```

### If something goes wrong

| Symptom | Cause |
|---|---|
| Uploads rejected with `503`, or `/api/health` reports `degraded` | TShark is not on `PATH`. Check `tshark --version`, then add the Wireshark directory to `PATH` or set `SHADOWPACKETS_TSHARK_PATH` / `SHADOWPACKETS_CAPINFOS_PATH`. |
| Upload returns `415 unsupported_file_type` | The magic bytes are not PCAP/PCAPNG. Truncated or renamed files are rejected on purpose. |
| Upload returns `400 invalid_capture` | Valid header, but TShark cannot read it — usually a truncated capture. |
| `/files` shows a finished analysis with warnings | An optional stage failed; the message names the stage and the exception. The rest of the analysis is intact. |
| A job stays `running` after a crash or a hard stop of the server | Expected. The worker lives in the API process, so in-flight work dies with it; nothing in the code re-sets those rows at startup, so delete the analysis and re-upload. (The repository README describes them as being "marked failed on next start"; that reconciliation does not exist in the current code — see [Architecture.md](Architecture.md) §5.) |

---

## Related

[README.md](README.md) · [Architecture.md](Architecture.md) ·
[Reference/API.md](Reference/API.md) · [PCAP-Files.md](PCAP-Files.md) ·
[Dashboard.md](Dashboard.md) · [Settings.md](Settings.md) ·
[docs/CONTRACT.md](../docs/CONTRACT.md)
