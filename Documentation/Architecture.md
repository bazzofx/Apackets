# Architecture

How a capture becomes a page: the stack, the pipeline stages and the tables they
fill, where the bytes and the index live on disk, and the two guarantees the
build is designed around — TShark does all the decoding, and nothing leaves the
host.

For the commands that start it, see [Getting-Started.md](Getting-Started.md); for
the wire shapes of the API, [Reference/API.md](Reference/API.md).

---

## 1. The stack

| Layer | What it is | Where |
|---|---|---|
| Decoder | **TShark** (Wireshark CLI), invoked as a local subprocess. 4.2+ recommended; 4.6.8 is what this build was developed against. | `backend/app/services/tshark.py` |
| Backend | **FastAPI** on Python 3.12+, served by uvicorn; Pydantic settings; one router module per feature area. | `backend/app/` |
| Store | **SQLite** in WAL mode, one database per installation, one schema for all analyses. | `backend/app/db/database.py`, `schema.sql` |
| Jobs | A bounded `ThreadPoolExecutor` inside the API process, plus a `jobs` table for the record. | `backend/app/services/jobs.py` |
| Front end | **React 18 + TypeScript**, built by **Vite 5**, styled with **Tailwind CSS 3**; `react-router-dom` for routes, `@tanstack/react-query` for data fetching, `@tanstack/react-virtual` for long virtualised lists (`frontend/src/components/findings/FindingsList.tsx`), `recharts` for charts, `lucide-react` for icons. | `frontend/src/` |
| Delivery | Two ways: the Vite dev server on `127.0.0.1:5173` proxying `/api` to the backend, or the built bundle in `frontend/dist` served by FastAPI itself. In the containerised build, nginx serves the bundle and proxies `/api` to the backend container. | `frontend/vite.config.ts`, `backend/app/main.py`, `frontend/Dockerfile`, `frontend/nginx.conf` |

```text
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

---

## 2. How a capture flows through the components

1. **Upload.** `POST /api/analyses` (`backend/app/api/routes_analyses.py`)
   streams the multipart body to disk in 1 MiB chunks under
   `data/uploads/<analysis-id><ext>`, enforcing the size ceiling as it goes.
   `capture_parser.validate_extension` checks the extension,
   `storage.sniff_capture_format` checks the magic bytes, and
   `capture_parser.inspect` asks `capinfos`/TShark whether the file is readable.
   Only then is an `analyses` row inserted (`status='pending'`) and a job
   submitted. The response is **202** with the analysis object.
2. **Job.** `JobManager.submit()` writes a `jobs` row and hands the work to the
   thread pool. `_run()` flips the job to `running` and the analysis to
   `processing`, then calls `pipeline.process_new_analysis`, which resolves the
   stored capture path and runs `run_analysis`.
3. **Pipeline.** `run_analysis()` (`backend/app/services/pipeline.py`) walks the
   stages of §3 in order, reporting progress into the job's band and checking the
   cancellation flag between stages. Optional stages are imported by name and
   called through `analyze(ctx, analysis_id, capture_path)`.
4. **Index.** Everything a stage learns is written to SQLite (or, for extracted
   files, to the analysis directory, with a row recording it). No stage keeps
   state in memory for a later request to read: the API is stateless over the
   database, which is why pages work after a restart.
5. **Read.** The routers query the index. A few read paths deliberately go back to
   the capture instead — an advanced display filter, the packet detail tree and
   hex dump, and TCP stream reassembly — and each does so by re-invoking TShark on
   the retained file (see §6).

---

## 3. The pipeline stages and what each analyser writes

The order below is the order `run_analysis()` performs it, and the progress band
is the span each stage owns in the `BANDS` dict at the top of `pipeline.py`.

| # | Stage | Band | Module | Entry point | Tables written |
|---|---|---|---|---|---|
| 1 | `metadata` | 0–5% | `services/capture_parser.py` | `inspect` | `analyses` (type, encapsulation, size, sha256, packet count) |
| 2 | `packets` | 5–50% | `services/packet_indexer.py` | `index_packets` | `packets` (one row per frame, in batches of `BATCH_SIZE`), then `analyses` aggregates |
| 3 | `conversations` | 50–58% | `services/conversation_analyzer.py` | `analyze` | `conversations`, `streams` |
| 4 | `http` | 58–68% | `services/http_analyzer.py` | `analyze` | `http_transactions` |
| 5 | `dns` | 68–76% | `services/dns_analyzer.py` | `analyze` | `dns_queries` |
| 6 | `tls` | 76–83% | `services/tls_analyzer.py` | `analyze` | `tls_sessions` |
| 7 | `protocols` | 83–90% | `services/protocol_analyzer.py` | `analyze` | `protocol_sessions` (Email, SSH, FTP, VoIP, SMB — see [PROTOCOLS.md](../docs/PROTOCOLS.md)) |
| 8 | `hosts` | 90–93% | `services/host_analyzer.py` | `analyze` | `hosts` |
| 9 | `objects` | 93–96% | `services/object_extractor.py` | `analyze` | `objects` + files under `data/analyses/<id>/objects/` |
| 10 | `credentials` | 96–97% | `services/credential_analyzer.py` | `analyze` | `credentials` (visible users, passwords, keys and tokens — see [CREDENTIALS.md](../docs/CREDENTIALS.md)). Reads the rows stages 4 and 7 wrote, and reassembles the control channel of the mail/FTP sessions those stages redacted values out of; skipped entirely when the setting is off |
| 11 | `detection` | 97–98% | `services/detection_engine.py` | `analyze` | `findings` (built-in rules) |
| 12 | `suricata` | 98–99% | `services/suricata_engine.py` | `analyze` | `findings` (`rule_id = suricata:<sid>`) |
| 13 | `finalise` | 99–100% | `services/pipeline.py` | `_cache_protocol_hierarchy`, `_store_warnings`, `_refresh_counts` | `stats_cache`, `analyses` counters |

Notes that matter when reading the code:

* **Stages 1–2 are mandatory, 3–11 are optional.** The optional loop catches every
  exception per stage, appends a warning and moves on, so one broken dissector
  costs you that stage's table and nothing else. The warnings are stored in
  `stats_cache` under `kind='warnings'` and returned by
  `GET /api/analyses/{id}`.
* **The packet index is the substrate.** Conversation, host, port, protocol,
  timeline, Threat Map and detection logic all read `packets` (or the tables
  derived from it) rather than the capture. `_aggregate()` in `packet_indexer.py`
  computes the capture-level counters, which are then copied onto `analyses`.
* **Detection runs after every extractor**, so the rules can see HTTP, DNS, TLS,
  host and object context; the Suricata matcher runs after `detection` and its
  matches land in the same `findings` table, distinguished by the
  `suricata:<sid>` rule id. See [`docs/CONTRACT.md`](../docs/CONTRACT.md) §8 and
  [Findings.md](Findings.md).
* **`suricata_rules` is not filled by the pipeline.** The rule table is populated
  from the vendored tree (`backend/rules/`, imported on demand from `/settings`)
  or from analyst uploads; an empty table simply produces no matches.

---

## 4. Where the data lives

Everything runtime lives under `APACKETS_DATA_DIR` (default `./data`, resolved
against the repository root).

| Path | What it holds | Created by |
|---|---|---|
| `data/apackets.db` | The whole index, all analyses, plus settings and Suricata rules. SQLite, WAL mode, `synchronous=NORMAL`, `foreign_keys=ON`, 30 s connect timeout / 10 s busy timeout. | `db.init_db()` at startup |
| `data/uploads/<analysis-id>.<ext>` | The original capture, under a server-generated name. Needed by packet detail, stream reassembly, display filters and object export. | the upload route |
| `data/analyses/<analysis-id>/` | Per-analysis directory. | the upload route |
| `data/analyses/<analysis-id>/objects/` | Files recovered from the capture, named after their server-generated object id and never executed. | `object_extractor` |
| `data/exports/` | Created by `settings.ensure_dirs()`; CSV and stream exports are streamed from memory rather than written here. | startup |

The database is small and self-contained: on this machine `data/apackets.db` is
24,440,832 bytes for 22 analyses holding **18,578** indexed packet rows totalling
13,726,676 frame bytes (measured read-only from `data/apackets.db`). Deleting an
analysis removes its rows from twelve tables
(`packets`, `conversations`, `streams`, `http_transactions`, `dns_queries`,
`tls_sessions`, `hosts`, `findings`, `objects`, `stats_cache`, `jobs`,
`indicators`), the `analyses` row, the analysis directory and the retained
upload.

### The tables, from `backend/app/db/schema.sql`

| Table | Key | What it holds |
|---|---|---|
| `analyses` | `id` | One row per capture: the stored path and hashes, status/progress/stage/error, and the capture-level aggregates (packets, bytes, window, duration, per-protocol counters). |
| `jobs` | `id` | The job record: `kind`, `status`, `stage`, `progress`, `message`, `error`, `cancel_requested`, timestamps. |
| `packets` | `(analysis_id, number)` | Packet **summaries**, never payloads: addresses, ports, transport, TCP flags and counters, TTL, protocol, info line, and a few dissected fields (DNS name/type/rcode, HTTP method/host/URI/status, TLS SNI/version). Eleven indexes cover the fields the UI sorts and filters on. |
| `conversations` | `(analysis_id, conv_id)` | One row per transport conversation: endpoints, per-direction packets and bytes, total, start/end/duration, TCP state, protocol list. |
| `streams` | `(analysis_id, transport, stream_id)` | Reassembled stream metadata: client/server endpoints, payload bytes per direction, packet count, window. Holds no payload. |
| `http_transactions` | `id` (autoincrement) | Method, host, URI, status, user agent, referer, content type, sizes, header text, capped body previews and the analyser's `flags`. |
| `dns_queries` | `id` (autoincrement) | Query name and type, client/server, rcode, answers, answer IPs, CNAMEs, TTL, RTT, and the derived name shape (`name_length`, `label_count`, `longest_label`, `entropy`) plus `flags`. |
| `tls_sessions` | `id` (autoincrement) | Handshake metadata only: versions, SNI, ALPN, cipher, JA3/JA3S/JA4, certificate subject/issuer/validity/serial, handshake status, alerts, `flags`. No decrypted payload. |
| `protocol_sessions` | `id` (autoincrement) | One row per session of the five protocol families that are not HTTP, DNS or TLS — Email (SMTP, POP3, IMAP), SSH, FTP, VoIP (SIP, RTP, RTCP) and SMB. Shared columns hold the endpoints, times, volume by direction and the flags; the per-protocol fields live in a JSON `detail` object, so adding a protocol never changes the table. Fixed by [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md). |
| `hosts` | `(analysis_id, ip)` | One row per endpoint: MAC, first/last seen, bytes and packets per direction, ports, protocols, DNS names observed, TLS SNI seen, `is_private`, `ip_version`, and the peer list with its count. |
| `ip_lookups` | `ip` | The registration record of a **public** address: its class, the registry that answered, the origin AS, the registered country, when it was fetched and the normalised payload. Keyed by address and not by analysis, because who holds a block does not depend on which capture asked. Written only by an explicit lookup; a failed lookup writes nothing. Fixed by [`docs/IP_LOOKUP.md`](../docs/IP_LOOKUP.md). |
| `findings` | `id` | The recorded detections — built-in rules and Suricata matches alike: rule id, severity, title, description, reason, evidence JSON, packet numbers, entities, recommendation. |
| `credentials` | `id` (autoincrement) | Visible credentials the capture carried — username, password, API key, bearer token or other secret — with the protocol and stream they came from, the location and field inside it, how the value was derived (`basic_decode`, `form_field`, `command_arg`, …), a confidence, the packet range and a **redacted** preview; the full value is served only when a caller asks for it with `reveal=1`. Written by a stage that reads the other analysers' rows rather than the capture, so it costs no extra dissection pass. Fixed by [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md). |
| `objects` | `id` | Files recovered from the capture: display filename, stored path, protocol, content type, size, md5/sha1/sha256, endpoints, status (`complete`/`partial`/`failed`) and note. |
| `indicators` | `id` (autoincrement) | Analyst-supplied indicator values used by the indicator-match rule, optionally scoped to one analysis. |
| `settings` | `key` | Key/value store: runtime overrides of the editable limits (`app_settings`), the detection thresholds (`detection_config`), the Suricata matcher configuration (`suricata_config`) and the credential scan's switch and protocol selection (`credential_config`). |
| `stats_cache` | `(analysis_id, kind)` | Expensive derived artefacts: the protocol hierarchy (`protocol_hierarchy`) and the pipeline warnings (`warnings`), each a JSON blob. |
| `suricata_rules` | `sid` | Imported Suricata-compatible rules: parsed header, `options` JSON, `unsupported` list, `supported`/`enabled`/`approximate` flags, source and the verbatim rule text. |

Column names and types are frozen by [`docs/CONTRACT.md`](../docs/CONTRACT.md) §3;
where this summary and that document differ, the contract and `schema.sql` win.

---

## 5. The background job manager

Long-running work never blocks a request. `JobManager`
(`backend/app/services/jobs.py`) is deliberately the **only** place that knows how
work is scheduled, so moving the worker into its own process later is a contained
change.

* **Pool.** One lazily created `ThreadPoolExecutor`, `max_workers =
  settings.worker_threads` (**2** by default, `APACKETS_WORKER_THREADS`), with
  threads named `apackets-job`. Jobs beyond that queue.
* **Record.** `submit()` inserts a `jobs` row (`status='queued'`, message
  "Waiting for a worker") and keeps a `JobContext` in an in-memory registry keyed
  by job id.
* **Progress.** `JobContext.set_stage()` coalesces writes: it only touches the
  database when the stage label changes or progress moves by ≥ 0.5 %, and it
  updates both the `jobs` row and the `analyses` row, so polling
  `GET /api/analyses/{id}` reports the same numbers the worker is publishing.
  Progress failures are swallowed by design — reporting progress must never break
  a job.
* **States.** `queued → running → completed | failed | cancelled`. `_finish()`
  maps a job outcome onto the analysis status, sets `progress = 100` on success,
  and stores the error text (truncated to 2000 characters) on the analysis.
* **Cancellation.** Cooperative, via a `threading.Event` per job.
  `cancel_for_analysis()` sets it; `ctx.check_cancelled()` raises `JobCancelled`
  at the pipeline's stage boundaries and inside the packet loop; `_run()` then
  records `cancelled`. Deleting an analysis cancels first, waits up to 5 s for
  the running job to notice, then deletes rows and the directory.
* **Lifetime.** `shutdown(wait=False, cancel_futures=True)` runs when the
  application's lifespan ends, and clears the pool reference so the manager can
  be reused in one process (uvicorn `--reload`, a `TestClient` per test).

One honest limit: because the worker is in the API process, a crashed or
force-stopped server leaves its in-flight job rows at `running` forever. There is
no startup reconciliation in `main.py`'s lifespan or in `jobs.py` — nothing
resets them (the repository README describes them as "marked failed on next
start", which the current code does not do). The practical recovery is to delete
the analysis and upload again.

---

## 6. The TShark-only decoding rule

**TShark is the only packet decoder. No protocol parsing is reimplemented in
Python, and `backend/app/services/tshark.py` is the only module that spawns a
subprocess to do work.** There is exactly one exception, added deliberately and
scoped as tightly as it can be: `backend/app/services/wireshark.py` starts the
Wireshark *GUI* when an operator asks for it (§6.1). Nothing else in the
application starts a program.

The rules the module holds itself to, all of which are visible at the top of the
file:

* **Explicit argument vector, `shell=False`.** Every invocation is `Popen([...])`
  with a list of arguments — never a command string, and never a string built
  from user or capture input. Windows runs are launched with
  `CREATE_NO_WINDOW` so a dissection does not flash a console window.
* **No name resolution.** Every run carries `-n`, so analysis never sends a
  packet or does a DNS lookup, and a capture full of private addresses cannot
  cause a query.
* **A hard wall-clock budget.** `APACKETS_TSHARK_TIMEOUT_S` (300 s default),
  overridable at runtime from `/settings`; exceeding it raises `TsharkTimeout`.
* **Streaming, never buffering the capture.** `stream_fields()` yields one dict
  per frame, and `packet_indexer` writes in batches, so a large capture is never
  held in memory.
* **A canary capture for filter validation.** `canary_capture()` writes a valid
  but empty pcap (`data/.filter-canary.pcap`) and `validate_filter()` dissects it
  with the candidate expression, so a display filter can be compiled and rejected
  without opening the analyst's capture at all. An empty file is enough: a
  display filter compiles independently of what the capture holds.
* **Availability is answered by TShark itself.** `version()` runs
  `tshark --version` (20 s timeout, exit codes 0 and 1 accepted) and parses the
  banner, so `GET /api/health` and `GET /api/capabilities` report the real
  binary, its path, its version and any error rather than assuming one.

Consequences that show up in behaviour:

* **Display filters are TShark's, not APackets'.** `POST /api/analyses/{id}/filter`
  and the `filter` parameter on the packets list pass the expression straight to
  TShark (`-Y`), which is why a filter that compiles but matches nothing is
  reported as **0 results** while an unparsable one is `422 invalid_filter` with
  TShark's own reason. The two states are never conflated.
* **TCP streams come from TShark's reassembly** (`-z follow,tcp,raw,<id>`), so
  sequence numbers, retransmissions and out-of-order segments are Wireshark's
  problem, not a Python concatenation of payloads. The known Windows quirk — the
  C runtime expanding every LF into CRLF — is inverted on the way in so byte and
  hex views match the capture.
* **`packets` holds summaries, never payloads.** The detail view
  (`GET /api/analyses/{id}/packets/{n}`) re-runs TShark against the retained
  capture for the layer tree and hex dump; stream reassembly and display-filter
  evaluation do the same. Extracted objects are stored as files, so their download
  serves those stored bytes — but re-running extraction
  (`POST /api/analyses/{id}/objects/extract`) needs the capture again. That is why
  `APACKETS_RETAIN_UPLOADS=false` makes packet detail, stream views and object
  extraction unavailable.
* **No payload inspection anywhere else.** HTTP bodies are previewed, not
  interpreted; TLS is not decrypted; Threat Map reads metadata only — see
  [Threat-Hunt.md](Threat-Hunt.md) §7.

### 6.1 The one process that is not a dissection: the Wireshark GUI

The IP context menu's **Pivot to Wireshark** action opens the analysis's own
capture in Wireshark, filtered. That means starting a program the operator will
keep using after the request that started it ends, so the door is built as
narrowly as one can be:

* **The client never sends a filter.** It sends an address and, at most, the other
  end of the conversation (`peer_ip`) and which of that address's conversations is
  meant (`transport`, `stream_id`, `port`). The display filter is composed in
  `backend/app/services/wireshark.py` from canonicalised addresses and integers, so
  no request can reach a command line as filter syntax. A body field the model does
  not declare — a `filter` string, say — is ignored by Pydantic and never reaches
  the process.
* **A conversation is a direction, not an address.** With a peer the filter is
  `ip.src == <address> && ip.dst == <peer>`: the endpoint the analyst acted on is the
  source, so the window opens on the side of the exchange they were reading. It is
  deliberately one way — the reply direction is one edit away in the window, and
  choosing it for them would be the tool guessing. An address on its own (a host row,
  a map node, an address in prose) keeps `ip.addr == <address>`, because there is no
  second end to name.
* **The capture path comes from the analysis row**, resolved by the same
  `capture_path` dependency every other capture-reading route uses, so no request
  can name a file.
* **`shell=False`, an explicit argument vector, and `DETACHED_PROCESS`.** The GUI
  outlives the request, so it is started detached and reaped by a daemon thread
  rather than waited on. `CREATE_NEW_PROCESS_GROUP` keeps a Ctrl-C in the server's
  console from closing the analyst's window; elsewhere `start_new_session` does
  the same job.
* **The filter is the number this application already stored.** TShark's
  `tcp.stream` *is* `conversations.stream_id`, so `tcp.stream == 30` selects the
  conversation the analyst was looking at — verified against a real capture, where
  the composed filter matched exactly the stream's frame count. UDP has no such
  field (Wireshark's `udp.stream` is not the stored number), so a UDP conversation
  is filtered by address and port instead, and the menu says which of the two it
  used.
* **The window opens *on* the packets, not merely with them.** Two options do it:
  `-Y <filter>` starts with the display filter applied, so the packet list shows
  the conversation and nothing else, and `-J <filter>` jumps the selection to the
  first packet matching it — the conversation's first frame. Wireshark's manual:
  *"After reading in a capture file using the -r flag, jump to the packet matching
  the filter."* `-j` would select the packet *before* a missing match instead, and
  `-g <packet number>` would need the index rather than the filter, so neither is
  used. Verified against Wireshark 4.6.8: an unknown option exits `1` at once,
  while this argument vector leaves the GUI running.
* **The reported pid is a launcher, not the window.** Windows Wireshark re-execs
  itself, so the process a request starts exits while the window it spawned keeps
  running. A pid that is already gone therefore proves nothing about whether the
  window opened; it is reported for the log's sake, not as a handle on the GUI.
* **Absence is reported, not guessed.** `resolve_binary()` looks in the
  configured path (`APACKETS_WIRESHARK_PATH`), on `PATH`, next to the TShark this
  application already uses, and in the known install directories, then reports the
  path as it exists on disk. When there is no GUI, `GET
  /api/analyses/{id}/wireshark` says so and the menu shows the reason instead of a
  button that would fail. No process is started to answer that question — the
  version reported is TShark's, memoised once per process.

### 6.2 The IP context menu: one menu, every address

Every address in the application — a host row, a conversation endpoint, a packet's
source or destination, a map node, a card on the Dashboard — answers a right click
with the same actions: **Pivot `<ip>` to Hunt**, **Show Conversations with `<ip>`**,
and the Wireshark pivot. When the element knows its conversation the pivot is labelled
**Open conversation in Wireshark** and filters to that stream, and a further
**Follow this conversation** item opens that stream on the Conversations **Timeline**
tab (`?tab=timeline&stream=<transport>:<id>`, the same landing every follow link in the
application uses); a packet row also offers **Copy frame number**. Three properties make that work without
each component knowing the menu exists:

* **It delegates from the document.** One `contextmenu` listener is installed on
  `document`; it walks up from whatever was clicked to the nearest `[data-ip]` and
  opens there. Adding the menu to a surface is one attribute (`data-ip`), and an
  element may add `data-ip-transport` / `data-ip-stream` / `data-ip-port` to say
  *which conversation* it is — which is what makes the Conversations link open
  that exchange and the filter name that stream.
* **It also reads the text under the pointer.** The attributes only cover the
  surfaces somebody annotated, so an address printed anywhere else is found by
  reading the caret's own text node (`caretRangeFromPoint` /
  `caretPositionFromPoint`) and validating what is there — so in a cell holding
  `192.168.8.229:51000 <-> 150.171.109.217:443` the address actually under the
  cursor wins rather than the first in the row. A candidate must survive a real
  check: `tcp:30`, `12:34:56`, a MAC address, `999.1.1.1` and `2.0.1` are not
  addresses, and a container holding a paragraph is ignored rather than mined.
* **It opens everywhere, and greys out when there is nothing to act on.** With no
  address under the click the menu still appears — all three actions present and
  disabled, each titled with the reason, and a note saying where addresses are —
  rather than silently falling back to the browser's menu or not appearing at all.
  The single exemption is a text field, where the browser's own menu (paste,
  spell-check) belongs to the field and no address is editable there.

The menu is a portal on `document.body`, positioned at the pointer and clamped
inside the viewport, so it is never clipped by the scroll container or the
`overflow: hidden` panel the address sits in. It is keyboard-reachable too:
`Shift+F10` (or the context-menu key) opens it at the focused element, arrows walk
the items, and Escape closes it and returns focus to where it came from.

---

## 7. The theme system

Themes are presentation only, and they are entirely client-side.

* **One source of truth.** `frontend/src/theme/themes.ts` is the only file in
  `src/**` allowed to contain a colour literal. It defines `ThemeTokens` (surfaces,
  brand, type, `glow`, four severity colours, three status colours, `chart` — exactly
  eight series hues chosen to stay distinguishable and free of the severity ambers
  and reds — and five network-map classifications) and four palettes:
  `steel-blue` (default), `cyber-punk`, `cyber-samurai` and `soc`.
* **Where the preference lives.** `localStorage` under the key
  `apackets.theme` (`THEME_STORAGE_KEY`), read and written by
  `frontend/src/theme/ThemeProvider.tsx`. Any value that is not a known
  `ThemeId` falls back to `DEFAULT_THEME_ID = 'steel-blue'`. It is a per-browser
  preference, not analysis data, so it never reaches the backend and never enters
  the database.
* **How it is applied.** `applyTheme()` publishes every channel token as a CSS
  custom property on `<html>` (`--c-bg`, `--c-accent`, … `--c-chart-1..8` as
  `r g b` triples) plus `data-theme` and `data-theme-ready`. Tailwind's
  configuration and `index.css` point at those variables, so ordinary classes
  (`bg-surface`, `border-danger/50`) re-theme automatically, and charts or inline
  SVG read the same values as strings through `useThemeTokens()`. The write
  happens in a `useLayoutEffect`, i.e. before paint, so switching themes never
  flashes an intermediate palette.
* **The pre-paint script.** `frontend/index.html` runs a small inline script
  before first paint so a reload does not flash Steel Blue. It duplicates **only
  three hints per theme** — the `r g b` triples for `bg`, `surface` and
  `surface2`, the largest painted areas — reads the same `apackets.theme` key,
  sets `data-theme`, and then `ThemeProvider` replaces every token on mount. Whole
  palettes are deliberately not duplicated in HTML.
* **The picker** is the `ThemePanel` on `/settings`
  (`frontend/src/components/ThemePanel.tsx`), which previews the four palettes
  as swatch chips.

Chart components in `frontend/src/components/threat/*` and the dashboard draw their
colours from `tokens.chart`. `themes.ts` states in its own header that it is the
only file in `src/**` allowed to contain a colour literal, and
[`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §4 repeats the rule for the plots;
a search of `frontend/src` for `#rrggbb` literals outside `themes.ts` returns
nothing.

---

## 8. The local-only guarantee

The application is designed to be fully functional with networking disabled, and
the build holds to it:

* **Loopback by default.** `APACKETS_HOST` defaults to `127.0.0.1` and the
  lifespan logs whether the bind address is local-only;
  `GET /api/health` reports `local_only`. Docker Compose publishes both ports as
  `127.0.0.1:8080:80` and `127.0.0.1:8000:8000`, so the containers are reachable
  from the host and nowhere else.
* **No telemetry, no analytics, no cloud call.** Nothing is sent anywhere. There
  is no outbound HTTP or TLS client in `backend/app/` at all: the only network-ish
  imports are `urllib.parse` (pure string parsing, in the detection engine, the
  object extractor and the Threat Map service) and `socket.getservbyport()`
  (`backend/app/api/routes_findings.py`), which reads the **local** services
  database to name a port and opens no connection.
* **TShark never resolves names.** Every invocation carries `-n` (§6), so
  dissecting a capture cannot leak the addresses in it to a resolver.
* **No threat-intelligence lookup, ever.** Detection is local and rule-based.
  The Suricata-compatible rule sets are vendored in `backend/rules/` and are never
  downloaded at runtime: rules arrive from that tree or from an analyst upload.
  A rule that would need an engine feature APackets cannot honour is stored,
  listed and flagged as skipped rather than approximated.
* **Extracted files are never executed and never fetched.** Objects are written
  under `data/analyses/<id>/objects/`, and served only through the explicit
  download endpoint, with `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store`.
* **CORS is loopback-only.** The default `APACKETS_CORS_ORIGINS` is the Vite dev
  origins (`127.0.0.1:5173`, `localhost:5173`, `127.0.0.1:4173`);
  `allow_credentials` is false.
* **The containers are defensive.** `no-new-privileges`, all capabilities dropped
  (nginx adds back only what it needs to bind), memory/CPU/PID limits, and a
  health check that hits `/api/health` on loopback.

The one thing this does **not** include is authentication: anyone who can reach
the port can read every capture and upload files. That is why the loopback
default is a guarantee and not a preference — LAN exposure belongs behind an
authenticating proxy or an SSH tunnel. [README.md](README.md) lists the full
security model and the known limitations.

---

## 9. Where to look in the code

| I want to understand… | Read |
|---|---|
| How the app starts, what routers exist, how the SPA is served | `backend/app/main.py` (`ROUTER_SPECS`, `lifespan`) |
| Settings, defaults and the derived data paths | `backend/app/core/config.py`; runtime-editable values in `backend/app/core/runtime_settings.py` |
| The error envelope and status codes | `backend/app/core/errors.py` |
| The schema, table by table | `backend/app/db/schema.sql`, `backend/app/db/database.py` |
| The stage order, bands, optional-stage handling, warnings | `backend/app/services/pipeline.py` |
| How a request is scheduled, cancelled and reported | `backend/app/services/jobs.py` |
| Every subprocess launch (and nothing else spawns one) | `backend/app/services/tshark.py` |
| Address-to-country lookup, and the one download in the app | `backend/app/services/geoip.py`, `backend/app/api/routes_geo.py` (see [GEOGRAPHY.md](../docs/GEOGRAPHY.md)) |
| Registration (whois/RDAP) lookup, its cache, and the only route that sends an address off the machine | `backend/app/services/ip_lookup.py`, `frontend/src/components/hosts/HostLookupPanel.tsx` (see [IP_LOOKUP.md](../docs/IP_LOOKUP.md)) |
| Opening a capture in the Wireshark GUI, and the right-click menu that offers it | `backend/app/services/wireshark.py`, `backend/app/api/routes_wireshark.py`, `frontend/src/components/context/IpContextMenu.tsx` (see §6.1) |
| Visible credentials: where each protocol keeps them, how a value is parsed, and how it is scored | `backend/app/services/credential_analyzer.py`, `frontend/src/pages/CredentialsPage.tsx` (see [CREDENTIALS.md](../docs/CREDENTIALS.md)) |
| Upload validation and capture metadata | `backend/app/services/capture_parser.py` |
| Packet extraction into SQLite | `backend/app/services/packet_indexer.py` |
| Conversations, streams and reassembly | `backend/app/services/conversation_analyzer.py`, `stream_analyzer.py` |
| HTTP, DNS and TLS metadata (and their lead flags) | `backend/app/services/http_analyzer.py`, `dns_analyzer.py`, `tls_analyzer.py` |
| The five protocol-session families and their lead flags | `backend/app/services/protocol_analyzer.py` (see [PROTOCOLS.md](../docs/PROTOCOLS.md)) |
| Host inventory, address classification, the graph | `backend/app/services/host_analyzer.py` |
| File recovery from captures | `backend/app/services/object_extractor.py` |
| Built-in detection rules and their thresholds | `backend/app/services/detection_engine.py` |
| The native Suricata-compatible matcher | `backend/app/services/suricata_engine.py`, `suricata_rules.py` |
| The seventeen Threat Map indicators | `backend/app/services/threat_hunt.py` (see [Threat-Hunt.md](Threat-Hunt.md)) |
| The global baseline network: profile, comparison, and the seven `baseline_*` rules | `backend/app/services/baseline.py` (see [Baseline.md](Baseline.md)) |
| Path safety, hashing and the on-disk layout | `backend/app/services/storage.py` |
| The REST surface | `backend/app/api/*.py` (see [Reference/API.md](Reference/API.md)) |
| The theme tokens and palettes | `frontend/src/theme/themes.ts`, `ThemeProvider.tsx` |
| How the front end talks to the API | `frontend/src/services/api.ts`, `frontend/vite.config.ts` |
| The pages and their routes | `frontend/src/pages/`, `frontend/src/App.tsx`, `frontend/src/layouts/AppLayout.tsx` |
| The five protocol-session pages, which are one component with a family | `frontend/src/pages/ProtocolSessionsPage.tsx`, `frontend/src/components/protocols/sessionCatalog.ts`, `SessionDetail.tsx` |
| The world map, its zoom, its country list, the destination panel a dot opens, and the generated outline asset | `frontend/src/components/dashboard/WorldMap.tsx`, `CountryList.tsx`, `DestinationPanel.tsx`, `frontend/src/theme/worldMap.ts` |

---

## Related

[README.md](README.md) · [Getting-Started.md](Getting-Started.md) ·
[Reference/API.md](Reference/API.md) · [Threat-Hunt.md](Threat-Hunt.md) ·
[PCAP-Files.md](PCAP-Files.md) · [Settings.md](Settings.md) ·
[docs/CONTRACT.md](../docs/CONTRACT.md) ·
[docs/THREAT_HUNT.md](../docs/THREAT_HUNT.md)
