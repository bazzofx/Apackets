# PCAP Files

The capture library (`/files`): upload a PCAP or PCAPNG, watch it being processed, make
one analysis the active capture, mark one capture as the global
[baseline network](Baseline.md), cancel one that is still running, or delete one along with
everything derived from it.

The component is `frontend/src/pages/PcapFilesPage.tsx`. Unlike the other data pages it is
**not** wrapped in `AnalysisGuard`: it is the page that has to work when no capture is
selected, because it is where a capture comes from.

---

## 1. What it is for

It answers "what have I uploaded, what state is each capture in, and which one am I looking
at?". It is the only place in the application that creates or destroys an analysis, and the
only place that shows a capture's processing progress while a run is in flight.

## 2. What is on the screen

### 2.1 The drop zone

A dashed panel at the top of the page. It accepts a file either way:

* **Drag and drop** onto the panel. While a drag is over it, the panel border turns to the
  accent colour and the background lightens.
* **Select capture**, a primary button that clicks a hidden
  `<input type="file" accept=".pcap,.pcapng,.cap">`.

The panel's own text states the accepted extensions and that parsing is local:
*Accepted: .pcap, .pcapng, .cap — parsed locally by TShark, nothing leaves this machine.*

Two client-side rules are applied before anything is sent:

| Situation | What happens |
|---|---|
| More than one file dropped at once | A warning notice appears: *Upload one capture at a time — the backend accepts a single file per request.* Nothing is uploaded. |
| A file whose name does not end in `.pcap`, `.pcapng` or `.cap` (case-insensitive) | A warning notice names the file and lists the allowed extensions. Nothing is uploaded. |
| Exactly one accepted file | The upload starts immediately; there is no second confirmation step. |

The warning notice is a warning-coloured strip below the drop zone with its own close
button. It is separate from the error panel, which is drawn only for a failed request.

While an upload is in flight the panel shows:

* the file name, truncated with the full value in the tooltip;
* `<percent>% · <loaded> / <total>`, or *unknown size* in place of the total when the
  browser could not determine it;
* a progress bar driven by `XMLHttpRequest.upload.onprogress`;
* a **Cancel upload** button beside the (now disabled) **Select capture** button.

**Cancel upload** aborts the XHR. The promise rejects with an `aborted` error and the page
shows its ordinary **Upload failed** panel with the message *Upload cancelled* — there is no
separate cancelled state. It stops the browser sending the rest of the file; it does not
undo bytes the backend has already written, and it does not create or cancel an analysis,
because no analysis row exists until the request completes.

### 2.2 The Analyses table

| Column | Content |
|---|---|
| File | `original_filename`, truncated to 260 px with the full name in the tooltip, plus an accent `active` chip on the capture currently selected in the top bar. |
| Baseline | A checkbox that makes this capture the one [baseline network](Baseline.md) every other analysis is compared against. Enabled only for a `completed` analysis; ticking one moves the baseline rather than adding a second, and unticking the ticked one clears it. The chosen row also carries a `baseline` chip whose tooltip distinguishes "compared against" from "selected but baseline mode is off". See §2.5. |
| Size | `file_size` — the stored upload's size in bytes, rendered as a byte size. |
| Status | A `StatusChip` (`pending`, `processing`, `completed`, `failed`, `cancelled`). Below it, while the analysis is pending or processing: a progress bar, the stage string (or `waiting` when the stage is null) and the percent. Below that, when the row carries an error, the error text truncated to 40 characters with the full text in the tooltip. When the analysis is not in flight and the latest job has a status, a faint `job <status>` line. |
| Packets | `packet_count` — the frames indexed, which for a running analysis is the count so far. |
| Capture start | `capture_start` as `YYYY-MM-DD HH:MM:SS.mmm`, or `—`. |
| Capture end | `capture_end`, same format, or `—`. |
| Duration | `duration` as a formatted duration, or `—`. |
| Created | A relative time (`just now`, `12 s ago`, `3 min ago`, `2 h ago`, `4 d ago`, …) with the absolute timestamp in the tooltip. |
| Actions | **Open**, **Cancel** (only while in flight) and **Delete**. |

The progress percentage is normalised in the browser: a `progress` value of 1 or less is
multiplied by 100, anything larger is used as-is.

Panel subtitle: *analysis in progress — refreshing every 2 seconds* while any analysis in
the list is pending or processing, and `<N> captures` otherwise — with ` · baseline mode on`
appended while [baseline mode](Baseline.md) is active. The header actions are a **Baseline
mode** checkbox (with an `on`/`off` chip, disabled until a baseline has been chosen) and a
**Refresh** button that reloads the list.

When the list is empty the panel says *No captures have been uploaded yet. Drop a file
above to start an analysis.*

### 2.3 The three row actions

| Action | Enabled when | What it does |
|---|---|---|
| **Open** | The row's status is exactly `completed` | Sets that analysis as the active capture and navigates to `/` (the [Dashboard](Dashboard.md)). |
| **Cancel** | The row is pending or processing | `POST /api/analyses/{id}/cancel`. See the caveats below. |
| **Delete** | Always | Opens the confirmation dialog. It does not delete anything on its own. |

The delete dialog cannot be dismissed by clicking the backdrop; it has a close button, a
**Cancel** button and a **Delete permanently** button, plus the delete request's progress
and error state. Its text names the file and says: *Delete `<file>` and every row derived
from it (packets, conversations, findings, extracted objects)?* followed by *The database
rows are removed and the analysis directory is deleted from disk. This cannot be undone —
re-upload the capture to analyse it again.*

If the deleted analysis was the active one, the selection is cleared (and the top bar falls
back to the newest remaining capture); if it was not, the selection is untouched.

### 2.4 The baseline strip

Between the panel header and the table, one line explains the global comparison:

* **When a baseline is set** — *Baseline network: `<file>` (`<N>` frames). Every analysis
  is compared against it…* or, with the mode off, *Baseline mode is off, so nothing is
  compared until you switch it on.* Both variants end with the sentence that matters:
  *Changing the baseline does not rewrite findings already stored — re-run the rules on an
  analysis to recompute them.*
* **When none is set** — *No baseline network is set. Tick a completed capture in the
  Baseline column and every later analysis will be compared against it — new addresses,
  destinations, services, names and TLS fingerprints become findings.*

The strip is informational: it holds no control. The comparison it describes is
[Baseline.md](Baseline.md).

### 2.5 Choosing the baseline

One baseline exists for the whole application, so the column is a radio group drawn as
checkboxes:

| Situation | What happens |
|---|---|
| Tick an unticked `completed` row | `PUT /api/baseline` with `{"analysis_id": <id>, "enabled": true}`. Any previous baseline is replaced **and** baseline mode is switched on, in one call. |
| Tick a row that is not `completed` | Nothing — the checkbox is disabled, and its tooltip says *A baseline must be a completed analysis*. |
| Untick the ticked row | `PUT /api/baseline` with `{"analysis_id": null}`: the baseline is cleared and the mode forced off. |
| Tick a second row | The first row's chip disappears; the baseline moved. |

The request is rejected by the backend, not only by the disabled checkbox: an id that does
not exist is `400 analysis_not_found`, one that has not finished `400
analysis_not_ready` (the status is in `details`), and one that indexed no packets `400
analysis_empty`. A toast reports the resulting state, or the cleared baseline.

### 2.6 The closing note

A single line under the table: *Analyses run locally through TShark. Deleting an analysis
removes its derived rows and the stored capture from `data/analyses/<id>/`.*

## 3. Where the data comes from

| Action | Call | Route module |
|---|---|---|
| Load the table (and the top bar's capture list) | `GET /api/analyses?page=1&page_size=200` via `useAnalyses` | `backend/app/api/routes_analyses.py` → `list_analyses()` |
| Upload | `POST /api/analyses`, multipart, via `uploadAnalysis` (XHR, not `fetch`) | `routes_analyses.py` → `upload_analysis()` |
| Cancel | `POST /api/analyses/{id}/cancel` | `routes_analyses.py` → `cancel_analysis()` |
| Delete | `DELETE /api/analyses/{id}?confirm=true` | `routes_analyses.py` → `delete_analysis()` |
| Read the baseline state | `GET /api/baseline` | `routes_baseline.py` → `baseline.status()` |
| Choose / clear / switch the baseline | `PUT /api/baseline` | `routes_baseline.py` → `baseline.save_config()` |

The client wrappers are in `frontend/src/services/api.ts`: `analysesApi.list`, `uploadAnalysis`,
`analysesApi.cancel`, `analysesApi.remove`, plus `isAllowedCaptureFile` and
`ALLOWED_CAPTURE_EXTENSIONS`, which are the single source of the three accepted extensions
in the browser. The extension list the backend enforces is a separate declaration,
`settings.allowed_extensions` in `backend/app/core/config.py`.

### 3.1 What the upload actually does

1. `capture_parser.validate_extension()` checks the name against
   `settings.allowed_extensions` **before anything is written to disk**; a mismatch is a
   `415 unsupported_file_type`.
2. The analysis id is generated as 32 hex characters, the data directories are created, and
   the file is streamed to `data/uploads/<analysis_id><suffix>` in 1 MiB chunks
   (`UPLOAD_CHUNK = 1 << 20`). The suffix is taken from the *sanitised* file name and
   defaults to `.pcap`. The stored path is never derived from the upload's name alone.
3. While streaming, the running size is checked against
   `runtime_settings.max_upload_bytes()` — 413 `file_too_large` past it. The partial file is
   removed before the error is raised.
4. An empty body is a `400 empty_file`, again with the partial file removed.
5. `capture_parser.inspect()` then has TShark read the file: magic-byte sniffing (a
   non-capture is `415 unsupported_file_type`), `capinfos` metadata, and a packet count. A
   missing TShark is `503 tshark_unavailable`; a slow one is `504 metadata_timeout`; an
   unreadable one is `400 invalid_capture`. Any failure here removes the stored file, so a
   rejected upload leaves nothing behind.
6. Only then is the `analyses` row inserted, with `status = 'pending'`, and the pipeline job
   submitted to the in-process thread pool. The response is **202** with the analysis row and
   its `job`; the validation warnings it collected are not in that response — they appear on
   `GET /api/analyses/{id}` and, once the pipeline has run, in the summary's `notes`. The
   browser does not wait for the pipeline.
7. The pipeline then runs in a worker: metadata, packets, conversations, HTTP, DNS, TLS,
   hosts, objects, detection, Suricata, finalise. Each optional stage is wrapped
   individually, so one failing dissector records a warning instead of failing the capture.
   The row moves `pending → processing → completed`, `failed` or `cancelled`, and the list's
   2 s poll is what makes the progress bar move.

The stored capture is what the analysis reads afterwards. The packet browser re-opens it by
path for every display filter and every per-packet detail request, object extraction reads
it, and CSV export reads it. Two families work from the index alone and therefore survive a
missing file: the findings routes (`get_ready_analysis`) and the threat-hunt route. Nothing
re-reads the original upload from the browser.

The practical consequence is the one worth knowing: **`stored_path` is a hard dependency of
most data pages.** `analysis_ready_row()` — used by the packets, hosts, conversations, DNS,
HTTP and TLS routers — returns `410 capture_missing` if the file is not on disk, so a capture
file removed out of band disables those pages even though the entire index is still in
SQLite. Findings, objects and threat hunt keep working under the same condition, which makes
the failure look arbitrary: some sections load and some do not, and the error names the
missing path rather than the analysis.

### 3.2 What "retained" means

`retain_uploads` exists as a setting, defaults to `true`, is editable on
[Settings](Settings.md), is persisted in the `settings` table, and is returned by
`GET /api/settings`. It is also echoed per analysis as `upload_retained` in the analyses
list — from the **environment-derived** value, not the runtime override.

What it does **not** do in this build: nothing in the codebase reads it in order to delete
anything. There is no purge after processing, no age-based cleanup, no startup sweep. The
stored upload lives in `data/uploads/` until the analysis itself is deleted, and deleting
the analysis removes it. Treat the flag as descriptive metadata, not as a retention policy,
and treat "captures are kept on disk" as the behaviour whatever it says.

`.env.example` — the file the repository ships as the configuration template, and the only
place this setting is described in prose — states that the flag is *required for packet
detail and stream views; disabling it makes those features unavailable*. That description
does not match the code in either direction: with `retain_uploads` set to `false` the packet
detail and stream views keep working exactly as before, and with it set to `true` those
views stop working as soon as the file is removed from disk by any other means. The
behaviour is governed entirely by whether `stored_path` exists, never by this flag.

### 3.3 Retention and disk usage — what is measured, and where

`GET /api/analyses` computes two extra fields for every row on every call:
`disk_usage` (a filesystem walk of `data/analyses/<id>/` plus the `data/uploads/<id>.*`
file, via `pipeline.analysis_disk_usage`) and `upload_retained`. **The table on this page
shows neither.** The Size column is `file_size`, the stored upload's size, which is a
subset of the analysis's real footprint. To see the whole footprint you have to add the
`data/analyses/<id>/` directory to the upload file yourself.

Measured on the library currently in `data/`:

| Capture | Upload file | `data/analyses/<id>/` | Total |
|---|---|---|---|
| `sf19us-MTA-lab-03.pcap` | 4,969,892 B | 4,672,491 B | 9,642,383 B (≈ 9.2 MiB) |
| `sf19us-MTA-lab-01.pcap` | 2,789,006 B | 1,631,269 B | 4,420,275 B (≈ 4.2 MiB) |
| `sf19us-MTA-lab-09.pcap` | 2,454,198 B | 2,025,570 B | 4,479,768 B |
| `nmap_sn_livehosts.pcapng` | 46,908 B | 0 B | 46,908 B |

The analysis directory holds the extracted objects and little else; for most captures in
this library it is empty (0 bytes of files), because no HTTP body or transferred file was
large enough or present to be written there.

Deleting an analysis removes its rows from `packets`, `conversations`, `streams`,
`http_transactions`, `dns_queries`, `tls_sessions`, `hosts`, `findings`, `objects`,
`stats_cache`, `jobs` and `indicators` (scoped to that analysis), then the `analyses` row,
then the analysis directory and the `<analysis_id>.*` file in `data/uploads/`. It waits up
to 5 s for a running job to notice the cancellation first.

Nothing calls `VACUUM`, so `data/apackets.db` **does not shrink** when an analysis is
deleted — the rows go, the file keeps its high-water mark. For scale: the database file is
currently 24,440,832 bytes (≈ 23.3 MiB) and the `data/` tree is `analyses` 9,345,795 B +
`uploads` 14,114,078 B + `exports` 0 B.

## 4. Links into the rest of the app

| Element | Opens |
|---|---|
| **Open** on a completed row | `/` — the capture becomes active and the Dashboard opens |
| **Delete** → **Delete permanently** | Nothing navigational; the row disappears and the selection is cleared when it was the active one |
| The **Baseline** checkbox | Nothing navigational; it changes global state described in [Baseline.md](Baseline.md) |
| The top bar's **Baseline mode : enabled** chip (present on every page while the mode is on) | `/files`, to this page |
| The top bar's Upload button (present on every page) | `/files` |
| `AnalysisGuard`'s empty state, on every gated page | `/files` |

Indirectly, `POST /api/analyses/{id}/suricata/run` (the **Run on capture** button on
[Settings](Settings.md)) requires the same analysis to be `completed`, and the Findings
page's rescan rewrites this capture's `findings` rows.

## 5. Limits and honest caveats

* **The table is one page of at most 200.** `useAnalyses` asks for `page_size: 200`, and
  this page has no paging control. Past 200 analyses the table, the panel's `N captures`
  subtitle and the sidebar's PCAP Files badge are all silently truncated. The endpoint
  itself accepts a `page_size` up to 1000.
* **Cancellation is a request, not a stop.** `jobs.cancel_for_analysis` sets a
  `threading.Event`; the worker notices it at the next `ctx.check_cancelled()` boundary. A
  stage already inside a TShark call finishes that call first. If the job is not in this
  process's registry — a job that already ended, or one submitted by a previous process' —
  the route falls back to setting `cancel_requested = 1` on running job rows, and returns
  `ok` either way. The UI cannot tell those two cases apart.
* **Cancelling an upload and cancelling an analysis are different things.** **Cancel
  upload** aborts the HTTP request and produces an *Upload failed* panel reading *Upload
  cancelled*; **Cancel** on a row asks the running pipeline to stop. Cancelling an upload
  leaves no analysis to clean up, because the analysis row is only created once the whole
  file has been received and validated.
* **Deleting is permanent and there is no trash.** No soft delete, no undo, no export of the
  findings before deletion. The confirmation dialog says so.
* **A gated page cannot be used while a capture is missing from disk.** `410 capture_missing`
  affects packets, hosts, conversations and the other index views, even though their data is
  intact in SQLite. Uploading the same file again analyses it from scratch under a new id.
* **The `retain_uploads` switch does not delete anything.** See §3.2. Until a real purge
  exists, "no — captures discarded" is a label, not a behaviour, and the disk figures in the
  Settings page's *Effective settings* panel will not change as a result of it.
* **The Size column is the upload, not the footprint.** The row that says 4.7 MiB on
  `sf19us-MTA-lab-03.pcap` occupies about 9.2 MiB once its index-directory files are
  counted, and the database rows are additional again. The page computes neither for you.
* **The database never shrinks.** Deleting every analysis leaves `data/apackets.db` at its
  largest size. There is no compaction step in the application.
* **The uploads directory can hold files nothing tracks.** `delete_analysis` globs
  `<analysis_id>.*`, and `analysis_disk_usage` sums the same pattern, so a file in
  `data/uploads/` that is not named after an analysis — the library currently contains a
  loose `nmap_sn_livehosts.pcapng` alongside `ef79e0d7….pcapng` — is invisible to both and
  is never cleaned up.
* **The upload limit has two different sources and they disagree upwards.** The streaming
  check uses the runtime value (editable on Settings); `capture_parser.inspect()` re-checks
  the same file against `settings.max_upload_bytes`, the environment-derived value, whose
  default is 512 MB. So raising *Max upload* above the environment's
  `APACKETS_MAX_UPLOAD_MB` makes the drop zone accept the number and stream the file, and
  then fails validation with a `413` quoting the *old* limit. Lowering it works as expected.
  Raise it with the environment variable, not only in the UI.
* **Extensions are a first filter, not the check.** A `.pcap` file that is not a capture is
  refused by magic-byte sniffing; a real capture with a `.txt` name is refused by extension
  before it is read. Both refusals delete the partial file.
* **Progress is coarse and can look stalled.** The pipeline maps its eleven progress bands
  onto fixed percentages, so a large capture sits at a fixed number for minutes while packets
  are indexed: `packets` occupies 5–50%, `conversations` 50–58%, `dns` 68–76%, `detection`
  94–97%, `finalise` 99–100%. `JobContext.set_stage` coalesces its writes and only persists a
  progress change of 0.5 points or more, or a change of stage text; the list polls every 2 s,
  so the bar moves in visible steps rather than smoothly.
* **A completed analysis is not a validated capture.** `warnings` collected during
  validation and processing are stored in `stats_cache` and shown on the
  [Info](Info.md) page, not here. A truncated but readable file completes with a warning the
  table does not show.
* **This page says nothing about what is inside a capture.** No packet counts beyond
  `packet_count`, no findings, no hosts, no size on the wire. Those are the other pages, and
  they need the capture to be `completed` and active.
* **Deleting the baseline capture silently ends every comparison.** The pointer is not
  cleaned up: `GET /api/baseline` starts reporting `configured: false` with the reason *the
  capture this baseline pointed at has been deleted*, baseline mode reads off, and no rule
  fires until a new reference is chosen. Nothing on this page warns you before the delete.
  See [Baseline.md](Baseline.md) §8.
* **The library in `data/` holds 22 analysis rows, not 21.** Counted directly: nine rows
  from the `sf19us-MTA-lab` set — seven distinct files, with `lab-02` and `lab-12` present
  twice under separate ids — plus `SpaceX_111025.pcapng`, `nmap_sn_livehosts.pcapng` and
  `tls.pcap`, and ten fixture runs: five `_probe.pcap`, two `verify_all.pcap`,
  `verify_dns.pcap`, `edge_empty.pcap` and `detect_verify.pcap`. All 22 are `completed`. Two
  of the fixtures (`verify_dns.pcap`, `edge_empty.pcap`) have no packets and no
  `capture_start` at all; they are the honest-empty cases this page renders as `—` in the
  Capture start, Capture end and Duration columns.

## 6. Related

Marking a capture as the reference for every other analysis — the Baseline column's
checkbox, the mode switch and what the comparison reports — is [Baseline.md](Baseline.md).
The pipeline stages that run after an upload and the storage layout they write into are
documented in [Architecture.md](Architecture.md); the settings that govern upload size,
object size and retention are on [Settings.md](Settings.md), and the rules that decide how
long a capture stays useful — the analyses that read `stored_path` — are the subject of
[Getting-Started.md](Getting-Started.md) and [Reference/API.md](Reference/API.md).
