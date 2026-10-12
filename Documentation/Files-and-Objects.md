# Files and Objects (`/objects`)

The content that could be carved back out of a capture — today, cleartext HTTP bodies — with
its size, status, hashes, the stream and frames it came from, a download link and a
re-extraction control.

It is reachable at `/objects`, under **Investigate** in the left-hand navigation, after
[Threat Map](Threat-Hunt.md) and [Investigate](Investigate.md): what it holds is carved
content rather than one entity's answers, which is why it is its own page inside that group.

---

## 1. What it is for

The page answers: **what content did this capture actually carry, and can I get a byte-exact
copy of it to hash, submit or detonate elsewhere?** A row exists only because TShark's
`--export-objects http` really wrote a file during the analysis; the page then reports the
size, the three hashes computed from the stored bytes, the extraction status, the endpoints
and frames the file was correlated with, the backend's own note about anything it could not
establish, and a download addressed by the server-side object id. It also lets an analyst
re-run extraction on a capture that has already been indexed.

## 2. What is on the screen

The page is wrapped in `AnalysisGuard`, so with no capture selected it shows the "no capture
selected" state.

### 2.1 Content warning banner

A permanent warning at the top of the page: extracted content is untrusted and should be
handled as potentially malicious. It states the posture the implementation actually keeps:
files are stored inside the local analysis directory, never executed, never previewed as
HTML, and never addressed by a capture-supplied filename — downloads use the server-generated
object id. It also says that a filename or content type in the table is itself an untrusted
string from the capture, and that object bytes are never fetched into the page (only names,
sizes, hashes and endpoints are).

### 2.2 Stat cards

A caption above the cards states that these five numbers are the whole analysis, unfiltered,
taken from the API's own `totals` object rather than from the rows on screen.

| Card | Value | Meaning |
|---|---|---|
| Objects extracted | `totals.objects` | Rows in the `objects` table for this analysis |
| Stored bytes | `totals.bytes` | `SUM(size)` of stored objects — the bytes on disk, not the capture's byte count |
| Complete | `totals.complete` | Rows whose status is `complete` |
| Partial | `totals.partial` | Rows whose status is `partial` |
| Failed | `totals.failed` | Rows that were refused or could not be stored |

### 2.3 Re-extraction report

After **Re-extract objects** runs, one line appears describing what actually happened, with
four possible outcomes: success (objects stored, bytes, the complete/partial/failed split and
the elapsed seconds), a warning returned by the extractor, "an object was found but none was
stored" (with the per-status split and a pointer to the reasons in the table), "no HTTP object
was found in this capture" (which states that export covers HTTP bodies only and that HTTPS
is not decrypted), and a failure line carrying the API's error code, message and HTTP status
along with the reassurance that the table still shows the previous extraction. Failures are
also rendered as the shared error state above the table.

### 2.4 The table

Panel title *Recovered files and objects*; subtitle states the number of matching objects and
that export covers HTTP bodies (`TShark --export-objects http`). Actions in the header:
*"updating…"* while a request is in flight, and the **Re-extract objects** button (which shows
*"Re-extracting…"* and a spinner while it runs).

Toolbar:

| Control | URL key | Behaviour |
|---|---|---|
| Search | `search` | Substring match on the displayed name **and** the original exported name, debounced 300 ms, matched literally (LIKE wildcards in the term are escaped) |
| Status | `status` | `any status` / `complete` / `partial` / `failed` |
| Sort | `sort` | `backend default`, `file name`, `size`, `extracted at`, `status`, `content type` |
| order button | `order` | Disabled while Sort is `backend default`; otherwise toggles `asc`/`desc` |
| hashes note | — | States that hashes are computed locally by the backend from the stored bytes |
| Clear filters | — | Removes `search`, `status` and `page` |

Columns:

| Column | Contents |
|---|---|
| Status | Chip: `complete`, `partial` or `failed`, each with a tooltip stating what the status means (see §4.4) |
| File name | The sanitised display name; the tooltip shows the original exported name when the two differ |
| Source / Destination | `ip:port` of the correlated endpoints, empty when the object could not be correlated to an endpoint |
| Protocol | Always `http` in this build, because HTTP object export is the only export that runs |
| Content type | The type recorded for the HTTP body, or empty when there is none |
| Size | The stored byte count |
| Stream / frames | `stream <id>` and the number of listed frames (with the frame numbers in the tooltip); `no frames recorded` when the list is empty |
| Hashes | SHA-256, SHA-1 and MD5 of the stored file, each with a copy button; `—` with the tooltip "No hash is recorded — the file was refused or not stored" when absent |
| Note | The backend's own explanation, truncated to 120 characters with the full text in the tooltip |
| Export | A **Download** link, enabled only when the object is not `failed` and has a size; otherwise a visibly disabled button whose tooltip says there is nothing to download |

Any row whose status is not `complete` also gets a second, full-width row underneath: the
status chip, the note (or a generic sentence when the backend recorded none), and in muted
monospace, the object's `stored_path`.

A footer under the table states that `stored_path` is shown for reference only, is a path
inside the analysis directory, and is never turned into a URL by the page.

Pagination uses page sizes 50 / 100 / 250 / 500 / 1000.

Empty states: with filters active, "No object matches these filters"; with none,
"No objects were extracted from this capture", which states that extraction covers HTTP
bodies only, that a capture with no HTTP or only HTTPS legitimately yields nothing here, and
that absence of objects is not evidence of absence because HTTPS payloads are not decrypted.
That state also carries the **Re-extract objects** button.

## 3. Where the data comes from

Page component `frontend/src/pages/ObjectsPage.tsx`; the API client is `objectsApi` in
`frontend/src/services/api.ts`; the routes are `backend/app/api/routes_objects.py`; the work
behind them is `backend/app/services/object_extractor.py`, with `storage.safe_filename`,
`storage.ensure_within` and `storage.hash_file` from `backend/app/services/storage.py`.

| Call | When | Route |
|---|---|---|
| List | Whenever a capture is selected, and on every filter/sort/page change | `GET /api/analyses/{analysis_id}/objects` |
| Download | Clicking a row's **Download** | `GET /api/analyses/{analysis_id}/objects/{object_id}/export` |
| Re-extract | Clicking **Re-extract objects** | `POST /api/analyses/{analysis_id}/objects/extract` |

The list also runs during analysis: extraction is the `objects` stage of the pipeline
(`backend/app/services/pipeline.py`), between the `hosts` stage and the `detection` stage.

### 3.1 URL parameters the page reads

| Parameter | Accepted values | Default when absent or invalid |
|---|---|---|
| `search` | Any string | no filter |
| `status` | `complete`, `partial`, `failed` | no filter (anything else is ignored, including `any`) |
| `sort` | `filename`, `size`, `created_at`, `status`, `content_type` | backend default: `filename ASC, id ASC` |
| `order` | `desc` for descending; anything else is ascending | `asc`, and it is only sent when a sort column is chosen |
| `page` | Positive integer | `1` |
| `page_size` | One of `50`, `100`, `250`, `500`, `1000` | `100` |

The API also accepts a `protocol` filter, which this page never sends, so it is always `any`.

### 3.2 What each request returns

* `GET /objects` → `{items, total, page, page_size, pages, totals}`. Each item is an `objects`
  row with `packet_numbers` parsed into a list of integers and an `export_url` added.
  `totals` is computed over the whole analysis, independent of the filters.
* `GET /objects/{object_id}/export` → the file as an attachment. The response always carries
  `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store`; the content type is sent only if it is on the allow list
  (`SAFE_CONTENT_TYPES`), otherwise the body is served as `application/octet-stream` with the
  observed type reported in the `X-Object-Content-Type` header instead.
* `POST /objects/extract` → `{ok, extracted, objects, by_status{complete,partial,failed},
  bytes, warning, seconds}`.

Tables behind all three: `objects` (rows), plus `http_transactions` for correlation and the
`packets` index for the frame lists. The filesystem behind the download is
`data/analyses/<analysis_id>/objects/`.

## 4. How an object is recorded

### 4.1 Which dissector can produce an object

Exactly one: TShark's HTTP object export. `object_extractor.analyze()` calls
`tshark.export_objects(capture, staging, protocol="http")`, which runs
`tshark -r <capture> -n --export-objects http,<staging>`. Nothing else in the app produces
rows in `objects`:

* SMB, TFTP, IMF and the other export protocols TShark supports are not invoked;
* HTTPS payloads are never decrypted, so an HTTPS-only capture yields nothing;
* a capture with no HTTP yields nothing, and the `protocol` column is the constant `http`.

Extraction happens into a staging directory inside the analysis directory
(`objects_staging`), never into a shared or user-visible location, and the staging directory
is removed at the end of every run — including on failure.

### 4.2 From staged file to row

For every file TShark wrote:

1. **The filename is never used as a path.** The name is sanitised for display only
   (`storage.safe_filename`, 160 characters) and kept verbatim as `original_filename`; the
   file on disk is renamed to `<uuid4 hex>.<sanitised suffix>`.
2. **Path containment is re-checked**: the destination is resolved through
   `storage.ensure_within(objects_dir, …)`, which raises for anything that escapes. The stored
   path is recorded relative to the analysis directory and always under `objects/`.
3. **Symlinks are never followed.** `_iter_files` skips a symlinked entry and logs it; the
   download refuses a path that is a symlink.
4. **Oversized objects are refused, not stored.** If the staged size exceeds
   `max_object_bytes` (default `50 * 1024 * 1024` bytes, adjustable in
   [Settings](Settings.md)), the staged file is deleted and the row is written with
   `status='failed'`, the real size, no hashes, and a note naming the limit and the setting to
   raise.
5. **Hashes are computed from the stored bytes** — `storage.hash_file()` streams the file once
   and returns MD5, SHA-1 and SHA-256. They are hashes of what this build actually stored, not
   of anything in the original capture, so they are directly comparable to a re-download of
   the same object and to any local copy.
6. **Content type** comes from the correlated HTTP transaction (the response's
   `content-type` for a response body, the request's for a request body) and is empty when the
   object could not be correlated.
7. **The previous run's rows survive a failed run.** `DELETE FROM objects WHERE analysis_id = ?`
   and the clearing of `objects/` happen only after TShark has produced at least one file; if
   export fails, or exports nothing while the index shows HTTP bodies exist, the old rows stay
   and the run returns a `warning` instead.

### 4.3 Correlation, and what a `note` means

Correlation reverses TShark's naming rule: `tshark_object_name(uri)` reproduces the exported
name from an indexed `http_transactions.uri` (last path segment, query appended with `?`
escaped as `%3f`, lowercased), and TShark's `(1)`/`(2)` duplicate suffixes are stripped. The
stored size then decides whether the file is that transaction's **response** or **request**
body. From that:

* endpoints are the transaction's client and server (swapped for a response body, so Source is
  the sender);
* `stream_id` is the transaction's TCP stream;
* `packet_numbers` are the payload frames in that direction of that stream, capped at 50, from
  the transaction's request frame (and up to its response frame for a response body).

When any of that cannot be established, the corresponding columns stay empty and `note`
records exactly which signal was missing — for example that no indexed transaction resolves to
the exported name, that several transactions match the name and none reports a body of that
size, that both the request and response bodies are the same size so the direction cannot be
determined, or that the frames could not be listed from the packet index. `status` is not
downgraded in those cases: it stays `complete` with a note saying completeness could not be
verified (§4.4).

### 4.4 What the three statuses mean

| Status | How the code decides it | What it implies |
|---|---|---|
| `complete` | The stored size equals the body size the transaction reports — **or** no size comparison was possible at all | The exported bytes match the recorded body, or nothing contradicted them |
| `partial` | The stored size is **smaller** than the recorded body size | The object was truncated: a capture snap length, a gap in the TCP stream or chunked transfer encoding |
| `failed` | The file was refused for exceeding `max_object_bytes`, or could not be moved into `objects/` | Nothing was stored, so there are no hashes and nothing to download |

Anything else — `note`-only cases such as an export larger than the recorded body — leaves the
status at `complete` with the discrepancy written into the note.

A worked example from `sf19us-MTA-lab-09.pcap` (analysis
`9e2ef6a921304dc9ac0c739133682641`): 8 objects, all `complete`, 2,025,570 bytes stored.
One of them is `tkraw_Protected99.exe` (2,025,472 bytes, `application/x-msdownload`,
SHA-256 beginning `6209953275…`), correlated to stream 14 with 50 frames listed. The other
seven are 14-byte files named `_5c`, `_5c_1_` … `_5c_6_`, whose `original_filename` values are
`%5c`, `%5c(1)` … `%5c(6)`, all with the same SHA-256 beginning `15ded1c516…`, with
`stream_id` empty, no endpoints, no frames — and a note saying no indexed transaction resolves
to that exported name. They are `complete` because nothing disproved completeness, not because
completeness was verified.

The same pattern holds across the library: of the 129 rows in `objects` in
`data/apackets.db`, every row is `complete`, 33 carry no `stream_id` and 48 list no frames.

## 5. Links into the rest of the app

| Element | Opens |
|---|---|
| **Download** on a row | `GET /api/analyses/{id}/objects/{object_id}/export`, an attachment download addressed by the server-generated object id |
| **Re-extract objects** | `POST …/objects/extract` for the selected analysis; the list is invalidated and reloaded |
| Status filter, sort, search, pagination | The same page, re-queried through the URL |
| `stored_path` in a non-complete row | Nothing. It is text for reference; the page never turns it into a link |
| A file named by a finding | The Findings workbench's **Files** tab links to the same export endpoint — see [Findings](Findings.md) |
| Object bytes on the wire | `/packets?sel=<frame>` or `/conversations?stream=<transport>:<id>&tab=timeline` to read the surrounding traffic, once the object's stream or frames are known — see [Packets](Packets.md) and [Conversations](Conversations.md) |

## 6. Limits and honest caveats

* **HTTP only.** One dissector produces objects. SMB shares, TFTP transfers and mail
  attachments that TShark could export under other protocol names are not exported here, and
  HTTPS is never decrypted. "No objects" is therefore a statement about this build, not about
  the capture.
* **`complete` is weaker than its tooltip suggests.** The in-page tooltip says the extracted
  bytes "match the body size the HTTP transaction reports"; the code also marks a row
  `complete` when no transaction could be matched at all, in which case completeness was never
  checked. Read the Note column before treating `complete` as verification. In the worked
  capture, 7 of 8 `complete` rows are in exactly that position.
* **`status='failed'` is the only state with no bytes.** A `partial` object is stored and
  downloadable.
* **Uncorrelated objects have no provenance.** With no `stream_id`, no endpoints and no
  frames, the page cannot say which conversation, host or request the file belongs to — only
  what its name and bytes are.
* **The frame list is a window, not a proof.** It is capped at 50 payload frames, and when the
  transaction did not record a request frame the listed frames are the earliest payload frames
  of that stream in that direction rather than an exact range; the note says so.
* **Re-extraction needs the retained capture.** `POST /objects/extract` resolves the capture
  path and returns `410 capture_missing` ("re-upload the file") when the stored capture is
  gone, so a purged upload can be listed and downloaded from but not re-extracted. Nothing in
  this build removes the upload on the strength of the `retain_uploads` flag; the realistic
  ways the capture disappears are deleting the analysis — which removes `objects/` with it —
  or moving the file outside the app.
* **Re-extraction needs TShark**, and it re-runs the whole export for the analysis, not a
  selected row. It is not incremental: a second run replaces the rows and the files.
* **A failed run leaves the old rows on screen on purpose.** The report line says so, which
  means the table after a failed re-extraction describes the *previous* extraction.
* **The download is not checked at render time.** `Download` is enabled for any row that is not
  `failed` and has a size, so a `complete` row whose file has since been removed from
  `objects/` still offers a link; the API then answers `410 object_missing` ("the object row
  exists but its file is no longer present on disk") and the browser shows that JSON error.
* **`totals` is not the table.** The stat cards describe the whole analysis; the table shows
  one filtered page. The two will not agree while a filter is on, and the caption above the
  cards says so.
* **Names are untrusted input.** The File name, Content type and Note columns all carry
  capture-derived strings. They are rendered as text, and downloads are addressed by id, but
  they are not evidence about what the file is.
* **Type is not determined from content.** The content type is whatever the HTTP transaction
  recorded; the page never sniffs the bytes, so a mislabelled body stays mislabelled.
* **No object previews and no VirusTotal-style enrichment.** Nothing is executed, rendered as
  HTML or uploaded anywhere. The page gives you a hash and a file; what you do with them is
  outside it.

## 7. Related

[Findings](Findings.md) for the alerts whose **Files** tab links to these objects ·
[HTTP](HTTP.md) for the transactions the objects were correlated against ·
[Conversations](Conversations.md) and [Packets](Packets.md) for the streams and frames they
were carried in · [PCAP-Files](PCAP-Files.md) for uploading and retaining the capture that
re-extraction reads back · [Settings](Settings.md) for `max_object_bytes` ·
[Architecture](Architecture.md) for where extracted content is stored on disk.
