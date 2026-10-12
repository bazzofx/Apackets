# FTP

FTP control channels from the selected capture: every command with its argument, every reply code,
the directories entered, the names of the files asked for, and how many data connections each session
opened.

The page is `frontend/src/pages/ProtocolSessionsPage.tsx` — the shared session page, rendered with
`family="ftp"` — and its route is `/ftp`. It sits under **Protocols** in the left-hand navigation
with [Email](Email.md), [SSH](SSH.md), [VoIP](VoIP.md) and [SMB](SMB.md), after [HTTP](HTTP.md),
[DNS](DNS.md) and [TLS](TLS.md). The normative contract for the section is
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md); this document explains behaviour and does not restate
it.

Those five sections are **one implementation, not five**: one page component with a `family` prop,
one `protocol_sessions` table, one extractor and one detail renderer, so a fix on any of the five is
a fix on all five. What differs between them — which protocols a family covers, their display names,
the labels the `detail` keys get, the lead-flag catalogue and the sentence each page uses to state
its own reach — lives in `frontend/src/components/protocols/sessionCatalog.ts`. FTP is one protocol,
so its page draws no protocol filter, and its `detail` vocabulary is the contract's §3.5.

---

## 1. What it is for

**Who moved files in this capture, from where, and under whose credentials?** FTP is one of the last
protocols still found running unencrypted, and its control channel is entirely readable: the client
says `USER`, `PASS`, `CWD`, `PASV`, `RETR`, `STOR`, `LIST`, `QUIT`, and the server answers `220`,
`230`, `331`, `150`, `226` and the rest. This page answers the questions an analyst brings to that
shape:

* which client talked to which FTP server, on what port, and for how long;
* which identity authenticated, whether a password crossed the wire in the clear, and whether the
  session ever upgraded to TLS;
* which directories were entered and which file names were requested — including uploads, because a
  `STOR` is as interesting as a `RETR`;
* whether the session was an anonymous one, and whether its authentication was rejected;
* how many data connections it opened, which is the difference between a directory listing and a
  transfer;
* and, on the volume columns, how much control-channel traffic the session produced.

It answers all of that **from one table filled once by one extractor**, not by re-dissecting the
capture when the page is opened. The page is SQL over `protocol_sessions`; every number on it was
written when the capture was analysed. The single exception is the **Re-read protocols** control,
which exists because an analysis indexed before this section existed holds no rows at all (§5).

## 2. What is on the screen

### The section head and the scope note

`Page` draws the section head from `SECTIONS.ftp` in `frontend/src/theme/sections.ts`: the label
**FTP**, the eyebrow **Protocols**, the one-line purpose ("FTP control channels: the commands, the
names of the files asked for, the response codes, and the data connections each session opened") and
the section's own hue.

Under it, `AnalysisGuard` requires a selected, completed analysis; with no capture selected it shows
the shared empty state pointing at [PCAP-Files.md](PCAP-Files.md), while a capture still processing
shows its live progress instead of a half-filled table.

The first panel on the page is the **collapsible scope note** — `ScopeNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`, titled *How to read this section* and
**collapsed by default**. The whole header is the control. Opened, it lists what the section can and
cannot read, each line marked with a tick or a struck-through circle:

* **can** — the control channel in full: every command with its argument, every reply code, the
  directories entered and the file names asked for;
* **can** — clear-text credentials, which FTP sends by default: `USER` and `PASS` are recorded as an
  identity plus the presence of a password;
* **can** — how many data connections the session opened, so a directory listing is distinguishable
  from a transfer;
* **cannot** — file contents: only names are recorded, and the bytes belong to
  [Files-and-Objects.md](Files-and-Objects.md), and only where the application can carve them;
* **cannot** — FTPS and SFTP: the first is FTP inside TLS and the second is a subsystem of SSH, so
  neither shows a readable command channel here.

It closes with the section's own caveat, under a warning triangle: *a file name is a string the client
sent — whether the transfer succeeded, and what the file held, are separate questions this table does
not answer.* The note is rendered whether or not the table has rows, so the limits are visible before
the data is.

### The lead flag legend

Directly below the scope note, also **collapsed by default**: the **How to read FTP lead flags**
panel. `FlagLegend` (`frontend/src/components/protocols/ProtocolFlags.tsx`) renders the title from the
section label and lists every flag this family can produce — the whole shared `SESSION_FLAG_CATALOG`,
because the five pages carry one catalogue — with its short label and the catalogue's full meaning.
*Show* opens it.

Two standing notes ride with it. The first is the legend's own: a flag means the analyser matched a
pattern in the fields it reads, and it is a lead to look into against the rest of the capture, never a
conclusion about a host or a user. The second is the threshold note this page passes in, quoting the
defaults the flags reason about (`large_transfer ≥ 10 MiB`, `many_commands ≥ 40`,
`long_session ≥ 1 h`). The legend's wording calls those thresholds "configurable"; in this build they
are the constants of [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, nothing on
[Settings.md](Settings.md) moves them, and the detail panel always shows which of them fired for the
session in front of you.

### The filter strip

Above the table, and only when the analysis has been read for these protocols. FTP covers a single
protocol, so the protocol filter is **not drawn** — there would be nothing to choose between — and
three controls remain:

| Control | URL key | What it does |
|---|---|---|
| **search** | `search` | A case-insensitive substring over the endpoints, server and share names, file names, paths, user names and command arguments — the contract's `q`. On this page it reaches the directories in `paths`, the names in `files_requested`, the user name and the command arguments, all four of which are on the contract's list for this parameter. The endpoint names the parameter `q`; the URL keeps it as `search`. |
| **flagged only** | `flagged` | Only sessions carrying at least one lead flag. The ticked box writes `true`; unticking removes the key entirely rather than writing `false`. |
| **Sort** | `sort` | `time` (the default), `bytes`, `packets` or `duration`. The dropdown lists only the four columns the endpoint allow-lists. Sorting is always **descending**: the shared control draws its asc/desc button, but this page passes only the sort key, so the direction never changes and `order` is never sent. |

**Reset filters** clears `search` and `flagged` and nothing else. Paging, sorting and the open row are
not filters: `NON_FILTER_KEYS` in `ProtocolFilters.tsx` keeps them out of "filters active" and out of
the reset, so clearing a filter never closes the session you are reading or sends you back to page 1.
Changing `search` or `flagged` does reset the page number.

### The session table

Columns, left to right, exactly as rendered:

| Column | Meaning |
|---|---|
| start | `start_time` of the session's first frame, as `YYYY-MM-DD HH:MM:SS.mmm` local time. |
| protocol | The row's own protocol, under its display label: `FTP`. A cell never prints the raw identifier from the wire. |
| client | Client address and port as `ip:port`, monospaced and clipped to the cell width. |
| server | Server address and port. The roles are assigned by the contract's rule — the protocol’s registered and well-known ports first (see the contract’s port table), then whichever side sent the `220` banner, then whichever side opened the session — and the rule that applied is in the row's `note`, shown in the detail panel. |
| duration | `end_time - start_time`, as `1.234 s`, `12.3 s`, `3 m 4 s` or `1 h 2 m`. |
| packets | Frames attributed to the session, right-aligned. |
| bytes (→ / ←) | `client_bytes / server_bytes`: what the client sent, then what the server sent, in the same human-readable units. |
| what it said | The per-protocol summary: the first five commands in order, then, when file names were dissected, `· N file(s): name, name, name`. The cell truncates, and its tooltip carries the row's whole `detail` object, one key per line, with `*_truncated` siblings left out. |
| flags | One badge per recorded flag. The badge shows the catalogue label, inline detail when it is short enough, and the full reasoning on hover. `—` when the row carries none. |

Above the table the panel header reads **FTP sessions** with the matching count and, when any filter
is active, the words "(filters active)". Above the table's header line the page states the protocol
this family covers and the envelope's totals — sessions, flagged, bytes — read from the response's own
`counts` block.

Below the table, the pager shows `from–to of total`, the page count, previous/next and a page-size
select of 50, 100, 250, 500 or 1000 rows (100 by default; the contract's `page_size` ceiling is
1000). Under that, a footer note states what the table is — one row per session, with endpoints, times
and volume in each direction — how many rows **on this page** carry a lead flag, and that every number
came from the analysis' indexed tables rather than from dissecting the capture again. The Re-read
control in the panel header is the one exception to that sentence, and it says so.

### The detail panel

Selecting a row sets `sel` and opens **FTP session** below the table. It re-reads that one session on
its own request (`GET /protocols/{session_id}`) and renders:

* **the panel head**: the protocol label, and either `tcp stream <n>` or, when the dissector reported
  no stream, `stream not reported by the dissector`; a copy-the-session-id button and **Close**;
* **the row's own facts**, in a three-column grid: Client, Server, Transport, Started, Ended, Duration,
  Frames (the packet count with its first and last frame numbers), Bytes, Client → server (bytes in N
  frames) and Server → client;
* **the role note**, when the row carries one, under a warning triangle — this is where the contract
  records how the client and server roles were decided, or a limit of that row;
* **the flags**, each with the catalogue's explanation, introduced by the sentence that the extraction
  flagged this session and that each explanation says what the pattern does and does not prove. A
  session with no flags instead says that no lead flag fired — which is an absence of the patterns the
  extractor looks for, not a statement that the session was benign;
* **the `detail` keys**, in the order the extractor wrote them — the command list as a small table of
  verb, argument and count, the reply codes as counts, the directories and file names as chips;
* **the links**, under the label **Check**: the chips the endpoint returns for this row, pointing at
  the packet view and at the pages that hold the same traffic.

The `detail` renderer is **generic**. `SessionDetail` knows how to draw a string, a number, a boolean,
a list of strings, a name-to-count map and a list of records, and it walks the object in the order the
backend wrote it. It never knows which protocol it is looking at, so:

* a key added for a new protocol appears here **without a line of new code**, and a key the browser
  cannot classify is printed as text rather than dropped;
* key labels come from `DETAIL_LABELS`, and a key with no entry falls back to its own name with the
  underscores turned into spaces, so it cannot vanish from the page just because the catalogue has not
  learned it yet;
* booleans render as `yes`/`no` and are marked as recorded by the extractor, not inferred; numbers get
  thousands separators; count maps become chips sorted by count; the `commands` array becomes a
  scrollable table whose columns are the union of the record keys;
* a list that hit the contract's cap says so in its own label (`Files asked for (first 50)`), because
  `SessionDetail` reads the sibling `*_truncated` boolean and shows it beside the list instead of as a
  row of its own.

When the extractor produced no protocol fields at all, the panel says so in one sentence — only the
endpoints, times and volume are known, and nothing is inferred from the port number.

### What the page shows when there is nothing

Four distinct states, and the page does not blur them:

* **No capture selected** — the shared `AnalysisGuard` empty state, pointing at
  [PCAP-Files.md](PCAP-Files.md).
* **The analysis has no protocol rows at all, and the capture is old enough that the extraction stage
  may never have run** — the endpoint returns `extracted: false` and the page shows **This capture has
  not been read for these protocols**, with the **Re-read protocols** button and the explanation that
  an empty table here means the extraction has not run, not that the capture is free of FTP traffic.
  The endpoint's one-sentence `note` is printed below it.
* **No session, no filters** — *"TShark dissected no FTP session in this capture."* followed by the
  honest reading: a session taken mid-flight, a protocol on a non-standard port the dissector was not
  told to read, or traffic inside a tunnel will not appear here. For FTP the second case is the
  common one, because an FTP service moved off port 21 is exactly the case the dissector has to be
  told about.
* **No rows matching active filters** — a different empty state, which says the extraction ran and the
  filters excluded everything it found; when the cause is the **flagged only** box, the title says so
  directly.

## 3. `detail`, per protocol

FTP is one protocol, so the contract's §3.5 is the whole vocabulary. A key is present **only when the
capture yielded it**: the extractor must not emit a key it could not fill, and must not emit a
plausible-looking value.

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | The control-channel verbs — `USER`, `PASS`, `CWD`, `TYPE`, `PASV`, `RETR`, `STOR`, `LIST`, `QUIT` — with their argument where there was one, deduplicated with a count. This is the session: what it asked for, in what mode, and how the transfer was arranged. |
| `response_codes` | `{code: count}` | The server's reply codes (`220`, `230`, `331`, `150`, `226`, …) with how often each appeared. The greeting, the authentication result and the per-transfer completion live here, and so does the `530` that `auth_failures` reads. |
| `username` | string | The user name from `USER`. FTP sends it in the clear by default, which is why the credential flags exist for this family at all. |
| `password_present` | bool | A `PASS` was seen — **never its value**, at any setting. It is what separates "an identity was used" from "credentials were readable on the path". |
| `paths` | string[] | Directories entered, from `CWD` and `PWD`. Directory names are intent: they say where in a tree the session went, which a file-name list alone does not. |
| `files_requested` | string[] | The arguments of `RETR`, `STOR`, `APPE` and `DELE` — names, never contents. Uploads are included on purpose: a session that only ever stored files is a different question from one that only retrieved them. |
| `data_streams` | int | How many data connections the session opened. A listing and a transfer both produce one, but a session that opened dozens was moving files, and the count is the only volume signal the control channel carries. |

What is absent is as deliberate as what is present: there is no key for file contents, no key for the
bytes of a transfer, and no key for the server's filesystem beyond the paths the client named. The
contract's §1.3 forbids copying payload into `detail`, and the scope note says so in the page's own
words.

## 4. What the flags mean

Nine of the shared catalogue's flags apply to this family, in the catalogue's own words from
`SESSION_FLAG_CATALOG` in `sessionCatalog.ts`. A flag is written into the row's `flags` array by the
extractor when the session is analysed; no page recomputes it, and the shared convention is a bare
`code` or `"code: detail"` where the detail is the measurement the flag rests on.

| Flag | The catalogue's meaning, and what it does not prove |
|---|---|
| `cleartext_credentials` | "A password crossed this session without transport encryption. Worth reviewing because it is readable by anything on the path — and it is also what plain legacy clients and badly configured mail, FTP or POP3 servers do, so it says the session was unencrypted, not that anyone abused it." |
| `cleartext_username` | "A user name was sent in the clear. It identifies who was using the session; on its own it is normal for the protocols that do not encrypt, which is why it is a low flag rather than a finding." |
| `no_encryption_upgrade` | "The session ran on a port that carries this protocol in the clear and expects an optional upgrade, and never negotiated TLS. That covers 25 and 587 for SMTP, 110 for POP3, 143 for IMAP and 21 for FTP. Common on internal and legacy infrastructure, and also what a downgrade attack looks like — the packets decide which." FTP's cleartext port is `21`; a session on another port raises `unusual_port` instead, and the two flags are mutually exclusive. |
| `anonymous_login` | "An anonymous, guest or default-style identity was attempted or accepted. Anonymous FTP and guest SMB are legitimate in some estates and are a way into others; the share or directory it reached is the question that follows." On this page "the directory it reached" means the `paths` and `files_requested` keys on the same row. |
| `unusual_port` | "The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol's own content is what makes the session that protocol at all." |
| `large_transfer` | "The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading." Read it on this family as the control channel's own volume: the file bytes cross a data connection, which is a different stream from the session this row describes. |
| `many_commands` | "The session issued an unusually high number of commands. Bulk mailbox operations and file mirroring look the same as enumeration; the commands themselves distinguish them." |
| `long_session` | "The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this." |
| `auth_failures` | "Repeated rejected authentications on one session. Clients with stale saved passwords produce exactly this pattern, and so does password guessing." FTP's rejected authentication is a `530`, which is why the reply codes are on the same row as the flag. |

At most ten flags are kept per session, most serious first — the contract's `FLAG_CAP` — and the
detail half of each string quotes the count or value that produced it. The threshold flags read the
row's own `packets`, `bytes` and `duration`; the credential flags read `username`, `password_present`
and the TLS negotiation; the port flags compare the server port with `21`.

Three flags the catalogue carries are **not** applicable here, and their absence is not an
observation: `legacy_dialect` and `signing_not_required` are SMB's, and `media_without_signalling` is
the VoIP family's.

**A flag is a lead, not a verdict.** Every entry above states why the pattern is worth reviewing *and*
what legitimate traffic looks like the same way; the page says it in the legend, in the detail panel
and in its own empty states. A row with no flags is an absence of the patterns the extractor looks
for, which is not the same as a clean session — and on this family, almost every ordinary FTP session
carries nothing at all.

## 5. Limits and honest caveats

* **File contents are not stored.** Not truncated, not previewed, not hashed on this page: absent.
  `files_requested` records the strings the client sent, and nothing about whether the transfer
  succeeded or what the file held. Content recovery is
  [Files-and-Objects.md](Files-and-Objects.md)'s job, and only where the application can carve it.
* **FTPS is invisible here, and SFTP was never here.** Explicit and implicit FTP-over-TLS encrypt the
  control channel, so their commands, codes, directories and credentials are inside TLS: those
  handshakes are read on [TLS.md](TLS.md), not on this page. SFTP is a subsystem of SSH, so a capture
  of it shows on [SSH.md](SSH.md) as banners and algorithms — and there is no readable command channel
  on either page. A capture whose file movement is entirely FTPS or SFTP legitimately stores no FTP
  rows at all.
* **Two streams, one row.** A data connection is its own stream, separate from the control channel
  this session is keyed on; `data_streams` counts how many the session opened rather than measuring
  them. For a transfer's actual volume, follow the stream on
  [Conversations.md](Conversations.md) — the contract's §4 is explicit that a row's `packets` and
  `bytes` are the session's own.
* **Credentials are records of presence.** A password is recorded as `password_present: true` and
  never as a value. FTP sends it in the clear by default, which is why the flag matters at all.
* **`paths` and `files_requested` are strings the client sent.** A name can be relative, encoded,
  mistyped or aimed at something the server refused; the reply code on the same row is what says
  whether the server accepted it.
* **Nothing is invented.** A session with no parsed commands is a session with an empty `commands`
  list, not an inference from the fact that it used port 21.
* **The capture decides what exists.** A control channel caught mid-transfer, an FTP service on a
  non-standard port the dissector was not told to read, or FTP inside a tunnel the dissector did not
  decode appears as no session at all. The empty state says exactly that rather than implying the
  traffic was clean.
* **A capture indexed before this section existed holds no rows.** The extraction runs as a pipeline
  stage, so older analyses report zero sessions until they are re-read with the control on the page —
  which is why `extracted: false` and **Re-read protocols** exist instead of a silent empty table.
* **The table is capped and paged.** At most `SESSION_CAP` sessions are read for one request, the
  contract caps `page_size` at 1000, and `LIST_CAP` (50 entries per list), `COMMAND_CAP` (25 distinct
  commands) and `COUNT_CAP` (200 distinct codes) bound what `detail` can hold. A capped list says so
  on its own label, so a truncated directory or file list is visible rather than plausible.
* **A session is not a person.** One address running many FTP sessions is a busy host, a scheduled
  job or a mirror, not a user; nothing here is correlated across captures, and no session is
  attributed to an identity the wire did not carry.
* **The thresholds are constants of this build.** The legend's wording calls them configurable; in
  this build they are the values in [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, and changing one
  means changing the code and re-reading the capture.

## 6. The endpoint

Everything on this page comes from one analysis-scoped resource. The full parameter table, the
envelope and the error codes are the contract's §5; what follows is the part a reader of this page
needs.

| Parameter | What the page sends |
|---|---|
| `family` | Always: `ftp`. The endpoint expands it to this family's protocols, which here is the single value `ftp`. |
| `protocol` | Never. The control is drawn only for the families that cover more than one protocol, and FTP is not one of them. |
| `q` | The **search** box, verbatim. The URL keeps the key as `search`; the request parameter is `q`. |
| `flagged` | `true` only, and only while the box is ticked. An unticked box sends nothing, which is different from sending `false`. |
| `sort` | One of `start_time`, `bytes`, `packets`, `duration`. Always descending — the ordering is the contract's, §5.1. |
| `page`, `page_size` | Straight from the pager: 1-based, 100 rows by default, capped at 1000. |

The response drives three different parts of the screen: `rows` is the table; `total`, `page` and
`page_size` are the panel subtitle and the pager; and `counts` — sessions, flagged, bytes, packets,
`by_protocol` and the first/last seen times — is the header line above the table.

Two fields of the envelope are about honesty rather than data:

* **`extracted`** is `false` when the analysis holds no `protocol_sessions` rows at all *and* the
  capture is old enough that the extraction stage may never have run. The page then shows the **This
  capture has not been read for these protocols** panel with the rescan control instead of reporting
  an empty capture as a clean one.
* **`note`** is one sentence stating the section's limits. It is printed in that same panel.

Three further calls belong to the section: `GET /protocols/summary` returns per-family totals for the
headers (this page reads its `note`), `GET /protocols/{session_id}` returns the one session the detail
panel renders, including its `frame_numbers` and `links`, and `POST /protocols/rescan` re-runs the
extraction for a capture that is already indexed, answering `202` with a job id the page shows. The
rescan never touches any table other than `protocol_sessions`. Errors — unknown analysis, an analysis
that has not finished, an unknown protocol or family, a bad page, an unknown session id — are the
contract's §5.5, and the page lets them surface through its shared loading and error states rather
than translating them.

## 7. Where the code lives

| Layer | Name |
|---|---|
| Page component | `frontend/src/pages/ProtocolSessionsPage.tsx` — `ProtocolSessionsPage` (wrapped in `AnalysisGuard`) and `SessionsContent`, which is the whole table for all five families |
| Section catalogue | `frontend/src/components/protocols/sessionCatalog.ts` — `FAMILY_PROTOCOLS`, `PROTOCOL_LABELS`, `DETAIL_LABELS`, `SESSION_FLAG_CATALOG`, `SESSION_FLAG_KEYS`, `FAMILY_SCOPE` and `sessionSummary` |
| Detail panel | `frontend/src/components/protocols/SessionDetail.tsx` |
| Presentation reused by every section | `ProtocolDetail.tsx` (`ScopeNote`, `SectionNote`, `DetailGrid`), `ProtocolFlags.tsx` (`FlagLegend`, `LeadFlagList`, `FlagExplanations`, the badges), `ProtocolFilters.tsx` (`useUrlFilters`, `FilterStrip`, `TextFilter`, `CheckFilter`, `SelectFilter`, `SortSelect`, `ResetFiltersButton`, `NON_FILTER_KEYS`) and `Pagination` |
| Frontend client | `protocolsApi.list` / `.summary` / `.get` / `.rescan` in `frontend/src/services/api.ts` |
| Endpoints | `GET /api/analyses/{analysis_id}/protocols` (list), `GET /api/analyses/{analysis_id}/protocols/summary`, `GET /api/analyses/{analysis_id}/protocols/{session_id}`, `POST /api/analyses/{analysis_id}/protocols/rescan` |
| Route module | `backend/app/api/routes_protocols.py` (router prefix `/api/analyses/{analysis_id}`) |
| Table | `protocol_sessions` in `backend/app/db/schema.sql`, with its four indexes and its `detail` / `flags` / `note` columns |
| Extraction that fills it | The protocol-session extractor, run as a pipeline stage — `backend/app/services/protocol_analyzer.py` by the naming convention the other sections follow (`http_analyzer.py`, `dns_analyzer.py`, `tls_analyzer.py`) |
| Contract | [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) — normative for all five sections; [`docs/CONTRACT.md`](../docs/CONTRACT.md) governs everything older and wins where the two touch |

**How the table is filled.** The extraction runs as the `protocols` stage of the analysis pipeline
(83–90% of the progress bar), which is why a capture indexed before this section existed holds no
rows until it is re-read: the page offers that, and answers `not extracted` rather than reporting an
empty capture as a clean one.

## 8. Related

[Email.md](Email.md) is the family whose read-only-TLS story is closest to this one — mail and FTP are
where clear-text credentials survive — and [SSH.md](SSH.md), [VoIP.md](VoIP.md) and [SMB.md](SMB.md)
are the other three pages of the same component and the same table. The frames and streams behind a
row, including the data connections this page only counts, are on [Packets.md](Packets.md) and
[Conversations.md](Conversations.md); [TLS.md](TLS.md) owns the FTPS handshake this page deliberately
does not see; the file bytes this page refuses to store belong to
[Files-and-Objects.md](Files-and-Objects.md); and the addresses in the client and server columns
belong to [Hosts.md](Hosts.md). The section index is [README.md](README.md), the endpoint is
registered in [Reference/API.md](Reference/API.md), and the normative rules for the table, the
`detail` keys, the flags, the caps and the limits are
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md).
