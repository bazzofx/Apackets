# SMB

SMB sessions from the selected capture: the dialect negotiated, whether signing and encryption were
required or advertised, the shares connected, the file names requested, and the NT statuses the
server returned — including the failures.

The page is `frontend/src/pages/ProtocolSessionsPage.tsx` — the shared session page, rendered with
`family="smb"` — and its route is `/smb`. It sits under **Protocols** in the left-hand navigation
with [Email](Email.md), [SSH](SSH.md), [FTP](FTP.md) and [VoIP](VoIP.md), after [HTTP](HTTP.md),
[DNS](DNS.md) and [TLS](TLS.md). The normative contract for the section is
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md); this document explains behaviour and does not restate
it.

Those five sections are **one implementation, not five**: one page component with a `family` prop,
one `protocol_sessions` table, one extractor and one detail renderer, so a fix on any of the five is
a fix on all five. What differs between them — which protocols a family covers, their display names,
the labels the `detail` keys get, the lead-flag catalogue and the sentence each page uses to state its
own reach — lives in `frontend/src/components/protocols/sessionCatalog.ts`. SMB is one protocol, so
its page draws no protocol filter, and its `detail` vocabulary is the contract's §3.8.

---

## 1. What it is for

**Which hosts spoke SMB to which, on what terms, and what did they ask for?** SMB is the file-sharing
protocol of a Windows estate, and it is where lateral movement and share enumeration are visible: a
client negotiates a dialect, authenticates, connects to a share, opens files by name, reads and
writes them. The control conversation is readable — right up until SMB3 encryption is negotiated,
after which the payload is not. This page answers the questions that survive that boundary:

* which client talked to which file server, on what port, and for how long;
* which dialect was negotiated, which is the single most useful fact about an implementation's age
  and posture, and whether the negotiation required signing or advertised encryption;
* which shares were connected, which is where an estate's exposure or a mapper's reach becomes visible;
* which file names were requested — names, never contents;
* which commands ran, as counts, so a session that negotiated and disconnected is distinguishable from
  one that read a directory tree;
* and every NT status code the server returned, **including the failures**, which is usually the
  interesting half.

It answers all of that **from one table filled once by one extractor**, not by re-dissecting the
capture when the page is opened. The page is SQL over `protocol_sessions`; every number on it was
written when the capture was analysed. The single exception is the **Re-read protocols** control,
which exists because an analysis indexed before this section existed holds no rows at all (§5).

## 2. What is on the screen

### The section head and the scope note

`Page` draws the section head from `SECTIONS.smb` in `frontend/src/theme/sections.ts`: the label
**SMB**, the eyebrow **Protocols**, the one-line purpose ("SMB sessions: the dialect negotiated, the
shares connected, the file names requested, and the failures the server returned") and the section's
own hue.

Under it, `AnalysisGuard` requires a selected, completed analysis; with no capture selected it shows
the shared empty state pointing at [PCAP-Files.md](PCAP-Files.md), while a capture still processing
shows its live progress instead of a half-filled table.

The first panel on the page is the **collapsible scope note** — `ScopeNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`, titled *How to read this section* and
**collapsed by default**. The whole header is the control. Opened, it lists what the section can and
cannot read, each line marked with a tick or a struck-through circle:

* **can** — the negotiation: the dialects offered, whether signing was required and whether encryption
  was advertised, plus the server name when it crossed the wire;
* **can** — the shares connected, the file names requested, the command counts and every NT status,
  including the failures;
* **cannot** — file contents, and anything inside an encrypted SMB3 session: those sessions record
  endpoints, times, volume and the negotiation, and nothing else;
* **cannot** — authentication material: SMB hashes and tickets are not in the clear here and are not
  reconstructed;
* **cannot** — sessions the dissector did not decode, including SMB inside a tunnel or on a port it
  was not told to treat as SMB.

It closes with the section's own caveat, under a warning triangle: *a share name and a file name are
strings the client sent — whether an open succeeded is answered by the NT status on the same row, not
by the name.* The note is rendered whether or not the table has rows, so the limits are visible before
the data is.

### The lead flag legend

Directly below the scope note, also **collapsed by default**: the **How to read SMB lead flags** panel.
`FlagLegend` (`frontend/src/components/protocols/ProtocolFlags.tsx`) renders the title from the section
label and lists every flag this family can produce — the whole shared `SESSION_FLAG_CATALOG`, because
the five pages carry one catalogue — with its short label and the catalogue's full meaning. *Show*
opens it.

Two standing notes ride with it. The first is the legend's own: a flag means the analyser matched a
pattern in the fields it reads, and it is a lead to look into against the rest of the capture, never a
conclusion about a host or a user. The second is the threshold note this page passes in, quoting the
defaults the flags reason about (`large_transfer ≥ 10 MiB`, `many_commands ≥ 40`,
`long_session ≥ 1 h`). The legend's wording calls those thresholds "configurable"; in this build they
are the constants of [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, nothing on
[Settings.md](Settings.md) moves them, and the detail panel always shows which of them fired for the
session in front of you. `many_commands` is not one of this family's flags, so that threshold never
fires here even though SMB does have a command histogram.

### The filter strip

Above the table, and only when the analysis has been read for these protocols. SMB covers a single
protocol, so the protocol filter is **not drawn** — there would be nothing to choose between — and
three controls remain:

| Control | URL key | What it does |
|---|---|---|
| **search** | `search` | A case-insensitive substring over the endpoints, server and share names, file names, paths, user names and command arguments — the contract's `q`. On this page it reaches the server name, the shares in `trees` and the names in `filenames`, which is the set of strings the SMB vocabulary actually records. The endpoint names the parameter `q`; the URL keeps it as `search`. |
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
| protocol | The row's own protocol, under its display label: `SMB`. A cell never prints the raw identifier from the wire. |
| client | Client address and port as `ip:port`, monospaced and clipped to the cell width. |
| server | Server address and port. The roles are assigned by the contract's rule — the protocol’s registered and well-known ports first (see the contract’s port table), then whichever side sent the first server-role message, then whichever side opened the session — and the rule that applied is in the row's `note`, shown in the detail panel. |
| duration | `end_time - start_time`, as `1.234 s`, `12.3 s`, `3 m 4 s` or `1 h 2 m`. |
| packets | Frames attributed to the session, right-aligned. |
| bytes (→ / ←) | `client_bytes / server_bytes`: what the client sent, then what the server sent, in the same human-readable units. A share-wide copy is lumpy in one direction; a negotiation and a disconnect is small in both. |
| what it said | The per-protocol summary: the dialects joined with `/`, then `share <names>` for the first two shares connected and `N file name(s)` when names were dissected. When none of those three was dissected the cell falls back to the command counts, rendered as `name ×count` pairs. The cell truncates, and its tooltip carries the row's whole `detail` object, one key per line, with `*_truncated` siblings left out. |
| flags | One badge per recorded flag. The badge shows the catalogue label, inline detail when it is short enough, and the full reasoning on hover. `—` when the row carries none. |

Above the table the panel header reads **SMB sessions** with the matching count and, when any filter is
active, the words "(filters active)". Above the table's header line the page states the protocol this
family covers and the envelope's totals — sessions, flagged, bytes — read from the response's own
`counts` block.

Below the table, the pager shows `from–to of total`, the page count, previous/next and a page-size
select of 50, 100, 250, 500 or 1000 rows (100 by default; the contract's `page_size` ceiling is 1000).
Under that, a footer note states what the table is — one row per session, with endpoints, times and
volume in each direction — how many rows **on this page** carry a lead flag, and that every number came
from the analysis' indexed tables rather than from dissecting the capture again. The Re-read control in
the panel header is the one exception to that sentence, and it says so.

### The detail panel

Selecting a row sets `sel` and opens **SMB session** below the table. It re-reads that one session on
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
* **the `detail` keys**, in the order the extractor wrote them: the command counts, the dialects, the
  shares, the file names, the NT statuses, the two negotiation booleans and the server name;
* **the links**, under the label **Check**: the chips the endpoint returns for this row, pointing at
  the packet view and at the pages that hold the same traffic.

The `detail` renderer is **generic**. `SessionDetail` knows how to draw a string, a number, a boolean,
a list of strings, a name-to-count map and a list of records, and it walks the object in the order the
backend wrote it. It never knows which protocol it is looking at, so:

* a key added for a new protocol appears here **without a line of new code**, and a key the browser
  cannot classify is printed as text rather than dropped;
* key labels come from `DETAIL_LABELS`, and a key with no entry falls back to its own name with the
  underscores turned into spaces, so it cannot vanish from the page just because the catalogue has not
  learned it yet — which is what carries the NT statuses, whose codes are decided by the dissector
  rather than by this page;
* the two negotiation booleans render as `yes`/`no` with a tooltip saying they were **recorded by the
  extractor, not inferred**. The renderer tones a boolean amber when it is true and green when it is
  false, so `Signing required: yes` is the amber chip and `Signing required: no` is the green one; that
  is the renderer's colour, not a verdict, and the flags in §4 are where the reading belongs;
* count maps — `commands` and `statuses` — become chips sorted by count, each with the number beside
  it and the full `name: count` list on hover; string lists — `dialects`, `trees`, `filenames` —
  become wrapped chips;
* a list that hit the contract's cap says so in its own label (`File names requested (first 50)`),
  because `SessionDetail` reads the sibling `*_truncated` boolean and shows it beside the list instead
  of as a row of its own.

When the extractor produced no protocol fields at all, the panel says so in one sentence — only the
endpoints, times and volume are known, and nothing is inferred from the port number. On this family
that is also what an encrypted SMB3 session looks like beyond its negotiation.

### What the page shows when there is nothing

Four distinct states, and the page does not blur them:

* **No capture selected** — the shared `AnalysisGuard` empty state, pointing at
  [PCAP-Files.md](PCAP-Files.md).
* **The analysis has no protocol rows at all, and the capture is old enough that the extraction stage
  may never have run** — the endpoint returns `extracted: false` and the page shows **This capture has
  not been read for these protocols**, with the **Re-read protocols** button and the explanation that
  an empty table here means the extraction has not run, not that the capture is free of SMB traffic.
  The endpoint's one-sentence `note` is printed below it.
* **No session, no filters** — *"TShark dissected no SMB session in this capture."* followed by the
  honest reading: a session taken mid-flight, a protocol on a non-standard port the dissector was not
  told to read, or traffic inside a tunnel will not appear here.
* **No rows matching active filters** — a different empty state, which says the extraction ran and the
  filters excluded everything it found; when the cause is the **flagged only** box, the title says so
  directly.

## 3. `detail`, per protocol

SMB is one protocol, so the contract's §3.8 is the whole vocabulary. A key is present **only when the
capture yielded it**: the extractor must not emit a key it could not fill, and must not emit a
plausible-looking value. Note that `commands` and `statuses` are name-to-count maps, not lists of
records: the contract records how often each command ran and how often each status came back, not a
per-call sequence.

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `commands` | `{cmd: count}` | `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, `READ`, `WRITE`, `CLOSE`, … as the dissector names them, with counts. It is the shape of the session: whether it got past setup, how much of it was directory work, and how much of it was reads and writes. |
| `dialects` | string[] | The dialects negotiated (`SMB 2.002`, `SMB 3.0.2`, …), and `SMB 1` for an SMB1 session. This is the row's most load-bearing fact: dialect decides whether signing and encryption were available at all, and SMB1 is the flag below. |
| `trees` | string[] | The share paths connected. A share is where a client's reach becomes concrete, and a short list of widely-shared administrative shares is a different question from one project share. |
| `filenames` | string[] | The file names requested — **names, never contents**. On this row they are the closest thing to "what was looked at", and the NT statuses on the same row are what say whether each request was served. |
| `statuses` | `{nt_status: count}` | NT status codes with counts, **including the failures**. The rejections are on the row on purpose: a run of `STATUS_ACCESS_DENIED` or `STATUS_OBJECT_NAME_NOT_FOUND` against one share is the difference between a normal client and an enumeration sweep, and it is only visible because the failures are kept. |
| `signing_required` | bool | Whether the negotiation required signing. Integrity protection against a relay is exactly this boolean, and it is recorded rather than inferred from the dialect. |
| `encryption_capable` | bool | Whether the negotiation advertised encryption. It says the session was *able* to encrypt, which is why the honest reading of an unreadable SMB3 session depends on it. |
| `server` | string | The server name from a session setup, when present. The address in the table's server column is what the wire carried; this is what the server called itself, and the two can disagree. |

What is absent is as deliberate as what is present. There is no key for file contents, no key for
byte ranges read or written, no key for SMB hashes, NTLM material or Kerberos tickets, and no key for
a per-request command sequence. The contract's §1.3 forbids copying payload into `detail`, and the
scope note says so in the page's own words.

## 4. What the flags mean

Six of the shared catalogue's flags apply to this family, in the catalogue's own words from
`SESSION_FLAG_CATALOG` in `sessionCatalog.ts`. A flag is written into the row's `flags` array by the
extractor when the session is analysed; no page recomputes it, and the shared convention is a bare
`code` or `"code: detail"` where the detail is the measurement the flag rests on.

| Flag | The catalogue's meaning, and what it does not prove |
|---|---|
| `legacy_dialect` | "An SMB1 session was negotiated. SMB1 is obsolete and its signing is weak, which is why it is worth reviewing — plenty of older embedded devices and printers still offer nothing else." The evidence is the `dialects` list on the same row, which is where the reader should look before drawing anything from the flag. |
| `signing_not_required` | "The negotiation did not require SMB signing, so this session's traffic is not integrity-protected against a relay. It is the default on many servers, and only exploitable when combined with a relay opportunity." One session without signing is not an attack; the peer, the share and the rest of the capture are what turn it into a question. |
| `anonymous_login` | "An anonymous, guest or default-style identity was attempted or accepted. Anonymous FTP and guest SMB are legitimate in some estates and are a way into others; the share or directory it reached is the question that follows." On this page "the share it reached" means the `trees` key on the same row, so the follow-up question is one line away. |
| `unusual_port` | "The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol's own content is what makes the session that protocol at all." SMB's registered port is `445` — the port the application's own service-name table maps to `microsoft-ds` — and the dissector recognised the protocol, so the port was not what made it SMB. |
| `large_transfer` | "The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading." On a share-wide copy the direction is the story: the read side is a server handing data out, the write side is a client pushing it in. |
| `long_session` | "The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this." A long SMB session is usually a mapped drive left open, and the command counts on the row say whether anything happened during it. |

Three things about these flags are worth stating plainly. `legacy_dialect` and `signing_not_required`
are read from the **negotiation**, which is exactly the part of an SMB session that remains readable
even when the rest of it is encrypted — so those two flags still fire on a session this page otherwise
knows nothing about. `anonymous_login` is one of the two families that carry it, FTP being the other.
And the clear-text credential flags, `no_encryption_upgrade`, `many_commands`, `auth_failures` and
`media_without_signalling` are **not** this family's, so their absence from a row is not an
observation.

At most ten flags are kept per session, most serious first — the contract's `FLAG_CAP` — and the
detail half of each string quotes the count or value that produced it.

**A flag is a lead, not a verdict.** Every entry above states why the pattern is worth reviewing *and*
what legitimate traffic looks like the same way; the page says it in the legend, in the detail panel
and in its own empty states. On this family in particular: SMB1 and unsigned SMB are the default state
of a great deal of ordinary, unremarkable infrastructure.

## 5. Limits and honest caveats

* **An SMB3-encrypted session is endpoints, times, volume and the negotiation, and nothing else.**
  Once encryption is negotiated, tree connects, file names, commands and NT statuses are inside the
  encrypted channel and are never decrypted by this app. Those rows still carry `dialects`,
  `signing_required` and `encryption_capable`, because the negotiation happened in the clear — which is
  the honest shape of the answer: this page can say what a session agreed to even when it cannot say
  what the session then did.
* **File contents are not stored.** Not truncated, not previewed, not hashed on this page: absent.
  Only `filenames` — the strings the client sent. Whether an open succeeded is answered by the NT
  status on the same row, and what the file held is [Files-and-Objects.md](Files-and-Objects.md)'s
  question, and only where the application can carve the content at all.
* **Authentication material is not reconstructed.** SMB hashes, NTLM exchanges and Kerberos tickets
  are not in the clear and are not reassembled from the capture; there is no `password_present` key on
  this family, and `anonymous_login` is the only identity-shaped flag here.
* **A name is a request, not a result.** `trees` and `filenames` are strings the client sent. A share
  it asked for and was refused still appears in `trees`, and a file it named and never opened still
  appears in `filenames` — the `statuses` map and the command counts are what tell the two apart.
* **Statuses are counts, not a sequence.** `statuses` records how often each NT status came back, so a
  row cannot tell you which request produced which rejection. The per-request detail is in the packets,
  reachable from the detail panel's links and on [Packets.md](Packets.md).
* **SMB1 is a dialect, not a verdict.** `SMB 1` in the `dialects` list says the session negotiated it.
  Plenty of printers, appliances and older servers offer nothing else, and `legacy_dialect` says so in
  the catalogue's own words.
* **The capture decides what exists.** A session taken mid-flight, SMB on a port the dissector was not
  told to treat as SMB, or SMB inside a tunnel the dissector did not decode appears as no session at
  all. The empty state says exactly that rather than implying the traffic was clean.
* **A capture indexed before this section existed holds no rows.** The extraction runs as a pipeline
  stage, so older analyses report zero sessions until they are re-read with the control on the page —
  which is why `extracted: false` and **Re-read protocols** exist instead of a silent empty table.
* **The table is capped and paged.** At most `SESSION_CAP` sessions are read for one request, the
  contract caps `page_size` at 1000, and `LIST_CAP` (50 entries per list) and `COUNT_CAP` (200 distinct
  codes) bound what `detail` can hold. A capped list says so on its own label, so a truncated share,
  file or status list is visible rather than plausible.
* **A session is not a user, and a share is not an entitlement.** One address running many SMB sessions
  is a busy host or a scanner, not a person; nothing here is correlated across captures, and no session
  is attributed to an identity the wire did not carry.
* **The thresholds are constants of this build.** The legend's wording calls them configurable; in
  this build they are the values in [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, and changing one
  means changing the code and re-reading the capture.

## 6. The endpoint

Everything on this page comes from one analysis-scoped resource. The full parameter table, the
envelope and the error codes are the contract's §5; what follows is the part a reader of this page
needs.

| Parameter | What the page sends |
|---|---|
| `family` | Always: `smb`. The endpoint expands it to this family's protocols, which here is the single value `smb`. |
| `protocol` | Never. The control is drawn only for the families that cover more than one protocol, and SMB is not one of them. |
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
  capture has not been read for these protocols** panel with the rescan control instead of reporting an
  empty capture as a clean one.
* **`note`** is one sentence stating the section's limits. It is printed in that same panel.

Three further calls belong to the section: `GET /protocols/summary` returns per-family totals for the
headers (this page reads its `note`), `GET /protocols/{session_id}` returns the one session the detail
panel renders, including its `frame_numbers` and `links`, and `POST /protocols/rescan` re-runs the
extraction for a capture that is already indexed, answering `202` with a job id the page shows. The
rescan never touches any table other than `protocol_sessions`. Errors — unknown analysis, an analysis
that has not finished, an unknown protocol or family, a bad page, an unknown session id — are the
contract's §5.5, and the page lets them surface through its shared loading and error states rather than
translating them.

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

[Email.md](Email.md), [SSH.md](SSH.md), [FTP.md](FTP.md) and [VoIP.md](VoIP.md) are the other four
pages of the same component and the same table; [FTP.md](FTP.md) is the other family whose protocol is
readable in the clear and whose credential flags this one does not share. The frames and streams behind
a row, and the per-request detail the status counts cannot hold, are on [Packets.md](Packets.md) and
[Conversations.md](Conversations.md); the client and server addresses belong to [Hosts.md](Hosts.md);
the file bytes this page refuses to store belong to [Files-and-Objects.md](Files-and-Objects.md); and
[TLS.md](TLS.md) is the section for the protocols whose payload a capture can only ever count. The
section index is [README.md](README.md), the endpoint is registered in
[Reference/API.md](Reference/API.md), and the normative rules for the table, the `detail` keys, the
flags, the caps and the limits are [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md).
