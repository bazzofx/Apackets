# VoIP

SIP signalling and the RTP/RTCP media streams in the selected capture: who called whom, which methods
and status codes crossed the wire, which parties and Call-IDs the signalling named, and which media
streams exist — the audio and video itself is neither decoded nor stored.

The page is `frontend/src/pages/ProtocolSessionsPage.tsx` — the shared session page, rendered with
`family="voip"` — and its route is `/voip`. It sits under **Protocols** in the left-hand navigation
with [Email](Email.md), [SSH](SSH.md), [FTP](FTP.md) and [SMB](SMB.md), after [HTTP](HTTP.md),
[DNS](DNS.md) and [TLS](TLS.md). The normative contract for the section is
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md); this document explains behaviour and does not restate
it.

Those five sections are **one implementation, not five**: one page component with a `family` prop,
one `protocol_sessions` table, one extractor and one detail renderer, so a fix on any of the five is
a fix on all five. What differs between them — which protocols a family covers, their display names,
the labels the `detail` keys get, the lead-flag catalogue and the sentence each page uses to state its
own reach — lives in `frontend/src/components/protocols/sessionCatalog.ts`. VoIP is the family where
that difference matters most, because it is the one family whose three protocols do different jobs:
SIP is the signalling, RTP carries the media, and RTCP reports on it.

---

## 1. What it is for

**Which calls were set up in this capture, and which media streams exist for them?** Voice and video
over IP arrive as two layers: a signalling conversation that decides who talks to whom, on which
addresses and ports, with which codecs — and then the media itself, on separate streams. This page
answers the questions an analyst brings to that split:

* which host signalled to which, with which SIP methods and which status codes;
* who the parties were as the signalling named them — the `From`, `To` and request-URI user parts and
  the `Call-ID` values that tie a dialog together;
* what the endpoints claimed to be, from the `User-Agent` values;
* which RTP and RTCP streams exist, with their payload type numbers, synchronisation sources and
  packet counts, and the sequence gaps the extractor can see;
* which RTP streams have **no** SIP session naming their addresses in this capture, which is a
  statement about the capture rather than about the media.

It answers all of that **from one table filled once by one extractor**, not by re-dissecting the
capture when the page is opened. The page is SQL over `protocol_sessions`; every number on it was
written when the capture was analysed. The single exception is the **Re-read protocols** control,
which exists because an analysis indexed before this section existed holds no rows at all (§5).

The honest centre of the family is the contract's sentence: **an RTP row is media seen, not a call.**
A row per media stream, with the volume and the payload types on it, is what a capture can support; a
call count would be an invention, and this page does not produce one.

## 2. What is on the screen

### The section head and the scope note

`Page` draws the section head from `SECTIONS.voip` in `frontend/src/theme/sections.ts`: the label
**VoIP**, the eyebrow **Protocols**, the one-line purpose ("SIP signalling and the RTP/RTCP streams it
produced: who called whom, which methods and status codes crossed, and which media streams exist") and
the section's own hue.

Under it, `AnalysisGuard` requires a selected, completed analysis; with no capture selected it shows
the shared empty state pointing at [PCAP-Files.md](PCAP-Files.md), while a capture still processing
shows its live progress instead of a half-filled table.

The first panel on the page is the **collapsible scope note** — `ScopeNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`, titled *How to read this section* and
**collapsed by default**. The whole header is the control. Opened, it lists what the section can and
cannot read, each line marked with a tick or a struck-through circle:

* **can** — SIP signalling: the methods and status codes, the parties in the `From`, `To` and request
  URI fields, the `Call-ID` values and the user agents;
* **can** — the RTP and RTCP streams that carried media, with their payload type numbers,
  synchronisation source and packet counts;
* **cannot** — audio or video: the media itself is not decoded, transcribed or stored;
* **cannot** — codecs, unless the dissector itself printed one: a payload type number is a number this
  build does not translate into a codec name;
* **cannot** — a call count as a claim about conversations: RTP is media seen, and without SIP
  signalling in the same capture the page says so rather than inventing a call.

It closes with the section's own caveat, under a warning triangle: *media and signalling are separate
streams, so an RTP row without a SIP row means the signalling was elsewhere, not that no call
happened.* The note is rendered whether or not the table has rows, so the limits are visible before
the data is.

### The lead flag legend

Directly below the scope note, also **collapsed by default**: the **How to read VoIP lead flags**
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
session in front of you. `many_commands` is not one of this family's flags, so that threshold never
fires here — the page's own protocols have no command counts to compare against it.

### The filter strip

Above the table, and only when the analysis has been read for these protocols. VoIP is one of the two
families that covers more than one protocol, so it gets all four controls:

| Control | URL key | What it does |
|---|---|---|
| **protocol** | `protocol` | `all` (the default), **SIP**, **RTP** or **RTCP**. Offered because this family covers three protocols — and on this page it is the primary control, because "show me only the signalling" and "show me only the media" are different investigations. |
| **search** | `search` | A case-insensitive substring over the endpoints, server and share names, file names, paths, user names and command arguments — the contract's `q`. On this page what it can reach is the session's endpoints and the server name the contract lists for the search, because the SIP party names, Call-IDs and request URIs are not part of that documented search surface. The endpoint names the parameter `q`; the URL keeps it as `search`. |
| **flagged only** | `flagged` | Only sessions carrying at least one lead flag. The ticked box writes `true`; unticking removes the key entirely rather than writing `false`. |
| **Sort** | `sort` | `time` (the default), `bytes`, `packets` or `duration`. The dropdown lists only the four columns the endpoint allow-lists. Sorting is always **descending**: the shared control draws its asc/desc button, but this page passes only the sort key, so the direction never changes and `order` is never sent. |

**Reset filters** clears `protocol`, `search` and `flagged` and nothing else. Paging, sorting and the
open row are not filters: `NON_FILTER_KEYS` in `ProtocolFilters.tsx` keeps them out of "filters
active" and out of the reset, so clearing a filter never closes the session you are reading or sends
you back to page 1. Changing `protocol`, `search` or `flagged` does reset the page number.

### The session table

Columns, left to right, exactly as rendered:

| Column | Meaning |
|---|---|
| start | `start_time` of the session's first frame, as `YYYY-MM-DD HH:MM:SS.mmm` local time. |
| protocol | The row's own protocol, under its display label: `SIP`, `RTP` or `RTCP`. A cell never prints the raw identifier from the wire. |
| client | Client address and port as `ip:port`, monospaced and clipped to the cell width. For a media row this is the sender; the contract gives RTP and RTCP the role of the SIP session that produced them, when one exists. |
| server | Server address and port. For SIP, the roles follow the contract's rule — the registered and well-known ports first (`5060`, `5061`), then whichever side sent a status line, then whichever side opened the session. RTP and RTCP have no registered port, so their roles come from the SIP session or fall back to the same order. The rule that applied is in the row's `note`, shown in the detail panel. |
| duration | `end_time - start_time`, as `1.234 s`, `12.3 s`, `3 m 4 s` or `1 h 2 m`. |
| packets | Frames attributed to the session, right-aligned. On an RTP row this is the media packet count, which is the number to read next to the payload types. |
| bytes (→ / ←) | `client_bytes / server_bytes`: what the sender sent, then what it received, in the same human-readable units. |
| what it said | The per-protocol summary: for SIP, the method counts and the status-code counts, each rendered as `name ×count` and the two groups separated by a `·`; for RTP and RTCP, the payload-type counts (or the RTCP packet types) in the same form, followed by `ssrc <value>`. The cell truncates, and its tooltip carries the row's whole `detail` object, one key per line, with `*_truncated` siblings left out. |
| flags | One badge per recorded flag. The badge shows the catalogue label, inline detail when it is short enough, and the full reasoning on hover. `—` when the row carries none. |

Above the table the panel header reads **VoIP sessions** with the matching count and, when any filter
is active, the words "(filters active)". Above the table's header line the page states the protocols
this family covers and the envelope's totals — sessions, flagged, bytes — read from the response's own
`counts` block. Since a call produces a SIP row and one or more media rows, those
totals count streams, not conversations.

Below the table, the pager shows `from–to of total`, the page count, previous/next and a page-size
select of 50, 100, 250, 500 or 1000 rows (100 by default; the contract's `page_size` ceiling is
1000). Under that, a footer note states what the table is — one row per session, with endpoints, times
and volume in each direction — how many rows **on this page** carry a lead flag, and that every number
came from the analysis' indexed tables rather than from dissecting the capture again. The Re-read
control in the panel header is the one exception to that sentence, and it says so.

### The detail panel

Selecting a row sets `sel` and opens **`<protocol>` session** below the table — for this family,
`SIP session`, `RTP session` or `RTCP session`. It re-reads that one session on its own request
(`GET /protocols/{session_id}`) and renders:

* **the panel head**: the protocol label, and either `<transport> stream <n>` or, when the dissector
  reported no stream, `stream not reported by the dissector`; a copy-the-session-id button and
  **Close**;
* **the row's own facts**, in a three-column grid: Client, Server, Transport, Started, Ended, Duration,
  Frames (the packet count with its first and last frame numbers), Bytes, Client → server (bytes in N
  frames) and Server → client;
* **the role note**, when the row carries one, under a warning triangle — for media rows this is where
  the contract records that the role came from the SIP session that produced the stream, or that no
  such session was found;
* **the flags**, each with the catalogue's explanation, introduced by the sentence that the extraction
  flagged this session and that each explanation says what the pattern does and does not prove. A
  session with no flags instead says that no lead flag fired — which is an absence of the patterns the
  extractor looks for, not a statement that the session was benign;
* **the `detail` keys**, in the order the extractor wrote them: on a SIP row the method and status-code
  counts, the parties, the Call-IDs, the request URIs and the user agents; on a media row the SSRC, the
  payload types and the sequence gaps;
* **the links**, under the label **Check**: the chips the endpoint returns for this row, pointing at
  the packet view and at the pages that hold the same traffic.

The `detail` renderer is **generic**. `SessionDetail` knows how to draw a string, a number, a boolean,
a list of strings, a name-to-count map and a list of records, and it walks the object in the order the
backend wrote it. It never knows which protocol it is looking at, so:

* a key added for a new protocol appears here **without a line of new code**, and a key the browser
  cannot classify is printed as text rather than dropped;
* key labels come from `DETAIL_LABELS`, and a key with no entry falls back to its own name with the
  underscores turned into spaces, so it cannot vanish from the page just because the catalogue has not
  learned it yet — which is how a key a future codec or signalling extension introduces appears here
  without a change to this component;
* booleans render as `yes`/`no` and are marked as recorded by the extractor, not inferred; numbers get
  thousands separators; count maps become chips sorted by count; lists of strings — the Call-IDs, the
  parties, the request URIs and the user agents — become wrapped chips;
* a list that hit the contract's cap says so in its own label (`Call-IDs (first 50)`), because
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
  an empty table here means the extraction has not run, not that the capture is free of VoIP traffic.
  The endpoint's one-sentence `note` is printed below it.
* **No session, no filters** — *"TShark dissected no SIP, RTP, RTCP session in this capture."*
  followed by the honest reading: a session taken mid-flight, a protocol on a non-standard port the
  dissector was not told to read, or traffic inside a tunnel will not appear here. For this family the
  third case is the common one, because signalling and media frequently run inside a tunnel the
  dissector did not decode.
* **No rows matching active filters** — a different empty state, which says the extraction ran and the
  filters excluded everything it found; when the cause is the **flagged only** box, the title says so
  directly, and with the protocol select it is easy to reach by asking for RTCP in a capture where no
  RTCP was seen.

## 3. `detail`, per protocol

This family has two distinct vocabularies and the contract keeps them apart: §3.6 for `sip` and §3.7
for `rtp` and `rtcp`. A key is present **only when the capture yielded it**: the extractor must not
emit a key it could not fill, and must not emit a plausible-looking value.

### 3.1 `sip`

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `methods` | `{method: count}` | `INVITE`, `ACK`, `BYE`, `REGISTER`, `OPTIONS`, `CANCEL` and the rest, with counts. The method mix is the dialog: whether a session was set up, torn down, registered or merely probed. |
| `status_codes` | `{code: count}` | `100`, `180`, `200`, `401`, `404`, `486`, … with counts. The status codes are where the failures are — a `401` challenge is normal, a run of `404` or `486` is a signal worth reading next to the request URIs those replies answered. |
| `call_ids` | string[] | The `Call-ID` values seen in this stream. A `Call-ID` is what makes two SIP messages the same conversation, and it is the only stable key the protocol offers for tying them together. |
| `from_users` | string[] | The `From` user parts. It is who the signalling claimed the call was from — a claim, not an identity the capture verified. |
| `to_users` | string[] | The `To` user parts. Together with `from_users` this is the "who called whom" the page's purpose line promises. |
| `request_uris` | string[] | The request-URI host and user parts. They say where the request was aimed, which can differ from the dialled party — a redirect, a proxy or a rewritten dial plan all show up here. |
| `user_agents` | string[] | The `User-Agent` values. Endpoint software, and the usual place to notice that a client is a softphone, a gateway or something that does not look like either. |

### 3.2 `rtp` / `rtcp`

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `ssrc` | string | The synchronisation source, **as the dissector printed it**. It is the media stream's own identifier: the same SSRC in two rows means two captures of the same stream, and a change of SSRC inside one row is a stream renegotiation. |
| `payload_types` | `{pt: count}` | RTP payload type numbers with the packet count of each. It says how the stream was encoded *by number* — and the number is all this build will say, because translating it into a codec name is exactly the kind of plausible-looking value the contract forbids. |
| `packets_lost` | int | The sequence-number gaps the extractor can see — and the contract adds the rider that it is **never a claim about jitter**. A gap can be loss, reordering or a capture that missed frames, and the page does not choose between them. |
| `rtcp_packet_types` | `{pt: count}` | RTCP only: `200` SR, `201` RR, `202` SDES and the rest, with counts. It is what the control half of the media stream reported about itself. |

An RTP row is **media seen**, and nothing more. The contract is explicit that a codec name is recorded
only when the dissector itself printed one, and that a payload type number is not translated by this
build — so a row showing `PT 8 ×900` is showing a number, and a reader who knows what payload type 8
usually is has supplied that knowledge themselves.

## 4. What the flags mean

Four of the shared catalogue's flags apply to this family, in the catalogue's own words from
`SESSION_FLAG_CATALOG` in `sessionCatalog.ts`. A flag is written into the row's `flags` array by the
extractor when the session is analysed; no page recomputes it, and the shared convention is a bare
`code` or `"code: detail"` where the detail is the measurement the flag rests on.

| Flag | The catalogue's meaning, and what it does not prove |
|---|---|
| `media_without_signalling` | "RTP or RTCP was seen with no SIP session naming those addresses in this capture. The signalling may simply be outside the capture window or on another interface — which is a limit of the capture, not an observation about the traffic." This is the family's own flag, and it fires on media rows only: it is the page's way of saying "this stream exists and nothing here explains it" rather than presenting an orphan media row as a call. |
| `unusual_port` | "The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol's own content is what makes the session that protocol at all." SIP's registered port is `5060`, which is the comparison the flag rests on. RTP and RTCP have no registered port at all — the contract's §1.2 says so, and gives a media row its role from the SIP session that produced it. |
| `large_transfer` | "The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading." On a media row, where the peer and the payload types are both on the same row, this is one of the few flags whose context is already in front of you. |
| `long_session` | "The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this." A long media stream is an ordinary long call or a stream left running; the duration and the peer are what distinguish those readings. |

Nine flags in the catalogue are **not** applicable here, and their absence is not an observation: the
clear-text credential flags and `no_encryption_upgrade` belong to the mail and FTP families,
`anonymous_login` to FTP and SMB, `legacy_dialect` and `signing_not_required` to SMB,
`many_commands` to the families whose protocols have command lists, and `auth_failures` to the
protocols that reject authentication readably. SIP has a `401` challenge, and that is a status code on
the row, not this flag.

At most ten flags are kept per session, most serious first — the contract's `FLAG_CAP` — and the
detail half of each string quotes the count or value that produced it.

**A flag is a lead, not a verdict.** Every entry above states why the pattern is worth reviewing *and*
what legitimate traffic looks like the same way; the page says it in the legend, in the detail panel
and in its own empty states. A media row with no flag says the extractor found nothing worth flagging
in the fields it reads, which is a statement about the capture.

## 5. Limits and honest caveats

* **The media is not there.** Audio and video are not decoded, transcribed, hashed or stored — not a
  sample of it, not a summary of it. RTP rows carry endpoints, times, volume, the SSRC, the payload
  type numbers and the visible sequence gaps, and that is the whole of what this section knows about a
  media stream.
* **No codec is inferred.** A payload type number stays a number. Some payload types are static, some
  are negotiated in SDP that this page does not store, and a build that turned `PT 8` into a codec
  name would be inventing a measurement — which is exactly what the contract forbids.
* **A media row is not a call, and the page offers no call count.** One call can produce several RTP
  and RTCP streams, and one stream can outlive several SIP dialogs. Counting rows and calling it a call
  count would be a false statement, so the totals on this page count sessions.
* **`packets_lost` is gaps, not loss.** It is the sequence-number gaps the extractor can see. Jitter,
  reordering, a mid-capture start and a capture that dropped frames all produce gaps without any loss
  having occurred on the wire, and the contract records the limit on the key itself.
* **A media row with no signalling is not evidence that no call happened.** That is what
  `media_without_signalling` says in the catalogue's own words: the signalling may be outside the
  capture window or on another interface.
* **SIP over TLS is invisible.** `SIPS` and any SIP inside TLS present as TLS sessions; their methods,
  status codes and parties are inside the encrypted channel and are read on [TLS.md](TLS.md), not
  here. Bearer and digest values inside SIP headers are likewise not credentials this page records —
  it has no credential keys at all.
* **Rows are never merged across streams.** Two media streams are two rows and a SIP dialog is a third,
  even when they belong to one call: the contract's §1.2 forbids merging, because a merged row could
  not honestly carry one set of endpoints.
* **No stream, no row identity.** Where TShark reported no stream, the session is keyed on its
  endpoints and its start time rather than a stream id, and the detail panel says `stream not reported
  by the dissector` in place of a stream number.
* **The capture decides what exists.** A session taken mid-flight, signalling or media on a
  non-standard port the dissector was not told to read, or traffic inside a tunnel the dissector did
  not decode appears as no session at all. The empty state says exactly that rather than implying the
  traffic was clean.
* **A capture indexed before this section existed holds no rows.** The extraction runs as a pipeline
  stage, so older analyses report zero sessions until they are re-read with the control on the page —
  which is why `extracted: false` and **Re-read protocols** exist instead of a silent empty table.
* **The table is capped and paged.** At most `SESSION_CAP` sessions are read for one request, the
  contract caps `page_size` at 1000, and `LIST_CAP` (50 entries per list) and `COUNT_CAP` (200 distinct
  codes or payload types) bound what `detail` can hold. A capped list says so on its own label, so a
  truncated Call-ID or payload-type list is visible rather than plausible.
* **A session is not a user, and a user part is a claim.** SIP names its parties itself; nothing here
  ties a `From` user part to an identity, a person or a device the capture verified, and nothing is
  correlated across captures.
* **The thresholds are constants of this build.** The legend's wording calls them configurable; in
  this build they are the values in [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, and changing one
  means changing the code and re-reading the capture.

## 6. The endpoint

Everything on this page comes from one analysis-scoped resource. The full parameter table, the
envelope and the error codes are the contract's §5; what follows is the part a reader of this page
needs.

| Parameter | What the page sends |
|---|---|
| `family` | Always: `voip`. The endpoint expands it to this family's protocols, so the page never has to spell out `sip`, `rtp` and `rtcp` itself. |
| `protocol` | Only when the protocol select is not on `all`, and only for a family that covers more than one protocol — which this one does. |
| `q` | The **search** box, verbatim. The URL keeps the key as `search`; the request parameter is `q`. |
| `flagged` | `true` only, and only while the box is ticked. An unticked box sends nothing, which is different from sending `false`. |
| `sort` | One of `start_time`, `bytes`, `packets`, `duration`. Always descending — the ordering is the contract's, §5.1. |
| `page`, `page_size` | Straight from the pager: 1-based, 100 rows by default, capped at 1000. |

The response drives three different parts of the screen: `rows` is the table; `total`, `page` and
`page_size` are the panel subtitle and the pager; and `counts` — sessions, flagged, bytes, packets,
`by_protocol` and the first/last seen times — is the header line above the table. `by_protocol` is the
one that matters most on this page: it is how
you see at a glance whether a capture holds signalling only, media only, or both.

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
| Contract | [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) — normative for all five sections, §3.6 and §3.7 for this family's two vocabularies; [`docs/CONTRACT.md`](../docs/CONTRACT.md) governs everything older and wins where the two touch |

**How the table is filled.** The extraction runs as the `protocols` stage of the analysis pipeline
(83–90% of the progress bar), which is why a capture indexed before this section existed holds no
rows until it is re-read: the page offers that, and answers `not extracted` rather than reporting an
empty capture as a clean one.

## 8. Related

[Email.md](Email.md), [SSH.md](SSH.md), [FTP.md](FTP.md) and [SMB.md](SMB.md) are the other four pages
of the same component and the same table; among them, [FTP.md](FTP.md) is the other family where the
protocol itself is plainly readable and [SMB.md](SMB.md) is the other one whose modern form is
encrypted. The frames and streams behind a media row are on [Packets.md](Packets.md) and
[Conversations.md](Conversations.md), the client and server addresses belong to
[Hosts.md](Hosts.md), and [TLS.md](TLS.md) owns the encrypted signalling this page cannot see. The
section index is [README.md](README.md), the endpoint is registered in
[Reference/API.md](Reference/API.md), and the normative rules for the table, the `detail` keys, the
flags, the caps and the limits are [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md).
