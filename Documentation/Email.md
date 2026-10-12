# Email

SMTP, POP3 and IMAP sessions from the selected capture: who connected to which mail service, what
the control channel said, and which credentials crossed the wire in the clear.

The page is `frontend/src/pages/ProtocolSessionsPage.tsx` — the shared session page, rendered with
`family="email"` — and its route is `/email`. It sits under **Protocols** in the left-hand
navigation with [SSH](SSH.md), [FTP](FTP.md), [VoIP](VoIP.md) and [SMB](SMB.md), after
[HTTP](HTTP.md), [DNS](DNS.md) and [TLS](TLS.md). The normative contract for the section is
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md); this document explains behaviour and does not restate
it.

Those five sections are **one implementation, not five**: one page component with a `family` prop,
one `protocol_sessions` table, one extractor and one detail renderer, so a fix on any of the five is
a fix on all five. What differs between them — which protocols a family covers, their display names,
the labels the `detail` keys get, the lead-flag catalogue and the sentence each page uses to state
its own reach — lives in `frontend/src/components/protocols/sessionCatalog.ts`.

---

## 1. What it is for

**Which mail sessions are in this capture, who authenticated to them, and was anything readable in
the clear?** A mail session is a conversation, not a request: a client opens a connection, the
server announces itself (`220`, `+OK`, `* OK`), a command/reply exchange follows, and the connection
closes. This page answers the questions an analyst brings to that shape:

* which client talked to which mail server, on what port, over what window of time;
* how much moved in each direction, so a mailbox download is distinguishable from a typing client;
* what the session actually said — the verbs, the reply codes, the envelope addresses, the mailboxes;
* whether an identity and a password crossed the wire unencrypted, and which authentication
  mechanism carried them;
* which of those sessions the extractor thought were worth a second look, and why.

It answers all of that **from one table filled once by one extractor**, not by re-dissecting the
capture when the page is opened. The page is SQL over `protocol_sessions`; every number on it was
written when the capture was analysed. The single exception is the **Re-read protocols** control,
which exists because an analysis indexed before this section existed holds no rows at all (§5).

SMTP, POP3 and IMAP share a page because they share that shape and are one query with a different
`protocol IN ('smtp','pop3','imap')` filter. They do not share a `detail` object: what a POP3 session
can say is not what an SMTP session can say, and §3 keeps them apart.

## 2. What is on the screen

### The section head and the scope note

`Page` draws the section head from `SECTIONS.email` in `frontend/src/theme/sections.ts`: the label
**Email**, the eyebrow **Protocols**, the one-line purpose ("SMTP, POP3 and IMAP sessions: who sent
what to whom, which mailboxes were touched, and which credentials crossed the wire in the clear")
and the section's own hue.

Under it, `AnalysisGuard` requires a selected, completed analysis; with no capture selected it shows
the shared empty state pointing at [PCAP-Files.md](PCAP-Files.md), while a capture still processing
shows its live progress instead of a half-filled table.

The first panel on the page is the **collapsible scope note** — `ScopeNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`, titled *How to read this section* and
**collapsed by default**. The whole header is the control. Opened, it lists what the section can and
cannot read, each line marked with a tick or a struck-through circle:

* **can** — one row per mail session with its endpoints, times and volume in each direction, plus the
  commands, reply codes, envelope addresses and mailboxes the dissector produced;
* **can** — clear-text authentication, with the user name and mechanism recorded and only the
  *presence* of a password;
* **cannot** — message contents: bodies and attachments are not copied into this table, because
  carved content belongs to [Files-and-Objects.md](Files-and-Objects.md);
* **cannot** — sessions where the mail ran inside TLS on a non-standard port the dissector did not
  decode: that handshake is [TLS.md](TLS.md)'s, not this page's;
* **cannot** — anything from a capture indexed before this section existed.

It closes with the section's own caveat, under a warning triangle: *a session is a connection, not a
person or a mailbox; the addresses are what the wire carried, and nothing here proves who read the
mail.* The note is rendered whether or not the table has rows, so the limits are visible before the
data is.

### The lead flag legend

Directly below the scope note, also **collapsed by default**: the **How to read Email lead flags**
panel. `FlagLegend` (`frontend/src/components/protocols/ProtocolFlags.tsx`) renders the title from
the section label and lists every flag this family can produce — the whole shared
`SESSION_FLAG_CATALOG`, because the five pages carry one catalogue — with its short label and the
catalogue's full meaning. *Show* opens it.

Two standing notes ride with it. The first is the legend's own: a flag means the analyser matched a
pattern in the fields it reads, and it is a lead to look into against the rest of the capture, never
a conclusion about a host or a user. The second is the threshold note this page passes in, quoting
the defaults the flags reason about (`large_transfer ≥ 10 MiB`, `many_commands ≥ 40`,
`long_session ≥ 1 h`). The legend's wording calls those thresholds "configurable"; in this build
they are the constants of [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, nothing on
[Settings.md](Settings.md) moves them, and the detail panel always shows which of them fired for the
session in front of you.

### The filter strip

Above the table, and only when the analysis has been read for these protocols. Email is one of the
two families that covers more than one protocol, so it gets all four controls:

| Control | URL key | What it does |
|---|---|---|
| **protocol** | `protocol` | `all` (the default), **SMTP**, **POP3** or **IMAP**. Offered only because this family covers three protocols; SSH, FTP and SMB draw no protocol filter at all. |
| **search** | `search` | A case-insensitive substring over the endpoints, server and share names, file names, paths, user names and command arguments — the contract's `q`. The endpoint the page sends it to names the parameter `q`; the URL keeps it as `search`. |
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
| protocol | The row's own protocol, under its display label: `SMTP`, `POP3` or `IMAP`. A cell never prints the raw identifier from the wire. |
| client | Client address and port as `ip:port`, monospaced and clipped to the cell width. |
| server | Server address and port. The roles are assigned by the contract's rule — the protocol’s registered and well-known ports first (see the contract’s port table), then whichever side sent the server-role greeting, then whichever side opened the session — and the rule that applied is in the row's `note`, shown in the detail panel. |
| duration | `end_time - start_time`, as `1.234 s`, `12.3 s`, `3 m 4 s` or `1 h 2 m`. |
| packets | Frames attributed to the session, right-aligned. |
| bytes (→ / ←) | `client_bytes / server_bytes`: what the client sent, then what the server sent, in the same human-readable units. |
| what it said | The per-protocol summary — for SMTP `from <sender>, N recipient(s)`, where the sender is the first envelope sender or, failing that, the name the client announced in `EHLO`, and the first six verbs are shown when there is no envelope address at all; for POP3 and IMAP `as <user name> · FIRST, VERBS, …`. The cell truncates, and its tooltip carries the row's whole `detail` object, one key per line, with `*_truncated` siblings left out. |
| flags | One badge per recorded flag. The badge shows the catalogue label, inline detail when it is short enough, and the full reasoning on hover. `—` when the row carries none. |

Above the table the panel header reads **Email sessions** with the matching count and, when any
filter is active, the words "(filters active)". Above the table's header line the page states the
protocols this family covers and the envelope's totals — sessions, flagged, bytes — read from the
response's own `counts` block.

Below the table, the pager shows `from–to of total`, the page count, previous/next and a page-size
select of 50, 100, 250, 500 or 1000 rows (100 by default; the contract's `page_size` ceiling is
1000). Under that, a footer note states what the table is — one row per session, with endpoints,
times and volume in each direction — how many rows **on this page** carry a lead flag, and that
every number came from the analysis' indexed tables rather than from dissecting the capture again.
The Re-read control in the panel header is the one exception to that sentence, and it says so.

### The detail panel

Selecting a row sets `sel` and opens **`<protocol>` session** below the table — for this family,
`SMTP session`, `POP3 session` or `IMAP session`. It re-reads that one session on its own request
(`GET /protocols/{session_id}`) and renders:

* **the panel head**: the protocol label, and either `tcp stream <n>` or, when the dissector reported
  no stream, `stream not reported by the dissector`; a copy-the-session-id button and **Close**;
* **the row's own facts**, in a three-column grid: Client, Server, Transport, Started, Ended,
  Duration, Frames (the packet count with its first and last frame numbers), Bytes,
  Client → server (bytes in N frames) and Server → client;
* **the role note**, when the row carries one, under a warning triangle — this is where the contract
  records how the client and server roles were decided, or a limit of that row;
* **the flags**, each with the catalogue's explanation, introduced by the sentence that the
  extraction flagged this session and that each explanation says what the pattern does and does not
  prove. A session with no flags instead says that no lead flag fired — which is an absence of the
  patterns the extractor looks for, not a statement that the session was benign;
* **the `detail` keys**, in the order the extractor wrote them;
* **the links**, under the label **Check**: the chips the endpoint returns for this row, pointing at
  the packet view and at the pages that hold the same traffic.

The `detail` renderer is **generic**. `SessionDetail` knows how to draw a string, a number, a
boolean, a list of strings, a name-to-count map and a list of records, and it walks the object in
the order the backend wrote it. It never knows which protocol it is looking at, so:

* a key added for a new protocol appears here **without a line of new code**, and a key the browser
  cannot classify is printed as text rather than dropped;
* key labels come from `DETAIL_LABELS`, and a key with no entry falls back to its own name with the
  underscores turned into spaces, so it cannot vanish from the page just because the catalogue has
  not learned it yet;
* booleans render as `yes`/`no` and are marked as recorded by the extractor, not inferred; numbers
  get thousands separators; count maps become chips sorted by count; lists of records — the
  `commands` arrays — become a small scrollable table whose columns are the union of the record keys;
* a list that hit the contract's cap says so in its own label (`Envelope senders (first 50)`), because
  `SessionDetail` reads the sibling `*_truncated` boolean and shows it beside the list instead of as
  a row of its own.

When the extractor produced no protocol fields at all, the panel says so in one sentence — only the
endpoints, times and volume are known, and nothing is inferred from the port number.

### What the page shows when there is nothing

Four distinct states, and the page does not blur them:

* **No capture selected** — the shared `AnalysisGuard` empty state, pointing at
  [PCAP-Files.md](PCAP-Files.md).
* **The analysis has no protocol rows at all, and the capture is old enough that the extraction
  stage may never have run** — the endpoint returns `extracted: false` and the page shows **This
  capture has not been read for these protocols**, with the **Re-read protocols** button and the
  explanation that an empty table here means the extraction has not run, not that the capture is free
  of mail traffic. The endpoint's one-sentence `note` is printed below it.
* **No session, no filters** — *"TShark dissected no SMTP, POP3, IMAP session in this capture."*
  followed by the honest reading: a session taken mid-flight, a protocol on a non-standard port the
  dissector was not told to read, or traffic inside a tunnel will not appear here.
* **No rows matching active filters** — a different empty state, which says the extraction ran and
  the filters excluded everything it found; when the cause is the **flagged only** box, the title
  says so directly.

## 3. `detail`, per protocol

The keys below are the contract's §3.1–§3.3. A key is present **only when the capture yielded it**:
the extractor must not emit a key it could not fill, and must not emit a plausible-looking value. An
empty list is therefore a real answer ("nothing was dissected"), while an absent key means the
session could not support it at all.

### 3.1 `smtp`

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | The client's verbs — `EHLO`, `MAIL`, `RCPT`, `AUTH`, `DATA`, `QUIT` — with their argument where there was one, deduplicated with a count. This is the skeleton of the session: it says whether mail was submitted, to how many recipients, and by which authentication path. |
| `response_codes` | `{code: count}` | The server's reply codes (`220`, `250`, `354`, `535`, …) with how often each appeared. The greeting is here, the acceptances are here, and so are the rejections — a `535` is what makes `auth_failures` possible. |
| `helo` | string | The name the client announced in `EHLO`/`HELO`. It is the client's own claim about itself, and the usual first thing to compare against the address it actually connected from. |
| `mail_from` | string[] | Envelope senders. The envelope, not the `From:` header — the header is inside the body this page does not store. |
| `rcpt_to` | string[] | Envelope recipients. One submission to many recipients is one row with several entries, which is what a distribution or an enumeration looks like. |
| `auth_username` | string | The `AUTH` user name. An identity is recorded; the app's other pages surface identities too, and a session that authenticated anonymously or not at all has no such key. |
| `password_present` | bool | A password crossed the wire — **never its value**, at any setting. It is the difference between "a user name was seen" and "credentials were readable on the path". |
| `auth_mechanisms` | string[] | The mechanisms offered or used: `PLAIN`, `LOGIN`, `CRAM-MD5`. Which mechanism it was decides how much of the credential exchange was readable, so it belongs next to `password_present`. |
| `data_blocks` | int | The number of `DATA` transfers that completed. It is the count of messages the capture actually shows being submitted, as opposed to messages the client merely announced. |

### 3.2 `pop3`

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | `USER`, `PASS`, `STAT`, `LIST`, `RETR`, `DELE`, `QUIT`, … with their arguments and counts. POP3 sessions are short and verb-driven, so this list is most of what happened. |
| `response_indicators` | `{indicator: count}` | The `+OK` / `-ERR` counts. POP3 answers with words rather than numbers, so this pair is the only success/failure signal the protocol offers. |
| `username` | string | The user name from `USER`. |
| `password_present` | bool | A `PASS` was seen. The value is not recorded. |
| `retrieved` | int | The `RETR` count — how many messages the client pulled out of the mailbox. |
| `deleted` | int | The `DELE` count — how many the client marked for deletion. Retrieval and deletion together are what distinguishes reading mail from clearing a mailbox. |
| `message_count` | int | The count reported by `STAT`/`LIST`, when it parsed. It is the mailbox size the server claimed, which is a different fact from how many messages were actually transferred. |

### 3.3 `imap`

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `commands` | `[{verb, count}]` | `CAPABILITY`, `LOGIN`, `SELECT`, `FETCH`, `UID`, `LOGOUT`, … with counts. IMAP is a mailbox-manipulation protocol, so the verb mix — how much `FETCH`, how much `LIST`, whether `EXPUNGE` appears — is the session's character. |
| `statuses` | `{status: count}` | `OK` / `NO` / `BAD` counts. IMAP tags every response with one of the three, so this is where the rejections are, and it is what `auth_failures` reads. |
| `username` | string | The user name from `LOGIN`. |
| `password_present` | bool | A `LOGIN` carried a password. Recorded as presence only. |
| `folders` | string[] | The mailboxes selected or listed. Names, not contents: which folders were touched is an intent question, and it is answerable from the control channel. |
| `fetches` | int | The `FETCH` / `UID FETCH` count. It separates a client that selected a mailbox from one that read it. |

Notice what is absent by design: no bodies, no subjects, no attachment names, no password values. The
contract's §1.3 forbids all of them, and the page says so rather than leaving the reader to wonder
whether the keys were simply not documented.

## 4. What the flags mean

These are the catalogue entries that apply to this family, in the catalogue's own words from
`SESSION_FLAG_CATALOG` in `sessionCatalog.ts`. A flag is written into the row's `flags` array by the
extractor when the session is analysed; no page recomputes it, and the shared convention is a bare
`code` or `"code: detail"` where the detail is the measurement the flag rests on.

| Flag | The catalogue's meaning, and what it does not prove |
|---|---|
| `cleartext_credentials` | "A password crossed this session without transport encryption. Worth reviewing because it is readable by anything on the path — and it is also what plain legacy clients and badly configured mail, FTP or POP3 servers do, so it says the session was unencrypted, not that anyone abused it." |
| `cleartext_username` | "A user name was sent in the clear. It identifies who was using the session; on its own it is normal for the protocols that do not encrypt, which is why it is a low flag rather than a finding." |
| `no_encryption_upgrade` | "The session ran on a port that carries this protocol in the clear and expects an optional upgrade, and never negotiated TLS. That covers 25 and 587 for SMTP, 110 for POP3, 143 for IMAP and 21 for FTP. Common on internal and legacy infrastructure, and also what a downgrade attack looks like — the packets decide which." |
| `unusual_port` | "The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol's own content is what makes the session that protocol at all." |
| `large_transfer` | "The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading." |
| `many_commands` | "The session issued an unusually high number of commands. Bulk mailbox operations and file mirroring look the same as enumeration; the commands themselves distinguish them." |
| `long_session` | "The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this." |
| `auth_failures` | "Repeated rejected authentications on one session. Clients with stale saved passwords produce exactly this pattern, and so does password guessing." |

Where a flag is decided: `auth_failures` reads the rejected replies (`535` for SMTP, `-ERR` for
POP3, `NO` for IMAP), `cleartext_credentials` and `cleartext_username` read the authentication keys
in `detail`, `no_encryption_upgrade` needs the session to have run on a port that carries the protocol in the clear (25 or 587 for SMTP)
without a TLS negotiation, and the threshold flags read the row's own `packets`, `bytes` and
`duration`. At most ten flags are kept per session, most serious first — the contract's `FLAG_CAP` —
and the detail half of each string quotes the count or value that produced it.

**A flag is a lead, not a verdict.** Every entry above states why the pattern is worth reviewing
*and* what legitimate traffic looks like the same way; the page says it in the legend, in the detail
panel and in its own empty states. A row with no flags is an absence of the patterns the extractor
looks for, which is not the same as benign mail.

## 5. Limits and honest caveats

* **Encrypted mail sessions are endpoints, times and volume only.** `SMTPS`, `POP3S` and `IMAPS` are
  TLS sessions; their commands, codes and credentials are inside the encrypted channel and are never
  decrypted by this app. Those handshakes are read on [TLS.md](TLS.md), not here, and a capture whose
  mail is entirely TLS legitimately stores no Email rows at all.
* **Nothing here is decrypted, and nothing is guessed from a port number.** A session with no parsed
  commands is a session with an empty `commands` list, not an inference from the fact that it used
  port 25.
* **Bodies and attachments are not stored.** Not truncated, not previewed, not hashed on this page:
  absent. Content recovery is [Files-and-Objects.md](Files-and-Objects.md)'s job, and only where the
  application can carve the content at all.
* **Credentials are records of presence.** A password is recorded as `password_present: true` and
  never as a value, so a document that shows only the key is showing the whole of what this section
  knows about the secret.
* **The capture decides what exists.** A session taken mid-flight, a mail service on a non-standard
  port the dissector was not told to read, or traffic inside a tunnel the dissector did not decode
  appears as no session at all. The empty state says exactly that rather than implying the traffic
  was clean.
* **A capture indexed before this section existed holds no rows.** The extraction runs as a pipeline
  stage, so older analyses report zero sessions until they are re-read with the control on the page —
  which is why `extracted: false` and **Re-read protocols** exist instead of a silent empty table.
* **The table is capped and paged.** At most `SESSION_CAP` sessions are read for one request, the
  contract caps `page_size` at 1000, and the contract's list caps (`LIST_CAP`, `COMMAND_CAP`,
  `COUNT_CAP`) bound every list and count map in `detail`. A capped list says so on its own label, so
  a truncated list is visible rather than plausible.
* **A session is not a person or a mailbox.** One address running many sessions is a busy host, not a
  user; nothing here is correlated across captures, and no session is attributed to an identity the
  wire did not carry.
* **The thresholds are constants of this build.** The legend's wording calls them configurable; in
  this build they are the values in [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, and changing one
  means changing the code and re-reading the capture.

## 6. The endpoint

Everything on this page comes from one analysis-scoped resource. The full parameter table, the
envelope and the error codes are the contract's §5; what follows is the part a reader of this page
needs.

| Parameter | What the page sends |
|---|---|
| `family` | Always: `email`. The endpoint expands it to this family's protocols, so the page never has to spell out `smtp`, `pop3` and `imap` itself. |
| `protocol` | Only when the protocol select is not on `all`, and only for a family that covers more than one protocol. |
| `q` | The **search** box, verbatim. The URL keeps the key as `search`; the request parameter is `q`. |
| `flagged` | `true` only, and only while the box is ticked. An unticked box sends nothing, which is different from sending `false`. |
| `sort` | One of `start_time`, `bytes`, `packets`, `duration`. Always descending — the ordering is the contract's, §5.1. |
| `page`, `page_size` | Straight from the pager: 1-based, 100 rows by default, capped at 1000. |

The response drives three different parts of the screen: `rows` is the table; `total`, `page` and
`page_size` are the panel subtitle and the pager; and `counts` — sessions, flagged, bytes, packets,
`by_protocol` and the first/last seen times — is the header line above the table.

Two fields of the envelope are about honesty rather than data:

* **`extracted`** is `false` when the analysis holds no `protocol_sessions` rows at all *and* the
  capture is old enough that the extraction stage may never have run. The page then shows the
  **This capture has not been read for these protocols** panel with the rescan control instead of
  reporting an empty capture as a clean one.
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

[HTTP.md](HTTP.md), [DNS.md](DNS.md) and [TLS.md](TLS.md) are the three sections that were already
there and the ones this family defers to when the mail is encrypted; [SSH.md](SSH.md),
[FTP.md](FTP.md), [VoIP.md](VoIP.md) and [SMB.md](SMB.md) are the other four pages of the same
component and the same table. The frames and streams behind a row are on [Packets.md](Packets.md)
and [Conversations.md](Conversations.md), the content this section refuses to store is
[Files-and-Objects.md](Files-and-Objects.md)'s, and the addresses in the client and server columns
belong to [Hosts.md](Hosts.md). The section index is [README.md](README.md), the endpoint is
registered in [Reference/API.md](Reference/API.md), and the normative rules for the table, the
`detail` keys, the flags, the caps and the limits are
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md).
