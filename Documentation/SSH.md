# SSH

SSH sessions from the selected capture: which host opened them, which banners both sides announced,
which algorithms they offered each other, and how much moved in each direction — the payload itself
is encrypted.

The page is `frontend/src/pages/ProtocolSessionsPage.tsx` — the shared session page, rendered with
`family="ssh"` — and its route is `/ssh`. It sits under **Protocols** in the left-hand navigation
with [Email](Email.md), [FTP](FTP.md), [VoIP](VoIP.md) and [SMB](SMB.md), after [HTTP](HTTP.md),
[DNS](DNS.md) and [TLS](TLS.md). The normative contract for the section is
[`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md); this document explains behaviour and does not restate
it.

Those five sections are **one implementation, not five**: one page component with a `family` prop,
one `protocol_sessions` table, one extractor and one detail renderer, so a fix on any of the five is
a fix on all five. What differs between them — which protocols a family covers, their display names,
the labels the `detail` keys get, the lead-flag catalogue and the sentence each page uses to state
its own reach — lives in `frontend/src/components/protocols/sessionCatalog.ts`. For SSH that
difference is unusually small, because this family is exactly one protocol, which is why its page
draws no protocol filter.

---

## 1. What it is for

**Which host opened an SSH connection to which, running what software, offering which algorithms, and
how much did it move?** SSH is the one family here whose payload the application can never read: the
identification exchange and the algorithm negotiation happen in the clear, and everything after the
key exchange is encrypted with a key this app does not have. So the page answers the questions that
survive that boundary:

* which client spoke SSH to which server, on what port, and for how long;
* what each side said it was — the version banner, which names software and, usually, a version;
* which key-exchange, host-key, cipher and MAC algorithms each side offered, which is the readable
  half of the negotiation;
* the shape of the handshake as a histogram of message types;
* how much moved in each direction, which is how an interactive shell is told apart from a bulk
  transfer or a port-forwarded file movement — without reading a byte of either.

It answers all of that **from one table filled once by one extractor**, not by re-dissecting the
capture when the page is opened. The page is SQL over `protocol_sessions`; every number on it was
written when the capture was analysed. The single exception is the **Re-read protocols** control,
which exists because an analysis indexed before this section existed holds no rows at all (§5).

## 2. What is on the screen

### The section head and the scope note

`Page` draws the section head from `SECTIONS.ssh` in `frontend/src/theme/sections.ts`: the label
**SSH**, the eyebrow **Protocols**, the one-line purpose ("SSH sessions: the banners both sides
announced, the algorithms they offered, and the handshake messages — the payload itself is
encrypted") and the section's own hue.

Under it, `AnalysisGuard` requires a selected, completed analysis; with no capture selected it shows
the shared empty state pointing at [PCAP-Files.md](PCAP-Files.md), while a capture still processing
shows its live progress instead of a half-filled table.

The first panel on the page is the **collapsible scope note** — `ScopeNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`, titled *How to read this section* and
**collapsed by default**. The whole header is the control. Opened, it lists what the section can and
cannot read, each line marked with a tick or a struck-through circle:

* **can** — the identification banners both sides announced, the key-exchange, host-key, cipher and
  MAC algorithms they offered, and a histogram of handshake message types;
* **can** — which endpoint was the client and which the server, and the volume in each direction:
  enough to see an interactive session next to a bulk transfer;
* **cannot** — session content: SSH encrypts after the key exchange, so commands, file names and
  passwords are not in this capture in readable form and are not guessed at here;
* **cannot** — authentication outcomes for most sessions: the method and the result are inside the
  encrypted channel, so a session that authenticated and one that failed can look identical;
* **cannot** — any claim about the client's operator: a banner names software and often a version,
  not a person.

It closes with the section's own caveat, under a warning triangle: *a banner is software's own claim
about itself, and it can be changed by anything that felt like changing it.* The note is rendered
whether or not the table has rows, so the limits are visible before the data is.

### The lead flag legend

Directly below the scope note, also **collapsed by default**: the **How to read SSH lead flags**
panel. `FlagLegend` (`frontend/src/components/protocols/ProtocolFlags.tsx`) renders the title from
the section label and lists every flag this family can produce — the whole shared
`SESSION_FLAG_CATALOG`, because the five pages carry one catalogue — with its short label and the
catalogue's full meaning. *Show* opens it.

Two standing notes ride with it. The first is the legend's own: a flag means the analyser matched a
pattern in the fields it reads, and it is a lead to look into against the rest of the capture, never
a conclusion about a host or a user. The second is the threshold note this page passes in, quoting
the defaults the flags reason about (`large_transfer ≥ 10 MiB`, `many_commands ≥ 40`,
`long_session ≥ 1 h`). The legend's wording calls those thresholds "configurable"; in this build they
are the constants of [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, nothing on
[Settings.md](Settings.md) moves them, and the detail panel always shows which of them fired for the
session in front of you. One of the three quoted thresholds — `many_commands` — never fires on this
page, because the contract does not apply the command-count flag to SSH.

### The filter strip

Above the table, and only when the analysis has been read for these protocols. SSH covers a single
protocol, so the protocol filter is **not drawn** — there would be nothing to choose between — and
three controls remain:

| Control | URL key | What it does |
|---|---|---|
| **search** | `search` | A case-insensitive substring over the endpoints, server and share names, file names, paths, user names and command arguments — the contract's `q`. On this page what it can reach is the session's endpoints, because SSH exposes no user name, path, file name or command argument for the search to match. The endpoint the page sends it to names the parameter `q`; the URL keeps it as `search`. |
| **flagged only** | `flagged` | Only sessions carrying at least one lead flag. The ticked box writes `true`; unticking removes the key entirely rather than writing `false`. |
| **Sort** | `sort` | `time` (the default), `bytes`, `packets` or `duration`. The dropdown lists only the four columns the endpoint allow-lists. Sorting is always **descending**: the shared control draws its asc/desc button, but this page passes only the sort key, so the direction never changes and `order` is never sent. |

**Reset filters** clears `search` and `flagged` and nothing else. Paging, sorting and the open row
are not filters: `NON_FILTER_KEYS` in `ProtocolFilters.tsx` keeps them out of "filters active" and out
of the reset, so clearing a filter never closes the session you are reading or sends you back to
page 1. Changing `search` or `flagged` does reset the page number.

### The session table

Columns, left to right, exactly as rendered:

| Column | Meaning |
|---|---|
| start | `start_time` of the session's first frame, as `YYYY-MM-DD HH:MM:SS.mmm` local time. |
| protocol | The row's own protocol, under its display label: `SSH`. A cell never prints the raw identifier from the wire. |
| client | Client address and port as `ip:port`, monospaced and clipped to the cell width. |
| server | Server address and port. The roles are assigned by the contract's rule — the protocol’s registered port first (`22`), then whichever side opened the session — an SSH identification string cannot decide the role, because both ends send one and the client sends first, so an off-port SSH session is assigned by who connected — and the rule that applied is in the row's `note`, shown in the detail panel. |
| duration | `end_time - start_time`, as `1.234 s`, `12.3 s`, `3 m 4 s` or `1 h 2 m`. |
| packets | Frames attributed to the session, right-aligned. |
| bytes (→ / ←) | `client_bytes / server_bytes`: what the client sent, then what the server sent, in the same human-readable units. On an interactive shell the two are small and roughly balanced; a port-forwarded transfer is not. |
| what it said | The per-protocol summary: `<client banner> → <server banner>` when either banner was dissected, and the handshake message histogram as `code ×count` pairs when neither was. The cell truncates, and its tooltip carries the row's whole `detail` object, one key per line, with `*_truncated` siblings left out. |
| flags | One badge per recorded flag. The badge shows the catalogue label, inline detail when it is short enough, and the full reasoning on hover. `—` when the row carries none. |

Above the table the panel header reads **SSH sessions** with the matching count and, when any filter
is active, the words "(filters active)". Above the table's header line the page states the protocol
this family covers and the envelope's totals — sessions, flagged, bytes — read from the response's own
`counts` block.

Below the table, the pager shows `from–to of total`, the page count, previous/next and a page-size
select of 50, 100, 250, 500 or 1000 rows (100 by default; the contract's `page_size` ceiling is
1000). Under that, a footer note states what the table is — one row per session, with endpoints,
times and volume in each direction — how many rows **on this page** carry a lead flag, and that every
number came from the analysis' indexed tables rather than from dissecting the capture again. The
Re-read control in the panel header is the one exception to that sentence, and it says so.

### The detail panel

Selecting a row sets `sel` and opens **SSH session** below the table. It re-reads that one session on
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
* **the `detail` keys**, in the order the extractor wrote them — on this page the banners and the
  algorithm lists, which are the only readable content the protocol offers;
* **the links**, under the label **Check**: the chips the endpoint returns for this row, pointing at
  the packet view and at the pages that hold the same traffic.

The `detail` renderer is **generic**. `SessionDetail` knows how to draw a string, a number, a
boolean, a list of strings, a name-to-count map and a list of records, and it walks the object in the
order the backend wrote it. It never knows which protocol it is looking at, so:

* a key added for a new protocol appears here **without a line of new code**, and a key the browser
  cannot classify is printed as text rather than dropped;
* key labels come from `DETAIL_LABELS`, and a key with no entry falls back to its own name with the
  underscores turned into spaces, so it cannot vanish from the page just because the catalogue has not
  learned it yet;
* the algorithm lists render as wrapped chips, and the message histogram renders as a count map of
  `code ×count` chips sorted by count, with the raw message-type numbers the dissector printed rather
  than names this page would have had to supply;
* a list that hit the contract's cap says so in its own label (`Ciphers, client to server (first 50)`),
  because `SessionDetail` reads the sibling `*_truncated` boolean and shows it beside the list instead
  of as a row of its own.

When the extractor produced no protocol fields at all, the panel says so in one sentence — only the
endpoints, times and volume are known, and nothing is inferred from the port number. That is the row
you get for a capture that caught the TCP connection but none of the identification exchange.

### What the page shows when there is nothing

Four distinct states, and the page does not blur them:

* **No capture selected** — the shared `AnalysisGuard` empty state, pointing at
  [PCAP-Files.md](PCAP-Files.md).
* **The analysis has no protocol rows at all, and the capture is old enough that the extraction stage
  may never have run** — the endpoint returns `extracted: false` and the page shows **This capture has
  not been read for these protocols**, with the **Re-read protocols** button and the explanation that
  an empty table here means the extraction has not run, not that the capture is free of SSH traffic.
  The endpoint's one-sentence `note` is printed below it.
* **No session, no filters** — *"TShark dissected no SSH session in this capture."* followed by the
  honest reading: a session taken mid-flight, a protocol on a non-standard port the dissector was not
  told to read, or traffic inside a tunnel will not appear here.
* **No rows matching active filters** — a different empty state, which says the extraction ran and the
  filters excluded everything it found; when the cause is the **flagged only** box, the title says so
  directly.

## 3. `detail`, per protocol

SSH is one protocol, so the contract's §3.4 is the whole vocabulary. A key is present **only when the
capture yielded it**: the extractor must not emit a key it could not fill, and must not emit a
plausible-looking value. A session whose handshake was missed therefore has banners but no algorithms,
or no keys at all.

| Key | Type | What it holds and why it is on the row |
|---|---|---|
| `client_banner` | string | The client's identification string, as sent — the `SSH-2.0-...` line. It is software identifying itself, which is the only place this page learns what the client was, and the most common starting point for judging whether both ends are what the estate expects. |
| `server_banner` | string | The server's identification string. Same value, other side: an outdated build, a vendor string or a banner that has been changed on purpose all show up here. |
| `kex_algorithms` | string[] | The key-exchange algorithms offered. This is the readable half of the negotiation, and what tells a modern client from a legacy one. |
| `server_host_key_algorithms` | string[] | The host-key algorithms offered. It says which host keys the server was prepared to present, which is the question behind "is this host still offering a weak key type". |
| `encryption_client_to_server` | string[] | The ciphers offered in that direction. The two directions are recorded separately because the negotiation is per direction, and a one-way list is itself a finding-shaped fact. |
| `encryption_server_to_client` | string[] | The ciphers offered in the other direction. |
| `mac_client_to_server` | string[] | The MACs offered in that direction. MAC choice is where weak integrity protections survive longest in a legacy estate. |
| `messages` | `{message_code: count}` | The message-type histogram — `20` KEXINIT, `30` KEXDH_INIT and so on — with how often each appeared. It is the shape of the handshake: which phases happened, and whether the session got past the key exchange at all. |

Two things are deliberately not in that table, and the contract says so explicitly rather than
leaving a silence: there is no key for commands, file names or passwords, because those are inside
the encrypted channel; and there is no key for the authenticated user, for the same reason. The
catalogue's scope note states both, so a reader is not left to wonder whether the extractor simply
failed.

## 4. What the flags mean

Three of the shared catalogue's flags apply to this family, in the catalogue's own words from
`SESSION_FLAG_CATALOG` in `sessionCatalog.ts`. A flag is written into the row's `flags` array by the
extractor when the session is analysed; no page recomputes it, and the shared convention is a bare
`code` or `"code: detail"` where the detail is the measurement the flag rests on.

| Flag | The catalogue's meaning, and what it does not prove |
|---|---|
| `unusual_port` | "The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol's own content is what makes the session that protocol at all." SSH's expected port is `22`, so a session whose server side is not on it is flagged even when TShark dissected it as SSH — which is the useful part: the dissector recognised the protocol, so the port was not what made it SSH. |
| `large_transfer` | "The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading." On SSH this is the only volume signal the page has, because the content is encrypted: the direction and the peer are the only context that exists. |
| `long_session` | "The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this." |

Several of the catalogue's flags are **not** applicable here, and their absence from a row is not an
observation: `cleartext_credentials`, `cleartext_username` and `no_encryption_upgrade` are the
contract's flags for the mail and FTP families, `anonymous_login` belongs to FTP and SMB,
`legacy_dialect` and `signing_not_required` to SMB, `media_without_signalling` to the VoIP family,
`auth_failures` reads rejected replies the SSH channel never shows in the clear, and `many_commands`
needs a command list this protocol does not expose. A row with no flags means the extractor saw
nothing worth flagging in the fields it can read — endpoints, volume, duration and the plaintext
handshake — which is a much thinner set of fields than any other family on this page has.

At most ten flags are kept per session, most serious first — the contract's `FLAG_CAP` — and the
detail half of each string quotes the count or value that produced it.

**A flag is a lead, not a verdict.** Every entry above states why the pattern is worth reviewing *and*
what legitimate traffic looks like the same way; the page says it in the legend, in the detail panel
and in its own empty states. Because SSH's readable surface is so small, this page's flags are the
thinnest evidence in the set: a quiet SSH row is quiet about the capture, not about the session.

## 5. Limits and honest caveats

* **Everything after the key exchange is encrypted, and it stays that way.** No command, no file name,
  no password, no authenticated user name and no port-forward target is available on this page, and
  none of it is guessed at from the banner or the volume. This is the honest centre of the section: a
  banner and an algorithm list are what a capture can lawfully say about an SSH session.
* **Authentication outcomes are usually invisible.** The method and the result travel inside the
  encrypted channel, so a session that authenticated and one that was rejected on the third attempt
  can be identical rows here. There is no `auth_failures` flag on this family because there is no
  readable rejection to read.
* **A banner is a claim, not a fact.** `client_banner` and `server_banner` are strings the peers chose
  to send. Banners are configurable, spoofable and sometimes absent; a version in a banner is a
  version the software asserts, not one the capture verified.
* **Algorithm lists are what was offered, not what was chosen.** The `kex_*`, `encryption_*` and
  `mac_*` lists are the offered sets the dissector produced. The negotiated selection is inside the
  encrypted exchange, so a row can show a modern list and still have ended up on a weak choice — the
  page does not claim otherwise.
* **No stream, no row identity.** Where TShark reported no stream, the session is keyed on its
  endpoints and its start time rather than a stream id, and the detail panel says `stream not reported
  by the dissector` in place of a stream number.
* **The capture decides what exists.** A connection caught after its identification exchange, an SSH
  listener on a non-standard port the dissector was not told to read, or SSH inside a tunnel the
  dissector did not decode appears as no session at all. A capture that ends mid-session shows the
  handshake and nothing after it. The empty state says exactly this rather than implying the traffic
  was clean.
* **A capture indexed before this section existed holds no rows.** The extraction runs as a pipeline
  stage, so older analyses report zero sessions until they are re-read with the control on the page —
  which is why `extracted: false` and **Re-read protocols** exist instead of a silent empty table.
* **The table is capped and paged.** At most `SESSION_CAP` sessions are read for one request, the
  contract caps `page_size` at 1000, and `LIST_CAP`, `COMMAND_CAP` and `COUNT_CAP` bound every list
  and count map in `detail`. A capped list says so on its own label, so a truncated algorithm list is
  visible rather than plausible.
* **A session is not a person.** One address running many SSH sessions is a busy host or a jump box,
  not a user; nothing here is correlated across captures, and no session is attributed to an identity
  the wire did not carry.
* **The thresholds are constants of this build.** The legend's wording calls them configurable; in
  this build they are the values in [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) §6, and changing one
  means changing the code and re-reading the capture.

## 6. The endpoint

Everything on this page comes from one analysis-scoped resource. The full parameter table, the
envelope and the error codes are the contract's §5; what follows is the part a reader of this page
needs.

| Parameter | What the page sends |
|---|---|
| `family` | Always: `ssh`. The endpoint expands it to this family's protocols, which here is the single value `ssh`. |
| `protocol` | Never. The control is drawn only for the families that cover more than one protocol, and SSH is not one of them. |
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

[Email.md](Email.md), [FTP.md](FTP.md), [VoIP.md](VoIP.md) and [SMB.md](SMB.md) are the other four
pages of the same component and the same table; [TLS.md](TLS.md) is the other section whose payload
this app never reads, and it answers the handshake questions for the encrypted protocols that present
a TLS handshake. The frames and streams behind a row are on [Packets.md](Packets.md) and
[Conversations.md](Conversations.md), the client and server addresses belong to [Hosts.md](Hosts.md),
and content this section cannot show because it is encrypted may still be recoverable from the
capture as an object on [Files-and-Objects.md](Files-and-Objects.md) if the application can carve it
at all. The section index is [README.md](README.md), the endpoint is registered in
[Reference/API.md](Reference/API.md), and the normative rules for the table, the `detail` keys, the
flags, the caps and the limits are [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md).
