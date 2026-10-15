# Users & Passwords (`/credentials`)

The cleartext credentials a capture carried — usernames, passwords, API keys, bearer tokens and
other secrets the dissectors could read off the wire — with every value redacted to a preview
until one row at a time is deliberately revealed, and with the scanner's own on/off state and
limited reading scope stated on the page rather than left to be inferred.

It is reachable at `/credentials`, under **Investigate** in the left-hand navigation, after
[Threat Map](Threat-Hunt.md), [Hunt](Investigate.md) and [Files and Objects](Files-and-Objects.md),
and it is the **Users & Passwords** item in the sidebar. The section's id is `credentials` and this
document's file name is `Credentials.md` — the feature is credential discovery, and the visible name
is what the wire actually carried. The normative contract for it — where the scanner reads, what it
looks for, how it scores what it finds, the endpoints that serve it and the limits it states — is
[`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md); this document describes the page as built against
it and does not restate the contract.

---

## 1. What it is for

The page answers one question in two halves: **did anything in this capture cross the wire in a
form a reader could have read, and what exactly did it say?** The first half is a summary and a
filterable evidence list; the second is a per-row **Reveal** action that fetches the stored value
for that row alone. Around both, it answers a third question that decides how to read the first
two: **was this capture even looked at?** The credential stage is switchable
([`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §7), and only the protocols an operator selected
are read, so an empty table can mean three different things — the stage is off, no protocol is
selected, or the scanner read faithfully and found nothing in the locations it can reach. The page
distinguishes all three, and never presents an empty table as a capture free of credentials.

## 2. What is on the screen

The page is wrapped in `AnalysisGuard`, so with no capture selected — or while one is still being
analysed — it shows the usual "no capture selected" or progress state instead of an empty list. The
layout is a row of summary tiles, a scan-state panel, a collapsed caveat panel, and then the
findings panel with its filter strip, table and pagination.

### 2.1 Summary tiles

Seven `StatCard` tiles in a `grid-cols-2 md:grid-cols-4 xl:grid-cols-7` grid, all of them read from
`GET /api/analyses/{analysis_id}/credentials/summary` and none of them from the rows on screen:

| Tile | Figure | Meaning |
|---|---|---|
| Findings | `total`, or the sum of `by_kind` when the response states no total | Every credential row this analysis holds, unfiltered by the table's filters |
| Streams involved | `stream_count`, or the length of the `streams` array | One per distinct `(protocol, stream)` pair the findings were recorded in |
| Usernames | `by_kind.username` | Values a location identified as a username |
| Passwords | `by_kind.password` | Values a location identified as a password |
| API keys | `by_kind.api_key` | Values a location identified as an API key |
| Bearer tokens | `by_kind.bearer_token` | Values a location identified as a bearer token |
| Other secrets | `by_kind.other_secret` | Secrets an `Authorization` scheme or a malformed Basic header yielded without naming the role |

A figure the response does not carry is an em dash (`—`), never a zero: "the endpoint did not say"
and "the scan found none" are different statements. The Findings tile is the one figure the page
will derive, and only in the arithmetic-safe direction: every row has exactly one kind, so the sum
of the kinds the endpoint did send is the same total the endpoint would have stated. It is never
borrowed from the filtered table total. The Streams tile states what it counts — a *pair* of
protocol and stream, so a stream id used by two protocols counts twice — and names the busiest
pairs in its tooltip, read from the endpoint's own `streams` array.

Under the tiles:

* a **Confidence** strip — `high`, `medium` and `low` chips with the counts from `by_confidence`,
  each clickable to filter the table on that level (clicking the active one clears the filter), and
  each carrying its §4 rule in the tooltip. A level the response omits reads `—`.
* a **Protocol** strip — the five protocols with the counts from `by_protocol`, each clickable to
  filter on that protocol, so the breakdown the contract asks the summary for is reachable without
  opening a dropdown. Drawn only when the response carries protocol counts.
* a **Secret shapes matched** line, drawn only for the shape kinds (`aws_access_key`, `jwt`,
  `pem_private_key`, `github_token`, `slack_token`, `google_api_key`, `stripe_key`) the endpoint
  counted above zero. The seven are what [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §3.3's
  patterns recognised inside a value, which is a different kind of statement from "a field called
  `password` held this", and the page keeps them visually separate for that reason. The endpoint
  reports a count for every kind, zeroes included; seven chips reading `0` would be noise rather
  than information, so a shape kind appears only when it matched something.
* the summary endpoint's own `note`, when it sent one.

### 2.2 Scan state

The panel directly under the tiles reports the setting's current state and what the stage's last
run did, because between them they decide what an empty table means. It is the house label/value
grid (`DetailGrid` / `DetailItem` from `components/protocols/ProtocolDetail.tsx`), so a figure the
block does not carry is that component's own em dash with the reason in its tooltip — never a zero
and never an invented default. Five states, and they are not interchangeable:

| State | What the page draws |
|---|---|
| `scan.enabled` is `false` | A **Users & Passwords discovery is switched off** panel rather than the grid: the stage writes no rows while it is off, the rows that do exist were written at `rows_written_at`, an empty table would mean the scanner looked at nothing, and the setting is one link away. The **Scan now** control is disabled and its tooltip names `409 credential_scan_disabled` as the reason |
| Enabled, `scan.protocols` is empty | The grid reading `Discovery: enabled` and `Protocols inspected: none selected`, the last scan time, and a warning that an empty table is the expected result of that setting |
| Enabled, `stage_ran` is `false` | The same grid reading `never run for this analysis` in place of a scan time, plus a warning that this is a statement about the analysis rather than about the capture |
| Enabled, `stage_ran` is `true` | The same grid reading `enabled`, the protocol names (`HTTP · FTP · SMTP · POP3 · IMAP`), the timestamp of the run, how many rows that run wrote (`findings`, with the protocols it read in the tooltip) and how many rows the table holds now (`rows`) |
| Neither read endpoint sent a `scan` block | Every figure an em dash — `Discovery` included, so no enabled/disabled state is invented — and a warning that the page cannot tell whether discovery ran for this analysis, so the table below is reported as what the endpoint returned and nothing more |

The panel never upgrades an unknown to an enabled, and never reports a missing timestamp as a
timestamp: `stage_ran: false` is "this analysis has never been read", which is a different
sentence from "the run recorded no time".

### 2.3 Caveat panel

A `ScopeNote` — a `help-panel`-styled card with the light-bulb mark, a muted body face and the
section-hue tick removed, so it cannot be mistaken for data — **collapsed by default**, exactly as
the Threat Map and the five protocol pages use the same component. Collapsed it shows one line of
its title; opened it states the contract's §10 limits:

* what the page does read: HTTP `Authorization`, `Cookie`, URL query and form or JSON bodies, the
  FTP `USER`/`PASS` commands, the SMTP, POP3 and IMAP authentication commands, and the Base64
  fields a protocol says are Base64;
* **encrypted traffic is not examined at all** — TLS, HTTPS, SSH, SMB signing, `AUTH TLS`,
  STARTTLS and `STLS` sessions, and anything on 443, 465, 993, 995 or 22. This build never
  decrypts, so a credential inside those sessions is unreachable, which is not the same as absent;
* **only what the earlier analysers kept**: bodies are read from the stored previews
  (`MAX_BODY_CHARS` = 262,144 characters per body) and commands from the stored command lists, and
  a stored value longer than `MAX_VALUE_CHARS` = 512 characters is truncated with the row saying so;
* **Base64 is encoding, not encryption** — which is why Basic and `AUTH LOGIN` are readable here;
* **a shape is not proof the credential works**: an `AKIA…`-shaped string is an AWS access-key
  *identifier*, the matching secret is not in it, and patterns only fire on values a field name
  already selected, so a secret pasted into an unlabelled body is scored `low` or not reported;
* **a finding is a lead, not a verdict**: a value in a field called `password` crossed the wire; it
  is not proof that it worked, that it is current, or that it is not a test value.

Its standing caveat adds §7's switch and §9's cap: the scan is off-switchable and the page reports
the switch above the table, and at most 200 findings are stored per analysis, highest confidence
first, so a capture with more than that is stored partially as well as read partially.

### 2.4 The findings table

Panel title *Credential findings*. The subtitle states the number of matching rows, whether filters
are active, and whether the response carried full values or redacted ones — `reveal` is in the
envelope for exactly this reason. The header also carries **Scan now** (§5). Nothing in this table
is a private copy of a shared component: the cells are `MonoCell` and `AddressFlag`, the pagination
is `Pagination`, the filter strip is `FilterStrip` and its controls, and the notices are
`SectionNote`.

| Column | Contents |
|---|---|
| kind | The kind the scanner recorded, labelled (`password`, `bearer token`, `AWS access key`, …). The tooltip adds how it was derived (`basic_decode`, `form_field`, `command_arg`, `pattern`, …), when the row was written — the time of the scan, not of the traffic — and the backend's one-sentence `note` when there is one |
| value | The redacted **preview** (`value_preview`), the stored value's length in characters, a `truncated` chip when `value_truncated` is set (with the `MAX_VALUE_CHARS` cap in its tooltip), and this row's **Reveal** control — see §4 |
| protocol | A chip linking to that protocol's own page: `HTTP` → `/http`, `FTP` → `/ftp`, and `SMTP`/`POP3`/`IMAP` → `/email` |
| confidence | `high`, `medium` or `low`, with §4's rule for the level in the tooltip. The level is the one the scanner stored; the page never re-scores a row |
| location / field | `location` in monospace (for example `authorization_basic`, `json_body`, `ftp_pass_command`) with the `source_field` that selected it underneath, or `—` when no field name vouched for the value. The tooltip carries the location, the field, the derivation method and the backend's note |
| stream | `tcp #36`, linking to `/conversations?stream=<transport>:<stream_id>&tab=timeline`, the application's conversation deep link. The key is built by `conversationUrlKey` from `components/findings/FollowConversationButton.tsx` — the module that owns the `transport:stream_id` form — so this page's link cannot drift from the Findings page's *Follow conversation* button or the Dashboard's destination panel. The tooltip says which direction the value was recorded in. `—` when the row records no transport or stream, because there is nothing to open |
| client → server | `client_ip:client_port → server_ip:server_port`, each endpoint carrying the `data-ip`, `data-ip-port`, `data-ip-transport` and `data-ip-stream` attributes, so the application-wide right-click menu applies to either address and to this row's conversation. Beside each address is the shared `AddressFlag` (`components/AddressFlag.tsx`): the local-machine icon when the address falls in an internal block per `utils/privateIp.ts`, otherwise the country's flag — and nothing here, because a credential row records no country, so there is nothing to draw a flag from and no placeholder is invented |
| packet | `#1450`, linking to `/packets?sel=1450` — the packet browser's own selection key. When the source row recorded a different `packet_last`, the tooltip names it. `—` when no frame was recorded |
| evidence | One redacted line of context from the backend (for example the header line), truncated to 320 px with the full text and the note in the tooltip |

Below the table: the pagination footer (page sizes 50 / 100 / 250 / 500 / 1000), a note stating
that every number is read from this analysis' credentials table — the capture is not dissected
again to draw the page — that values are redacted to a preview, that **Reveal** fetches one row's
value and nothing else, and that the confidence shown is what the scanner stored. When the summary
endpoint sends its `limits` list — the scanner's own notes on what it had to interpret in the
contract — those are printed verbatim under the table rather than paraphrased, because a reader
comparing the page against [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) should see the build's
reading and not a component's summary of it.

### 2.5 The filters

A `FilterStrip` above the table, with every filter in the URL (see §3.1):

| Control | Behaviour |
|---|---|
| kind | Dropdown of the kinds the summary actually counted, labelled; the full §6 vocabulary is offered when the summary has not answered. `all kinds` clears it |
| protocol | `all`, `HTTP`, `FTP`, `SMTP`, `POP3`, `IMAP` — the five protocols §2 can read |
| confidence | `any`, `high`, `medium`, `low` (the same filter as the confidence chips) |
| stream | Exact `stream_id`, typed. Only rows the conversation reassembly could tie to a stream carry one |
| Sort | `confidence` (the endpoint's default), `kind`, `protocol`, `found at` (`created_at`), with the `asc`/`desc` toggle beside it |
| Reset filters | Drops every *filter* from the URL and leaves view state alone |

An empty table with filters active says the scanner ran and the filters excluded what it found, and
offers the reset control. An empty table with no filters says one of four things instead, in this
order of precedence: the scan is switched off; no protocol is selected, so nothing was read; **the
stage has never run for this analysis**, so nothing has been read yet and the control that fixes it
is on the panel above; or the scanner read the locations it can reach and found no visible
credential there.

## 3. Where the data comes from

Page component `frontend/src/pages/CredentialsPage.tsx`; the API client is `credentialsApi` in
`frontend/src/services/api.ts`. The response types are `CredentialsListResponse`,
`CredentialsSummaryResponse`, `CredentialFinding`, `CredentialScanState`, `CredentialStreamGroup`,
`CredentialCounts`, `CredentialScanResult` and `CredentialListParams` in
`frontend/src/types/index.ts`. Every piece of
furniture on the page is a shared component rather than a private copy: `Page`, `Panel`, `StatCard`,
`Pagination`, `MonoCell`, `EmptyState`, `ErrorState`, `LoadingState`, `AnalysisGuard`, and
`DetailGrid` / `DetailItem` / `ScopeNote` / `SectionNote` from
`frontend/src/components/protocols/ProtocolDetail.tsx`; the filter strip and its controls
(`FilterStrip`, `TextFilter`, `SelectFilter`, `SortSelect`, `ResetFiltersButton`, `useUrlFilters`)
from `frontend/src/components/protocols/ProtocolFilters.tsx`; `conversationUrlKey` from
`frontend/src/components/findings/FollowConversationButton.tsx` for the stream key; and
`frontend/src/components/AddressFlag.tsx` for the icon beside each address (extracted from
`components/hosts/HostsTable.tsx`, which needed the same mark, so it lives in one place rather than
two). The page's own stylesheet rules are `.cred-value` and `.cred-value-preview` in
`frontend/src/index.css`.

| Call | When | Notes |
|---|---|---|
| `GET /api/analyses/{analysis_id}/credentials` | On load and on every filter, sort or page change | Reads the `credentials` table. The envelope carries `items`, `total`, `page`, `page_size`, `reveal`, `scan`, `counts` (over the same filters) and `note` |
| `GET /api/analyses/{analysis_id}/credentials/summary` | Once per analysis, on load | Every figure in the tiles, the protocol strip and the whole scan state, plus the scanner's `limits` notes. No values at all, not even previews |
| `GET /api/analyses/{analysis_id}/credentials?reveal=1` (narrowed) | Only when a row's **Reveal** is pressed, once per row | See §4 |
| `POST /api/analyses/{analysis_id}/credentials/scan` | **Scan now** | Answers `202` with `{job_id, kind, status}`; `409` when the analysis is not ready and `409 credential_scan_disabled` when the setting is off. It is gated on the retained capture like every other rescan, so a purged upload answers `410` |

The queries are held under the react-query keys `['credentials', analysisId, params]`,
`['credentials-summary', analysisId]` and `['credential-value', analysisId, id, kind, protocol,
confidence, stream_id]`. A rescan invalidates the first two. On the backend the stage is
`backend/app/services/credential_analyzer.py` and the endpoints are
`backend/app/api/routes_credentials.py`; the scanner makes no capture pass of its own — it reads
the rows `http_transactions` and `protocol_sessions` already hold
([`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §2).

### 3.1 URL parameters the page reads

The URL is the whole view, as on every other page: a filtered table is a link that can be pasted
into a ticket.

| Parameter | Accepted values | Default when absent or invalid |
|---|---|---|
| `kind` | A kind from §6 (`password`, `bearer_token`, `aws_access_key`, …) | no filter |
| `protocol` | `http`, `ftp`, `smtp`, `pop3`, `imap` | no filter |
| `confidence` | `high`, `medium`, `low` | no filter |
| `stream` | A positive integer, sent as `stream_id` | no filter |
| `sort` | `confidence`, `kind`, `protocol`, `created_at` | `confidence` (anything else falls back to it) |
| `order` | `asc` for ascending, anything else descending | `desc`, always sent |
| `page` | Positive integer | `1` |
| `page_size` | A positive integer; the footer offers 50, 100, 250, 500, 1000 | `100` |

A working example: `/credentials?kind=password&confidence=high&stream=36&sort=kind&order=asc`.

### 3.2 What the reveal request asks for

The full value is served only when the request asks for it, and the endpoint has no per-row
parameter, so a reveal narrows the request to everything the row already fixes — its `kind`,
`protocol`, `confidence` and `stream_id`, plus `reveal=1` — and the page renders the item whose `id`
matches. Nothing else about the table changes: the list request the page always sends carries no
`reveal`, so no full value is in the response behind the table. The detail is in §4.

## 4. Redaction and reveal

Redaction is the default and reveals are per row, because the contract says so
([`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §5) and because a screen full of working
credentials is a worse artefact than a screen full of leads.

* **What every list response carries** is `value_preview`: the value with its middle removed. The
  page draws that preview in the muted shade (`.cred-value-preview`) so it does not read as the
  value, and shows the stored length beside it. The full value is not in the JSON, so it cannot be
  in the markup — including in a tooltip or an attribute — and the scratch harness asserts exactly
  that against fixture values.
* **Reveal** on a row issues one request with `reveal=1` and draws the answer in the foreground
  monospace face (`.cred-value`) with a **Hide** control. Its tooltip says that this is the value as
  it crossed the wire and that captured content is exact without being proof it works.
* Revealed values are cached under their own query key (with an infinite stale time), so hiding and
  showing the same row again costs nothing, and turning the page does not re-fetch them.
* A reveal that fails says so beside that row and keeps the preview; a reveal whose response does
  not include the row's value says that too, and substitutes nothing. The page never falls back to
  a whole-table revealed fetch.
* An opened row does not stay open when the table is re-filtered or the page is changed: the state
  belongs to the mounted row, and a new row starts closed.

## 5. The scan control

**Scan now** in the findings panel header calls `POST /api/analyses/{analysis_id}/credentials/scan`
and reports the `202` the way the protocol pages report their rescan: `Credential scan started as
job <job_id> (<status>)`, followed by a sentence that the stage re-reads the stored rows in the
background, rewrites only the `credentials` table, and that the list refreshes when it finishes. A
failure renders as the shared error state, so the operator sees the backend's own code — in
particular `credential_scan_disabled` — rather than a generic failure.

The button is disabled in two cases, and its tooltip says which: while a scan is in flight, and
while `credential_scan_enabled` is off, because the backend would answer `409
credential_scan_disabled`. The disabled-scan panel in §2.2 carries the same control, so the way out
of that state — turn the setting on at `/settings`, then scan — is on the screen.

A rescan is **not** a new capture pass. It re-runs the credential stage over the rows the other
analysers already wrote, so it can never discover a credential the earlier stages did not record,
and it changes no other table. Re-running the whole pipeline, or raising the body-preview limit,
belongs to the pages that own those stages.

## 6. Links into the rest of the app

| Element | Opens |
|---|---|
| A row's stream (`tcp #36`) | `/conversations?stream=<transport>:<stream_id>&tab=timeline` — the conversation deep link the Findings page and the Dashboard's destination panel use, so the flow highlights the right band and opens its timeline — see [Conversations](Conversations.md) |
| A row's packet (`#1450`) | `/packets?sel=<frame>` — the packet browser's own selection key, which opens the frame's dissection — see [Packets](Packets.md) |
| A row's protocol chip | `/http`, `/ftp` or `/email` — the protocol page for the rows this credential was read from — see [HTTP](HTTP.md), [FTP](FTP.md) and [Email](Email.md) |
| Either endpoint address | Nothing by click; a right-click opens the application-wide address menu (Hunt pivot, Conversations, Wireshark), because the cell carries `data-ip` and the row's transport, stream and port with it |
| The disabled-scan panel and its empty state | `/settings`, where the switch and the protocol selection live — see [Settings](Settings.md) |
| The **Scan now** control | Nothing navigational; it starts the job and the table refreshes in place |
| A filter, sort or page change | The same page, re-queried through the URL |

Inbound: the **Credentials** item in the sidebar, present on every page. Nothing else in the
application links here yet; the [Hunt](Investigate.md) page answers a related question for one
entity (its "Clear-text credentials" tile reads credential keywords in an address's own HTTP
requests), but it is a separate computation over a different table and the two are not substitutes.

## 7. Limits and honest caveats

* **A finding is a lead, not a verdict.** This is the first bullet of
  [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §10 and the page states it in the caveat panel. A
  value in a field called `password` is a credential the capture carried; whether it worked, whether
  it is current and whether it is a test value are all outside what this page can know.
* **Encrypted traffic is not examined at all.** TLS, HTTPS, SSH, SMB signing, STARTTLS and `STLS`
  sessions, and anything on 443, 465, 993, 995 or 22, are never decrypted by this build. Nothing on
  this page implies such a session holds no credentials, and the disabled and empty states say so
  in as many words.
* **Only what the other analysers kept.** The scanner reads stored rows: HTTP body previews
  (`MAX_BODY_CHARS` = 262,144 characters) and the per-session command lists. A credential in a body
  the earlier stage truncated, or in a session the protocol analyser did not classify, cannot be
  found here — and the page cannot tell the difference between "not present" and "not recorded".
* **The reveal is narrowed, not addressed by id.** The contract's list endpoint offers `kind`,
  `protocol`, `confidence`, `stream_id` and `reveal`, but no row id, so a reveal asks for the
  narrowest page the row's own dimensions allow and then renders the matching item. A capture with
  many findings in one stream therefore answers a reveal with a page of rows whose values travel
  over the local API; only the requested row's value is rendered, and the row says so when its
  value was not in the answer.
* **Values are stored as the wire carried them, and the page cannot verify them.** A password the
  application hashed after sending it is still reported as sent; a token that expired a minute
  later is still reported as present. Nothing here validates a credential — §3.3's shapes are
  shapes, not checks — and nothing tries it anywhere.
* **`value_length` is the stored length, not the wire length.** A value longer than
  `MAX_VALUE_CHARS` = 512 characters is stored truncated, `value_truncated` is set, and the page
  says so on the row; the full value is not recoverable from this build.
* **Tiles describe the analysis, the table describes the filters.** The tiles are unfiltered by
  design, so with a filter active the two legitimately disagree; the table's subtitle says when a
  filter is responsible. A figure the summary endpoint does not state is an em dash, and the page
  does not fill it in from the filtered table.
* **The summary endpoint's stream figure counts pairs.** `stream_count` is one per distinct
  `(protocol, stream_id)` pair the findings were recorded in, so a stream id that carried both HTTP
  and FTP findings counts twice. The `streams` array behind it names each pair and its finding
  count; the tile says so in its tooltip, and the page reads the scalar first and the array's length
  second, so either spelling yields a real figure.
* **The page shows no more than the contract stores.** At most `MAX_FINDINGS` = 200 findings are
  stored per analysis, highest confidence first, so a capture with more credentials than that is
  reported partially; the caveat panel states the cap, and the page has no control that can raise
  it. There is no export and no copy button here on purpose: a revealed value is captured content
  and the page does not help it out of the interface.
* **The scan state is only as good as the response.** If neither read endpoint returns a `scan`
  block the page reports the state as unknown rather than assuming the default, and it keeps
  `enabled`/`disabled` out of the markup in that case. `stage_ran: false` is drawn as *never run for
  this analysis* — the analysis is simply older than the stage or had it skipped — and a missing
  timestamp alone is drawn as *no time recorded*. Those are three different sentences and the page
  never merges them.
* **The `limits` notes are the scanner's, not the page's.** The summary endpoint's `limits` list is
  printed verbatim. It is a statement about how this build read the contract's ambiguities, not a
  list of caps, and a build that has resolved one of them differently would say so there.
* **The Settings block reports what the settings API exposes.** The credential switch and protocol
  list are saved through `PUT /api/settings`, so a backend that does not return
  `credential_scan_enabled` and `credential_protocols` gets a block that says it cannot show or
  change them; the page does not display the contract's defaults as if they were this
  installation's configuration. When the payload carries `credential_protocols_available` the block
  offers that list rather than its own copy of the five, and a save writes the response's settings
  view into the settings query, so the controls show what the server actually stored.
* **Nothing is revealed by rendering, by filtering or by paging.** The `/credentials` URL never
  carries a full value and there is no "reveal all" control; the harness that renders this page
  asserts that the fixture's full values appear nowhere in its markup.

## 8. Related

[`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) is the normative contract for this page, and
[Reference/API.md](Reference/API.md) lists the REST surface it calls ·
[Settings](Settings.md) for the switch and the protocol selection this page reads back ·
[Findings](Findings.md) for the `http_cleartext_credentials` and `indicator_match` alerts, which
are the detection engine's separate, behavioural view of exposed credentials ·
[HTTP](HTTP.md) for the transactions the HTTP locations are read from, and [FTP](FTP.md) and
[Email](Email.md) for the command locations · [Conversations](Conversations.md) and
[Packets](Packets.md) for the stream and frame links every row carries ·
[Files and Objects](Files-and-Objects.md) for the other artefacts carved out of the same traffic ·
[Investigate](Investigate.md) for the one-entity view of clear-text credential keywords ·
[Architecture](Architecture.md) for the pipeline stage that writes the table.
