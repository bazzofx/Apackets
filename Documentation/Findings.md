# Findings (`/findings`)

The alert workbench: a triage list on the left, and for the selected finding a seven-tab detail
view that ties the alert to the frames that triggered it, when its activity happened, the
conversation they belong to, the application-layer records, any recovered files and the findings
that share its artefacts.

---

## 1. What it is for

The page answers two questions in sequence. First, **what fired in this capture, and which of
it matters most?** — a filterable list of every finding the analysis recorded, ordered by
severity. Second, for one finding: **why did it fire, where did it happen, and what else do I
know about it?** The right-hand pane gathers the finding's own text, the endpoints and ports it
involved, the exact evidence the analyser recorded, a timeline of when each recorded event
happened, the packets themselves, the reassembled conversation with TShark's follow output, the
HTTP/DNS/TLS rows on those streams, the files carried over them, and other findings that share
an address, name, URI or frame. A finding is presented throughout as a lead to check rather than
a verdict, and the page carries that sentence itself in the Overview tab.

## 2. What is on the screen

The page is wrapped in `AnalysisGuard`. The layout is a toolbar on top, then two columns: the
triage list (22 rem `xl` column) and the detail workbench.

### 2.1 Toolbar

| Control | Behaviour |
|---|---|
| Severity chips: `all`, `high`, `medium`, `low`, `informational` | Sets the severity filter; the active chip is highlighted. Each chip shows a count |
| Search box | Substring match on title, reason, description and rule id. Matched literally (LIKE wildcards escaped), applied on the backend |
| Rule dropdown | `all rules`, then **every built-in detection rule** in the catalogue with its hit count for this analysis. It does not list `suricata:<sid>` rules — see §6 |
| **Suricata only** | Client-side filter: keeps only findings whose `rule_id` starts with `suricata:` |
| **Refresh** | Reloads the findings list |
| **Re-run rules** | Runs `POST /findings/rescan` and then `POST /suricata/run`, described in §4.6. Shows *"Re-running…"* while in flight |

The counts on the severity chips come from the API's `counts` object, which is a
`GROUP BY severity` over **every** finding in the analysis regardless of the active search or
rule filter; the `all` chip is the sum of the four. The number in the list panel header
(*"N total"*) is the filtered total, so the two can legitimately disagree.

After a re-run, one line appears under the toolbar:
*"Re-ran N built-in rule(s) → M finding(s); Suricata matched K rule(s) → J finding(s)."*
It can be dismissed. A failed re-run shows the shared error state instead.

### 2.2 Triage list

A virtualised list, one row per finding: severity badge, rule id, a packet count when the
finding recorded frames, and the title (clamped to two lines). The selected row is
highlighted. A footer reads *"N of M findings"* — the number loaded versus the filtered total.
An empty list says to adjust the filters or re-run the rules, and states that an empty list
means no rule matched rather than that the capture is clean.

Keyboard: `j` / `ArrowDown` and `k` / `ArrowUp` walk the list. The handler ignores keys typed
into an input, textarea or select.

If the URL has no finding id, the page immediately replaces it with the first finding of the
current filter, carrying the current `tab`.

### 2.3 Detail header and tabs

A header row shows the severity badge, the title and the rule id. Below it, seven tabs, each
with a count badge:

| Tab | Badge | Contents |
|---|---|---|
| **Overview** | none | The panels in §2.4 |
| **Timeline** | `context.timeline.length` — the number of timeline entries | The alert's activity as a vertical rail, described below |
| **Packets** | `counts.alerting_packets` — the number of frames the finding recorded | The finding's own frames as a table (#, Time, Source, Destination, Proto, Length, Flags, Info) with previous/next buttons, plus the full dissection of the selected frame |
| **Conversation** | `counts.conversations` | One panel per correlated conversation, then one panel per stream with TShark's reassembled content |
| **Application** | `counts.http + counts.dns + counts.tls` | HTTP transactions, DNS queries and TLS sessions on the alert's streams |
| **Files** | `counts.objects` | Extracted files matched to the alert |
| **Related** | `counts.related` | Other findings that share artefacts |

The tab is the only part of the workbench state that lives in the URL (see §3.2).

**Timeline tab.** The alert's activity on a vertical rail, ordered by time: its first and last
alerting packets plus every correlated HTTP, DNS and TLS row, capped at 60 entries. Each entry
shows the clock time (`HH:MM:SS`), a `kind` chip (`packet`, `http`, `dns` or `tls`), a `first` /
`last` marker on the boundary entries, the label (truncated to the row, with the full text on
hover, or *"no label recorded"*) and a `#<frame>` button that opens `/packets?sel=<frame>` when
the entry names a frame. The subtitle names the real span — *"HH:MM:SS → HH:MM:SS"*, then
*"· over `<duration>`"* when the two boundary timestamps differ, then *"· N entries"* — falling
back to *"first and last activity of this alert · N entries"* when a boundary has no usable
timestamp. A timeline with nothing to show says *"No timestamps recorded."*, and when the
60-entry cap bit, a footer reads *"Showing the first 60 of a longer timeline."*

**Packets tab.** The header line reads *"N packet(s) shown [of a cap of C — the rule matched
more] · A alerting packet(s) in the finding"*, so a cap that bit is visible. `A` is the number
of frame numbers the finding recorded, which can exceed the rows drawn. A finding with no
recorded frames says so and explains that some rules describe a host or a summary rather than a
single frame. Selecting a row loads `GET /packets/{number}` and renders the dissection below
the table.

**Conversation tab.** For each correlated conversation: its `conv_id`, `TRANSPORT stream <id>`,
state, protocols and duration, with the A → B and B → A packet and byte splits and the totals.
Then, per stream, a *"Reassembled content"* panel showing the client/server endpoints and a
viewer with client → server / server → client and `ascii` / `hex` / `raw` toggles, the byte
counts, the chunk count and *"showing N of M characters"* (the panel renders at most 20,000
characters). When a stream's content could not be fetched, the panel shows the backend's own
message instead of failing the tab. If no conversation was recorded at all, the tab explains
that the alerting packets are not part of a reassembled conversation.

**Application tab.** HTTP transactions (Time, Method, Host, URI, Status, Req, Resp) with the
selected transaction's request and response headers and bodies below; DNS queries (Time,
Client, Query, Type, Rcode, Answers, Delay, Flags); TLS sessions (Time, SNI, Version, Cipher,
ALPN, Handshake, JA3) with the selected session's certificate, validity window, serial and
fingerprints. Each table holds at most 20 rows. HTTP bodies are previewed at up to 8,192
characters each and say *"truncated for this view"* when they were cut. Encrypted payloads are
never decrypted.

**Files tab.** File, Protocol, Type, Size, Status, SHA-256 (truncated to 20 characters with a
copy button), Link and Download. The Link column states how the file was tied to the alert:
*matched by stream*, *matched by packet*, or *inferred from the request URI* — the last of
which means the object store had no stream or packet link, so the filename was matched against
the request path. Files are matched by `stream_id`, by recorded frame numbers, then by that
filename comparison; the same object is never listed twice.

**Related tab.** One row per related finding: severity, rule id, title and the shared artefacts
(addresses, names, URIs, and the first overlapping frame). Clicking one opens it on the Related
tab.

### 2.4 Overview tab: panel order

The panels appear in exactly this order, top to bottom:

1. **Alert** — **minimised by default**, opened by the *show* toggle in its header (the button
   reads *hide* once open, and reports `aria-expanded`). While minimised its subtitle carries one
   line of the `reason`, so the panel still says what fired without being opened — the subtitle is
   truncated to that single line, with the whole text on hover, and a finding with no recorded
   `reason` has no subtitle at all. Opened, the subtitle switches to `<rule_id> · <severity>`. The
   header also carries the severity badge and a *Copy finding id* button, and the body shows the
   title, the finding's description when it has one, the `reason` text in a monospace block, the
   `recommendation` under a lamp icon, and — for findings whose evidence carries them —
   *"Match basis: … · buffers: …"*.
2. **Endpoints and artefacts** — **one merged card** (*"who was involved, and every address,
   name, port and URI this finding mentions"*) that replaces the two separate cards the tab used
   to draw. It holds two labelled sections, in this order, each introduced by a small uppercase
   label with a rule beside it — the same treatment as the **Rules** divider further down. The
   sections are drawn, not collapsible: both are always open.
   * **Endpoints** — one card per endpoint. The backend returns at most
     `_CONTEXT_CAPS["endpoints"] = 8` of them. When the finding has **exactly one source and
     exactly one destination** the two cards are drawn side by side with a right arrow between
     them; in **every other case** they render as a grid with **no arrow**, including a finding
     whose endpoints are all sources or all destinations, and a finding with a single endpoint.
     Each card shows the direction, a `private` chip when `is_private` is 1, the address (a button
     that opens `/packets?ip=<ip>`), a chip per port (`TRANSPORT/port`, with the local service name
     when the operating system knows it; clicking opens `/packets?ip=<ip>&port=<port>`), the MAC
     with up to two hostnames after it — a line that is absent when the endpoint has no MAC — and
     *"N packet(s) in this alert · host totals X sent / Y received"*. If more endpoints were
     involved than the backend returned, the section says *"More endpoints were involved than are
     shown."*; a finding the endpoint builder derived nothing for says *"No endpoints could be
     derived from this finding."*
   * **Artefacts** — clickable chips for addresses (`/packets?ip=`), names (`/packets?search=`),
     ports (`/packets?port=`) and URIs (`/packets?search=`), built from `finding.entities` exactly
     as before. A row with no values reads *"none"*, and a row of more than 24 values shows the
     first 24 followed by *"+N more"*.
3. **Matched evidence** — drawn **only when `evidence.matches` is non-empty**, and it is the
   panel that carries the **Follow conversation** button. A table of Packet, Where, Buffers,
   Excerpt: the frame number (a button that opens `/packets?sel=<frame>`), the
   `src:port -> dst:port` (or `src -> dst (host)`) description, the buffers the rule matched on,
   and a 120-character excerpt.
4. A **Rules** divider — a labelled rule, not a panel.
5. **Suricata rule behind this alert** — drawn **only for a `suricata:<sid>` finding whose sid
   is still present in `suricata_rules`**. Subtitle: `sid <sid> rev <rev> · <source> ·
   <category>`. Actions: *show rule text* / *hide rule text* (renders the stored signature
   verbatim) and **edit in settings**, which navigates to `/settings?sid=<sid>` — the Settings
   page's rule panel seeds its search box with that sid. Fields: Action / protocol, Classtype,
   Header (`src_net src_port direction dst_net dst_port`), State (`enabled` / `disabled`, plus a
   *"not evaluable by the matcher"* chip whose tooltip names the unsupported options), and the
   reference when the rule has one. The panel is absent for built-in-engine findings and for a
   Suricata finding whose rule has since been deleted.
6. **Scope of this alert** — the **last** card, and its contents are unchanged: the
   definition-list grid of counts (alerting packets, conversations, streams with content, HTTP /
   DNS / TLS row counts, files, related findings, the capture filename, the capture length and the
   first packet timestamp), followed by the analyst caution. The panel repeats the caveat: a
   signature match is a lead, not a verdict.

Two cards that used to sit on this tab are no longer here. The **Timeline** card is the
**Timeline** tab (§2.3), which gives it the full width, and the **Related findings** card is the
**Related** tab, where a list of other findings already belonged — so nothing was lost, each view
simply moved.

### 2.5 The Follow conversation button

One shared component (`frontend/src/components/findings/FollowConversationButton.tsx`) supplies
the button in both places it appears: the **Matched evidence** panel on the Overview tab, and
the panel of the conversation the alert belongs to on the **Conversation** tab (or the first
panel when nothing resolves). Its label is always *"Follow conversation"* and its tooltip names
the exact target — *"Open `<TRANSPORT>` stream `<id>` (`<bytes>`, `<packets>` packets) on the
Timeline tab of the Conversations page, with this conversation selected."* — plus a sentence
when the alert is linked to more than one conversation, naming the one the first matched packet
belongs to. When no conversation can be resolved the button is disabled and the tooltip says to
open a packet number instead.

Clicking it navigates to
`/conversations?stream=<transport>:<stream_id>&tab=timeline` — the value is
`encodeURIComponent`-ed, so `tcp:14` travels as `tcp%3A14`. That is the Conversations flow's own
conversation key, so the flow highlights the right band, selects it, and opens its **Timeline**
tab rather than dropping the analyst on an unfiltered list. See
[Conversations](Conversations.md) and §4.5.

## 3. Where the data comes from

Page component `frontend/src/pages/FindingsPage.tsx`; components under
`frontend/src/components/findings/` (`FindingsList.tsx`, `FindingOverview.tsx`,
`FindingTimeline.tsx`, `FindingPackets.tsx`, `PacketDetailView.tsx`, `FindingConversation.tsx`,
`FindingAppLayer.tsx`, `FindingObjects.tsx`, `FindingRelated.tsx`,
`FollowConversationButton.tsx`, `EntityChips.tsx`). API clients `findingsApi`, `suricataApi`
and `conversationsApi` in `frontend/src/services/api.ts`. The routes are
`backend/app/api/routes_findings.py` (findings, the context endpoint and the alert-to-
conversation linker) and `backend/app/api/routes_suricata.py` (`POST /analyses/{id}/suricata/run`);
the engines are `backend/app/services/detection_engine.py` and
`backend/app/services/suricata_engine.py`, with the rule store in
`backend/app/services/suricata_rules.py`.

| Call | When | Tables read |
|---|---|---|
| `GET /api/analyses/{id}/findings?page=1&page_size=500[&severity=…][&search=…][&rule_id=…]` | On load and on every filter change | `findings` |
| `GET /api/analyses/{id}/findings/rules` | On load (60 s stale time) | `findings` (for hit counts) + `settings.detection_config` |
| `GET /api/analyses/{id}/findings/{finding_id}/context` | Whenever a finding is selected | `findings`, `packets`, `conversations`, `streams`, `http_transactions`, `dns_queries`, `tls_sessions`, `objects`, `hosts`, `analyses` |
| `GET /api/analyses/{id}/packets/{number}` | Selecting a frame on the Packets tab | `packets` |
| `GET /api/analyses/{id}/streams/{stream_id}?mode=ascii\|hex\|raw` | Conversation tab, per stream | `streams`, `packets` + a live TShark `-z follow` run |
| `GET /api/analyses/{id}/objects/{object_id}/export` | The Files tab's download link | `objects` |
| `POST /api/analyses/{id}/findings/rescan` | **Re-run rules** | clears and rewrites `findings` |
| `POST /api/analyses/{id}/suricata/run` | **Re-run rules**, second step | `suricata_rules`, `packets`, `http_transactions`, replaces `findings` rows with `rule_id LIKE 'suricata:%'` |

The context endpoint accepts `packets_limit`, `streams_limit`, `http_limit`, `dns_limit`,
`tls_limit`, `objects_limit`, `related_limit`, `include_follow` and `follow_mode`; the page
never passes any of them, so the defaults apply (see §6).

### 3.1 Evidence and entity shapes

`findings.evidence`, `findings.entities` and `findings.packet_numbers` are JSON text columns.
The route parses them before returning them: `entities` always comes back as
`{ips, hostnames, ports, uris}` (missing keys filled with empty lists), `evidence` as an object,
and `packet_numbers` as a sorted, de-duplicated list of integers.

### 3.2 URL parameters the page reads

The Findings page reads its search parameters **directly** from `useSearchParams`, and it reads
exactly one of them:

| Parameter | Accepted values | Behaviour |
|---|---|---|
| `tab` | `overview`, `timeline`, `packets`, `conversation`, `application`, `files`, `related` | Selects the detail tab; absent means `overview`. Any other value is not recognised and leaves the detail area **empty** (§6) |

plus the route parameter `:findingId` from the path — `/findings/{findingId}` — which is
percent-encoded when the page builds a link (`encodeURIComponent`), because finding ids contain
a colon (`suricata:51000006:2ef66e553fe5`).

**Severity, search, rule id and "Suricata only" are not URL parameters.** They are component
state, so `/findings?severity=high` does not filter anything: the page reads the search string,
ignores the value, and renders the unfiltered list. This matches
[`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §5, which lists `/findings` and `/findings/{id}`
under "path only", and it is why links into this section carry a finding id and nothing else.

## 4. How a finding is built

Two independent producers write into the same `findings` table: the built-in detection engine
(ten rules) and the Suricata-compatible matcher. Both run during analysis — they are the
`detection` and `suricata` stages of the pipeline, after `objects` — and both can be re-run from
this page. Every row they write has the same columns: `id`, `analysis_id`, `rule_id`,
`severity`, `title`, `description`, `reason`, `evidence`, `packet_numbers`, `entities`,
`recommendation`, `created_at`.

### 4.1 The built-in detection engine

`detection_engine.analyze()` reads the **already indexed** tables — `packets`, `dns_queries`,
`http_transactions`, `conversations`, `hosts`, `indicators` — and never re-dissects the capture.
The capture path is used only to report whether the file is still on disk
(`capture_present`). It clears every finding for the analysis first, then runs each enabled rule
in registry order.

Severity is a property of the rule, never of the individual finding (`list_rules` says so in
its own comment), so a rule's severity is fixed and known in advance:

| Rule id | Severity | Default threshold (`settings.detection_config`) |
|---|---|---|
| `tcp_syn_scan` | high | `max_ports` 20, `window_s` 10.0, `syn_ratio` 0.8 — 20 distinct destination ports from one source inside 10 s with at least 80 % SYN-only frames |
| `dns_nxdomain_burst` | medium | `min_nxdomain` 5 |
| `dns_high_volume` | low | `min_queries` 100 |
| `dns_long_labels` | medium | `max_label` 40, `max_name` 100, `max_findings` 40 |
| `http_suspicious_path` | medium | any match in `SUSPICIOUS_PATTERNS` (no numeric threshold) |
| `http_cleartext_credentials` | high | any `SENSITIVE_FIELDS` name visible in plaintext HTTP |
| `outbound_volume` | medium | `max_bytes` 52,428,800 (50 MB) **or** `median_multiplier` 10 × the median sender volume with at least 2 senders |
| `rare_destination_port` | informational | a destination port seen exactly once, outside `COMMON_PORTS`; `max_findings` 40 |
| `repeated_failed_connections` | medium | `min_syn` 10 SYNs to one destination port with no SYN/ACK |
| `indicator_match` | high | traffic matching an analyst-supplied indicator of type `ip`, `domain`, `port`, `ja3`, `ja4`, `ua` or `sha256` |

Thresholds are editable in [Settings](Settings.md) and are read from the `settings` table at the
moment the engine runs, so a rescan uses the current configuration.

Caps applied by the engine: at most `MAX_FINDINGS_PER_RULE = 60` findings per rule per run
(the first 60 produced), `MAX_PACKET_NUMBERS = 50` frame numbers per finding (sorted, de-
duplicated, ascending), and `MAX_ENTITY_VALUES = 25` values per entity list
(`ips`, `hostnames`, `ports`, `uris`, each de-duplicated and order-preserving).

Finding ids are deterministic: `f"{rule_id}:{sha1(json([analysis_id, rule_id, key]) )[:12]}"`,
where the key identifies what the rule found (for example the scanning source address, or
`[uri, packet_number, method]`). Re-running therefore produces byte-identical ids, and the
insert is `INSERT OR REPLACE`, which is what makes repeated runs idempotent rather than
duplicating. A rule that raises is logged and skipped; its failure is reported in the run's
`rule_errors` rather than failing the pipeline.

### 4.2 The Suricata matcher

`suricata_engine` is a **matcher over indexed fields, not the Suricata IDS**: there is no
Suricata binary in this project. Rules are read from the `suricata_rules` table with
`enabled = 1 AND supported = 1`, then compiled. A rule is only ever evaluated when every one of
its options can be honoured:

* `pass` rules are counted and skipped — without a rule engine there is nothing for them to
  steer, and calling them alerts would be wrong;
* a rule whose address or port expressions cannot be parsed is skipped (counted in
  `skipped_unsupported_binding`);
* rules using options the matcher does not implement are stored with `supported = 0` and
  skipped, never partially matched. On the Overview tab, a rule that is stored but not
  supported is labelled *"not evaluable by the matcher"* with the option names in the tooltip.

Evaluation is bucketed by protocol. **Packet-scope** rules are evaluated against every row of
the `packets` index, with buffers built from the dissected fields (`http.uri`, `http.raw_uri`,
`http.host`, `http.method`, `http.status_code`, `dns.query`, `tls.sni`, and a default buffer
joining the frame's `info` and application fields). **HTTP-scope** rules — those whose contents
name an HTTP-only buffer such as `http.header` — are evaluated once per reassembled
`http_transactions` row, where the buffers include headers, request and response bodies, cookie
and status code. A rule with no buffer selector is evaluated against the available text and is
marked `approximate`, both in the rule store and in every finding it produces.

Matches are grouped per rule and per key: `src:port->dst:port` for packet scope,
`src->dst hosturi` for HTTP scope. Each group produces one finding, and a rule produces at most
`max_findings_per_rule` findings (the Suricata configuration's value, default 25). A run first
deletes only this analysis's `suricata:%` rows and then inserts the new ones.

### 4.3 What a rule's `reason` and `evidence` contain

`reason` is prose that states what was observed and what the threshold was; it never asserts a
verdict. Its shape depends on the producer:

| Producer | `reason` contains |
|---|---|
| Built-in rules | The observed numbers, the configured threshold that was crossed, the window or span with epochs, and the counts behind the decision — e.g. a SYN-scan reason names the source, the number of distinct destination ports and addresses, the window duration, the SYN-only frame count and ratio, and both thresholds |
| Suricata matcher | `Suricata rule <sid> (rev <rev>, classtype <classtype>) matched N time(s) in this capture, involving <where>. First match at epoch <t>. Matched on <buffers>. Evaluation basis: <basis>.` followed by the sentence that a signature match is consistent with the described activity but is not proof the traffic was malicious |

`evidence` is a JSON object whose keys differ per producer:

| Producer | Keys |
|---|---|
| Built-in `tcp_syn_scan` | `source_ip`, `distinct_destination_ports`, `distinct_destination_ips`, `destination_ips`, `ports` (`{port, frames}` up to 40), `window_seconds`, `window_start_epoch`, `window_end_epoch`, `frames_in_window`, `syn_only_frames`, `syn_only_ratio`, `thresholds` |
| Built-in DNS rules | Client, counts, distinct name counts, sample query names, resolvers, first/last epoch, threshold (and `rcodes` for `dns_long_labels`) |
| Built-in HTTP rules | `uri` (masked for cleartext credentials), `host`, `method`, `status_code`, matched patterns/categories or the credential field list with value lengths, `stream_id`, `packet_number`, `time_epoch`, `indexed_from` |
| Suricata | `suricata_sid`, `rev`, `action`, `classtype`, `reference`, `rule_source`, `category`, `match_basis`, `approximate`, `buffers`, `matches`, `match_count`, `rule` |

A Suricata finding's `matches` array holds up to 10 entries; each has `packet`,
`response_packet`, `time_epoch`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `host`, `uri`,
`fields` (the buffers that matched), `where` and a 120-character `excerpt`. Hits beyond the
per-key limit are counted in an `extra` field on the first entry that neither the page nor the
`reason` renders, so `match_count` is capped at 10 in practice. `entities` is built from the
matched rows: addresses, hostnames (HTTP host or DNS query name), ports and URIs.

Measured example — the Log4Shell alert in `sf19us-MTA-lab-09.pcap` (analysis
`9e2ef6a921304dc9ac0c739133682641`). The capture holds 40 findings in total: 2 high, 2 medium
and 36 informational. Both high findings are sid 51000006, *"Possible JNDI Injection attack
(Log4Shell), jndi lookup in HTTP header"*, rev 1, classtype `web-application-attack`, source
`bundled:daffainfo http/web-attacks`:

| Finding id | Frames | Reason in one line |
|---|---|---|
| `suricata:51000006:2ef66e553fe5` | `[210]` | Matched 1 time, `10.4.10.132 -> 217.182.138.150 (proforma-invoices.com)`, first match at epoch 1554928674.727, on `http.header`, basis "the reassembled HTTP transaction" |
| `suricata:51000006:e3367f9e77e9` | `[3164, 3295, 3382, 3467, 3582, 3837, 3915]` | Matched 7 times, `10.4.10.132 -> 66.171.248.178 (bot.whatismyipaddress.com)`, on `http.header` |

The two medium findings in that capture come from the built-in engine: one `dns_nxdomain_burst`
(client `10.4.10.132`, 6 recorded frames) and one `outbound_volume`. The other 36 are
`rare_destination_port`, all informational.

### 4.4 How a finding is tied to a conversation

The link is by **recorded frame numbers**, not by address similarity, and it has four steps:

1. **The finding's frames.** `findings.packet_numbers` is a JSON array of frame numbers. The
   built-in engine sorts and de-duplicates them and keeps at most 50; the Suricata matcher keeps
   the first 50 in match order.
2. **Frames → stream ids.** Each frame number is looked up in the `packets` index, which
   records `tcp_stream` and `udp_stream`. A TCP stream id yields the key `tcp:<id>` and a UDP
   stream id the key `udp:<id>`; the backend collects whichever of the two the frame carries
   (usually exactly one), and the frontend picks one by the frame's own `transport`. A frame in
   neither, or a frame number that is absent from the index, yields nothing.
3. **Stream ids → conversations.** A key counts only if a `conversations` row for this analysis
   has the same `transport` and `stream_id`. That pairing — `<transport>:<stream_id>` — is the
   conversation key the Conversations flow uses for its bands and nodes.
4. **Conversations → the detail view.** The context endpoint returns the matched
   `conversations` rows (ordered by `bytes_total` descending) and the `packets` rows themselves,
   and the frontend runs the same resolution once more to pick the single conversation the
   Follow conversation button targets.

If the conversation lookup by stream id finds nothing, the backend falls back to matching the
endpoint quadruples (`src_ip`, `src_port`, `dst_ip`, `dst_port`) of the finding's own packets
against `conversations`, taking at most the first six pairs. Nothing is inferred beyond that.

`unlinked_findings` is the count produced by the endpoint that drives the Conversations flow
overlay — `GET /api/analyses/{id}/alerts/conversations`, in `routes_findings.py`. That endpoint
takes the findings at or above `min_severity` (default `medium`, `source=all` by default) and
counts a finding as **unlinked** when none of its recorded frames resolves to a conversation
the diagram can address: the finding has no frame numbers, its frames are not in the packet
index, or those frames carry no stream id, or no such conversation exists. Those findings get
`linked_by: "none"` and `conversations: []`; every other alert gets `linked_by: "packets"` and
the sorted list of keys it belongs to. The endpoint's own note says unlinked findings are
counted rather than guessed at.

**The Findings page does not call that endpoint.** `unlinked_findings` is reported to the
Conversations page, which draws it in the alert overlay; the Findings workbench reaches the same
conclusion per finding through the context endpoint, showing *"No conversation recorded"* on the
Conversation tab and disabling **Follow conversation**. In `sf19us-MTA-lab-09.pcap` all four
alerts at `medium` and above link cleanly (the two Log4Shell findings to `tcp:14` and to
`tcp:15`, `tcp:20`, `tcp:23`, `tcp:26`, `tcp:28`, `tcp:34`, `tcp:36`; the NXDOMAIN burst to six
UDP streams; `outbound_volume` to `tcp:14`), so `unlinked_findings` is 0 for that capture.

### 4.5 The Follow conversation target

`resolveFollowConversation()` in `FollowConversationButton.tsx` implements the resolution the
button uses, in this order:

1. take `finding.evidence.matches`;
2. build a frame → stream map from the context's own `packets` rows, using `tcp_stream` for a
   TCP frame and `udp_stream` otherwise;
3. for each match **in order**, read its `packet` number and find the conversation in
   `context.conversations` whose `transport` and `stream_id` equal that frame's stream — the
   first match that resolves wins, so the button targets the conversation of the alert's first
   matched frame;
4. if no match resolves, fall back to `context.conversations[0]`, which the backend ordered by
   `bytes_total` descending — the largest conversation the alert touches;
5. if there are no conversations at all, return null: the button is disabled rather than
   jumping somewhere unrelated.

The destination is always
`/conversations?stream=<encodeURIComponent(transport + ':' + stream_id)>&tab=timeline`. For the
worked example (`suricata:51000006:2ef66e553fe5`) the target is
`/conversations?stream=tcp%3A14&tab=timeline`, because frame 210 records `tcp_stream = 14` and
that conversation is `tcp:10.4.10.132:49204-217.182.138.150:80` — 2,947 packets and 2,185,196
bytes, `established`, protocols `http,tcp`. The Overview tab shows the button on the Matched
evidence panel and the Conversation tab shows the same button on that panel, both from one
component so the two cannot drift apart.

### 4.6 What a re-run does, and what it leaves alone

**Re-run rules** performs two requests in order, because the first one destroys the second one's
work:

1. `POST /api/analyses/{id}/findings/rescan` → `detection_engine.analyze()`. This **deletes
   every finding row for the analysis** (`DELETE FROM findings WHERE analysis_id = ?`) — built-in
   *and* Suricata — and re-runs the enabled built-in rules, rewriting the table with
   deterministic ids. It returns `findings`, `by_severity`, `rules_run`, `rule_errors` and
   `seconds`.
2. `POST /api/analyses/{id}/suricata/run` → `suricata_engine.run_rules()`. This re-evaluates the
   enabled, supported rules against the `packets` and `http_transactions` indexes and replaces
   only the `suricata:%` rows.

So a re-run re-runs **the detection rules and the Suricata matcher, from the existing index**,
and nothing else. Specifically:

* it does **not** re-dissect the capture, and it does **not** re-run the conversation, HTTP, DNS,
  TLS, host or object stages — a rescan can therefore never discover a new HTTP transaction or a
  new extracted file;
* it does **not** need the capture file: the rescan route reads `stored_path` from the analysis
  row only to report whether the file is still present, and the Suricata route requires only that
  the analysis is `completed`;
* it **does** change `created_at` for every finding it writes, so the recording time is the time
  of the last run, not the time of the event;
* it leaves the thresholds as they are in [Settings](Settings.md) at the moment it runs, and
  honours disabled rules;
* it leaves `packets`, `conversations`, `http_transactions`, `dns_queries`, `tls_sessions`,
  `hosts`, `objects` and `indicators` untouched.

The page then invalidates the findings list, the rule catalogue, the finding context, the
findings counts and the dashboard summary, so everything visible re-reads.

## 5. Links into the rest of the app

| Element | Opens |
|---|---|
| **Follow conversation** (Overview and Conversation tabs) | `/conversations?stream=<transport>:<stream_id>&tab=timeline` — see [Conversations](Conversations.md) |
| A frame number on the Matched evidence table (Overview tab), or a `#<frame>` button on the Timeline tab | `/packets?sel=<frame>` — see [Packets](Packets.md) |
| An endpoint card address | `/packets?ip=<ip>` |
| An endpoint port chip | `/packets?ip=<ip>&port=<port>` |
| Artefact chips | `/packets?ip=`, `/packets?port=`, `/packets?search=` |
| **edit in settings** on the Suricata rule panel | `/settings?sid=<sid>`, which seeds the Suricata rule panel's search box with that sid — see [Settings](Settings.md) |
| A related finding on the Related tab | `/findings/<id>?tab=related` |
| A file on the Files tab | `GET /api/analyses/{id}/objects/{object_id}/export` — the same download as on [Files-and-Objects](Files-and-Objects.md) |
| A tab change | The same finding with a different `tab`, so a tab is shareable |
| The list's rule dropdown | Nothing navigational; it is a filter over the built-in rule catalogue |

## 6. Limits and honest caveats

* **Only `tab` is in the URL.** Severity, search text, rule id and the Suricata-only switch are
  component state, so a link such as `/findings?severity=high` silently shows everything. Use
  `/findings/<id>` (with `?tab=`) to point at a specific finding.
* **An unrecognised `tab` value blanks the detail area.** Any value other than the seven listed
  renders no tab body at all: the header and the tab strip appear, and nothing under them.
* **The list is capped at 500 rows.** The page requests `page=1&page_size=500` and has no
  pagination, so on a capture with more than 500 findings the list holds only the first 500 in
  backend order (severity, then rule id, then id) — the panel header still shows the true
  filtered total, and the footer says "500 of N".
* **The rule dropdown only lists built-in rules.** `GET /findings/rules` enumerates the ten
  built-in rules, so `suricata:<sid>` never appears in it and cannot be selected; the only way to
  isolate IDS matches on this page is the **Suricata only** checkbox, which filters the rows that
  were already loaded — so it can never reveal a Suricata match beyond the 500-row list.
* **Severity chip counts ignore the other filters.** They are a `GROUP BY severity` over the
  whole analysis, so with a search or rule filter active they describe a different set from the
  list, and the `all` chip is the sum of the four rather than the row count.
* **Caps on the context endpoint, which the page cannot raise.** Defaults: 50 packets, 5 streams,
  20 HTTP rows, 20 DNS rows, 20 TLS rows, 25 objects, 10 related findings, 60 timeline entries,
  8 endpoints. The API accepts a limit for most of them (up to 500 packets, 50 streams, 200
  HTTP/DNS/TLS/object rows, 50 related findings) but the page never passes any, and the endpoint
  count has no query parameter at all. Some caps announce themselves — the Packets tab prints its
  cap and the alerting count, the Endpoints section of the merged card says when more were
  involved, the Timeline tab's footer says *"Showing the first 60 of a longer timeline."* when its
  own cap bit, the Conversation tab says more streams belong to the alert, the Files tab appends
  *"capped, more objects belong to this alert"*, and the Related tab says more findings share
  artefacts — but the Application tab's three tables (20 rows each) are cut silently.
* **Frame numbers are capped before they are used.** Both producers store at most 50 frame
  numbers per finding, so the `alerting_packets` badge on the Packets tab and the length of the
  stored list agree; the tab then draws up to `packets_limit` (default 50) of them and prints both
  numbers, so a caller who lowered the limit would see the badge exceed the rows.
* **`evidence.matches` is a sample.** At most 10 matches are stored per finding (the matcher also
  stops at 10 hits per key and counts the rest in an `extra` field nobody renders), so the
  Matched evidence table and the `match_count` in the evidence both understate how often a rule
  actually fired.
* **The Conversation tab asks for a stream by number only.** `GET /streams/{stream_id}` carries no
  transport, and the backend prefers TCP when the same id exists for both transports — the stream
  table is keyed by `(analysis_id, transport, stream_id)`. In `sf19us-MTA-lab-09.pcap` id 14 is
  both `tcp:14` and `udp:14`. The trailing panel also requires the retained capture
  (`410 capture_missing` if it is gone), and TShark cannot reassemble UDP at all, so a UDP
  alert's content panel may show another transport's stream or report that content is
  unavailable.
* **The Files tab link can be wrong by construction.** A file matched only by request URI
  (*inferred from the request URI*) shares a filename with the path in the alert's HTTP
  transaction and nothing more — the object store recorded no stream or packet link. A filename
  is not evidence of identity, and the tab says which link type it used for that reason.
* **The Files tab's Save link is always rendered**, even for an object whose status is `failed`
  (nothing stored) or whose file has since been removed: the download then answers
  `410 object_missing` and the browser shows the API's JSON error. The Objects page disables that
  button; this tab does not.
* **`Related` is a similarity score, not a link.** Related findings are found by intersecting
  entity values (up to 3 addresses, names and URIs) and frame numbers, scanning at most
  `_RELATED_SCAN_LIMIT = 500` other findings of the analysis and returning the 10 with the most
  overlaps. Two findings sharing a frame may share nothing but a rule that fired on the same
  packet; two findings that share a public address may share nothing at all.
* **A finding is not a verdict.** Every built-in rule's copy is written to describe behaviour
  ("consistent with", "worth reviewing"), the Suricata reason ends with the sentence that a
  signature match is not proof of malice, and the Overview's Scope panel repeats the caveat. The
  page cannot tell you whether an exploit succeeded, who was at the keyboard, or whether a
  matched path was served — the recommendation text tells you which frame, response code or log
  to check next.
* **Severity comes from the rule, not from the evidence.** A `high` rule that fires on a false
  positive is still drawn as `high`, and the same rule always produces the same severity. A
  severity value that is not one of the four sorts last (`CASE … ELSE 4`) and is drawn by the
  badge as `info`; every value present in the captures in `data/` is inside the vocabulary.
* **Time is recorded, not correlated.** `findings.created_at` is when the finding was written
  (and is rewritten by every rescan); no column stores an event timestamp, so ordering findings
  on a timeline is only possible through the frames they recorded.
* **A re-run can lose information.** It deletes and rewrites findings, so any Suricata match
  whose rule has since been disabled or made unsupported disappears, and the recording times all
  change. It never re-runs the dissectors, so it cannot repair a stage that produced nothing.
* **No capture, no page.** Selecting the analysis (and every other data page) is gated by
  `AnalysisGuard`, and the findings list requires a `completed` analysis; while a capture is
  processing, the guard shows progress instead of findings.

## 7. Related

[Threat-Hunt](Threat-Hunt.md) and the per-detection pages under
[ThreatHunter/](ThreatHunter/ThreatHunter.md) for the hunt-level patterns that corroborate
these alerts, including [IDS Signature Matches](ThreatHunter/IdsSignatureMatches.md) ·
[Conversations](Conversations.md) for the flow every **Follow conversation** lands on ·
[Packets](Packets.md) for the frames behind every alert · [HTTP](HTTP.md), [DNS](DNS.md) and
[TLS](TLS.md) for the application-layer rows the Application tab summarises ·
[Files-and-Objects](Files-and-Objects.md) for the exports the Files tab points at ·
[Hosts](Hosts.md) for the endpoints named in a finding · [Settings](Settings.md) for detection
thresholds and the Suricata rule store · [Reference/API.md](Reference/API.md) for the exact
response shapes.
