# Info

The reference view for one capture (`/info`): every figure the backend derived for it,
with the caveats that came with them, and no chart that is not backed by a column.

The component is `frontend/src/pages/InfoPage.tsx`, wrapped in
`frontend/src/components/AnalysisGuard.tsx`. It reads the same summary payload the
[Dashboard](Dashboard.md) reads and renders a different part of it.

---

## 1. What it is for

It answers "what exactly did the analyser measure for this capture, in numbers I can
quote?". The Dashboard answers the same payload's *visual* questions — the map, the
donuts, the busiest host. This page is the flat, tabular version: ten counters, a capture
window, four ranked tables, a protocol hierarchy, the findings that were produced, and a
list of the limitations the backend recorded while producing them.

## 2. What is on the screen

### 2.1 Header line

One sentence — *Reference view: every number the backend derived for this capture,
including the caveats.* — and a **Visual overview** button on the right.

### 2.2 Summary cards

Ten `StatCard`s (`frontend/src/components/StatCard.tsx`) in a
`grid-cols-2 md:grid-cols-3 xl:grid-cols-5` grid. None of them is a link.

| Card | Field | Format |
|---|---|---|
| Packets | `totals.packets` | thousands-separated integer |
| Bytes | `totals.bytes` | byte size, binary units (`KiB`, `MiB`, …) |
| Duration | `totals.duration` | `1.234 s` under ten seconds, `12.3 s` under a minute, then `3 m 4 s` or `1 h 2 m` |
| Unique src IPs | `totals.unique_src_ips` | integer |
| Unique dst IPs | `totals.unique_dst_ips` | integer |
| TCP packets | `totals.tcp_packets` | integer |
| UDP packets | `totals.udp_packets` | integer |
| DNS queries | `totals.dns_queries` | integer |
| HTTP requests | `totals.http_requests` | integer |
| TLS connections | `totals.tls_connections` | integer |

### 2.3 Capture window

A definition list in a narrow left-hand panel.

| Row | Field |
|---|---|
| First packet | `totals.start_time`, as `YYYY-MM-DD HH:MM:SS.mmm` in local time |
| Last packet | `totals.end_time`, same format |
| Conversations | `totals.conversations` |
| Hosts | `totals.hosts` |
| Findings | `totals.findings` |

### 2.4 Protocol distribution

A horizontal bar chart of `protocol_distribution`, one bar per protocol, labelled on the
Y axis with the protocol name and coloured from the theme's eight-hue chart series with
wraparound. Two toggle buttons switch the metric: `packets` (the default) and `bytes`.
The panel subtitle reads `top N protocols by <metric>`.

The rows are re-sorted in the browser by the selected metric, so switching to `bytes` can
reorder the chart. The endpoint returns at most **15** rows, ranked by packets when it was
queried.

### 2.5 Traffic over time

An area chart of `traffic_series` with three toggles: `both` (the default), `packets` and
`bytes`.

* `both` draws two series on two Y axes — packets solid in the accent colour on the left,
  bytes dashed in the second accent on the right.
* `packets` or `bytes` draws only that one, on a single axis; the other axis and series are
  not rendered at all.
* The X axis is local clock time (`HH:MM:SS`) with a minimum tick gap of 28 px. The
  tooltip label is the full timestamp, printed as `t = YYYY-MM-DD HH:MM:SS.mmm`.

Panel subtitle: `N buckets · <interval> per bucket`, or `N buckets` when the response
carries no positive interval.

### 2.6 Top talkers

Columns **IP**, **Direction**, **Packets**, **Bytes**. Subtitle: *by packets observed* —
note that the panel's subtitle says packets while the rows are ordered by **bytes**,
because that is what the endpoint sorts on. At most **10** rows, each one an
address/direction pair, so the same address can legitimately appear twice: on
`sf19us-MTA-lab-01.pcap` `192.168.1.103` is row one as a destination
(2,498,111 bytes over 2,714 packets) and row three as a source (218,871 bytes over 1,786
packets). Direction is the literal string `source` or `destination`.

### 2.7 Top ports

Columns **Port**, **Protocol**, **Packets**, **Service**. Subtitle: *by packets observed*,
which matches the ordering here. At most **15** rows, grouped by destination port *and*
transport, so the same port number can appear twice — `SpaceX_111025.pcapng` lists
`443 tcp` (490 packets) and `443 udp` (19 packets) as separate rows.

The **Service** column is looked up in a fixed table of 51 well-known ports declared in
`routes_analyses.py` as `KNOWN_PORTS` (IANA service names such as `https` for 443,
`microsoft-ds` for 445). A port that is not in that table renders as `—`. The table is
application data shipped with APackets, not a fact about the capture, and it is a different
mechanism from the operating-system service lookup the Findings page uses.

The endpoint also returns a `bytes` figure per port; this table does not show it.

### 2.8 Top conversations

Columns **A**, **B**, **Transport**, **Packets**, **Bytes**, with the endpoints truncated
to 220 px (`MonoCell maxWidth={220}`, full value in the tooltip). Subtitle: *by total
bytes*, which is how the endpoint orders them. At most **10** rows. `conv_id` and `state`
are returned by the endpoint but are not shown here.

### 2.9 Protocol hierarchy

Columns **Protocol**, **Frames**, **Bytes**. The protocol name is indented by
`depth × 12 px`, and a layer icon marks depth-0 rows. Subtitle: *tshark -z io,phs*, which
is literally how the data was produced.

These rows are **nested and cumulative**, not disjoint. `tshark -z io,phs` prints a tree in
which each protocol's frame count is the number of frames that protocol was found in, and
each level is indented under its parent: `frame` is every frame in the file, `eth` every
frame with an Ethernet layer, `ip` every frame carrying an IP layer, `udp` every UDP frame,
`dns` the DNS frames inside those, and so on — on `SpaceX_111025.pcapng` the same protocol
name even appears twice, at depth 4 and depth 5, because TLS was found nested inside TLS.
On `sf19us-MTA-lab-01.pcap` the hierarchy has **22 rows** beginning
`frame 4500/2716982`, `eth 4500/2716982`, `ip 4500/2716982`, `udp 295/32916`,
`dns 230/25931`, `mdns 2/164`. Do not add those rows up: they are layer counts, not
categories.

### 2.10 Findings

Panel subtitle: either the four severity counts (`high N · medium N · low N · info N`) or
the sentence *no detection rules matched*.

* A row of four `SeverityBadge`s, always drawn, including zero counts.
* Up to **10** findings, ordered by severity rank (high, medium, low, then everything
  else) and then by `rule_id`. Each row shows the severity badge, the title, and the rule
  id as a chip; the title is truncated in the row and complete in its tooltip.
* Two actions in the header: an `updating…` indicator while the summary query is fetching,
  a **Refresh** button that refetches it, and an **Open findings** button.
* When no finding matched, the panel says so and adds: *that means no rule matched, not
  that the traffic is clean.*

Every finding row is a link to `/findings`; the row does not carry the finding's id, so it
opens the workbench rather than that one alert.

### 2.11 Analysis limitations

A list of the caveats the backend recorded for this capture, each with an info icon.
Subtitle: *real caveats recorded by the backend for this capture*. The list is assembled
from two things: sentences `_notes()` generates from the capture's own shape, plus every
warning the pipeline stages stored. The sentences are generated when:

| Condition | Sentence |
|---|---|
| `totals.tls_connections > 0` | TLS sessions come from handshake metadata only; payloads are not decrypted, so HTTP paths, headers and bodies inside HTTPS are unavailable unless decryption keys are supplied. |
| The file is `pcapng` **and** no packet was indexed | The capture reports no packets, so no statistics could be derived. |
| Some `http_transactions` row has a `Host` header that is a literal IPv4 address | That many requests used an IP literal as the Host header — common for appliances and APIs, but it hides the hostname. |
| Packets were indexed **and** no conversation was reconstructed | No transport conversations could be reconstructed from this capture. |

Pipeline warnings are appended afterwards from `stats_cache`. When the list is empty the
panel says *No limitations were recorded. Absence of a note is not proof that the capture
is complete.*

Two measured examples from this library, so the list's real size is not a surprise: on
`sf19us-MTA-lab-01.pcap` it holds **one** note (the TLS one, from its 41 TLS sessions); on
`sf19us-MTA-lab-11.pcap` and `sf19us-MTA-lab-12.pcap` it is **empty**, because neither
capture has a TLS session and most of the conditions above never fire.

### 2.12 Footer

One line: `analysis <first 12 chars of the id>… · <original filename>`, then
`· started <capture start>` when the capture start is known, then
`· sha256 <first 12 chars>…` when a hash is recorded. On the right:
*values shown as — are unknown, never guessed*.

## 3. Where the data comes from

The page makes exactly **one** API call for its data:

| Call | Route module |
|---|---|
| `GET /api/analyses/{id}/summary` via `useAnalysisSummary` | `backend/app/api/routes_analyses.py` → `analysis_summary()` → `build_summary()` |

The client wrapper is `analysesApi.summary` in `frontend/src/services/api.ts`, the shared
hook is in `frontend/src/hooks/useAnalysis.tsx`, and the request is built with no query
string, so the endpoint's `domain_limit` keeps its default of `5`. `AnalysisGuard`
additionally calls `GET /api/analyses` and `GET /api/analyses/{id}` to decide whether the
capture is ready, and the top bar calls `GET /api/analyses?page=1&page_size=200`.

`build_summary()` composes the payload from these queries:

| Payload key | Query | Tables read |
|---|---|---|
| `totals` | Seven `COUNT(*)`/`SUM` scalars plus distinct-address counts | `packets` (count, `SUM(frame_len)`, distinct `src_ip`, distinct `dst_ip`, `transport = 'tcp'`, `transport = 'udp'`), `dns_queries`, `http_transactions` (`method IS NOT NULL`), `tls_sessions`, `conversations`, `hosts`, `findings` |
| `protocol_distribution` | `GROUP BY protocol` over `packets`, ordered by packets, `LIMIT 15` | `packets.protocol`, `packets.frame_len` |
| `traffic_series` | Bucketed `GROUP BY CAST((time_epoch - start) / interval AS INTEGER)` | `packets.time_epoch`, `packets.frame_len` |
| `series_interval` | Computed as `span / buckets` | `analyses.capture_start`, `analyses.capture_end` |
| `top_talkers` | A `UNION ALL` of source rows and destination rows, grouped by address and direction, ordered by bytes, `LIMIT 10` | `packets.src_ip`, `packets.dst_ip`, `packets.frame_len` |
| `top_ports` | `GROUP BY dst_port, transport`, ordered by packets, `LIMIT 15` | `packets.dst_port`, `packets.transport`, `packets.frame_len` |
| `top_conversations` | Ordered by `bytes_total` desc, `LIMIT 10` | `conversations` |
| `protocol_hierarchy` | A cached JSON blob | `stats_cache` where `kind = 'protocol_hierarchy'` |
| `findings_summary` | Ordered by a severity `CASE` then `rule_id`, `LIMIT 10` | `findings` |
| `severity_counts` | `GROUP BY severity` | `findings` |
| `notes` | Generated in Python, then concatenated with stored warnings | `packets`, `analyses`, `http_transactions`, `conversations`, `stats_cache` (`warnings`) |
| `analysis` | The `analyses` row plus `job_status` and `disk_usage` | `analyses`, `jobs`, and a filesystem walk |
| `top_domains`, `top_domains_note`, `traffic_extremes` | Returned by the same call, **not rendered on this page** — they belong to the [Dashboard](Dashboard.md) | `dns_queries`, `conversations`, `hosts` |

The protocol hierarchy was produced at the end of the pipeline by
`tshark -z io,phs` and parsed by `parse_protocol_hierarchy()` in
`backend/app/services/pipeline.py`, which reads two spaces of indentation per level. It is
written once per analysis; a rescan of findings does not touch it.

## 4. Links into the rest of the app

This page has fewer outgoing links than any other section, and that is worth stating
plainly rather than finding links that do not exist.

| Element | Opens |
|---|---|
| Visual overview button | `/` |
| Open findings button | `/findings` |
| Any finding row in the Findings panel | `/findings` (the list, not that single finding) |
| Refresh button | Nothing — it refetches `GET /api/analyses/{id}/summary` in place |

The capture selector in the top bar changes which capture every figure on this page
describes. It is the same selection the Dashboard uses, so switching capture here never
leaves the Dashboard on a different analysis.

There is no link from a summary card to the page holding its rows — unlike the Dashboard's
KPI tiles, these cards are plain text. To go from *HTTP requests 102* to the rows, use the
sidebar.

## 5. Limits and honest caveats

* **One call, one capture, no refresh of the index.** Every figure here was derived when
  the analysis ran. Re-dissecting a capture to pick up a changed setting means re-uploading
  it; a findings *rescan* rewrites only `findings`.
* **Staleness follows the same rule as the Dashboard.** The summary refetches every 5 s
  while the capture is fresh — `finished_at` (else `updated_at`) within 300 s — and
  otherwise only when the window regains focus or the Refresh button is pressed.
* **Everything is capped, and the caps are not all visible on screen.** Top talkers 10 rows,
  top ports 15, top conversations 10, findings 10, protocol rows 15, hierarchy rows as many
  as TShark emits. None of these tables says "showing 10 of 1,240" — the counts simply end,
  and no on-screen label tells you a cap is in force. The Findings panel is the only one
  that hints at more, because the severity badges carry the true totals beside the ten rows.
* **The Top talkers subtitle contradicts its ordering.** It reads *by packets observed*
  while the rows are sorted by bytes, so the first row is not necessarily the largest packet
  count. The all-pairs query that feeds it counts one "packet" per row per direction, so an
  address's `packets` value here is frames seen as that role.
* **Address counts are not host counts.** Unique src IPs and unique dst IPs come from
  `packets.src_ip`/`dst_ip`; the Hosts row comes from the `hosts` table. On
  `sf19us-MTA-lab-01.pcap` there are **61** distinct sources and **67** distinct
  destinations, against **67** host rows. They are different measurements of a similar
  idea; neither is wrong, and they need not match.
* **The protocol distribution and the protocol hierarchy answer different questions and
  must not be compared row by row.** The distribution assigns each frame one name — the
  highest-level protocol TShark reported for it — and its rows therefore sum to the packet
  count (on `sf19us-MTA-lab-01.pcap`: 3038 + 838 + 230 + 204 + 76 + 41 + 37 + 16 + 8 + 5 +
  2 + 2 + 2 + 1 = **4500**, the whole capture). The hierarchy counts layers, so its rows
  overlap and total far more than the frame count.
* **The distribution shows only the top 15 by packets.** A capture with a long tail of
  rare protocols hides all of them here; the hierarchy is the complete list.
* **The hierarchy is absent when TShark's `io,phs` call failed.** `_cache_protocol_hierarchy`
  logs a warning and returns without writing a row, and the endpoint then reports an empty
  list — which this page renders as *No protocol hierarchy was recorded for this capture.*
  An empty list here means "not computed", not "no protocols".
* **The traffic series is 240 buckets, zero-filled, and the X axis shows no date.** The
  same structure the [Dashboard](Dashboard.md) draws: `min(240, floor(span) + 1)` buckets,
  interval `span / buckets`, every empty bucket emitted as a measured zero. On
  `sf19us-MTA-lab-12.pcap` (32 packets over 414.5 s) that is 240 buckets of which 11 hold
  data, at 1.727 s per bucket; on `sf19us-MTA-lab-09.pcap` (4003 packets over 3821.6 s) the
  240 cap makes each bucket ≈ 15.9 s. `both` mode is the only way to see packets and bytes
  together, and because the two series use separate axes their heights are not comparable.
* **Service names are not capture evidence.** The `KNOWN_PORTS` map is a static table. A
  capture that runs SSH on 2222 shows `2222` with no service name, and nothing here hints
  that it might be SSH. Conversely a service name is never proof that the protocol ran —
  a server on 443 that never did TLS still reads `https`.
* **Conversations and talkers are addresses, not identities.** NAT, proxies and CDNs make
  one address stand for many hosts, and a talker row is an address in a role, not a machine.
* **The findings list is a summary of the detection run, not the run itself.** Ten rows,
  no evidence, no packet numbers, no reason text, no entity list. The Findings workbench
  holds all of that; use **Open findings**.
* **An empty limitations list is not an all-clear.** It means the four conditions above
  were not met and no pipeline stage stored a warning. Nothing here can detect a capture
  that was truncated before it reached this machine, that was filtered upstream, or that is
  simply not representative of the incident. The one shape that *is* checked — `capinfos`
  reporting fewer bytes than the stored file holds — is recorded as a warning during upload
  validation and reaches this list only once the analysis has run to completion.
* **The page does not show everything the payload contains.** `top_domains`,
  `top_domains_note`, `traffic_extremes`, `analysis.job_status`, `analysis.disk_usage`,
  `analysis.upload_retained`, `top_domains.clients`, `top_ports.bytes` and each
  conversation's `conv_id` and `state` are all returned by the same call and none of them is
  rendered here.
* **The footer's em-dash rule is a promise about this page only.** `—` appears when a value
  is null, which for this endpoint means the analyser could not derive it; it never means
  zero.

## 6. Related

The visual half of the same payload — the conversation map, the domain attribution and the
busiest sender and receiver — is documented in [Dashboard.md](Dashboard.md). The rows
behind the counters are on [Packets.md](Packets.md), [Conversations.md](Conversations.md),
[Hosts.md](Hosts.md) and [Findings.md](Findings.md), and the endpoint itself is specified
in [Reference/API.md](Reference/API.md) against the frozen contract in
[`docs/CONTRACT.md`](../docs/CONTRACT.md).
