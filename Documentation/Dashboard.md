# Dashboard

The first page of the running application (`/`): seven headline figures, the shape of the
traffic over time, a conversation map, the busiest senders and receivers, the domains this
capture resolved and the protocol mix — all for the one capture selected in the top bar.

The component is `frontend/src/pages/DashboardPage.tsx`, wrapped in
`frontend/src/components/AnalysisGuard.tsx`. Its pieces live in
`frontend/src/components/dashboard/`.

---

## 1. What it is for

It answers "what is in this capture, at a glance, and where do I go to see the rows
behind it?". It is a summary of one analysis, not a comparison between analyses and not
a timeline of activity across captures. Every number on it is computed from the tables
that capture already produced; nothing is re-dissected and nothing is estimated.

## 2. What is on the screen

### 2.1 The KPI tiles

Seven tiles in a responsive grid
(`grid-cols-2 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7`).
Every tile carries a link: `frontend/src/components/dashboard/KpiTile.tsx` renders the
whole tile as a `<Link>` when it is given a `to`, and the only visual difference is the
corner arrow and a hover border — the figure, label and detail line render identically
whether or not the tile is a link.

| Tile | Figure | Detail line | Opens |
|---|---|---|---|
| DNS requests | `totals.dns_queries` | `queries seen in this capture` | `/dns` |
| Conversations | `totals.conversations` | `reassembled streams` | `/conversations` |
| Hosts | `totals.hosts` | `distinct addresses` | `/hosts` |
| Findings | see below | `high N · medium N · low N · info N` | `/findings` |
| Packets | `totals.packets` | `indexed frames` | `/packets` |
| Bytes | `totals.bytes`, formatted as a byte size | `on the wire` | `/packets` |
| Duration | `totals.duration`, formatted as a duration | `N TCP · N UDP` | `/info` |

Two tiles need care:

* **Findings.** The figure is `totals.findings` when the backend supplies it, and the sum
  of `severity_counts` otherwise. The tile is drawn with the `danger` tone — a red icon
  and a red number — only when `severity_counts.high > 0`; otherwise it uses the accent
  tone. The tooltip is `Open the findings workbench behind this number`.
* **Bytes.** `totals.bytes` is `SUM(frame_len)` over `packets`, so it is every frame's
  full length including link and transport headers, not payload only. It opens
  `/packets`, where each frame's own length is a column.

A missing figure renders as an em-dash (`—`) in faint text rather than as `0`:
`formatNumber`, `formatBytes` and `formatDuration` in `frontend/src/utils/format.ts` all
return `EMPTY = '—'` for `null`/`undefined`/non-finite input.

### 2.2 Traffic over time

`frontend/src/components/dashboard/TrafficSparkline.tsx` inside a `ChartPanel`: a filled
area chart of `traffic_series`, the X axis formatted as local clock time (`HH:MM:SS`).

It is the **first panel under the KPI tiles and spans the full width**, directly above the
map: the shape of a capture over time is the thing to read first, and a time series needs
the width. Everything below it — the map, the extremes, the domains, the protocol mix —
keeps its own full or half width as §2.3 to §2.6 describe.

**Three views**, chosen by the toggles above the plot:

| View | What is drawn |
|---|---|
| **both** (the view it opens on) | Packets and bytes as two overlaid areas, each on **its own axis** — packets on the left, bytes on the right, every tick formatted in its own unit |
| `packets` | One area, one left axis |
| `bytes` | One area, one right axis |

Overlaying the two series on a single scale would be a lie of arithmetic rather than a
chart: bytes outrun packets by two or three orders of magnitude, so the packet line would
sit flat on the floor. Two axes keep both readable, and the two series are told apart twice
over so colour is never the only cue — **packets** is a solid `accent` line, **bytes** a
dashed `accent2` one, and the swatch legend beside the toggles names both (the same
packets/bytes colours and dashes the Info page's traffic chart uses). Both colours come from
the theme palette; the component carries no colour literal.

Panel subtitle: `N buckets · <interval> per bucket` when the response carries an interval
greater than zero, and just `N buckets` otherwise. The X value of a point is the **start**
of its bucket (`t = start + index × interval`). The tooltip names each series and formats it
in its own unit, so an overlapped point is never read as one number.

### 2.3 The map panel: geography, or conversations

The panel in the middle of the Dashboard answers "where does this capture talk to" by default,
and "who talked to whom" on request. A two-way toggle in the panel header switches between
them and the choice lives in the URL (`?map=graph`), so a link to either view is shareable and
Back returns to the other. The panel's other header action is a **Host inventory** button.

* **Geography** is the default: the world map, described in §2.3.1.
* **Conversations** is the graph this panel has always drawn, described in §2.3.2. Neither
  view replaces the other — topology and geography are different questions about the same
  capture — so both stay.

#### 2.3.1 Geography — where the capture's addresses are

`frontend/src/components/dashboard/WorldMap.tsx` draws it and
`frontend/src/components/dashboard/CountryList.tsx` lists it underneath. The contract for the
whole feature — the dataset, its licence and provenance, the endpoint, the caps and the limits
— is [`docs/GEOGRAPHY.md`](../docs/GEOGRAPHY.md); this is what a reader sees.

| Element | Meaning |
|---|---|
| World outline | One path per ISO 3166-1 alpha-2 code, from the bundled Natural Earth 110m asset (`frontend/src/theme/worldMap.ts`, generated, public domain). No tile server and no fetch at render time. |
| Origin | The capture's own side, drawn as a **dashed inset in the corner** with its address count and volume — never a point on the map. A private address carries no country, and the capture does not hold this installation's public address, so placing the hub anywhere would be an invention. |
| Arc | One per country, from the origin to that country's label point, with a single travelling dash (`7s`, staggered per country) showing direction. |
| Destination dot | **One per country**, never one per address, at that country's label point, radius `3 + 9 × sqrt(bytes / largest country's bytes)`. A capture with four hundred destinations draws at most `COUNTRY_CAP` (60) dots. |
| Dot label | Drawn for the six largest countries and for whichever is focused, as `US · 16` — the code and the address count. |
| Hover readout | Under the map: the country's name, addresses, volume, packets, and its first four addresses as buttons that open the host page. |
| Corner chips | Top-left counts the destinations and located addresses; top-right counts the addresses **not placed** in any country. |
| Country list | Under the map, one row per country in the API's order (bytes descending): code, name, address count, volume, packet count, and the addresses themselves as buttons. |
| Own-network row | The first row: the capture's own addresses, with a note that a private address has no country. |
| Unknown row | The addresses the dataset could not place, listed separately and never folded into a country's totals. |
| Provenance line | Under the map, when the dataset is installed: the dataset's own month, its range count and the licence attribution (*IP geolocation by DB-IP*), which CC BY 4.0 requires. |

Motion is a promise, not decoration: the arcs move slowly and the pinned dot pulses, and both
are switched off entirely under `prefers-reduced-motion: reduce`.

**Zooming.** The wheel or a pinch zooms about the pointer, dragging pans, and the controls in
the bottom-right corner zoom in, zoom out and fit the world again; the current scale is in
their tooltips. The scale is clamped to `1×–8×` and the pan is clamped, so the world never
leaves the frame. The zoom is one CSS transform on a group, interpolated over 220 ms — and
`transform-box: view-box` with `transform-origin: 0 0` is what makes the numbers the component
computes mean what they say; with CSS's default origin of `50% 50%` every pan would drift.

**The destination panel.** Selecting a country — clicking its dot, or its row in the list under
the map — zooms to it, and **half a second later** opens a card docked against the right edge of
the map frame, vertically centred, fetched at that moment from
`/api/analyses/{id}/geography/{code}`:

| In the panel | Meaning |
|---|---|
| Addresses, packets, bytes | The country's totals, summed over the `hosts` rows it contains. |
| `sent` / `received` | Packets and bytes in each direction, **from this capture's own side** — a `hosts` row's `bytes_sent` is what this side sent, which is what the destination received. The panel says whose side it means, because getting this backwards would invert every number. |
| Ports | From the country's conversations, with the side that owned each port: `remote` is the port on the destination's address (the service port), `local` is this side's, usually the ephemeral one. At most 25, busiest first. |
| One row per address | The address (a button that opens it on the Hosts page), its volume, its own `↑`/`↓` split, and its own ports. |
| **Follow conversation** | A link to `/conversations?stream=<transport>:<stream_id>&tab=timeline` for the **earliest** conversation involving that address — the same deep link the Findings page's Follow conversation button uses. An address whose conversation was never recorded gets a disabled button whose tooltip explains why, rather than a link that lands nowhere, and an address whose only conversation was never reassembled into a stream says *No stream* for the same reason. |

The panel sits **inside the map's own element**, which is why the map's drag handling has to
exclude it: the map starts a pan on `pointerdown` and captures the pointer, and a captured pointer
retargets the following `click` at the map — so without the exclusion the panel's links and buttons
did nothing at all, **Follow conversation** included. The rule that decides whether a press may
start a pan therefore refuses dots, anything interactive, and anything inside the panel; the panel
stops propagation of its own presses as well, and the rule is unit-tested because none of it is
visible in markup.

The card is **docked, not anchored to its dot**: at the right edge, centred vertically, never
taller or wider than the frame, so it is in the same place every time and never covers the
country it describes. The half-second wait is deliberate — the zoom transition takes 220 ms, and
a card that appears mid-movement reads as if it belonged to wherever the dot *was* — and it is
skipped entirely under `prefers-reduced-motion: reduce`, where there is no movement to wait for.
Closing is immediate: only the appearance is delayed.

`Esc` closes the panel, as does its close control, and a country whose dataset entry is missing
is listed but has no dot to open.

**When the dataset is not installed** the world is still drawn, no dot is invented, and the map
carries the reason the backend gave plus a **Build the location dataset** button. That button is
the only thing in APackets that downloads anything: one public CC BY 4.0 file, about 4.4 MB,
with no account and no API key, fetched by the backend when the reader asks and never at render
time. No capture data is involved in the request.

#### 2.3.2 The conversation graph

`frontend/src/components/dashboard/NetworkMap.tsx`; its subtitle is *who talked to whom in this
capture, sized by bytes*.

| Element | Meaning |
|---|---|
| Node | One IP address that appears in a `conversations` row (`id` and `label` are both the address). |
| Node radius | `4 + 15 × sqrt(bytes / max node bytes)` — area-proportional, so twice the radius is four times the bytes. |
| Node colour | The endpoint's `scope`, resolved from the active theme: private, public, multicast/broadcast, loopback/link-local, unclassified. `is_private` is only a fallback for responses that carry no `scope`. |
| Node label | Drawn for the eight busiest nodes by bytes (`labelCount = 8`) and for whichever node is focused. |
| Edge | One line per **unordered IP pair**, not per conversation row. |
| Edge width | `0.6 + 4.4 × sqrt(edge bytes / max edge bytes)`. |
| Edge opacity | Dimmed to `0.12` for edges that do not touch the focused node; `0.75` otherwise. |
| Legend | Top-left: private, public, multicast / broadcast, loopback / link-local, unclassified. |
| Hover panel | Bottom-right: for the focused node, its label, packet count, bytes, MAC when known, a plain-language scope description, then up to five peers sorted by bytes with up to three of each peer's ports. When nothing is focused it reads *Hover a node for its peers, ports and protocols. Click to open the host.* |
| Caption | Under the drawing: *Drawn only from connections observed in this capture — this is not a physical network topology.* plus `N hosts, N conversations`. |

The layout is computed once per graph: a deterministic force-directed pass
(`ITERATIONS = 140`) over a canvas of `1000 × 620` with `PADDING = 56`, seeded from a
stable hash of each address so the map never re-shuffles between renders and never
animates. Heavier conversations pull their endpoints closer (`target` distance falls from
240 to 90 as an edge's bytes approach the maximum).

Nodes are focusable (`tabIndex=0`, `role="button"`), and Enter or space activates them
exactly as a click does.

### 2.4 Most data sent / Most data received

Two cards from `frontend/src/components/dashboard/TrafficExtremeCard.tsx`, side by side
from the `md` breakpoint. *Most data sent* reads `traffic_extremes.max_sender`; *Most data
received* reads `traffic_extremes.max_receiver`. Each card shows:

* the address as a button (opens the host);
* a private / public / unclassified chip, with `Classification not available` as the
  tooltip when the field is null;
* the byte figure for **that direction only** (`bytes_sent` on the first card,
  `bytes_received` on the second), then the packet count for that direction, then both
  directions as `sent X · received Y`;
* the MAC address when the capture recorded one;
* up to four observed names, then `+N more`; when there are none, the line
  *no names observed for this address*.

When no host has a non-zero value in that column the card draws a question-mark icon and
the sentence *No host sent (or received) any data in this capture — nothing to rank.
Shown honestly rather than as a zero row.*

### 2.5 Top domains

`frontend/src/components/dashboard/DomainBars.tsx`. One row per domain, ranked by total
bytes, with a split bar on a single scale: the accent segment is `bytes_sent`, the second
accent segment is `bytes_received`, and the bar's right-hand figure is `bytes_total`. The
row header carries the rank, the name, and `N pkts · N clients`. Under the bar: the sent
and received figures, then up to three addresses as buttons and `+N more` with the rest in
the tooltip. The panel legend states which colour is sent and which is received.

The panel's footer is not hard-coded in the component: it renders `top_domains_note` from
the response when present, and falls back to a shorter sentence otherwise. The note the
backend actually sends says that totals are attributed from the addresses observed in DNS
answers and summed from the conversations with those addresses, that directions are
measured rather than guessed, that names which never appeared in a captured answer are
absent, that CNAME chains are not followed, and that a shared or CDN address can
legitimately carry several names.

The list is not capped by the page: it renders every row the endpoint returned, and the
endpoint's `domain_limit` query parameter defaults to `5` and is not sent by the
Dashboard. In practice this panel shows **at most five domains**, and there is no control
on the page to ask for more.

### 2.6 Protocol mix

`frontend/src/components/dashboard/ProtocolMix.tsx` inside a `ChartPanel`. A donut of the
**seven** largest protocols from `protocol_distribution`, with two toggle buttons —
`packets` (the default) and `bytes` — that change both the slice sizes and the legend's
percentages. The legend shows each protocol's share of the seven drawn slices, not of the
whole capture. Each colour is a position in the theme's eight-hue `chart` series, taken
with wraparound.

Panel subtitle: `top N protocols`, where N is the smaller of 7 and the number of rows the
endpoint returned.

### 2.7 The two closing lines

* A pointer to the reference view with an **Open Info** button.
* A statement that every figure is derived from this capture's own packets, that nothing
  is estimated, that values which could not be derived show as `—`, and that empty panels
  stay empty. A high-severity badge appears on the right when
  `severity_counts.high > 0`.

## 3. Where the data comes from

| What the page shows | Call | Route module |
|---|---|---|
| The KPI tiles, protocol mix, traffic series, top domains, traffic extremes | `GET /api/analyses/{id}/summary` via `useAnalysisSummary` | `backend/app/api/routes_analyses.py` → `analysis_summary()` → `build_summary()` |
| The conversation map | `GET /api/analyses/{id}/hosts/graph` via `hostsApi.graph` | `backend/app/api/routes_hosts.py` → `host_graph()` |
| The capture list, the active capture, and the freshness test that drives polling | `GET /api/analyses?page=1&page_size=200` via `useAnalysis` | `backend/app/api/routes_analyses.py` → `list_analyses()` |

The client wrappers are in `frontend/src/services/api.ts` (`analysesApi.summary`,
`hostsApi.graph`, `analysesApi.list`) and the shared query hooks in
`frontend/src/hooks/useAnalysis.tsx`.

The tables those endpoints read:

| Table | Supplies |
|---|---|
| `analyses` | `duration`, `capture_start`, `capture_end`, `file_type`, filename and SHA-256 for the footer; the freshness timestamp (`finished_at`, else `updated_at`). |
| `packets` | `COUNT(*)` for the Packets tile; `SUM(frame_len)` for Bytes; the distinct-source and distinct-destination counts; `transport` for the TCP/UDP breakdown; `protocol` and `frame_len` for the protocol donut; `time_epoch` and `frame_len` for the traffic series. |
| `dns_queries` | The DNS-requests tile, and `query_name` + `answer_ips` for domain attribution. |
| `http_transactions` | The HTTP-request total (`method IS NOT NULL`), returned in the payload but not shown on this page. |
| `tls_sessions` | The TLS-connection total, returned but not shown on this page. |
| `conversations` | The Conversations tile, `top_conversations`, and both `host_graph` endpoints and every edge. |
| `hosts` | The Hosts tile, and the busiest sender/receiver with their MAC, names and private/public flag. |
| `findings` | `severity_counts` and `totals.findings`. |
| `jobs` | The latest job's status and the analyses list's `job_status`. |
| `stats_cache` | The protocol hierarchy, returned in the payload but not drawn here. |

What the map's builder does, precisely: it reads every `conversations` row for the
analysis, skips any row with a missing address or with `ip_a = ip_b`, keys each edge on the
sorted address pair, and sums `packets_total` and `bytes_total` onto that pair. A pair's
`source`/`target` direction is decided by its **busiest single conversation**, and the
ports it reports are the destination ports of that direction, unioned across the pair and
truncated to `GRAPH_MAX_PORTS = 5`. Node totals come from the matching `hosts` row when one
exists and from the summed conversation totals when it does not; the node's `scope` is
always recomputed from the address text.


**Geography** is the one panel whose numbers do not come from the capture's index. It reads
`/api/analyses/{id}/geography`, which joins the analysis's own `hosts` rows to a country lookup
performed against a local file: DB-IP Lite *country*, CC BY 4.0, downloaded on request into
`data/geoip/` and never queried over the network. The lookup is the address block's registered
country, which is why the page says so; the endpoint and its caps are in
[`docs/GEOGRAPHY.md`](../docs/GEOGRAPHY.md).

## 4. Links into the rest of the app

| Element | Opens |
|---|---|
| DNS requests tile | `/dns` |
| Conversations tile | `/conversations` |
| Hosts tile | `/hosts` |
| Findings tile | `/findings` |
| Packets and Bytes tiles | `/packets` |
| Duration tile | `/info` |
| Host inventory button (map panel) | `/hosts` |
| A map node (click, Enter or space) | `/hosts?ip=<address>` |
| An address button in *Most data sent* / *Most data received* | `/hosts?ip=<address>` |
| An address button under a domain bar | `/hosts?ip=<address>` |
| Open Info button | `/info` |

The map node and every address button encode the address with
`encodeURIComponent`, so an IPv6 literal such as `fe80::1` survives the round trip.

**Right-clicking an address** — a node in the conversation graph, an address in the
geography hover readout, a card in *Most data sent* / *Most data received*, or a row in a
country's destination panel — opens the application's address menu: **Pivot <ip> to Hunt**,
**Show Conversations with <ip>**, and **Pivot to Wireshark**. Where the element is one
conversation (a destination panel row, which already knows the first conversation with that
address) the menu carries it, so the Conversations link opens that exchange and the Wireshark
pivot filters to it and jumps to its first frame; where it is only an address, the pivot opens
every frame it appears in. See [Architecture.md](Architecture.md) §6.1 and §6.2.

## 5. Limits and honest caveats

* **One capture at a time.** Everything is scoped to the analysis selected in the top bar.
  There is no cross-capture view here and no baseline: "1.3 MB from one host" is a fact
  about this capture, not a comparison with the network's normal behaviour.
* **The map is not a topology, and it is not the Conversations count.** Its caption counts
  *unordered IP pairs*, while the Conversations tile counts rows in the `conversations`
  table. On `sf19us-MTA-lab-01.pcap` the tile reads **195** reassembled streams and the map
  caption reads **66 hosts, 65 conversations** — the same capture, two different meanings
  of the word. Treat the map's number as "distinct address pairs".
* **Hosts with no conversation never appear on the map.** On the same capture the `hosts`
  table holds 67 rows and the map draws 66 nodes. The extra row is `224.0.0.22`, an IGMPv3
  multicast group with 5 received frames, 270 bytes and `peer_count = 0` — it is in the
  Hosts inventory and in the protocol donut, but it was never an endpoint of a reassembled
  conversation, so the map has nothing to draw it from. The Hosts tile and the map therefore
  legitimately disagree by one.
* **Direction on the map is one-sided.** An edge is a single undirected line whose
  declared direction comes from its busiest conversation, so a pair that mostly pushes data
  one way and also answers the other way is drawn as if the bulk direction were the whole
  relationship.
* **Domain attribution is attribution.** A domain's bytes are the conversations with the
  addresses that appeared in a captured DNS answer for that name. Two consequences are
  visible in the library rather than hypothetical:
  * A name that resolves to a **local** address swallows that host's traffic. On
    `sf19us-MTA-lab-01.pcap` the captured answer set for the `SOA` query `cocoaten.org`
    contains the private address `192.168.1.103`, so the panel's largest row is
    `cocoaten.org` at **2,716,712 bytes across 65 clients** — 99.99% of the capture's
    2,716,982 bytes, attributed to a domain name. A name resolving inside the network is not
    a domain any traffic can be meaningfully attributed to.
  * One address can carry several names, so aliases show identical totals. The same capture
    lists `blog.eskill.com` and `www.eskill.com` at **1,393,877 bytes** each, because both
    resolved to `162.243.48.117`.
  Names that never appeared in a captured answer are absent entirely, and CNAME chains are
  not followed.
* **Only five domains, and no control to widen it.** A capture with forty resolved,
  traffic-bearing names shows the top five by total bytes.
* **The protocol donut is seven slices of up to fifteen rows.** The endpoint returns at
  most 15 protocol rows; the donut draws the 7 largest of those and reports each slice's
  share of *those seven*, not of the capture. A protocol ranked eighth or lower is
  invisible here even though the Info page's bar chart lists it.
* **Bytes are frame bytes.** `SUM(frame_len)` counts headers; retransmissions, ACK-only
  frames and reset frames all contribute. It is a wire-volume figure, not a payload figure.
* **The Bytes and Packets tiles open the same page.** Only `/packets` holds the rows behind
  both figures, so the two tiles are not two destinations.
* **The traffic series is fixed at 240 buckets and zero-filled.** The bucket count is
  `min(240, floor(span) + 1)`, and every empty bucket is emitted as a measured zero. A short
  capture spread over a long span therefore draws a long tail of zeros: on
  `sf19us-MTA-lab-12.pcap`, 32 packets over 414.5 s become **240 buckets of which 11 hold
  data** (interval 1.727 s). Likewise `sf19us-MTA-lab-09.pcap` and `sf19us-MTA-lab-07.pcap`
  both hit the 240 cap (interval ≈ 15.9 s per bucket), so their buckets are much coarser
  than the traffic they summarise.
* **The X axis shows a clock time only.** `formatClockTime` prints `HH:MM:SS` in the
  browser's local zone, with no date. A capture that runs past midnight or across days looks
  continuous on this chart; hover the point to see the full `YYYY-MM-DD HH:MM:SS.mmm` in the
  tooltip.
* **Refresh behaviour is uneven.** The summary refetches every 5 s only while the capture is
  "fresh" — `finished_at` (else `updated_at`) within the last 300 s — and otherwise only
  when the window regains focus. A re-run of Suricata rules from `/settings` invalidates the
  summary directly, so findings counts usually update at once; anything else changed
  server-side may not appear until the window is focused again.
* **The header counts and this page can disagree.** The top bar's Findings badge is a
  separate `GET /api/analyses/{id}/findings?page_size=1` query with its own 10 s poll.
* **Empty is drawn as empty.** No conversations draws the map's "No conversations to map"
  state and nothing else; no protocol distribution draws an empty chart panel; an
  unattributable domain list explains that attribution needs both a captured answer and
  traffic to that address in the same capture. None of these is replaced by a placeholder,
  and none of them means the capture is clean.
* **What this page does not show at all:** HTTP transactions, TLS sessions, extracted
  objects, the threat-hunt indicators, per-packet detail, or any conversation-level table.
  Those live on their own pages.

## 6. Related

The full reference view for the same capture is [Info.md](Info.md); the rows behind the
address links are on [Hosts.md](Hosts.md), the streams behind the conversations figure on
[Conversations.md](Conversations.md), and the alerts behind the findings figure on
[Findings.md](Findings.md). Uploading another capture, and the retention rules that decide
how long this one stays on disk, are documented in [PCAP-Files.md](PCAP-Files.md); the
picker that chooses which capture this page summarises is shared with every page and is
described in [Architecture.md](Architecture.md). The geography view's dataset, its licence, its
endpoint and the limits of turning an address into a country are fixed by
[`docs/GEOGRAPHY.md`](../docs/GEOGRAPHY.md), which is normative for that panel.
