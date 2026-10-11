# Conversations (`/conversations`)

Every TCP and UDP flow the analysis derived, in three views of the same rows: a five-column
alluvial Flow diagram, the dense Info table with a full conversation detail pane, and a
Timeline of one conversation's events, frames and reassembled stream.

The page is `frontend/src/pages/ConversationsPage.tsx` (default export `ConversationsPage`,
mounted on `/conversations` in `frontend/src/App.tsx`); the diagram and its engine live in
`frontend/src/components/conversations/`, and the table, detail pane, timeline and stream
viewer in `frontend/src/components/streams/`. The endpoint behind it is
`backend/app/api/routes_conversations.py`, with the alert overlay served by
`backend/app/api/routes_findings.py`. Where this document and
[`docs/CONTRACT.md`](../docs/CONTRACT.md) disagree, the contract is normative for the API
shape and this document records what the running build does.

Like every data page it is wrapped in `AnalysisGuard`, so an analysis that is still
processing shows the shared progress bar instead of the tabs.

---

## 1. What it is for

**Which hosts talked to which, on which ports, in what state, and how much did that carry?**

The [Packets](Packets.md) page answers what is on the wire frame by frame; this one answers
what the frames add up to as flows. It is the page for the question an analyst asks after
seeing a suspicious frame — *was this a one-off, or a stream? who else was involved? did
anything come back?* — and it is the only page that reassembles application payloads, by
asking TShark to follow the TCP stream rather than by concatenating packets itself.

The three tabs are three depths of the same data: the **Flow** diagram shows the whole
filtered set at once as five stages, the **Info** table shows one page of it with every
number the `conversations` row holds, and the **Timeline** follows exactly one conversation
from its protocol events down to its bytes.

## 2. What is on the screen

### 2.1 The toolbar, shared by every tab

`FilterStrip` from `frontend/src/components/protocols/ProtocolFilters.tsx`, above the tabs.

| Control | What it does |
|---|---|
| `transport` | `any` / `tcp` / `udp` |
| `ip` | Either endpoint matches this address exactly |
| `port` | Either endpoint port equals this value; digits only, five digits maximum |
| `search` | Substring over the conversation id, both endpoints and the observed protocols |
| `sort` | `total bytes`, `packets`, `start time`, `duration`, `endpoint A` — applied by the backend over the whole conversation set |
| order button | Shows `asc` or `desc` and flips it |
| read-only totals | `N conversations in this analysis · X total`. These are **whole-analysis** numbers, not the filtered page's |
| **Reset** | Clears the four toolbar filters, and the Alerts filter when it is on. Disabled when no toolbar filter is active and the Alerts filter is off |

The filters are shared by the table query and the diagram query, so the Info table and the
Flow diagram always describe the same set of conversations. They do not affect the
whole-analysis totals in the strip, which is why those are labelled as the analysis's, not
the filter's.

### 2.2 The three tabs

`CONVERSATIONS_TABS` in `ConversationsPage.tsx`. `Flow` is the default, and is the value
used when `?tab=` is absent or unrecognised. Hovering a tab shows its hint.

| Tab | What it shows |
|---|---|
| **Flow** | The five-stage alluvial diagram (§2.3) plus the conversations behind whatever is selected |
| **Info** | The dense table with sorting, paging and the detail pane — what this page showed before the diagram existed |
| **Timeline** | One conversation over time: its protocol events, every indexed frame, and the reassembled stream with its chunk timeline (§2.7) |

### 2.3 The Flow tab

`ConversationFlow` in `frontend/src/components/conversations/ConversationFlow.tsx`, drawn
from the graph built by `buildFlowGraph` in `flowLayout.ts`. Everything on screen comes from
the rows matching the current filter, in one request.

**The diagram.** Five columns, left to right, with the labels used on screen:

| Position | Column | Node id prefix | What a node is |
|---|---|---|---|
| 1 | `SOURCE IP` | `source:` | An address, or a `/24` (IPv4) / `/64` (IPv6) group of addresses |
| 2 | `SOURCE PORT` | `sourcePort:` | One port, or `unknown` when the row carries none |
| 3 | `STATE` | `state:` | `established`, `closed`, `reset`, `half_open`, `unknown` |
| 4 | `DESTINATION PORT` | `destinationPort:` | One port, or `unknown` |
| 5 | `DESTINATION IP` | `destination:` | An address or a group, as column 1 |

* **Thickness is bytes.** Each ribbon's thickness is `minimum + bytes × scale`, scaled so the
  layer fills its height; the minimum is `FLOW_MIN_BAND = 1.5` px so thin flows stay
  clickable. When a layer carries more bands than its height can give 1.5 px to, the floor is
  dropped for that layer and thickness stays strictly proportional. The legend prints the
  thinnest band on screen next to the floor, so the distortion is visible rather than
  implied. A ribbon has one thickness, identical at both ends.
* **Solid TCP, dashed UDP.** A band carries exactly one transport, so a pair of columns
  carrying both is drawn as two stacked ribbons rather than a blend. The legend counts such
  pairs, and a footer line counts whole five-stage paths that carry both.
* **Colour is the state**, taken from the active theme, with a legend that spells each state
  out in words next to its swatch. In the default theme `established` is `ok` (green),
  `closed` is `muted`, `reset` is `warn` (amber), `half_open` is `accent2` (blue) and
  `unknown` is `mapUnclassified`; a different theme repaints those tokens, which is why the
  legend never relies on colour alone. Where a band mixes states, its colour is the state most
  of its bytes are in. States are labels, not verdicts; `unknown` is the normal reading for
  UDP, which carries no TCP state to derive.
* **IP grouping.** The two IP columns group addresses by subnet so they stay readable. A
  group holding exactly one observed address is labelled with that address instead of its
  CIDR, because the group *is* that address; a group holding two or more carries a `+` marker
  and expands.
* **Folding, never squashing.** Each column has a node budget (§3.5). A column with more
  entities than its budget keeps the largest and folds the rest into one dashed node
  labelled `N more`, which is itself selectable. Every fold is reported in a footer line
  ("`26` of `193` source ports shown — the rest are folded into one `167 more` node so the
  spacing never drops below the minimum"), so the diagram never silently drops a flow.

**Reading it.**

* Hovering a node or a band lights up every path that conversation takes and dims the rest.
  The readout in the bottom-right corner of the panel gives the hovered element's aggregate:
  for a band, the columns it joins, its conversation count, bytes, packets, transport,
  states and the distinct source IPs, ports and destination IPs behind it; for a node, its
  column, kind, bytes, packets, conversation count, share of the diagram, transport and
  states. Lists in that readout are capped at `FLOW_DETAIL_LIMIT = 24` distinct values and
  say `+N more` when they are.
* **Clicking a band** opens the largest conversation it carries — by `bytes_total` — in the
  detail pane below.
* **Clicking a node** selects it and lists every conversation behind it in a panel under the
  diagram, and, unless a conversation is already open for that selection, opens the largest
  one behind it straight away. A group node with the `+` marker also toggles that group's
  expansion, so one click both expands and selects it.
* **Clicking a band or node is suppressed for the click that ends a drag**, so panning never
  selects something on the way.

**Viewport.** Zoom and pan are a viewport transform over one group, never a re-layout, so
thickness still means bytes at any zoom and hit testing stays with the browser.

| Control | Effect |
|---|---|
| `+` / `−` | Zoom by ×1.25 / ÷1.25 about the centre; disabled at `FLOW_MAX_SCALE = 4` and `FLOW_MIN_SCALE = 0.4` |
| **Fit** | Back to the whole diagram (`scale 1`, no translation) |
| **1:1** | One diagram unit per screen pixel, whatever the panel width |
| percentage | The current zoom, announced to assistive technology |
| drag | Pan; a press becomes a drag after `DRAG_THRESHOLD_PX = 3` screen pixels, and pointer capture is taken only at that moment. Panning is clamped to `FLOW_PAN_MARGIN = 24` units past the edge |
| wheel | Zoom about the pointer. At either limit the wheel is not swallowed, so the page scrolls instead of zooming |
| arrow keys | Pan by 40 units; `+`/`−` zoom, `0` fits |

Labels are drawn at a constant size on screen, so zooming in gives each node more room and
reveals more labels. Which labels fit is decided by a deterministic collision pass over the
largest nodes first; when any are suppressed the toolbar says `labels shown for the largest
N nodes — zoom in to reveal the rest (every node still has its tooltip)`. A label is never
truncated into nonsense: ports and state names are dropped rather than cut, addresses and
CIDRs shorten by their middle, and a CIDR keeps its prefix length.

Footers under the diagram report the node budget in use (`27` slots per column at this panel
height, `13` for the two IP columns), which column uses the most of the plot, each column's
node count, and every fold that happened.

**The Alerts filter.** A button labelled `Alerts only` in the viewport toolbar, off by
default, toggled by `?alerts=1`.

* With it **on**, the diagram is **filtered, not highlighted**: only the conversations the
  alert endpoint tied to a finding are drawn, and everything else is removed from the
  diagram. So a flagged band keeps the colour its own state gives it, and there is no
  highlight to interpret — the diagram *is* the alert list. What remains on the markup and in
  the hover readout is the evidence: the level, the rule ids, the titles, the finding ids and
  how the element matched.
* The button is disabled when the alert request has not landed, when it failed, or when
  nothing reaches the threshold. It never hides why: the tooltip says either that no alerts
  were found for the analysis at all, or that the analysis has N alerts and *none* at medium
  or higher so there is nothing to filter to, or what the endpoint's own note says. A failed
  request offers a **Retry** and leaves the diagram unaffected.
* Beside it sit chips for `N high` and `N medium`, plus, when some are below the threshold,
  `N below threshold`. **Those are counts of alerts, not of conversations**: one conversation
  can carry several. The legend says so.
* Because the filter is a URL flag, a filtered view is shareable and survives a reload.

**The selection panel**, under the diagram, appears once a node is selected. It lists the
conversations behind that node in the toolbar's sort order, with the count, the summed bytes
and packets, a note when the diagram fetched fewer rows than the filter matched, and a
**Clear selection** button. Sorting here applies to the rows the diagram already fetched;
the Info tab sorts the whole set on the backend. When a node resolves to no rows at all — a
node id that a filter change has invalidated — the panel is replaced by an empty state
offering both ways out (clear the selection, or reset the filters) instead of a dead end.

### 2.4 The Info tab

The `ConversationTable` from `frontend/src/components/streams/ConversationTable.tsx`, one
row per conversation, sorted and paged by the backend.

| Column | Source column | Sortable |
|---|---|---|
| `endpoint A` | `endpoint_a` — the side whose SYN (TCP) or first datagram (UDP) was seen first | Yes |
| `endpoint B` | `endpoint_b` | No |
| `transport` | `transport` | No |
| `stream` | `stream_id` | No |
| `pkts A->B`, `pkts B->A` | `packets_a_to_b`, `packets_b_to_a` | No |
| `pkts` | `packets_total` | Yes |
| `bytes A->B`, `bytes B->A` | `bytes_a_to_b`, `bytes_b_to_a` | No |
| `bytes` | `bytes_total` | Yes |
| `start` | `start_time` | Yes |
| `end` | `end_time` | No |
| `duration` | `duration` | Yes |
| `state` | `state`, as a colour-coded chip | No |
| `protocols` | `protocols`, comma separated | No |

Every number is the indexed value; nothing is re-derived on the page and a missing value
renders an em dash. Rows are focusable and respond to `Enter`/`Space`; a hovered row reveals
copy buttons for both endpoints; the row's tooltip carries the conversation id. Pagination is
the same `Pagination` component as the Packets page: range, page count, page size
(`50`, `100`, `250`, `500`, `1000`; default `100`).

Selecting a row opens the detail pane below the table. When the selected diagram node is a
`state:` node, the Info tab says plainly that the conversations endpoint has no state filter,
so this table is not filtered by it — the selection still lists the right rows under the
diagram, but the table above stays unfiltered.

An empty result is presented as an empty result, not an error: with a filter active it says
no TCP/UDP flow matches those endpoint values and offers to clear the filter; with no filter
it says the analyzer found no TCP or UDP flow, which is what a capture of only ARP or ICMP
traffic produces, and offers the packet browser instead.

### 2.5 The conversation detail pane

`ConversationDetail` in `frontend/src/components/streams/ConversationDetail.tsx`, used by
both the Info tab and the Flow tab — one renderer, never a second one.

* **Header** — `Conversation <conv_id>`, the two endpoints, an **Open in packet browser**
  button and a **Close** button. When the selected conversation is not on the page currently
  loaded, the header says the summary below is limited and that the panes are addressed by
  `transport stream <id>` directly.
* **Summary** — a three-column grid: both endpoints, stream id, packets and bytes in each
  direction and in total, start, end, duration, transport, protocols seen and TCP state. The
  A/B naming follows `endpoint_a`, and a note under the grid says so.
* **Packets in this conversation** — the first `PACKET_PREVIEW_LIMIT = 50` indexed frames of
  that stream in frame order, with a subtitle giving the total and pointing at the packet
  browser for the rest. Clicking a row opens that frame on the [Packets](Packets.md) page.
* **Follow stream** — §2.6.

### 2.6 The stream viewer

`StreamViewer` in `frontend/src/components/streams/StreamViewer.tsx`. The payload always
comes from TShark's own `follow,tcp,<mode>,<stream>` output; nothing on the page concatenates
packets itself.

* **UDP never calls the stream endpoint.** A UDP "stream" has no ordering, and the backend
  deliberately does not synthesise one, so the panel says so and offers the stream's packets
  instead. Presenting an invented ordering would be a guess about application semantics.
* **Rendering mode** — `ascii` (decoded text, UTF-8 with replacement), `hex` (lowercase hex)
  and `raw` (non-printables as `.`), stored in the URL as `smode`; `ascii` is stored as an
  absent key.
* **Export** — four download buttons built from the same URL: `txt` (the reassembled payload
  in the current mode), `hex`, `csv` (the chunk list: index, direction, byte length, hex) and
  `raw` (the exact reassembled bytes as a `.bin`). Each reports the filename and size, or the
  backend's error.
* **Metadata grid** — TShark's node 0 and node 1, which node is the client, both endpoints,
  the stream id, reassembled payload bytes in each direction, packets in the stream, start
  time, duration and the chunk count (with `(N inline)` when only part is listed). Copy
  buttons take the whole client-to-server and server-to-client payload in the current mode.
* **Two payload blocks**, one per direction, labelled `client → server` and
  `server → client`. The label is derived from the response itself — the per-side
  `direction` field first, then TShark's client node, and only then the two TShark nodes by
  name — so the viewer never guesses which side is the client. A block longer than
  `TEXT_RENDER_LIMIT = 10_000` characters is rendered in part and says exactly how many of
  how many characters are on screen, with a button to render everything. The default is
  deliberately small: every rendered character has to be laid out by the browser, and at
  the previous 200,000 a multi-megabyte stream made this page slow to paint.
* **Chunk timeline** — one row per reassembled payload segment in capture order, which is
  what makes direction changes visible: chunk index, direction chip, byte length and a text
  preview (truncated to `PREVIEW_LIMIT = 400` characters on screen, with the hex preview in
  the row's tooltip).
* **Search** — `StreamSearchPanel`, case-insensitive over the reassembled bytes, reporting
  each hit as a direction plus a byte offset inside that direction's payload, with up to 240
  characters of context on either side. Stepping through hits scrolls the chunk timeline to the
  chunk that carried the offset and selects it; when the offset falls in a chunk the backend
  did not return inline, the panel says so instead of highlighting the wrong row.
* **Caps** are stated on screen when they bite: a per-direction rendering is stored up to
  2 MiB of source bytes and at most 500 chunk previews, with the export buttons and the byte
  totals still covering the whole stream.

### 2.7 The Timeline tab

`ConversationTimeline` in `frontend/src/components/streams/ConversationTimeline.tsx`. It
follows **one** conversation, so without a selection it offers to send you to the Info tab
rather than drawing three empty panels. With one selected it renders a summary strip and
three panels, each from its own data:

| Panel | Where its data comes from |
|---|---|
| Summary strip | The selected `conversations` row: state chip, transport, start, end, duration, packet and byte totals, protocols. When the row is not on the current page it says the summary is limited to what the index holds |
| **Packets in this conversation** | `GET /packets?stream_id=<id>&transport=<tcp\|udp>&page_size=50&sort=number&order=asc` — every indexed frame of the stream, shared with the Info tab so both list the same frames in the same order |
| **Timeline of events** | `GET /packets?stream_id=<id>&transport=<tcp\|udp>&filter=<event filter>&page_size=500&sort=number&order=asc` — the frames that carry protocol meaning |
| **Follow stream** | `GET /streams/<id>?mode=` — TShark's reassembly, exactly the panel §2.6 describes |

The event filter is transport-aware, because `tcp.flags` cannot match on a UDP flow and a
filter the backend would reject turns the panel into an error state:

| Transport | Display filter |
|---|---|
| `tcp` | `http or dns or tls or tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1` |
| `udp` | `dns or tls` |

Each event row shows the clock time, a protocol chip, the frame number as a link to the
Packets page, and a label that prefers dissected fields over the raw summary — an HTTP
request reads as `GET /path · host → 200`, a DNS row as `DNS <name>`, a TLS row as
`TLS <sni>` — falling back to TShark's own info line, which for TCP control frames already
carries the flags that make the event meaningful. A chip row above the list gives the event
count by protocol. The panel's subtitle says `first N of M event frame(s)` when the
`EVENT_LIMIT = 500` cap truncates the list, and otherwise how many event frames there were
out of the conversation's indexed total.

The point of the event list is reduction. The code's worked example is the conversation
`tcp:10.4.10.132:49204-217.182.138.150:80` in `sf19us-MTA-lab-09.pcap`, which it says reduces
to its SYN and SYN-ACK, the request and the response that carried the alert, and the RST that
ended it. The frame count in that example is confirmed in the library — that row's
`packets_total` is **2,947** frames of that capture's 4,003 — but the seven-row event list
itself was not re-measured for this document.

## 3. Where the data comes from

| File | What it owns |
|---|---|
| `frontend/src/pages/ConversationsPage.tsx` | The page: URL reading, the three queries, the tab switch, the selection effects, `CONVERSATION_URL_KEYS` |
| `frontend/src/components/conversations/flowLayout.ts` | The graph engine: grouping, folding, layout, bands, labels, viewport maths |
| `frontend/src/components/conversations/ConversationFlow.tsx` | The diagram, legend, viewport controls, hover readout, alerts button |
| `frontend/src/components/conversations/alertOverlay.ts` | Turning the alert response into per-band and per-node evidence |
| `frontend/src/components/conversations/pointerGesture.ts` | Press/drag/click bookkeeping |
| `frontend/src/components/streams/ConversationTable.tsx` | The table, the state chip, the `transport:id` key |
| `frontend/src/components/streams/ConversationDetail.tsx`, `ConversationPackets.tsx`, `ConversationTimeline.tsx`, `StreamViewer.tsx`, `StreamSearchPanel.tsx`, `streamClient.tsx` | The detail panes, the frame lists, the timeline, the stream |
| `backend/app/api/routes_conversations.py` | The conversations list and the three stream endpoints |
| `backend/app/api/routes_findings.py` | `GET /alerts/conversations`, behind the Alerts filter |
| `backend/app/services/stream_analyzer.py` | TShark `follow` reassembly, the caps, the export formats |

### 3.1 The endpoints

| Page action | Request | Endpoint |
|---|---|---|
| Info table, and the whole-analysis totals in the toolbar | `GET /api/analyses/{id}/conversations?transport&ip&port&search&sort&order&page&page_size` | `list_conversations` |
| The Flow diagram | `GET /api/analyses/{id}/conversations?<same filters>&sort=bytes_total&order=desc&page=1&page_size=1000` | `list_conversations` |
| The Alerts filter | `GET /api/analyses/{id}/alerts/conversations` (no parameters, so the endpoint's defaults `min_severity=medium`, `source=all` apply) | `alert_conversations` |
| The stream viewer | `GET /api/analyses/{id}/streams/{id}?mode=ascii\|hex\|raw` | `get_stream` |
| Stream search | `GET /api/analyses/{id}/streams/{id}/search?q=…&mode=…` (built in `streamClient.tsx`) | `search_stream` |
| Stream export | `GET /api/analyses/{id}/streams/{id}/export?mode=…&format=txt\|hex\|csv\|raw` | `export_stream` |
| Frames of a conversation | `GET /api/analyses/{id}/packets?stream_id=<id>&transport=<tcp\|udp>&page_size=50` | `list_packets` |
| Timeline events | `GET /api/analyses/{id}/packets?stream_id=<id>&transport=<tcp\|udp>&filter=…&page_size=500` | `list_packets` |

The Flow tab therefore runs more requests than it looks: the Info list query stays enabled
on every tab (the toolbar totals come from it), the flow query runs while the tab is open,
and the alert query runs only on the Flow tab, because the button exists nowhere else. The
Flow query deliberately does **not** follow the toolbar's sort or paging: it asks for the
1,000 largest conversations by bytes in one request, because the diagram needs every filtered
row rather than one page of them.

### 3.2 Tables behind the page

| Table | Columns read |
|---|---|
| `conversations` | Everything the table shows — `conv_id`, `transport`, `stream_id`, `endpoint_a`, `endpoint_b`, `packets_a_to_b`, `bytes_a_to_b`, `packets_b_to_a`, `bytes_b_to_a`, `packets_total`, `bytes_total`, `start_time`, `end_time`, `duration`, `state`, `protocols` — plus `ip_a`, `port_a`, `ip_b`, `port_b`, which the diagram groups on |
| `streams` | The viewer's metadata: client and server endpoints, payload bytes per side, packet count, start and end time. PK `(analysis_id, transport, stream_id)` |
| `packets` | The frames of a conversation (`stream_id` matched against `tcp_stream` **or** `udp_stream`), and the timeline's event subset |
| `findings` | The Alerts filter: `severity`, `rule_id`, `title`, `packet_numbers`. Each finding's recorded frames are looked up in `packets` to find their stream ids, which are turned into the same `transport:stream_id` keys the diagram uses. A finding whose frames are absent from the index, or which records no frames, is counted in `unlinked_findings` rather than guessed at |

The reassembled payload is not stored: `get_stream` reads the `streams` row and runs TShark's
`follow` on the retained capture each time. That is why the viewer can show bytes the index
never held, and why it needs the file.

### 3.3 The URL parameters this page reads

`CONVERSATION_URL_KEYS` in `ConversationsPage.tsx` lists all 14 keys the page owns; anything
else in the query string is preserved untouched and ignored.

| URL key | Accepted values | What it does |
|---|---|---|
| `transport` | `tcp` or `udp`; anything else is ignored | Filters on `conversations.transport`. Sent as a filter |
| `ip` | text | `ip_a = ? OR ip_b = ?` |
| `port` | digits | `port_a = ? OR port_b = ?` |
| `search` | text | Substring over `conv_id`, `endpoint_a`, `endpoint_b`, `protocols` |
| `sort` | `bytes_total`, `packets_total`, `start_time`, `duration`, `endpoint_a`; anything else falls back to `bytes_total` | Backend sort key |
| `order` | `asc`; anything else (including absent) is `desc` | Sort direction |
| `page` | integer ≥ 1 | Page, Info tab only |
| `page_size` | integer ≥ 1 | Rows per page, default `100`, endpoint maximum `1000`. Info tab only |
| `stream` | `transport:id`, for example `tcp:14` | **The selected conversation.** Parsed by `parseConversationKey`, which requires `tcp` or `udp` before the colon and a finite number after it; `14` alone or `tcp:abc` selects nothing |
| `smode` | `hex` or `raw`; anything else, including absent, is `ascii` | Stream rendering mode |
| `alerts` | exactly `1` | Turns the Alerts filter on; any other value is off |
| `tab` | `info` or `timeline`; anything else, including absent, is `flow` | Which tab is open |
| `node` | a diagram node id, for example `source:10.4.10.0/24`, `sourcePort:443`, `state:established`, `destination:192.0.2.7` | The selected diagram node; whitespace is trimmed and an empty value means none |
| `expand` | comma-separated subnets, for example `192.168.8.0/24,10.4.10.0/24` | The IP groups drawn as their individual addresses. Duplicates are removed and the list is sorted before use |

Four of these are worth stating plainly, because they are how links from other sections and
the diagram's own clicks work:

* **`stream` is a `transport:id` key, not a bare id.** `?stream=tcp:14` is a TCP stream 14;
  `?stream=udp:14` is the UDP stream of the same number. The key is also the identity the
  table, the alert map and the diagram all use, so it is what a link from the
  [Findings](Findings.md) page carries.
* **A node selection is `?node=<column>:<key>`**, and node ids are *not* stable across a
  filter change: a `/24` group that holds two addresses is `source:10.4.10.0/24`, but the
  same subnet holding one observed address is `source:10.4.10.132`. The page drops a
  selection that no longer resolves to any row, once, rather than collapsing around it — and
  a selection that still resolves is left exactly as it is, so tweaking a filter never loses
  it.
* **`expand` holds a list, not a flag**, so several groups can be open at once and the
  expanded chips are shown above the diagram with an `X` on each.
* **`tab`, `alerts`, `node`, `expand`, `stream` and `smode` are view state, not filters.**
  `useUrlFilters` keeps them in a list of non-filter keys, so the toolbar's **Reset** leaves
  the open conversation, the open tab and the expanded groups alone. That is deliberate:
  clearing a filter must not close the conversation being read.

### 3.4 How the Flow tab decides which conversations are drawn

1. The graph is built from the flow query's rows — up to 1,000 conversations matching the
   toolbar filters, largest by `bytes_total` first, so a cap that did bite would keep the
   heaviest flows and say so.
2. If the Alerts filter is on **and** the alert response has landed, those rows are filtered
   down to the ones whose `transport:stream_id` key appears in the endpoint's
   `by_conversation` map. Nothing else survives to be drawn.
3. Every row is then placed in one node per column and one band per layer, so each layer
   carries every conversation exactly once and the sums are checkable.
4. Entities that exceed a column's node budget are folded into a single `N more` node, and
   the fold is reported in a footer line.

`alertOverlay.ts` does the flagging: an element is flagged when any of its `keys` is in the
map, and its level is the worst severity among the keys that matched — `high` or `medium`,
nothing lower is drawn. A node with no key match falls back to the endpoint's `by_ip` map,
which exists for entities the diagram cannot address by stream id; a node matched through its
keys is never overridden by that fallback.

### 3.5 The constants that govern the diagram

| Constant | Value | What it does |
|---|---|---|
| `FLOW_VIEW.width` × `FLOW_VIEW.height` | `1200` × `520` | The viewBox. The SVG scales to its container and matches the viewBox's aspect ratio, so the five columns always fit the panel width |
| `FLOW_VIEW.headerSpace` | `22` | Room for the column headings |
| `FLOW_VIEW.gap` | `4` | Vertical space between two nodes of a column |
| `FLOW_VIEW.minNodeHeight` | `14` | The smallest slot a column budgets for a node, a little taller than one label line so a full slot can carry its own label |
| `FLOW_VIEW.nodeWidth` / `stateWidth` | `11` / `80` | Width of an address or port bar, and of the labelled state box |
| `FLOW_VIEW.gutter` | `170` | Room reserved for the outer column labels |
| `flowNodeBudget()` | `27` at the default height | Node slots per port/state column: `floor((498 + 4) / (14 + 4))` |
| `flowIpNodeBudget()` | `13` | Slots for the two IP columns, half the shared budget: a long address list adds height without adding information, so the IP columns fold sooner |
| `FLOW_MIN_BAND` | `1.5` | The thinnest band, in viewBox units, and the floor each layer's thickness scale adds |
| `FLOW_MIN_SCALE` / `FLOW_MAX_SCALE` | `0.4` / `4` | Zoom limits |
| `FLOW_PAN_MARGIN` | `24` | How far the diagram may be pulled past the edge of the view |
| `DRAG_THRESHOLD_PX` | `3` | How far a press may move before it counts as a drag and consumes the following click |
| `FLOW_LABEL_PX`, `FLOW_LABEL_SCREEN_HEIGHT`, `FLOW_LABEL_HEADROOM`, `FLOW_LABEL_MIN_CHARS` | `10`, `13`, `1.15`, `4` | Label size on screen, the height one line needs, the headroom a node must have before it may carry a label, and the fewest characters worth drawing |
| `FLOW_DETAIL_LIMIT` | `24` | Distinct values a tooltip may name before it starts counting instead |
| `EVENT_LIMIT` | `500` | Timeline event frames listed |
| `PACKET_PREVIEW_LIMIT` | `50` | Frames listed inline by **Packets in this conversation** |
| `FLOW_PAGE_SIZE` | `1000` | The diagram's request size — the endpoint's maximum |
| `DEFAULT_PAGE_SIZE` | `100` | The Info table's page size |
| `MAX_PAGE_SIZE` (backend) | `1000` | The largest `page_size` the conversations endpoint accepts |
| `MAX_SUMMARY_BYTES` (backend) | `2 × 1024 × 1024` | Per-direction rendering stored inline |
| `MAX_CHUNKS` (backend) | `500` | Chunk previews returned inline |
| `MAX_SEARCH_MATCHES` (backend) | `500` | Hits the stream search returns before it stops and flags `truncated` |
| `TEXT_RENDER_LIMIT`, `PREVIEW_LIMIT`, `CONTEXT_CHARS` | `10_000`, `400`, `240` | Characters rendered in a payload block, in a chunk preview row, and around each search hit |

What the caps do when they bite:

* **The flow fetch (1,000 rows).** The diagram's subtitle changes to `showing the top N of M
  conversations by bytes`, the selection panel adds the same sentence, and the rows that were
  dropped are the smallest ones, by construction. Measured in the library: the largest
  capture, `sf19us-MTA-lab-01.pcap`, holds **195** conversations and the flow fetch returns
  195 of 195, so this cap does not bite anywhere in the library today.
* **A column's node budget.** The fold is drawn as a labelled node and reported in the
  footer. Measured on `sf19us-MTA-lab-01.pcap`, whose 195 conversations carry 2 source IP
  groups, **193** source ports, 3 states, 13 destination ports and **52** destination IP
  groups: the source-port column keeps 26 ports and folds the remaining **167** into one
  node, and the destination-IP column keeps 12 groups and folds **40** — while the
  destination-port column and the state column fit without folding. Both source groups on that
  capture hold a single observed address (`192.168.1.103` and `162.243.48.117`), so each is
  drawn under its own address with no `+` marker.
* **The stream caps.** A warning block above the payload blocks names what was capped, and
  says that the export buttons still download the whole stream and that the byte totals are
  always the true ones.

### 3.6 What the Alerts filter actually selects

These figures were measured in the library in `data/`, by replaying the endpoint's own join —
each finding's recorded frame numbers looked up in `packets`, their stream ids turned into
`transport:stream_id` keys, and those keys intersected with `conversations`: the same
algorithm `alert_conversations` runs, read from the database rather than from a live request.

| Figure | Value | Capture |
|---|---|---|
| Medium-or-higher findings | 9 | `sf19us-MTA-lab-01.pcap` |
| Conversations those findings resolve to | 34 of 195 | `sf19us-MTA-lab-01.pcap` |
| Findings that could not be placed on the diagram | 0 | `sf19us-MTA-lab-01.pcap` |

Across the library's 22 analyses, 12 have at least one medium-or-higher finding, which is
what enables the button; the remaining 10 have no findings at all, so the button is disabled
and its tooltip says so. No analysis in the library has findings that are *all* below medium,
so the "none at medium or higher" wording is present in the code but is not exercised by this
data.

## 4. Links into the rest of the app

| Element | Opens |
|---|---|
| Band click | `?stream=<transport>:<id>` — the largest conversation behind the band, in the pane below |
| Node click | `?node=<node id>`, and `?expand=<subnet>` for a group with more than one address; the conversations behind it are listed under the diagram, and the largest one opens in the pane below |
| Selection panel row | `?stream=<transport>:<id>` for that conversation |
| **Open in packet browser** (detail pane, timeline, UDP note) | `/packets?mode=basic&stream_id=<id>` — see below |
| Frame link on the Timeline tab, and a row of **Packets in this conversation** | `/packets?mode=basic&stream_id=<id>&sel=<frame>` |
| The Info table's empty state, with no filter active | `/packets` — the packet browser unfiltered |
| The Timeline tab with nothing selected | The Info tab, so a conversation can be chosen |

The outbound packet links carry `stream_id` but **no `transport`**, and the
packets endpoint matches `tcp_stream` *or* `udp_stream`. In the library, 14 of the 22
analyses have TCP and UDP stream ids that overlap — `sf19us-MTA-lab-01.pcap` has both a TCP
and a UDP stream `0` through `9` — so such a link can list both transports' frames of that
number. The
[Packets](Packets.md) page's `transport` filter is what separates them, and its stream chip
can be removed without disturbing the rest of the filter.

Pages that link in:

| Source | Link |
|---|---|
| [Dashboard](Dashboard.md) | `/conversations` — the section entry |
| [Hosts](Hosts.md) host detail | `/conversations?ip=<address>` |
| [Findings](Findings.md) **Follow conversation** | `/conversations?stream=tcp:<id>&tab=timeline` — the conversation, open on the Timeline tab |
| Threat Hunt pages | `/conversations?ip=<address>&tab=info`, the form the per-detection documents use |

The alert chips do not link anywhere: they are counts. The findings themselves are read on
[Findings](Findings.md), which is where the rule, the severity and the evidence live.

## 5. Limits and honest caveats

* **The page cannot work from the index alone.** `list_conversations`, the alert endpoint and
  the stream endpoints all begin with `analysis_ready_row`, which resolves the retained
  capture on disk and raises `410 capture_missing` when the upload has been purged. The
  timeline's event filter runs TShark, and the stream viewer reassembles with it. Only the
  `conversations` table itself is index-only, and it is not reachable without the file.
* **`stream` is not the whole identity of a conversation.** The stream endpoint path carries
  the numeric id only, and `stream_analyzer._stream_row` prefers the TCP row when an id
  exists for both transports — TCP being the only transport TShark can reassemble. The page
  avoids asking for the UDP row at all: the stream query is disabled unless the selected
  transport is TCP. A hand-written `?stream=udp:5` therefore shows the UDP explanation and
  never calls the endpoint.
* **`transport=other|sctp` is not a value this page accepts.** Only `tcp` and `udp` are read;
  anything else is treated as no filter, is not counted as an active filter for the **Reset**
  button, and leaves the key sitting in the URL.
* **The diagram is drawn from a different request than the table.** It ignores the toolbar's
  sort and paging (it asks for the 1,000 largest by bytes), so a toolbar sort changes the
  Info table and the *order of the selection panel's rows*, not the diagram's geometry. The
  selection panel's sorting is local to the rows the diagram already fetched — a limited set
  — which is why it says so under the list.
* **A band's thickness is proportional to bytes only above the floor, and the floor is
  dropped rather than the proportions.** Where a layer has more bands than its height can give
  1.5 px each, the whole layer is scaled down proportionally so thickness still means bytes;
  the legend prints the thinnest band on screen, so a reader can see when the floor is in
  play. Thickness is never a count of packets, and a band carrying a thousand tiny flows looks
  exactly like a band carrying one large one.
* **Folding hides entities, and only the count is guaranteed.** A folded node's members are
  listed in its tooltip up to `FLOW_DETAIL_LIMIT = 24` values; the node itself remains
  selectable and its conversations are real, but a specific folded address or port has to be
  found by expanding, filtering, or reading the tooltip's `+N more` count.
* **Labels are dropped when they do not fit**, on purpose: a label that would leave the
  viewBox or touch its neighbour is not drawn. Every node keeps its tooltip, and the node's
  identity is also in the selection chip once selected, and in the list under the diagram.
* **Subnet grouping is `/24` for IPv4 and `/64` for IPv6, with no option to change it.** A
  capture whose hosts spread across many `/24`s folds those groups rather than showing
  individual addresses; a `/24` holding one observed address is shown as that address, so the
  same subnet can legitimately appear under two different labels before and after a filter
  change. This is why a stale `?node=` selection is dropped rather than kept.
* **`state` is derived from the TCP flags that were actually observed**, and `unknown` is the
  normal reading for UDP and for a stream the analyzer could not classify. It is not a
  verdict about a connection's intent, and a capture that starts mid-connection will show
  `unknown` or `half_open` for traffic that was in fact established.
* **The Alerts filter is a filter, not a highlight, and it depends on frame numbers.**
  A finding is placed on the diagram only through the frames it records: a finding with no
  frame numbers, whose frames are absent from the index, or whose frames carry no stream id
  cannot be placed, and is counted in `unlinked_findings` with a warning line under the
  diagram. When `packets_truncated` is set, only part of each finding's frames were scanned
  and the page says that some links may be missing. The counts beside the button are counts
  of *alerts*, and one conversation can carry several.
* **Only `high` and `medium` are drawn or filtered on.** Lower severities are counted in a
  `N below threshold` chip and otherwise ignored; the page sends no `min_severity` parameter,
  so the endpoint's own default of `medium` and its default `source=all` (both the imported
  Suricata rules and the built-in engine) apply.
* **While the alert request is in flight the diagram is not yet filtered.** The filtering
  set is null until the response lands, so a flagged view briefly shows every conversation;
  the button carries an ellipsis while the request is busy, and the chips appear when it
  returns.
* **UDP has no reassembled stream, and the page will not invent one.** The viewer says so and
  points at the frame list instead; the stream search and the four stream export formats are
  unavailable for a UDP conversation for the same reason.
* **Reassembly is TShark's, with TShark's rules.** Sequence numbers, retransmissions and
  out-of-order segments are handled by `follow`, not by this page; a stream TShark cannot
  reassemble produces an error state. `raw` mode exports the reassembled payload in capture
  order, which is not the same as the bytes on the wire.
* **The stream caps are real and partial.** A per-direction rendering stores up to 2 MiB of
  source bytes and at most 500 chunk previews; the warning block names which cap bit. Byte
  totals and the export buttons are unaffected, but a search hit whose offset falls outside
  the chunks returned inline cannot be highlighted.
* **A conversation the analyzer did not derive is invisible here.** Only TCP and UDP flows
  become `conversations` rows, so a capture of ARP, ICMP or other traffic shows an empty
  table — which is an empty result, stated as one, not an error. The frames themselves are
  still on the [Packets](Packets.md) page.
* **The diagram's first paint depends on the whole filtered set.** It is one request for up
  to 1,000 rows plus the alert request, so on a large filtered set the Flow tab is the
  heaviest view in the section; the panel dims and its action line reads `updating the
  diagram…` while a new set is on its way, and keeps drawing the previous one.
* **Nothing here proves intent.** A long-lived stream, a `reset` state, a large transfer and
  a flagged conversation are all leads. A conversation drawn from one alert is a reason to
  read its frames on the [Packets](Packets.md) page, not a conclusion.

## 6. Related

**Related:** [Packets](Packets.md) · [Hosts](Hosts.md) · [Findings](Findings.md) · [Dashboard](Dashboard.md) · [Threat Hunt](Threat-Hunt.md) · [HTTP](HTTP.md) · [DNS](DNS.md) · [TLS](TLS.md) · [Reference/API](Reference/API.md)
