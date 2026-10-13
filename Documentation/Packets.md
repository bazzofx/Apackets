# Packets (`/packets`)

The packet browser: a dense, sortable table of every indexed frame, filtered either by
typed fields (indexed SQL) or by a raw Wireshark display filter (TShark), with
next/previous match navigation, the decoded layer tree and hex/ASCII dump of one frame,
and a CSV export of exactly the current filter.

The page is `frontend/src/pages/PacketsPage.tsx` (default export `PacketsPage`, mounted on
`/packets` in `frontend/src/App.tsx`); its pieces live in
`frontend/src/components/packets/`. The endpoint behind it is
`backend/app/api/routes_packets.py`. Where this document and
[`docs/CONTRACT.md`](../docs/CONTRACT.md) disagree, the contract is normative for the API
shape and this document records what the running build does; where the code and the
contract disagree about behaviour, the disagreement is written down rather than smoothed
over.

The page is wrapped in the shared `AnalysisGuard`, so with no analysis selected it shows
the upload prompt, and while an analysis is still processing it shows the progress bar
from `frontend/src/components/AnalysisGuard.tsx` instead of the table.

---

## 1. What it is for

Every other section answers a question about the capture; this one answers *"what is
actually on the wire, frame by frame, and what do those bytes contain?"* It is the page an
analyst lands on to confirm something another section only suggested: the exact flags on
the frame that reset a connection, the Host header in one request, the raw bytes of a
payload. It is also the page built to be *linked into* with a specific frame already
selected, and — with [Conversations](Conversations.md) — one of only two pages that read the
retained capture again rather than only the index: the layer tree and the byte dump below the
table come from TShark, not from the database.

Two filter modes exist and are deliberately never combined: **basic**, where each field
becomes an indexed SQL predicate over `packets`, and **advanced**, where one Wireshark
display filter is compiled and executed by TShark against the retained capture and its
matching frame numbers are joined against the index. Only the active mode is ever sent to
the API.

## 2. What is on the screen

### 2.1 The filter bar

`PacketFilterBar` in `frontend/src/components/packets/PacketFilters.tsx` is the whole
strip, in one panel above the table.

| Control | What it does |
|---|---|
| **Basic** / **Advanced** buttons | Switch the active mode. The inactive half is explicitly labelled as ignored: in advanced mode the typed fields disappear and the strip says *"the typed basic fields above are ignored while advanced mode is on"*. Only the active mode is sent to the API. |
| rows counter | The number of rows the current filter matches, taken from the list response's `total`. It is blank while the response is an error or an invalid filter. |
| **Prev match** / **Next match** | Step to the previous/next frame matching the *display-filter form* of the current filter. See §2.4. |
| traversal expression | The display filter the buttons step through, truncated on screen, with the full text and any approximation notes in the tooltip. Reads `not traversable` in red when TShark rejects that expression. |
| **CSV** | Download every frame matching the current filter, capped by the backend. Reports `exported N of M matching rows · packets-xxxxxxxx.csv` below the strip, and warns when the backend capped the file. Disabled while the filter is invalid. |
| **Reset** | Clear the filter. It is also enabled whenever a packet is selected, and then clears the selection too (it is disabled only when no filter is active *and* nothing is selected). |

In **basic** mode the fields below are drawn. Each numeric input keeps digits only
(`digitsOnly`), so a malformed port or length cannot reach the API as a validation error.

| Field | Meaning |
|---|---|
| `search` | Substring match over `info`, `protocol`, `src_ip` and `dst_ip` |
| `ip` | Either endpoint matches this address exactly |
| `src ip`, `dst ip` | One endpoint matches exactly |
| `port` | Either port equals this value |
| `src port`, `dst port` | One port equals this value |
| `protocol` | Exact display protocol, compared case-insensitively by the backend. A datalist offers the display protocols the list most often shows (`TCP`, `UDP`, `HTTP`, `DNS`, `TLS`, `ICMP`, `ARP`, `SMB2`, `SSH`, `DHCP`), as hints only |
| `transport` | `any` / `tcp` / `udp` |
| `tcp flags` | A substring of TShark's 12-character `tcp.flags.str`. Datalist hints: `S`, `SA`, `A`, `PA`, `FA`, `RA`, `R`, `AS`, `AP` — see §5 for what those actually match |
| `min len`, `max len` | `frame_len` bounds, in bytes |
| `from`, `to` | Frame time bounds, entered as local `datetime-local` values and stored in the URL as epoch seconds |

In **advanced** mode the strip draws one `display filter` textarea (contents passed to
TShark verbatim) and six example chips that fill it: `ip.addr == 192.168.1.10`,
`tcp.port == 443`, `dns`, `http`, `tls.handshake.type == 1`,
`tcp.flags.syn == 1 && tcp.flags.ack == 0`.

When the URL carries `stream_id`, a chip appears next to the fields reading `stream <n>`
with an `X` to remove it. That chip is set by a link from the
[Conversations](Conversations.md) page; there is no field to type it into.

### 2.2 The table

`PacketTable` in `frontend/src/components/packets/PacketTable.tsx`. Ten columns, dense
rows, monospace data, no payload bytes — the list endpoint never returns payloads.

| Column | Source field | Sortable |
|---|---|---|
| `#` | `frame.number` | Yes |
| `time` | `frame.time_epoch` | Yes |
| `source` | `ip.src` / `ipv6.src` | Yes |
| `sport` | `tcp.srcport` / `udp.srcport` | Yes |
| `destination` | `ip.dst` / `ipv6.dst` | Yes |
| `dport` | `tcp.dstport` / `udp.dstport` | Yes |
| `protocol` | `_ws.col.Protocol` | Yes |
| `len` | `frame.len` | Yes |
| `tcp flags` | `tcp.flags.str`, with the `·` padding shown as `.` | No — not in the sort allow-list |
| `info` | `_ws.col.Info` | No — not in the sort allow-list |

Clicking a header sorts by it; clicking the active header flips the direction. The
comparison is performed by the backend over the whole filtered set, not over the page, and
the request sends the sort key and direction to the endpoint. Rows are focusable
(`tabIndex=0`) and respond to `Enter` or `Space` as well as a click. A hovered or focused
row reveals copy buttons for the source IP, source port, destination IP, destination port
and info text. A row's tooltip carries the frame's full dissection chain (`protocols`).

An em dash marks a value the packet does not have — a port on an ARP or ICMP frame, for
instance — and is never a zero.

### 2.3 Pagination

`frontend/src/components/Pagination.tsx`, below the table: the visible range, the current
page and page count, a page-size select (`50`, `100`, `250`, `500`, `1000`; default `100`)
and previous/next buttons. Changing any filter returns to page 1; changing the page size
does too; changing the page or the sort does not.

### 2.4 Next/previous match

`PacketNavigator` in `frontend/src/components/packets/PacketNavigator.tsx`. The neighbours
endpoint understands only a Wireshark display filter, so the current filter is first
translated by `buildNeighborFilter` (in `PacketFilters.tsx`) into an equivalent display
filter — the same translation table is in §3.3. Three things are visible here:

* the buttons are disabled until a packet is selected, because traversal needs a starting
  frame, and while the list itself is loading;
* the expression being stepped through is printed on the strip, and the tooltip carries
  every approximation note;
* when the display-filter set and the filtered list disagree in size, the strip shows
  `traversal set differs (N vs M)` and the tooltip explains which set the buttons walk.

When a direction runs out of matches the endpoint answers `packet_number: null` with
`boundary: true`; that is a real answer, so the button turns itself off rather than showing
an error. The navigator validates the derived expression through `POST /filter` before it
is used, so a translation TShark refuses disables the buttons with the reason instead of
failing a click.

### 2.5 Invalid filter versus zero matches

`frontend/src/components/packets/FilterStateNotice.tsx` keeps these two apart, which is the
point of the page's error handling:

| State | What is drawn |
|---|---|
| **Invalid filter** | The `Invalid display filter` panel: the `422 invalid_filter` chip, the backend's message, the expression echoed back (advanced mode only), and TShark's own reason. Above the table, in place of it. This is a syntax error: no rows were evaluated. |
| **Valid filter, zero matches** | The `0 packets match this filter` empty state below the strip, worded so it cannot be read as an error: how many basic filters are active, or which display filter was accepted, plus the capture's own indexed packet count so the zero can be seen as a real answer. A capture whose index is genuinely empty says so instead. |

A third state is neither: when the request fails for any other reason the page shows the
plain error state with a retry.

### 2.6 The packet detail pane

`PacketDetailPanel` in `frontend/src/components/packets/PacketDetailPanel.tsx`, drawn
whenever `?sel=` names a frame; when nothing is selected the page shows a short prompt
instead.

* **Header** — `Packet <n>`, with the dissection chain, the frame length and the info line
  as a subtitle, a **Reload** button that re-reads the frame from the capture, and
  **Close**.
* **Summary** — a three-column grid of 23 items: time, time since the first frame, frame
  length, source, source port, destination, destination port, protocol, transport, TCP
  flags, dissection chain, TCP stream, TTL/hop limit, VLAN id, IP version, source MAC,
  destination MAC, HTTP request line, HTTP host, HTTP status, DNS query name, TLS SNI and
  TLS version. An absent field renders an em dash with the reason in its tooltip — the pane
  never prints `null` and never invents a value.
* **Protocol layers** — `LayerTree` in `LayerTree.tsx`, rendered from the API's `layers`
  object as ordered collapsible sections, one per layer, with a field count per layer. The
  first three layers start expanded. `frame` is pinned first (it is not part of
  `frame.protocols`), any layer present in `layers` but absent from the dissection chain is
  listed last, and a layer named in the chain but missing from `layers` is reported in a
  warning strip. An array of primitives is shown inline; an array of objects becomes a
  sub-tree; a value longer than 400 characters is collapsed behind a `N chars` toggle; an
  object nested deeper than 8 levels is not expanded.
* **Bytes** — `HexDumpView` in `HexDumpView.tsx`, with two views: `Hex + ASCII` (offset,
  hex and ASCII, 16 bytes per row) and `Text` (the ASCII rendering of the captured bytes,
  non-printables as `.`). The header reports how many bytes were captured, how many dump
  rows came back, and offers a copy of the raw hex.

When the selected frame is not on the page being displayed, the page says so above the
detail pane: the pane is loaded by frame number from the capture, so it is still accurate.

### 2.7 CSV export

The **CSV** button fetches `packets/export.csv` itself rather than navigating to it, so it
can report the numbers the backend sends back. The file has ten columns, exactly:
`number, time, src_ip, src_port, dst_ip, dst_port, protocol, length, tcp_flags, info`.
`time` is ISO-8601 UTC with microseconds, `tcp_flags` uses `.` where the table does, and
newlines and carriage returns in `info` are replaced with spaces. The filename is
`packets-<first 8 characters of the analysis id>.csv`. The export follows the current
filter, sort and order, and never the current page: it is the whole filtered set, capped by
the backend.

## 3. Where the data comes from

| File | What it owns |
|---|---|
| `frontend/src/pages/PacketsPage.tsx` | The page: URL reading, the request set, the state notices, the layout |
| `frontend/src/components/packets/PacketFilters.tsx` | Filter state, URL keys, the parameter mapping, the neighbour-filter derivation |
| `frontend/src/components/packets/PacketTable.tsx` | The column list and the sort headers |
| `frontend/src/components/packets/PacketNavigator.tsx` | Traversal, boundary handling, expression validation |
| `frontend/src/components/packets/FilterStateNotice.tsx` | Invalid-filter and zero-match states |
| `frontend/src/components/packets/PacketDetailPanel.tsx`, `LayerTree.tsx`, `HexDumpView.tsx` | Detail, layers, bytes |
| `frontend/src/components/packets/DownloadAction.tsx` | The download button and the header report |
| `frontend/src/components/protocols/ProtocolFilters.tsx` | `useUrlFilters` (the URL-backed filter machinery) and the strip layout |
| `backend/app/api/routes_packets.py` | Every endpoint the page calls |
| `backend/app/api/deps.py` | Pagination (`MAX_PAGE_SIZE`), sort and order resolution, readiness gating |

### 3.1 The endpoints

| Page action | Request | Endpoint |
|---|---|---|
| The table, on every filter/page/sort change | `GET /api/analyses/{id}/packets?…` | `list_packets` |
| Selecting a frame | `GET /api/analyses/{id}/packets/{number}` | `get_packet` |
| **Prev match** / **Next match** | `GET /api/analyses/{id}/packets/{number}/neighbors?filter=…&direction=next\|prev` | `packet_neighbors` |
| Validating the traversal expression (once per expression, 5-minute cache) | `POST /api/analyses/{id}/filter` with `{"filter": …, "page_size": 1}` | `apply_filter` |
| **CSV** | `GET /api/analyses/{id}/packets/export.csv?…` | `export_packets_csv` |
| The page shell (analysis name, status, `packet_count` for the empty state) | `GET /api/analyses` and `GET /api/analyses/{id}` | `useAnalysis` / `AnalysisGuard` |

### 3.2 Tables behind the page

| Table | Columns read |
|---|---|
| `packets` | The whole `SUMMARY_COLUMNS` list: `number`, `time_epoch`, `time_relative`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `transport`, `frame_len`, `tcp_flags`, `info`, `protocols`, `eth_src`, `eth_dst`, `vlan_id`, `ttl`, `ip_version`, `dns_query`, `http_method`, `http_host`, `http_uri`, `http_status`, `tls_sni`, `tls_version`, `tcp_stream`. The list query reads all of them; the table renders ten |
| `packets.tcp_stream`, `packets.udp_stream` | The `stream_id` filter matches *either* column |
| `analyses.packet_count` | The "the capture has N indexed packets" sentence in the zero-match state |

The layer tree and the byte dump are **not** in the database: `get_packet` reads the
summary row from `packets` and then runs TShark again on the retained capture
(`tshark.packet_json` and `tshark.packet_hexdump`), so the pane shows the dissection rather
than the index. An advanced display filter is likewise evaluated by TShark
(`tshark.matching_frame_numbers`); its frame numbers are loaded into a temporary table and
joined against `packets` so the result set is still served from SQLite.

### 3.3 The URL parameters this page reads

`PACKET_FILTER_URL_KEYS` in `PacketFilters.tsx` lists all 22 keys the page owns; anything
else in the query string is preserved untouched and ignored. `mode` is the only key that
decides which half of the filter is applied, and it is written only when it is advanced —
an absent `mode` means basic.

| URL key | Read as | Sent to the API as | Meaning |
|---|---|---|---|
| `mode` | `advanced` → advanced mode, anything else → basic | not sent | Which half of the filter is applied |
| `search` | text | `search` | Substring over `info`, `protocol`, `src_ip`, `dst_ip` |
| `ip` | text | `ip` | Either endpoint equals exactly |
| `src_ip` | text | `src_ip` | Source equals exactly |
| `dst_ip` | text | `dst_ip` | Destination equals exactly |
| `port` | digits | `port` (number) | Either port equals |
| `src_port` | digits | `src_port` | Source port equals |
| `dst_port` | digits | `dst_port` | Destination port equals |
| `protocol` | text | `protocol` | Exact display protocol, case-insensitive |
| `transport` | `tcp` or `udp`; any other value is **not** sent | `transport` | Indexed transport |
| `tcp_flags` | text | `tcp_flags` | Substring of `tcp.flags.str` |
| `min_length` | digits | `min_length` | `frame_len >=` |
| `max_length` | digits | `max_length` | `frame_len <=` |
| `start_time` | epoch seconds as a string | `start_time` | `time_epoch >=` |
| `end_time` | epoch seconds as a string | `end_time` | `time_epoch <=` |
| `filter` | raw expression | `filter` | **Advanced mode only**; ignored in basic mode |
| `stream_id` | number | `stream_id` | Matches `tcp_stream` **or** `udp_stream`. Set by the Conversations link, shown as a removable chip |
| `sort` | one of the eight sort columns | `sort` | A value outside the page's allow-list silently falls back to `number` |
| `order` | `desc` → descending, anything else → ascending | `order` | Sort direction |
| `page` | integer ≥ 1 | `page` | 1-based page |
| `page_size` | integer ≥ 1 | `page_size` | Rows per page; default 100, endpoint maximum 1000 |
| `sel` | integer > 0 | **not sent** | The frame number shown in the detail pane |

Three of these deserve emphasis because links from other sections depend on them:

* **A selection is `?sel=<frame number>`**, not `?number=`. `sel` is read as a number,
  anything `<= 0` means "nothing selected", and it is never sent to the API: the detail
  pane is fetched by frame number from the capture, so the selection survives a filter
  change, a sort change and a page change, and the page says so when the frame is not on
  screen. `?number=42` is ignored entirely.
* **`stream_id` is an ambiguous key on its own**, because the predicate is
  `p.tcp_stream = ? OR p.udp_stream = ?`. Measured in the library in `data/`: 14 of the 22
  analyses have TCP and UDP stream-id namespaces that overlap — `sf19us-MTA-lab-01.pcap`
  has both TCP and UDP ids `0` through `9`. The Conversations page's
  **Open in packet browser** link sends `mode=basic&stream_id=<id>` and no `transport`, so
  such a link can list both a TCP and a UDP stream of that number. Adding `transport=tcp`
  or `transport=udp` to the link is what disambiguates it, and the chip can be removed
  without touching the rest of the filter.
* `tcp_flags` is a substring match on TShark's `tcp.flags.str`, which is a 12-character
  string such as `·······AP···`, not Wireshark's filter spelling. `SYN` therefore matches
  nothing; `S` matches SYN frames. See §5 for the measured detail, including the hints the
  UI offers that cannot match.

Two smaller notes on the time keys: the `from` and `to` inputs write epoch seconds, while the
endpoint also accepts an ISO-8601 timestamp (contract §5) — so a hand-written
`?start_time=2024-01-01T00:00:00Z` filters correctly but leaves the `datetime-local` input
blank, because the input can only render a numeric epoch. And `min_length`, `max_length`,
`start_time` and `end_time` are sent as strings, so a value outside what the endpoint
validates is a validation error rather than a filter (see §5).

The translation `buildNeighborFilter` uses for traversal, verified in the source comments
against the live backend by comparing list totals with `POST /filter` totals:

| Basic field | Display filter it becomes |
|---|---|
| `ip` | `(ip.addr == A)` |
| `src_ip`, `dst_ip` | `(ip.src == A)` / `(ip.dst == A)` |
| `port` | `(tcp.port == P \|\| udp.port == P)` |
| `src_port`, `dst_port` | `(tcp.srcport == P \|\| udp.srcport == P)`, and the `dstport` pair |
| `protocol` | `_ws.col.protocol matches "(?i)^X$"` (an exact, case-insensitive match) |
| `transport` | `tcp` or `udp` |
| `tcp_flags` | `tcp.flags.str contains "X"` |
| `min_length`, `max_length` | `frame.len >= N` / `frame.len <= N` |
| `start_time`, `end_time` | `frame.time_epoch >= S` / `frame.time_epoch <= S` |
| `stream_id` | `(tcp.stream == N \|\| udp.stream == N)` |
| nothing at all | `frame.number >= 1` — every frame |
| `search` | the one approximation: `_ws.col.info` and `_ws.col.protocol` matched case-insensitively, plus `ip.src`/`ip.dst` **exact** equality when the term looks like an address; the notes are surfaced in the tooltip |

## 4. Links into the rest of the app

This page is a **destination**: it links nowhere else. Its elements select frames and
export files; they do not navigate. What it opens, and what opens it:

| Element | Effect |
|---|---|
| A table row, or `?sel=` | Selects a frame in place. No navigation |
| **Open in packet browser** on [Conversations](Conversations.md) | `?mode=basic&stream_id=<id>` — the stream's frames, with the stream chip set |
| A frame link on the Conversations Timeline tab | `?mode=basic&stream_id=<id>&sel=<frame>` — the stream's frames with that frame decoded |
| A pivot on [Findings](Findings.md) | `?ip=<address>` or `?ip=<address>&port=<port>` |
| A signature match or entity pivot on Findings | `?sel=<frame>` — one frame |
| The Threat Map pages | `?mode=basic&sel=<frame>`, with `&stream_id=<id>` and `&transport=udp` added where the detection recorded a stream — the form the per-detection documents use |
| **CSV** | A file download, not a route |

The fields the page displays are the same ones the protocol sections document in detail:
an HTTP request line, host and status are dissected on [HTTP](HTTP.md), a query name on
[DNS](DNS.md), an SNI and a version on [TLS](TLS.md). Files extracted from a capture are
listed on [Files and Objects](Files-and-Objects.md). The normative parameter list is
[`docs/CONTRACT.md`](../docs/CONTRACT.md) §5, and the packet summary and detail shapes are
§7 of the same document.

**Right-clicking a source or destination address** opens the application's address menu:
**Pivot <ip> to Hunt**, **Show Conversations with <ip>**, and **Pivot to Wireshark** — here
the last one opens the capture filtered to every frame the address appears in, jumped to the
first of them, since a packet row is one frame rather than a conversation. See
[Architecture.md](Architecture.md) §6.1 and §6.2.

## 5. Limits and honest caveats

* **The page cannot work from the index alone.** Every endpoint it calls begins with
  `analysis_ready_row`, which resolves the retained capture on disk and raises
  `410 capture_missing` when the upload has been purged. That is true even of the plain list
  request, because the display filter, the neighbours endpoint and the packet detail all run
  TShark. Unlike [Threat Map](Threat-Hunt.md), this page has no index-only mode.
* **The two filter modes never compose.** Only the active mode is sent: in basic mode the
  `filter` key is ignored, in advanced mode every typed field is ignored. Values typed in
  one mode stay in the URL and reappear when you switch back, but they never affect the
  other mode's result. `activeFilterCount` counts only the active mode, so the **Reset**
  button's enabled state follows that mode too.
* **A 422 is always shown as an invalid filter.** `filterDiagnostics` classifies any error
  with `status === 422` (or `code === 'invalid_filter'`) as invalid, so two other things are
  dressed as a Wireshark syntax error: a `filter_timeout` from a display filter that took
  too long, and FastAPI's own parameter-validation 422 — reachable from the UI, since
  `port`, `src_port` and `dst_port` accept up to ten digits and the endpoint requires
  `0..65535`. In both cases the panel's "TShark reported" block is empty and says the
  backend attached no reason.
* **The page's sort allow-list is narrower than the endpoint's.** `routes_packets.py`
  accepts `length` and `time_relative` as sort keys; `PACKET_SORT_COLUMNS` does not, so
  `?sort=length` is silently replaced by packet number, ascending. The endpoint itself
  answers `400 invalid_sort` for a key outside its own list, but the page never sends one.
* **Page size.** The page defaults to 100 rows and the footer offers up to 1000; the
  endpoint rejects anything above `MAX_PAGE_SIZE = 1000` with a validation error (which the
  invalid-filter notice then mislabels, as above). The library's largest capture,
  `sf19us-MTA-lab-01.pcap`, holds 4,500 indexed frames — 45 pages at the default size — so
  nothing here needs the top of the range.
* **The display filter is capped** at `MAX_FILTER_ROWS = 500_000` frame numbers per
  evaluation, and a filter that times out in TShark is reported as an error rather than
  partially applied. Neither cap is reachable in this library: the largest capture holds
  4,500 frames.
* **CSV export is capped at 200,000 rows** (`settings.max_export_rows`). When the cap bites
  the file is short and the page says so in a warning strip, quoting `X-Total-Rows` and
  `X-Exported-Rows`; if those headers are not readable, the report degrades to "exported a
  CSV file" rather than guessing. The export carries ten columns and no payload bytes, so it
  is smaller than what the screen shows — the frame length and flags are there, the
  dissection is not.
* **The detail pane is a second reading of the capture, not a re-render of the row.** The
  layers and bytes come from separate TShark invocations; if either fails, the backend logs
  a warning and returns empty layers/bytes, and the pane says the dissection or the byte
  read failed instead of inventing content. A frame number that is not in the index gives
  `404 packet_not_found` and an error state, not an empty pane.
* **Caps inside the detail pane.** The text rendering is capped at 8,192 characters and
  flagged `raw_truncated` on screen ("the hex dump is not affected"); the layer tree stops
  expanding objects below 8 levels; a single value over 400 characters is collapsed behind a
  toggle. Selected-byte-range highlighting is deliberately absent: the API sends no
  offset-to-field mapping, so any highlight would be a guess.
* **`tcp_flags` is a substring of a fixed-layout string.** TShark's `tcp.flags.str` is
  always 12 characters and each flag owns a fixed position. Measured across the whole
  library (8 distinct strings over 16,853 TCP frames): `S` matches 610 frames, `A` 16,518,
  `AP` 6,846, `R` 143 — and `SYN`, `SA`, `PA`, `FA`, `RA` and `AS` each match **zero**. The
  letters occupy fixed slots, so the only two-letter pair that is ever adjacent is `AP`
  (ACK+PSH); `SA` cannot occur at all, since a SYN+ACK frame reads `·······A··S·`, and the
  Wireshark spelling `SYN` is not part of the stored value in any form.
  [`docs/CONTRACT.md`](../docs/CONTRACT.md) §5
  states that `S` is SYN "and `SA` is SYN+ACK"; the library does not bear the second half of
  that out, and this document records the disagreement rather than repeating it. Use single
  letters (`S`, `A`, `R`, `F`, `P`) — the detection engine's own correlation code does
  exactly that (`conversation_analyzer._flag_bit` tests `INSTR` for one letter per flag).
* **Text search means different things in the two paths.** The SQL predicate is a
  case-insensitive `LIKE` over four columns; the display-filter form matches the two string
  columns case-insensitively and the IP columns only by exact equality, and a search term
  containing `\`, `^` or `$` falls back to a case-sensitive `contains`. The navigator warns
  when the two sets differ in size, but the traversal set is the display-filter set, so
  "next match" can in principle differ from what the table shows.
* **`transport` values beyond tcp and udp are ignored by the page.** The endpoint accepts
  `sctp` and `other`, but the page only sends `tcp` or `udp`, so a hand-edited
  `?transport=sctp` neither filters nor counts as an active filter while the key sits in the
  URL.
* **Selection is not a filter.** `?sel=` is not sent to the API, so the table is not
  restricted to the selected frame, and the detail pane can show a frame that the current
  filter excludes. That is deliberate: it is how a link to one frame works.
* **Nothing here is a payload inspection.** The list never carries payloads. The byte dump
  is one frame's captured bytes, read from the file, and the pane says so when the dump
  fails for a frame that dissected fine. Following an application-layer conversation is the
  [Conversations](Conversations.md) page's job.
* **An empty table is not evidence of absence.** Rows only exist for frames TShark
  dissected and the indexer wrote; a frame the indexer skipped appears in no view, and the
  zero-match state quotes the capture's indexed count, not the file's frame count.

## 6. Related

**Related:** [Conversations](Conversations.md) · [HTTP](HTTP.md) · [DNS](DNS.md) · [TLS](TLS.md) · [Findings](Findings.md) · [Threat Map](Threat-Hunt.md) · [Getting-Started](Getting-Started.md) · [Reference/API](Reference/API.md)
