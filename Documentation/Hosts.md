# Hosts (`/hosts`)

The endpoint inventory for one capture — one row per IP address the dissector actually saw —
and a relationship map built strictly from the conversations that were reassembled out of
that traffic.

---

## 1. What it is for

The page answers: **which addresses appear in this capture, what did each of them do, and
which addresses talked to which?** Per address it holds the MAC the Ethernet layer showed,
the first and last frame timestamps, packets and bytes in each direction, the ports and
display protocols observed, the DNS names and TLS SNI values attributed to it, and its
conversation peers. The **Network map** view reduces the same capture to nodes and edges so
the fan-out of one address — or the absence of any connection at all — is visible at a
glance. Everything on the page is an aggregate over indexed rows; nothing is inferred from
subnets, naming conventions or ports.

## 2. What is on the screen

The page is wrapped in `AnalysisGuard`, so with no capture selected it shows the
"no capture selected" state, and while a capture is still processing it shows the live
progress panel instead of the inventory.

### 2.1 Stat cards (always visible)

| Card | Value | Source and scope |
|---|---|---|
| Endpoints observed | `total_hosts` | Rows in the `hosts` table for this analysis, **unfiltered** |
| Matching filters | `total` | Rows matching the current filters; sublabel counts how many filters are active |
| Bytes sent by hosts | `total_bytes` | `SUM(bytes_sent)` over every host in this analysis, unfiltered — bytes *sent* only, not sent plus received |
| Map endpoints | Number of `nodes` in `GET /hosts/graph`, sublabel the number of `edges` | Endpoints that appear in at least one observed conversation, not rows in `hosts` |

The first three come from the list request; the fourth from the graph request, which is
issued whenever a capture is selected — including while the Inventory view is showing.

### 2.2 View switch and refresh

| Control | Effect |
|---|---|
| **Inventory** | Sets `view` to empty; the dense table is drawn |
| **Network map** | Sets `view=graph`; the relationship map is drawn |
| **Refresh** | Re-reads the inventory and the graph (`refetch` on both queries) |

### 2.3 Inventory view

The Panel is titled *Host inventory* and its subtitle states how many endpoints match and
which column the backend sorted by, so the sort is never implied.

Toolbar:

| Control | URL key | Behaviour |
|---|---|---|
| IP | `ip` | Substring match on the address (`ip LIKE %…%`), debounced 300 ms |
| Search | `search` | Substring match on the address, MAC, protocol map, DNS names and TLS SNI. It does **not** search peers |
| Scope | `is_private` | `any` / `private only` (`true`) / `public only` (`false`) |
| Protocol | `protocol` | Exact key match inside the host's protocol map, e.g. `HTTP`; case sensitive |
| Sort | `sort` | Allow-listed columns only (see the parameter table in §3). Choosing a new column also picks a direction: descending for `packets_sent`, `bytes_sent`, `bytes_received`, `last_seen` and `peer_count`, ascending for the rest. Clicking a sortable column header toggles the direction when that column is already active |
| order button | `order` | Toggles `asc`/`desc` and shows the current direction; it is always enabled, and every explicit sort change picks a sensible default for the column |
| Clear filters | — | Removes `ip`, `search`, `protocol`, `is_private` and `page` from the URL |

Columns. Sortable headers are marked S.

| Column | Contents |
|---|---|
| IP (S) | The address; clicking it selects the host (sets `host=<ip>`) and opens the detail panel |
| MAC | The most frequently observed MAC for that address, or `—` |
| Scope | `private` (RFC1918/RFC4193/loopback/link-local), `public`, or `unknown` when the address cannot be parsed |
| First seen (S) / Last seen (S) | Capture-relative frame timestamps, from `MIN`/`MAX(time_epoch)` |
| Pkts sent (S) / Pkts recv | Frames in which the address is source / destination |
| Bytes sent (S) / Bytes recv (S) | Sum of `frame_len` over those frames |
| Top ports | `port · packets` chips, up to 3 shown, `+N more` beyond that; each port carries its direction in the tooltip |
| Protocols | Display-protocol names with packet counts, most frequent first, up to 3 shown |
| Names | DNS names (grey) and TLS SNI values (blue), up to 2 shown |
| Peers (S) | `N peers`, with the peer list in the tooltip |

A footer under the table states the chip convention and that every column comes from the
backend.

Pagination uses page sizes 50 / 100 / 250 / 500 / 1000; a `page_size` that is not one of
those five falls back to 100.

Empty states are distinguished: with filters active the page says the filters are valid and
the backend returned no rows; with no filters it says no IP address was indexed (for example
a capture carrying only non-IP traffic) rather than inventing a row.

### 2.4 Host detail panel

Opened by clicking an IP in the table or a node in the map, and addressed by the `host`
query parameter so it can be linked. It is three bands, top to bottom:

| Band | Contents |
|---|---|
| Panel header | Address, copy button, scope chip, MAC, `ip_version`, first and last seen, and **Close** (which clears the `host` parameter). Spans the whole width |
| Two cards side by side | **Host info** — the counters, pivots, chips and cap note below — next to **Registration lookup**, the rail of §2.5 |
| Full-width records section | The four capped tables, each still its own panel with its own cap line, and the closing note |

From the `xl` breakpoint up the two cards sit side by side, each filling its own column:
host info flexes, the rail is 23 rem. Below `xl` they stack, so neither is squeezed.

**Host info** carries the traffic the capture recorded for this address.

Fields: packets sent, packets received, bytes sent, bytes received, **packets involving this
IP** (counted live from the `packets` table, `src_ip` or `dst_ip`), and peers.

Pivot buttons, each of which leaves the page with the same IP as a filter:

| Button | Target |
|---|---|
| Packets | `/packets?ip=<ip>` |
| HTTP as client | `/http?client_ip=<ip>` |
| HTTP as server | `/http?server_ip=<ip>` |
| DNS as client | `/dns?client_ip=<ip>` |
| DNS as server | `/dns?server_ip=<ip>` |
| TLS | `/tls?ip=<ip>` |
| Conversations | `/conversations?ip=<ip>` |

Capped chip blocks: Ports, Protocols, Names, Peers (each draws up to 12 chips with a
`+N more` counter whose tooltip lists the rest).

Four capped tables follow in the full-width section below the cards, each at most
`DETAIL_LIST_LIMIT = 50` rows:

| Table | Columns |
|---|---|
| Conversations | Endpoint A, Endpoint B, `transport #stream_id`, Packets, Bytes, Duration, State, Protocols |
| HTTP transactions | Time, Method, Host, URI, Status, Role (`client` / `server`) |
| DNS queries | Time, Query name, Type, Rcode, Response (`unanswered` or the response delay), Answers |
| TLS sessions | Time, SNI, Version, Server, Handshake, Cipher suite |

Each subtitle states *"N of at most 50"*, and when any list reaches the cap the panel adds
a visible note in the **Host info** card — next to the counters it is about — that a full
list may hold more and points at the pivots for the complete set.

### 2.5 Registration rail (whois / RDAP)

The right-hand card of that pair: who holds the address, rather than what it did.
It is a rail rather than another data card because it answers a different question from a
different source. It is specified by [../docs/IP_LOOKUP.md](../docs/IP_LOOKUP.md) and served
by `GET` / `POST /api/analyses/{id}/hosts/{ip}/lookup`.

The rail is split in two, and the order matters: what the capture already knows comes
**first**, because it needs nothing from the network.

**From this capture** — computed locally, marked *no request made*:

| Element | Source |
|---|---|
| Class chip (`Public address`, `Private address`, `Reserved address`, `Loopback address`, `Multicast address`, `Link-local address`) and, when there is nothing to ask, the API's `reason` verbatim | `kind`, `reason` |
| **Country (geolocation)**, named in full with its code, plus the dataset it came from | `local.country`, `local.country_source` (the DB-IP Lite country dataset) |
| **Domains seen** — the count, then each name with where it was seen (`DNS answer` or `TLS SNI`) and how many rows carried it | `local.names[]` (`name`, `from`, `rows`), capped at `LOCAL_NAME_CAP = 25` by rows seen. Those two are the only sources the API emits. DNS names come from answers carrying this address; an SNI counts only when this address is the session's **server**, because that is the direction in which a name points *at* an address. The Names chips on the left are the other direction — what this host asked for — so the same page can legitimately show a name in one column and not the other |
| *"no request made"*, and, when a name list is capped, a note that the busiest names are shown | `local.names_truncated` |
| When nothing named the address: a statement that a name appears only if the capture carried it and that nothing is resolved on demand | — |

**From the registry** — empty until the button is pressed:

| Element | Source |
|---|---|
| **Look up registration data** (primary) for a public address with no cached record | `POST`, the only action in the app that sends an address off the machine |
| **Registrar / registry**, with the legacy whois host as its hint | `record.registry`, `record.port43` |
| Network name, handle, address range, allocation type, status | `record.network_name`, `handle`, `range`, `allocation_type`, `status` |
| **Registered country**, named in full, marked *"As registered by the RIR"* — or, when it disagrees with the geolocated country, a visible warning giving both | `record.country` vs `local.country` |
| **ASN** as `AS<number>` with the prefix, registry, country and allocation date as its hint | `record.asn` |
| **Contacts** — role (registrant, administrative, technical, abuse, routing), handle, name, and each email as a `mailto:` link; abuse contacts are marked | `record.contacts[]`, capped at `CONTACT_CAP = 10` |
| **Registry remarks** | `record.remarks[]`, capped at `REMARK_CAP = 5` and 400 characters each |
| A warning naming the steps that failed, when only part of the lookup answered | `record.failures[]` |
| **Open the registry's own RDAP record** (external link, new tab) | `record.rdap_url` |
| **Fetched** timestamp, the registry it came from, cache age, `stale` when past `LOOKUP_MAX_AGE_DAYS = 30`, and **Look up again** | `cache.*` (a secondary button, never the primary one) |
| For a non-public address: an explanation that no registry holds it, and **no button at all** | `lookup_possible: false` |

Two footers close the rail. The **egress statement** is always visible: only the button sends
anything, it sends that one address to the responsible RIR's RDAP service and to Team Cymru's
DNS service, no capture data leaves the host, and the answer is stored locally so the same
address is not asked for twice. Below it, **What this lookup is, and is not** is collapsed —
the API's own provenance paragraph, disclosed by clicking its header, the same way every other
explanation in the app opens.

Opening a host panel never contacts anything. The rail's first paint is local: the class, the
geolocated country, the capture-observed names and the cached record, if one exists.

### 2.6 Network map view

| Element | Meaning |
|---|---|
| Banner | States that the map is drawn only from connections observed in this capture, that it is not a physical or logical topology, and that nothing is inferred from names, subnets or ports |
| Legend | `private`, `public`, `unclassified`, and a dashed dot for "no observed connection"; also notes that node size and line width scale with bytes |
| Diagram | SVG. The busiest endpoint by bytes sits at the centre, the rest fill concentric rings in decreasing-byte order. Node radius `4 + 12 * sqrt(bytes / maxBytes)`; edge width `1 + 2.5 * sqrt(bytes / maxEdgeBytes)` |
| Edge tooltip | Both endpoints, packet count, bytes, the union of the conversations' protocols, and up to 5 destination ports |
| Node tooltip | Address, scope label, MAC, packets, bytes, and its number of observed connections |
| Footer counters | Endpoints drawn, observed connections, whether labels are limited to the hovered selection, and — when the drawn set was clipped — how many nodes and edges are in the API response but not drawn |
| Endpoint focus panel | Hover shows measured traffic (MAC, packets, bytes, share of bytes, connections); clicking a node keeps the focus, opens the host record below, and shows its neighbours by bytes (up to 6, each clickable) |

Clicking the background clears the selection. Above 70 nodes only the hovered/selected node
and its neighbours are labelled; above 300 nodes only the 300 highest-volume endpoints are
drawn (the footer says so).

## 3. Where the data comes from

Page component `frontend/src/pages/HostsPage.tsx`; presentational components
`frontend/src/components/hosts/HostsTable.tsx`, `NetworkGraph.tsx`, `HostDetailPanel.tsx`
and the shared chip/parse helpers in `frontend/src/components/hosts/chips.tsx`. The API
client is `hostsApi` in `frontend/src/services/api.ts`. The routes are
`backend/app/api/routes_hosts.py`; the analysis is `backend/app/services/host_analyzer.py`.

| Call | When | Route | Tables read |
|---|---|---|---|
| Inventory | Whenever a capture is selected, and on every filter/sort/page change | `GET /api/analyses/{analysis_id}/hosts` | `hosts` |
| Graph | Whenever a capture is selected (both views) | `GET /api/analyses/{analysis_id}/hosts/graph` | `conversations`, `hosts` |
| Detail | Only while a host is selected | `GET /api/analyses/{analysis_id}/hosts/{ip}` | `hosts`, `conversations`, `dns_queries`, `http_transactions`, `tls_sessions`, `packets` |

All three go through `deps.analysis_ready_row`, so they return `404 analysis_not_found`,
`409 analysis_not_ready` while the capture is still processing, and — importantly —
`410 capture_missing` when the retained capture file is no longer on disk (§6). The route
declares `/hosts/graph` before `/hosts/{ip}` so the literal path is not swallowed by the
path parameter.

### 3.1 URL parameters the page reads

Every filter, sort, pagination, view and selection value lives in the query string, so a
filtered inventory can be bookmarked or pasted to a colleague.

| Parameter | Accepted values | Default when absent or invalid |
|---|---|---|
| `view` | `graph` selects the map; anything else is the inventory | inventory |
| `ip` | Any string; substring match on the address | no filter |
| `search` | Any string; substring match on address, MAC, protocol map, DNS names, TLS SNI | no filter |
| `protocol` | Exact protocol-map key, e.g. `HTTP` | no filter |
| `is_private` | Exactly `true` or `false` (the string); anything else, including `1`, is ignored | no filter |
| `sort` | `ip`, `packets_sent`, `bytes_sent`, `bytes_received`, `first_seen`, `last_seen`, `peer_count` | `ip` |
| `order` | `desc` for descending; anything else is ascending | `asc` |
| `page` | Positive integer | `1` |
| `page_size` | One of `50`, `100`, `250`, `500`, `1000` | `100` |
| `host` | An IP address, naming the endpoint whose detail panel is open | no panel |

`page` and `page_size` are parsed with a positive-integer helper, so `page=0`, `page=abc`
and negative values fall back rather than erroring. Selecting a host sets `host` **without**
clearing `page`; every other filter change deletes `page`.

### 3.2 The request parameters the page sends

The page passes `page`, `page_size`, `sort`, `order`, `ip`, `search` and `protocol` through
to the backend, plus `is_private` only when the Scope control is set. The backend accepts
`page` (≥1), `page_size` (1–1000), `ip`, `search`, `is_private`, `protocol`, `sort` and
`order`; `sort` is mapped onto a fixed SQL expression (`SORTABLE` in `routes_hosts.py`) and
an unknown value is rejected with `400 invalid_sort`, which is why the page only offers
allow-listed columns.

The page makes four requests, and only the last one can leave the machine:

| Request | When | Sends anything off the machine? |
|---|---|---|
| `GET /hosts` (or `/hosts/graph`) | On every filter, sort, page or view change | No |
| `GET /hosts/{ip}` | When the detail panel opens or `host` changes | No |
| `GET /hosts/{ip}/lookup` | With the detail panel, for the rail's first paint | No — it reads the local `ip_lookups` row and the capture |
| `POST /hosts/{ip}/lookup` | Only while the rail's **Look up registration data** / **Look up again** button is pressed | **Yes** — that one address, to its RIR's RDAP service and to Team Cymru's DNS service |

## 4. How a host row and the map are built

### 4.1 The `hosts` row

`backend/app/services/host_analyzer.py` builds one row per address from the **packet index**
— not from a capture re-read:

* packets, bytes, first and last seen: a two-branch union over `packets` (sender row and
  receiver row per frame), grouped by address;
* MAC: the most frequently observed MAC for the address, with an `eth.src` observation
  breaking a tie — a single value per host, always the address's own L2 neighbours' view of
  it;
* ports: `(port, direction)` pairs with frame counts, capped at `MAX_PORTS = 15` entries,
  largest first;
* protocols: display-protocol counts from `packets.protocol`, uncapped in storage;
* DNS names: query names this address asked for (`dns_queries`, and the `dns_query` column of
  `packets` so a missing DNS stage cannot empty the list), plus query names whose **answers**
  contain this address; capped at `MAX_NAMES = 100`, sorted;
* TLS SNI: names from `tls_sessions` and the `tls_sni` column of `packets`, capped at
  `MAX_NAMES = 100`, sorted;
* `is_private`, `ip_version`: computed locally with the `ipaddress` module;
* peers: `peer_count` plus at most `MAX_PEERS = 25` peers, from `conversations` rows only,
  ordered by packet count. A peer never equals the host itself.

The stage deletes and rewrites every row for the analysis (`DELETE FROM hosts WHERE
analysis_id = ?`), so the inventory is a snapshot of the last completed run.

### 4.2 The map: observed conversations only

`GET /hosts/graph` in `routes_hosts.py` reads `conversations` and `hosts` and nothing else.
There is no inference anywhere in it:

* **One node per endpoint that appears in a conversation**, so a row in `hosts` that is in no
  conversation is not a node at all. On `sf19us-MTA-lab-09.pcap`
  (analysis `9e2ef6a921304dc9ac0c739133682641`) the `hosts` table holds 12 rows while the
  graph returns 11 nodes, and the missing one is `224.0.0.22` — an IGMPv3 group address
  with `peer_count = 0` that never appeared in a reassembled conversation.
* **One edge per unordered address pair.** Every conversation between the same two addresses
  is folded into one edge: packets and bytes are summed, the protocol strings are unioned,
  and `conversations` counts how many were folded in.
* **Direction is decided by the busiest conversation.** The conversation with the largest
  `bytes_total` between the pair sets the edge's `source` and `target`; the other
  conversations' ports are counted in that same declared direction.
* **Edge ports** are destination ports with packet weights, largest first, cut to
  `GRAPH_MAX_PORTS = 5`.
* **Node metrics** come from the `hosts` row when one exists (`packets_sent +
  packets_received`, `bytes_sent + bytes_received`); otherwise they are summed from the
  conversations themselves. `is_private` likewise comes from the row, or is computed from
  the address when there is no row.
* **`scope`** is computed for every node from the address alone (see §4.3).
* Self-edges are dropped: a conversation whose two addresses are equal is skipped, as is any
  conversation missing an endpoint.

Edges are returned sorted by bytes descending; nodes sorted by address. The frontend then
re-orders nodes by bytes for the concentric layout, which is deterministic — the same capture
always produces the same picture, because there is no force simulation anywhere in
`NetworkGraph.tsx`.

### 4.3 Address classification

Two different things are computed, and they disagree by design.

`is_private_address()` is the boolean stored in `hosts.is_private` and returned as
`is_private` (`1`/`0`, `null` when the value is not an address):

* `1` — private, loopback or link-local: IPv4 `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`; IPv6 `fc00::/7`, `::1/128`,
  `fe80::/10`;
* `0` — everything else, including multicast, broadcast and reserved space;
* IPv4-mapped IPv6 addresses are unwrapped first, so `::ffff:10.0.0.5` classifies as
  private.

`address_scope()` is the precise label the API returns as `scope`; it is checked in this
order, and the first match wins:

| `scope` | Address |
|---|---|
| `multicast` | `224.0.0.0/4`, `ff00::/8` and similar |
| `broadcast` | IPv4 `255.255.255.255` only |
| `unspecified` | `0.0.0.0`, `::` |
| `loopback` | `127.0.0.0/8`, `::1` |
| `link_local` | `169.254.0.0/16`, `fe80::/10` |
| `reserved` | Reserved ranges such as `240.0.0.0/4` |
| `private` | RFC1918 / RFC4193 as listed above |
| `public` | Everything else |
| `null` | The value is not a parseable address |

Measured against the two functions in this build:

| Address | `scope` | `is_private` |
|---|---|---|
| `10.4.10.132` | `private` | 1 |
| `10.4.10.255` | `private` | 1 |
| `239.255.255.250` | `multicast` | 0 |
| `224.0.0.252` | `multicast` | 0 |
| `255.255.255.255` | `broadcast` | 0 |
| `169.254.1.1` | `link_local` | 1 |
| `127.0.0.1` | `loopback` | 1 |
| `240.0.0.1` | `reserved` | 0 |
| `8.8.8.8` | `public` | 0 |
| `::ffff:10.0.0.5` | `private` | 1 |
| `not-an-ip` | `null` | `null` |

### 4.4 The `is_private` filter

The Scope control is the only filter on the page that is applied in SQL, as
`is_private = ?`. On `sf19us-MTA-lab-09.pcap` the 12 host rows split 4 / 8:

* `private only` (`is_private=true`) → 4 rows: `10.4.10.132`, `10.4.10.4`, `10.4.10.2`,
  `10.4.10.255`;
* `public only` (`is_private=false`) → 8 rows, and four of them are not public hosts at all:
  `239.255.255.250` and `224.0.0.252` (multicast groups), `224.0.0.22` (multicast), and
  `255.255.255.255` (broadcast). The multicast group addresses are in this analysis because
  the capture contains SSDP and LLMNR traffic.

That is exactly the case `address_scope()` exists to describe: a boolean cannot tell a
multicast group or a broadcast address from a routable internet host.

## 5. Links into the rest of the app

| Element | Opens |
|---|---|
| An IP in the table, or a node in the map | The host detail panel on this page (`?host=<ip>`); the panel scrolls into view |
| Packets pivot | `/packets?ip=<ip>` — see [Packets](Packets.md) |
| HTTP as client / as server | `/http?client_ip=<ip>` / `/http?server_ip=<ip>` — see [HTTP](HTTP.md) |
| DNS as client / as server | `/dns?client_ip=<ip>` / `/dns?server_ip=<ip>` — see [DNS](DNS.md) |
| TLS pivot | `/tls?ip=<ip>` — see [TLS](TLS.md) |
| Conversations pivot | `/conversations?ip=<ip>` — see [Conversations](Conversations.md) |
| **Look up registration data** in the rail | No route: it calls `POST /hosts/{ip}/lookup`, the only action in the app that sends an address to a public service. Nothing moves until it is pressed |
| **Open the registry's own RDAP record** | The registry's own page for the network, in a new tab — an external URL the registry published, not part of this app |
| Scope filter, sort, pagination, view | The same page, re-queried; nothing is hidden in client state, so the URL is the whole view |

There is no link from the Hosts page into the Findings page: a finding is addressed by its
own id (`/findings/{id}`) and there is no host filter on that page. To reach the findings
that concern an address, read the host's name and address on this page and search for them
on [Findings](Findings.md).

## 6. Limits and honest caveats

* **The whole section depends on the retained capture.** All three endpoints call
  `analysis_ready_row`, which resolves the capture path and raises `410 capture_missing` when
  the file is gone. A capture whose upload has been removed therefore shows an error state on
  this page even though the `hosts` table is intact — unlike the detection engine's rescan,
  which reads the index only.
* **`is_private` is a boolean; `scope` is the precise answer, and this page does not use it.**
  The page's Scope chip and the map's node colours are driven by `is_private`, so a multicast
  group or the limited broadcast address is drawn and labelled "public" here. The `scope`
  field *is* in the payload and *is* rendered by the Dashboard's map — see
  [Dashboard](Dashboard.md). Within this page the classification is therefore
  private/public/unknown only.
* **No netmask is known**, so a subnet-directed broadcast inside RFC1918 space is
  indistinguishable from a host: `10.4.10.255` in the worked capture classifies as
  `private`. Only `255.255.255.255` is reported as `broadcast`.
* **`public only` is not "remote hosts".** It includes multicast, broadcast, loopback-excluded
  but reserved-range addresses, and any address that failed to parse is excluded from both
  sides of the filter.
* **A MAC does not identify an endpoint.** It is the MAC most often observed for the address
  — for a remote address that is the last-hop router's, not the remote device's. Five
  addresses in `sf19us-MTA-lab-09.pcap` (`217.182.138.150`, `23.229.162.69`, `216.58.193.131`,
  `66.171.248.178`, `10.4.10.2`) all carry `20:e5:2a:b6:93:f1`. Two addresses that share a
  MAC are not necessarily the same device, and one device behind an address change appears as
  two rows.
* **Names are attributed, not proven.** A DNS name is attached to an address either because
  that address asked for it or because it appeared in an answer for that name; SNI is attached
  to the client that offered it. Neither proves the address hosted that name.
* **The map is not a topology.** It contains only connections that were reassembled. A link
  that carried no traffic is absent, a host in no conversation is absent, and no relationship
  is drawn from a shared name, subnet or port. An empty map means "no conversation was
  reassembled", not "nothing happened".
* **Stored caps.** The `hosts` row keeps at most 15 ports, 25 peer addresses and 100 names per
  address, and 100 names **sorted alphabetically** rather than by importance — so on a busy
  host the names list is a truncation, not a ranking. The table draws 3 ports / 3 protocols /
  2 names and the detail panel 12 of each.
* **Detail lists are capped at 50 rows each** and the panel says so only when a list actually
  reaches the cap; a list of exactly 50 may be a truncation.
* **`host` is not validated.** Pasting `?host=<ip>` for an address that is not in this
  analysis — or for a stale capture — produces the backend's `404 host_not_found` and an
  error panel rather than an empty one.
* **Sorting `ip` is a text sort.** Addresses are stored and ordered as text, so
  `10.0.0.20` sorts before `10.0.0.5`. The other sortable columns are numeric or timestamps.
* **The graph is capped twice.** Each edge keeps 5 ports; the frontend draws at most 300
  nodes (and their edges) and reports the omitted counts only in the map footer.
* **Nothing here proves intent.** Volume, ports and peers describe observed traffic. A large
  send is a large send; a multicast group is not a remote host; a peer list is not a trust
  relationship.
* **The registration rail is not a location and not an owner.** A registry says who holds a
  block, not who used an address at the time of the capture. The registered country and the
  geolocated country are both shown with their sources and are frequently different — for
  `195.63.128.106` in `2026-10-01-traffic-analysis-exercise.pcap` the block is registered to
  RIPE NCC (NL) while its origin AS `216071` is registered in AE. Neither is "where the host
  was". Contacts are often an abuse desk, frequently redacted, and an empty contact list means
  the registry published none — not that nobody owns the address.
* **The rail's cache is shared across captures and can be stale.** `ip_lookups` is keyed by
  address, so a second capture that contains the same peer reuses the record; past
  `LOOKUP_MAX_AGE_DAYS = 30` the record is marked `stale` and still shown rather than hidden.
  A record is a snapshot at its fetch time, and nothing re-checks it on its own.
* **A lookup leaves the machine.** It is the one action here that does. The address alone is
  sent — no payload, no capture name, no other address in the file — to the responsible RIR's
  RDAP service and to Team Cymru's DNS service, and private, loopback, multicast, link-local
  and reserved addresses are never sent at all. Opening a host panel sends nothing.
* **Domains in the rail come only from the capture.** The registry does not publish the domain
  names that point at an address, so the list is what this capture already observed in DNS
  answers, DNS queries or TLS SNI, capped at 25 names by rows seen. There is no reverse lookup
  and no passive-DNS service behind it.

## 7. Related

[Conversations](Conversations.md) for the reassembled flows behind every edge ·
[Packets](Packets.md) for the frames behind every counter · [HTTP](HTTP.md),
[DNS](DNS.md) and [TLS](TLS.md) for the application-layer records attributed to a host ·
[Dashboard](Dashboard.md) for the same graph payload drawn with the precise `scope` labels ·
[Findings](Findings.md) for alerts raised about these endpoints ·
[Files-and-Objects](Files-and-Objects.md) for content recovered from them —
[Hunt](Investigate.md) to read one of these addresses on its own. The registration rail's
rule is [`docs/IP_LOOKUP.md`](../docs/IP_LOOKUP.md).
