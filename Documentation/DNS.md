# DNS

Every DNS query TShark dissected from the selected capture, with the matching response merged into
the same row, plus a second view that aggregates the same rows per query name.

The page is `frontend/src/pages/DnsPage.tsx` and its route is `/dns`. It sits with the other two
protocol pages, [HTTP](HTTP.md) and [TLS](TLS.md), under **Protocols** in the left-hand navigation;
the Threat Map detections that reason about name shape are built on this table and are documented
under [ThreatHunter/](ThreatHunter/ThreatHunter.md). The normative interface shape is
[`docs/CONTRACT.md`](../docs/CONTRACT.md) §5.

---

## 1. What it is for

**What did this host ask the resolver for, what came back, and which names deserve a second
look?** DNS is the one protocol here that stays readable without decryption, so this page answers
what was looked up, by whom, through which resolver, with what answer, response code, TTL and
delay — and it computes the shape of each name (length, label count, entropy) so that
machine-generated names can be ranked for review. The second view answers the complementary
question: which names recur, how many clients asked for them, and what did they ever resolve to.

## 2. What is on the screen

### Lead flag legend

The first thing on the page, and **collapsed by default**: a **How to read DNS lead flags** panel
listing every DNS flag with its meaning, quoting the backend defaults it mirrors
(`long_label ≥ 40`, `long_name ≥ 100`, `entropy > 3.8` with at least 3 labels,
`many_ips ≥ 4`). *Show* opens it. It is not gated on the view, so it is there for the query and
the domain view alike.

There is no scope panel on this page. The limits it used to state still apply and are worth
knowing: answer data of types other than A, AAAA and CNAME is not stored, a query whose response
is missing from the capture reads as unanswered, and encrypted DNS (DoH or DoT) travels inside
TLS and is not decrypted.

### The view switch

A **View** toggle with two options, and a one-line description of the current one. The view is the
`view` parameter:

| `view` | What it shows |
|---|---|
| `queries` (default) | One row per DNS query, with the matching response merged in. This is the default also for any value other than `domains`. |
| `domains` | One row per distinct query name, aggregated by the backend from the same stored rows. |

### The filters

Every filter lives in the query string, so a view can be copied and shared. The complete list of
parameters this page owns, transcribed from `URL_KEYS` in `DnsPage.tsx`, in order:

```ts
const URL_KEYS = [
  'view',
  'domain',
  'client_ip',
  'server_ip',
  'qtype',
  'rcode',
  'search',
  'unanswered',
  'nxdomain',
  'suspicious',
  'sort',
  'order',
  'page',
  'page_size',
  'sel',
  'dsearch',
  'dsort',
]
```

| Parameter | What it filters |
|---|---|
| `view` | `queries` or `domains`. Any value other than `domains` falls back to the queries view, so `view=queries` and an absent `view` are the same thing. |
| `domain` | **Substring** match on the query name (`LIKE`; `%` and `_` in the value are escaped so they stay literal). Because it is a substring, `example.com` also matches `www.example.com`, `cdn.example.com` and `notexample.com`. |
| `client_ip` | **Exact** client address. |
| `server_ip` | **Exact** DNS server address. |
| `qtype` | Matches the stored type against the upper-cased value or the value as typed (`A`, `AAAA`, `TXT`, …). The dropdown lists only the types stored in this analysis. |
| `rcode` | The response code. A known name (`NXDOMAIN`, `SERVFAIL`, …) is mapped to its numeric rcode by the backend's `RCODE_LOOKUP`; a number is parsed as an integer; anything else is matched against the stored `rcode_name`, upper-cased. The dropdown lists the stored rcode names. |
| `search` | One substring tested against the query name, the stored `answers` JSON text and the query type. |
| `unanswered` | `true` — only rows with no matched response (`response_packet IS NULL`). The checkbox writes `true` only; the API also accepts `false`, which the page never produces. |
| `nxdomain` | `true` — only rows whose merged response had `rcode = 3`. |
| `suspicious` | `true` — only rows whose stored `flags` array is non-empty. |
| `sort` | Sort column. The UI offers `time_epoch`, `query_name`, `query_type`, `rcode_name` and `response_delay`; the endpoint also allows `packet_number`. |
| `order` | `asc` (the page's default) or `desc`. |
| `page` | 1-based page number. |
| `page_size` | Rows per page; default `100`, capped by the API at `MAX_PAGE_SIZE = 1000`. |
| `sel` | The id of the row whose detail panel is open. Selection state, not a filter. |
| `dsearch` | **Client-side** substring filter over the aggregated rows of the domains view. It never reaches the API, and it is applied to the names the browser already holds. |
| `dsort` | **Client-side** sort of the domains view: `queries` (the default), `name`, `clients` or `last_seen`. |

`view`, `sel`, `dsearch`, `dsort`, `sort`, `order`, `page` and `page_size` are in `NON_FILTER_KEYS`
(`frontend/src/components/protocols/ProtocolFilters.tsx`), so they do not count towards "filters
active", they survive **Reset filters**, and changing one of them does not reset the page number.
Changing any real filter resets `page` to 1. **Reset filters** calls `clear()` and then explicitly
drops `dsearch` and `dsort` as well, because those two are browser-side state rather than filters —
the page's own comment says so.

### The queries view

**Noisiest clients** (top panel). A table of the ten clients with the most queries, computed over
the **whole analysis** — the page subtitle says the filters below do not apply to it. Columns:
Client, Queries, Share (that client's percentage of the analysis total) and Volume, which carries a
`≥ 100 queries` chip once the count reaches the page's `HIGH_VOLUME_THRESHOLD = 100`, the default of
the backend's `dns_high_volume` rule. Clicking a row sets the `client_ip` filter to that client
(clicking it again clears it); the panel footer states the analysis total and names the busiest
client, with the note that a high count alone is not evidence of abuse.

When any filter is active the page issues a second, tiny request (`page=1&page_size=1`) purely to
read the unfiltered total, so that the Share column states a real proportion rather than a
proportion of the filtered subset.

**Lead flag legend.** The collapsed panel at the top of the page lists every DNS flag with its
meaning, quoting the
backend defaults it mirrors: `long_label ≥ 40`, `long_name ≥ 100`, `entropy > 3.8` with at least
3 labels, `many_ips ≥ 4`.

**DNS queries** (main panel). Columns:

| Column | Meaning |
|---|---|
| Time | `time_epoch` of the query packet. |
| Client | The query source address. |
| DNS server | The query destination address — the resolver as seen in the capture. |
| Query name | `dns.qry.name`, verbatim. |
| Type | The query type, mapped from TShark's numeric `dns.qry.type` to its IANA mnemonic (`A`, `AAAA`, `TXT`, …). |
| Rcode | The merged response's response code, colour-coded: NOERROR green; NXDOMAIN, SERVFAIL and REFUSED amber. `—` when no response was matched. |
| Answers | The number of parsed answer records stored on the row — the count of A, AAAA and CNAME entries. The cell tooltip lists them as `type=value` lines. |
| Answer IPs | The comma-joined resolved addresses, de-duplicated. |
| Min TTL | `formatNumber(min_ttl) s` — the smallest TTL seen in the response. |
| Delay | `formatDuration(response_delay)` — response time minus query time, to six decimals in the row data. `—` with the tooltip "No response was matched to this query, so no delay can be measured." |
| Lead flags | One badge per recorded flag, with the full reasoning on hover. `—` when there are none. |

Above the table: a **Sort** select (time, query name, query type, response code, response delay), a
direction toggle, and **Reset filters**. Below it a footer states how many rows on the current page
carry at least one flag.

**Query detail.** Selecting a row sets `sel` and opens a panel with the query name, its type and
its rcode as chips (each copyable), then:

* a detail grid — Time, Client, DNS server, Query packet, Response packet, Response time, Response
  delay, DNS transaction id, Row is (`query`/`response`), Response code, Rcode value,
  Authoritative, Truncated (TC bit), Minimum TTL;
* **Answers** — a table of the stored records (Type, Value, Other fields), the answer IP list, the
  CNAME list and the minimum TTL, with a copy button. A TXT query additionally gets a note that the
  backend derives records from A, AAAA and CNAME fields only, so the text carried by a TXT answer is
  not stored on the row;
* **Computed name shape — why this row was flagged** — a table of Name length, Longest label,
  Labels and Entropy with the threshold each one is compared against, whether the corresponding
  flag was actually recorded, and a one-line explanation of why the metric is ambiguous;
* the full reasoning for each recorded flag.

### The domains view

**Domains** panel, fed by its own endpoint. Above the table are two **client-side** controls: a
Domain substring box and a Sort select (`queries` most first — the default — `name`, `clients`,
`last_seen`). Neither is sent to the backend: they filter and sort the aggregated rows the browser
already holds, which is what the panel subtitle means by "filtered in the browser".

Columns: Query name, Queries, Clients (distinct client addresses), Answered (rows with a matched
response packet), NXDOMAIN (rows with `rcode = 3`, amber when non-zero), Response codes as
`CODE×count` pairs, Resolved IPs (every address ever seen in an answer for that name), First seen
and Last seen. Rows are not clickable in this view — there is no per-row navigation here, unlike
the queries view.

The panel footer states that the aggregation is one row per distinct query name, and — when the
back end returned its maximum — that more distinct names exist in the capture and are not listed.
The page does not pass the endpoint's `limit` parameter, so that maximum is the endpoint default of
**500 names** (`/dns/domains` accepts 1–5000 but the page never asks for more). In
`sf19us-MTA-lab-01.pcap` the capture holds 81 distinct query names, well under the cap, so that
footer reads "Every distinct name in this capture is listed."

### What the page shows when there is nothing

* **No capture selected** — the shared `AnalysisGuard` points at [PCAP-Files.md](PCAP-Files.md); a
  running analysis shows its progress instead, and a failed or cancelled one shows why.
* **No queries, no filters** — *"TShark dissected no DNS messages in this capture. If it uses
  encrypted DNS (DoH or DoT), the queries are inside TLS and are not decrypted by this app."*
* **No rows matching active filters** — a separate empty state that names "unanswered only" and
  "NXDOMAIN only" as filters that can legitimately match nothing in a clean capture, with a reset
  button.
* **Domains view** — either "No domains in this analysis" (nothing to aggregate) or "No domain
  matches that filter" (the aggregation came back, the client-side substring matched nothing). The
  noisiest-clients panel has its own case: when no query carried a client address, it says so
  rather than showing an empty table.

## 3. Where the data comes from

| Layer | Name |
|---|---|
| Page component | `frontend/src/pages/DnsPage.tsx` — `DnsPage` (wrapped in `AnalysisGuard`), `DnsContent`, `TopClientsPanel`, `DomainsPanel`, `QueryDetail`, `QueryDetailBody` |
| Shared filter state | `useUrlFilters` in `frontend/src/components/protocols/ProtocolFilters.tsx` |
| Flags and legends | `DNS_FLAG_CATALOG`, `DNS_FLAG_KEYS`, `DNS_SHAPE_THRESHOLDS` in `frontend/src/components/protocols/ProtocolFlags.tsx` |
| Answer and shape rendering | `frontend/src/components/protocols/DnsAnswers.tsx` |
| Frontend client | `dnsApi.list` / `dnsApi.get` / `dnsApi.domains` in `frontend/src/services/api.ts` |
| Endpoints | `GET /api/analyses/{analysis_id}/dns` (list, plus `qtypes`, `rcodes` and `top_clients`), `GET /api/analyses/{analysis_id}/dns/{row_id}` (detail), `GET /api/analyses/{analysis_id}/dns/domains` (aggregation) |
| Route module | `backend/app/api/routes_dns.py` (router prefix `/api/analyses/{analysis_id}`) |
| Table | `dns_queries` in `backend/app/db/schema.sql` |
| Analysis that fills it | `backend/app/services/dns_analyzer.py`, run as the `dns` stage of `backend/app/services/pipeline.py` |

The list serves `dns_queries` only; `qtypes`, `rcodes` and `top_clients` are computed from the same
table for the whole analysis, so no filter value can be offered that is absent from the capture.
The domains endpoint aggregates the same rows with `GROUP BY query_name`, plus one extra query per
group for the rcode breakdown and one for the resolved addresses.

The analyser streams one TShark field pass (`frame.number`, `frame.time_epoch`, `dns.id`,
`dns.flags.response`, `dns.flags.rcode`, `dns.qry.name`, `dns.qry.type`, `dns.a`, `dns.aaaa`,
`dns.cname`, `dns.resp.ttl`, `ip.src`, `ip.dst`, `dns.flags.authoritative`, `dns.flags.truncated`,
`dns.count.answers`), then pairs query rows with responses on `(dns.id, client, server)`, taking the
first response that appears after the query in capture order. Note that `dns.ttl` does not exist in
TShark 4.6.8; the per-record TTL is `dns.resp.ttl`, as the module comment records.

## 4. What the flags mean

Every flag is computed by `lead_flags(row, query_type)` in `backend/app/services/dns_analyzer.py`
at analysis time and stored in `dns_queries.flags`. The route does not recompute them:
`suspicious=true` is a test on the stored JSON array, and the shape metrics shown in the detail
panel are read from the row's own columns.

| Flag | Exact condition (as written in the code) | What it does not establish |
|---|---|---|
| `unanswered` | `row.response_packet is None` | That the resolver failed. The response may be missing from the capture, or the capture may have ended first. |
| `nxdomain` | `row.rcode == 3` | Anything about intent. Mistyped hosts, blocked names, expired ad domains and DGA rotation all produce NXDOMAIN; volume and timing matter far more than one answer. |
| `servfail` | `row.rcode == 2` | A deliberate attack. Resolver and upstream outages produce it routinely. |
| `long_label` | `longest >= LONG_LABEL`, with `LONG_LABEL = 40`, where `longest` is the longest dot-separated label of the name | Tunnelling. DKIM selectors, ACME/DCV validation names and CDN edge names are routinely this long. |
| `long_name` | `len(row.query_name) >= LONG_NAME`, with `LONG_NAME = 100` | The same thing. It makes tunnelling easier and is also normal for cloud and anti-abuse names that embed long identifiers. |
| `high_entropy` | `entropy > HIGH_ENTROPY` **and** `label_count >= 3`, with `HIGH_ENTROPY = 3.8`. Entropy is Shannon entropy in bits per character over the name's labels concatenated without dots, rounded to two decimals. | That the name is generated by malware. CDN edges, cloud load balancers and telemetry endpoints embed random or hashed IDs by design. Both conditions must hold: a very random two-label name raises nothing. |
| `many_ips` | `len(set(row.answer_ips)) >= MANY_IPS`, with `MANY_IPS = 4` | Fast flux. Large answer sets are the normal shape of CDNs, load balancers and round-robin pools, and inside a single capture fast flux looks identical. |
| `txt_record` | `(query_type or "").upper() == "TXT"` | Anything by itself. TXT is the standard carrier for SPF, DKIM and DMARC policy, so most TXT traffic on a real network is routine mail authentication. |

Measured, on `sf19us-MTA-lab-01.pcap`: 136 stored rows, of which 87 carry at least one flag — 42
`unanswered`, 26 `many_ips`, 16 `nxdomain` and 4 `high_entropy`. Those four are the names a browser
on that capture loaded analytics from (`buttons-config.sharethis.com`, `platform-cdn.sharethis.com`)
and one hostname that is not ordinary browsing (`Finance-8f25-PC.cocoaten.org`) — which is exactly
the point: the same flag covers both.

A note on a claim the page makes. The legend says the shape thresholds "are configurable". In this
build they are module-level constants in `dns_analyzer.py` (`LONG_LABEL`, `LONG_NAME`,
`HIGH_ENTROPY`, `MANY_IPS`), mirrored in `DNS_SHAPE_THRESHOLDS` on the front end, and
`backend/app/core/runtime_settings.py` exposes only `max_upload_mb`, `max_object_bytes`,
`body_preview_bytes`, `tshark_timeout_s` and `retain_uploads`. Changing a DNS threshold therefore
means changing the code and re-analysing the capture; nothing on the [Settings.md](Settings.md)
page moves it.

## 5. Links into the rest of the app

The page navigates only within itself — the noisiest-clients rows set `client_ip`, and table rows
set `sel`. It has no link out to the hosts table or the packet view. The parameters below are the
hand-off, and they are the ones the detections in [Threat-Hunt.md](Threat-Hunt.md) already use:

| To get there | Use | What to look for |
|---|---|---|
| One name's rows | `/dns?domain=<name>` | Substring match, so a base domain also brings in its subdomains — use the whole name to isolate one. |
| One name from one client | `/dns?domain=<name>&client_ip=<client>` | The run of names a single host generated, which is where a DGA or a tunnel shows its shape. |
| One client's behaviour | `/dns?client_ip=<client>` | Whether one domain dominates, or the client looks up everything it does. |
| The resolver | `/dns?server_ip=<resolver>` | Whether queries went to the resolver the network expects. |
| Only failures | `/dns?nxdomain=true` | The full set of names that do not exist, which is where a DGA lives. |
| Only unanswered queries | `/dns?unanswered=true` | Whether the capture is one-directional, or a specific resolver stopped answering. |
| By record type | `/dns?qtype=TXT` | TXT-heavy traffic in a capture that has no business using it. |
| Only flagged rows | `/dns?suspicious=true` | The analyser's second opinion on the same traffic. |
| The aggregated names | `/dns?view=domains` | Which names recur, how many clients asked, and everything they ever resolved to. |
| A TXT name's content | `/packets?mode=basic&sel=<frame>&transport=udp` | TXT text is not stored in the row, so the answer has to be read from the packet bytes; the detail panel gives the query and response frame numbers, and DNS is UDP here. |

The client's other protocol activity is one parameter hop away in [HTTP.md](HTTP.md)
(`/http?client_ip=<client>`) and [TLS.md](TLS.md) (`/tls?ip=<client>`), and the host roll-up that
ties the address to everything else is [Hosts.md](Hosts.md). The detections that consume this page's
columns are [ThreatHunter/DnsAnomalies.md](ThreatHunter/DnsAnomalies.md),
[ThreatHunter/DnsTunnelling.md](ThreatHunter/DnsTunnelling.md) and
[ThreatHunter/RareCommunicationPairs.md](ThreatHunter/RareCommunicationPairs.md).

## 6. Limits and honest caveats

* **Encrypted DNS is invisible.** DoH and DoT queries travel inside TLS or HTTPS and are not
  decrypted by this app. A capture whose resolver traffic is DoH can legitimately store no DNS rows
  at all.
* **TXT and other record content is not stored.** `answers`, `answer_ips` and `cnames` are built
  from A, AAAA and CNAME fields only (`_merge_response` in `dns_analyzer.py`), so the Answers count
  on the table is the number of those records — not TShark's `dns.count.answers`, which is read into
  the frame but never persisted. A TXT answer's text, an MX, an SOA, a CAA record: none of it is on
  the row, and the page says so. Read those from the packet bytes with
  [Packets.md](Packets.md).
* **A response whose query is not in the capture is dropped**, not shown as an orphan row. The
  asymmetry is deliberate but it is a blind spot: response-only traffic never appears.
* **`unanswered` is about the file.** A query is unanswered within this capture. That can mean the
  resolver never replied, or that the reply was not captured — the page states both readings.
* **Merging is a heuristic.** Queries and responses are paired on `(dns.id, client, server)`, taking
  the first response after the query in capture order. A repeated transaction id with a reordered or
  duplicated response can therefore attach the wrong answer, and the row will look internally
  consistent.
* **TTL is one number.** `min_ttl` is the smallest TShark per-record TTL in the merged response;
  per-record TTLs are not kept, so a response mixing a 30-second A record with a 3600-second CNAME
  shows only 30.
* **A missing response means missing columns.** With no merged response, `rcode`, `rcode_name`,
  `answers`, `answer_ips`, `min_ttl`, `authoritative`, `truncated` and `response_delay` are all NULL
  and the page renders `—`. In `sf19us-MTA-lab-01.pcap` that is 42 of 136 rows with no rcode at all
  — a third of the table showing dashes in the Rcode column is normal, not an error.
* **Codes outside the tables are shown as numbers.** A query type with no IANA mnemonic in the
  analyser's table renders as `TYPE<n>`; an rcode outside the six known ones renders as `RCODE_<n>`.
* **Client identity is an address only.** Several machines behind one NAT address are one client and
  can collectively cross the volume threshold.
* **The domains view is capped and unfiltered server-side.** At most 500 distinct names are returned
  and the page never asks for more; its Domain box and Sort select filter what came back rather than
  re-running the aggregation, so on a capture with more than 500 names a search can miss a name that
  was never returned.
* **Paging is bounded** by `MAX_PAGE_SIZE = 1000` rows per request.
* **A flag is not a verdict.** The page's own caveat: long labels, random-looking strings, large
  answer sets and TXT queries are produced by CDNs, cloud platforms, anti-abuse systems and
  telemetry just as readily as by abuse.

---

**Related:** [HTTP](HTTP.md) · [TLS](TLS.md) · [Hosts](Hosts.md) · [Packets](Packets.md) · [Threat-Hunt.md](Threat-Hunt.md) · [Investigate.md](Investigate.md) · [DnsAnomalies](ThreatHunter/DnsAnomalies.md) · [DnsTunnelling](ThreatHunter/DnsTunnelling.md) · [README.md](README.md)
