# ShinboShark database layer — what breaks at 1M packets

Analysis of the SQLite/schema/read-path/write-path layer at `C:\_deepSeekApps\ShinboShark`.
**Nothing in the repository or in `data/apackets.db` was modified.** All write-side and
large-scale measurements were taken on throwaway databases built under
`%TEMP%\dsh-*/apackets_scale\`; the real database was opened read-only
(`file:...?immutable=1`, never `mode=ro`).

## How the numbers were produced

| Source | What it is |
|---|---|
| `data/apackets.db` | the real DB: 23 analyses, 74,012 packets, 895 conversations, 497 DNS, 155 HTTP, 276 TLS, 299 hosts, 891 streams, 312 findings, 129 objects, 1,615 Suricata rules. 74.6 MB, `page_size=4096`, 18,231 pages, `freelist_count=0`, **no `sqlite_stat1` (never `ANALYZE`d)**. 39 explicit indexes + 10 implicit PK autoindexes. |
| `full.db` | 1,000,000 packet rows built by taking the 55,434 real rows of the largest analysis (`48076897292d4663b5fb4938537d4dc6`, `SpaceX_loads_of_tabs.pcapng`), cycling them with incremented `number`/`time_epoch`/stream ids, inserted **with the exact DDL and the exact batching `packet_indexer.py` uses** (1,000/commit, `BEGIN` … `commit()`), all 11 explicit indexes + PK present. |
| `lean.db` | same 1,000,000 rows, same table, **PK only**. |
| `side2.db` | `conversations` 50,000 / `streams` 50,000 / `dns_queries` 25,000 / `http_transactions` 12,000 / `tls_sessions` 20,000 / `hosts` 3,000 / `findings` 800 rows, real column values cycled from the real DB (counts are an assumption — see *Could not determine*). |

Python 3.12, SQLite **3.45.3** (the version bundled in `backend\.venv`), Windows, warm OS
file cache. Timings are the best of 2–3 runs.

### Inventory of every index in `schema.sql`

| table | indexes (line in `schema.sql`) |
|---|---|
| `analyses` | `idx_analyses_created(created_at DESC)` (35) |
| `jobs` | `idx_jobs_analysis(analysis_id, created_at DESC)` (51) |
| `packets` | PK → implicit `sqlite_autoindex_packets_1(analysis_id, number)` (92); `idx_pk_number(analysis_id, number)` (94); `idx_pk_time(analysis_id, time_epoch)` (95); `idx_pk_src(analysis_id, src_ip)` (96); `idx_pk_dst(analysis_id, dst_ip)` (97); `idx_pk_srcport(analysis_id, src_port)` (98); `idx_pk_dstport(analysis_id, dst_port)` (99); `idx_pk_proto(analysis_id, protocol)` (100); `idx_pk_transport(analysis_id, transport)` (101); `idx_pk_len(analysis_id, frame_len)` (102); `idx_pk_tcpstream(analysis_id, tcp_stream)` (103); `idx_pk_udpstream(analysis_id, udp_stream)` (104) |
| `conversations` | PK autoindex (128); `idx_conv_transport(analysis_id, transport)` (130); `idx_conv_bytes(analysis_id, bytes_total DESC)` (131); `idx_conv_a(analysis_id, endpoint_a)` (132) |
| `streams` | PK autoindex `(analysis_id, transport, stream_id)` (147) |
| `http_transactions` | `idx_http_analysis(analysis_id, time_epoch)` (184); `idx_http_host(analysis_id, host)` (185); `idx_http_method(analysis_id, method)` (186); `idx_http_status(analysis_id, status_code)` (187); `idx_http_stream(analysis_id, stream_id)` (188) |
| `dns_queries` | `idx_dns_analysis(analysis_id, time_epoch)` (218); `idx_dns_name(analysis_id, query_name)` (219); `idx_dns_client(analysis_id, client_ip)` (220); `idx_dns_rcode(analysis_id, rcode_name)` (221); `idx_dns_qtype(analysis_id, query_type)` (222) |
| `tls_sessions` | `idx_tls_analysis(analysis_id, time_epoch)` (256); `idx_tls_sni(analysis_id, sni)` (257); `idx_tls_version(analysis_id, version)` (258); `idx_tls_stream(analysis_id, stream_id)` (259) |
| `hosts` | PK autoindex `(analysis_id, ip)` (279); `idx_hosts_bytes(analysis_id, bytes_sent DESC)` (281) |
| `findings` | `idx_findings_analysis(analysis_id, severity)` (297); `idx_findings_rule(analysis_id, rule_id)` (298) |
| `objects` | `idx_objects_analysis(analysis_id)` (322) |
| `indicators` | `idx_indicators_analysis(analysis_id, type)` (332) |
| `stats_cache` | PK autoindex `(analysis_id, kind)` (346) |
| `suricata_rules` | `idx_suricata_enabled(enabled, supported)` (382); `idx_suricata_severity(severity)` (383); `idx_suricata_protocol(protocol)` (384); `idx_suricata_source(source)` (385) |

**Important structural fact:** every index on every capture-derived table starts with
`analysis_id`. The consequence is that **no packet query ever produces a bare `SCAN`** — the
`EXPLAIN QUERY PLAN` output for all 60 query shapes I tested on the real DB contains
`SEARCH … USING INDEX/COVERING INDEX` or `SEARCH … USING INTEGER PRIMARY KEY`, never
`SCAN packets`. The scaling failure is therefore *not* "missing index → full table scan"; it
is **(a)** `SEARCH … USING INDEX idx_pk_number (analysis_id=?)` — an index "search" whose only
usable term is `analysis_id`, i.e. a scan of *the whole analysis* — and **(b)** temp B-tree
sorts. Both are quoted verbatim below.

---

## Findings, ordered by impact

### 1. BLOCKER — `GET /analyses/{id}/summary` (Dashboard *and* Info) costs 12.3 s of packet aggregates at 1M rows, and its top-domains block is quadratic in Python

*One-line:* the summary is recomputed on every request from ~26 queries, 10 of which scan the
whole packet index for the analysis; the last one is an in-process nested loop.

Evidence — `backend/app/api/routes_analyses.py`:

* `_totals` (346–406) issues **11 separate queries** against `packets`
  (`routes_analyses.py:349-366`), each of which is a scan of 1M index entries.
* `_top_talkers` (464–481) — `UNION ALL` of `packets` with itself, then `GROUP BY ip, direction`.
* `_top_ports` (484–504) — `GROUP BY dst_port, transport` over every packet.
* `_protocol_distribution` (409–423), `_traffic_series` (426–461).
* `_top_domains` (566–655) loads **all** `dns_queries.answer_ips` rows and **all**
  `conversations` rows and then loops `for name, addresses in domain_ips: for conv in conversations:`
  (608–632) in pure Python.

Measured on `full.db` (1,000,000 rows), plans verbatim:

```
SELECT COUNT(*) FROM packets WHERE analysis_id=?
  SEARCH packets USING COVERING INDEX idx_pk_udpstream (analysis_id=?)                    →  148 ms
SELECT COALESCE(SUM(frame_len),0) FROM packets WHERE analysis_id=?
  SEARCH packets USING COVERING INDEX idx_pk_len (analysis_id=?)                          →  221 ms
SELECT COUNT(DISTINCT src_ip) … AND src_ip IS NOT NULL
  SEARCH packets USING COVERING INDEX idx_pk_src (analysis_id=? AND src_ip>?)             →  237 ms (no stats)
SELECT COALESCE(protocol,'Unknown'), COUNT(*), SUM(frame_len) … GROUP BY protocol ORDER BY packets DESC LIMIT 15
  SEARCH packets USING INDEX idx_pk_proto (analysis_id=?) | USE TEMP B-TREE FOR ORDER BY  → 1287 ms
SELECT CAST((time_epoch-?)/? AS INTEGER) AS bucket, … GROUP BY bucket ORDER BY bucket
  SEARCH packets USING INDEX idx_pk_time (analysis_id=? AND time_epoch>?) | USE TEMP B-TREE FOR GROUP BY → 1287 ms
SELECT ip, direction, SUM(packets), SUM(bytes) FROM (SELECT src_ip … UNION ALL SELECT dst_ip …) GROUP BY …
  CO-ROUTINE (subquery-2) | COMPOUND QUERY | LEFT-MOST SUBQUERY |
  SEARCH packets USING INDEX idx_pk_src (analysis_id=? AND src_ip>?) | UNION ALL |
  SEARCH packets USING INDEX idx_pk_dst (analysis_id=? AND dst_ip>?) | SCAN (subquery-2) |
  USE TEMP B-TREE FOR GROUP BY | USE TEMP B-TREE FOR ORDER BY                             → 6435 ms
SELECT dst_port AS port, COALESCE(transport,'other'), COUNT(*), SUM(frame_len) … GROUP BY dst_port, transport
  SEARCH packets USING INDEX idx_pk_dstport (analysis_id=? AND dst_port>?) |
  USE TEMP B-TREE FOR GROUP BY | USE TEMP B-TREE FOR ORDER BY                             → 2267 ms
TOTAL for those 10 packet queries: 12,319 ms
```

`_top_domains` nested loop, measured on a stand-in workload and projected
(285 ns per inner iteration, Python 3.12):

| distinct domains | conversations | iterations | pure-Python time |
|---|---|---|---|
| 2,000 | 20,000 | 40 M | 11 s |
| 8,000 | 50,000 | 400 M | **114 s** |
| 25,000 | 100,000 | 2.5 G | **713 s** |

Cost and growth: the 10 aggregate queries are each O(packets in the analysis) — they do not
grow with capture size *per unit of work*, they grow linearly with the capture, and there are
ten of them, so the dashboard goes from ~40 ms at 74k packets to ~12 s at 1M. `_top_domains`
is O(domains × conversations), i.e. quadratic: it is the single worst-scaling piece of read
code in the app. Both Dashboard and Info pages call this endpoint (`frontend/src/pages/DashboardPage.tsx:57`,
`InfoPage.tsx:100`), and Info re-polls it every `FRESH_POLL_MS` while the analysis is recent.

Fix (no new index will help):
1. Compute the summary once, at the end of the pipeline, and store it in `stats_cache`
   (the table already exists and is used for exactly this purpose — `pipeline.py:254-261`),
   then serve `/summary` from that row. Everything the summary needs is already available in
   `analyses` (`packet_count`, `bytes_total`, `capture_start/end`, `tcp_count`, …,
   `pipeline.py:127-153`).
2. Replace `_top_domains` with one SQL pass: `dns_queries.answer_ips` exploded to IPs joined
   against `conversations` on `ip_a`/`ip_b`, or materialise a `domain_traffic` table during
   the DNS stage.
3. Replace `_top_talkers`, `_top_ports`, `_protocol_distribution`, `_traffic_series` with a
   single `GROUP BY` pass, or read them from `hosts` / `conversations` (already aggregated
   per-conversation and per-host) instead of re-deriving them from `packets`.

**Verified** (all timings and plans above were executed).

---

### 2. BLOCKER — the packets list runs an unfiltered `COUNT(*)` *and* `LIMIT/OFFSET` on every request

*One-line:* each page costs 148 ms just to count 1M rows, plus 180 ms at `OFFSET 900000`.

Evidence — `backend/app/api/routes_packets.py:247-257`:

```python
247  count_sql = f"SELECT COUNT(*) AS n FROM packets p WHERE {where}"
248  total = int(connection.execute(count_sql, tuple(bound)).fetchone()["n"])
250  sql = (f"SELECT {SUMMARY_COLUMNS} FROM packets p WHERE {where} "
251         f"ORDER BY {order_sql} {direction} LIMIT ? OFFSET ?")
```

and `backend/app/api/deps.py:29-34` — the offset is page-derived, there is no keyset path:

```python
29  @property
30  def offset(self) -> int:
31      return (self.page - 1) * self.page_size
```

Measured on 1M rows (`SELECT <26-column SUMMARY_COLUMNS> … ORDER BY p.number ASC LIMIT 100 OFFSET ?`,
plan `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` at every depth):

| depth | time |
|---|---|
| OFFSET 0 | 0.7 ms |
| OFFSET 1,000 | 0.8 ms |
| OFFSET 100,000 | 20.9 ms |
| OFFSET 500,000 | 103.1 ms |
| OFFSET 900,000 | **179.8 ms** |
| keyset `WHERE number > 900000 ORDER BY number LIMIT 100` | **0.6 ms** |

Same shape for the sort keys:
`ORDER BY src_ip LIMIT 100 OFFSET 900000` → **194 ms** (vs 0.1 ms at OFFSET 0);
`ORDER BY frame_len DESC … OFFSET 900000` → **176 ms**.
The counting queries: `COUNT(*)` 148 ms; `COUNT(*) WHERE transport='tcp'` 120 ms;
`COUNT(*) WHERE (src_ip=? OR dst_ip=?)` 885 ms.

Cost and growth: `OFFSET n` is linear in `n` — SQLite walks and discards `n` index entries
(the plan says `SEARCH`, so SQLite behaves, but "search on `analysis_id` only" *is* a walk).
At 1M rows the packet explorer's first paint costs 0.7 + 148 = ~150 ms and the last page costs
~330 ms; at 100k rows it is ~5 + 15 ms, which is why it feels fine today. The unqualified
`COUNT(*)` is pure waste: `analyses.packet_count` is maintained by the pipeline
(`pipeline.py:130-153`) and agrees with the real count — verified for the biggest analysis
(`stored=55,434 actual=55,434`).

Fix:
1. When no filter is active (the common case), take `total` from the analysis row that
   `_ready()` already fetched (`packet_count`, or `bytes_total`/`dns_count`/… per endpoint)
   instead of running `COUNT(*)`.
2. Keyset pagination: the client already knows the sort key and the last row's values, so
   `WHERE analysis_id=? AND (number) > ? ORDER BY number LIMIT 100` replaces `OFFSET`
   (0.6 ms, measured). This needs a **unique tiebreak** in the packets `ORDER BY`
   (`routes_packets.py:51-64` sorts by `p.number` only for the default; `time_epoch`, `src_ip`,
   `frame_len`, … are not unique) — add `, p.number` as the last sort term.
3. For the filtered cases, keep `LIMIT/OFFSET` but bound the page number (deep pages are
   inherently O(offset) in SQLite), or `OFFSET`-cap at, say, 10,000 and tell the UI to narrow
   the filter.

**Verified.**

---

### 3. HIGH — `analysis_id = ?` + `ORDER BY number` makes the planner choose the *sort-friendly* index and throw away filter selectivity: 0.2–1.1 s per filtered packet request

*One-line:* the structured filters are indexed, but the default `ORDER BY p.number` makes
SQLite read every index entry for the analysis and check the filter per row.

Evidence — `routes_packets.py:156-207` builds the predicates; the default sort is
`DEFAULT_SORT = "p.number"` (`routes_packets.py:64`) and every structured filter composes with it.

Real DB (`48076897…`, 55,434 packets) plans:

```
SELECT … FROM packets p WHERE p.analysis_id = ? AND p.src_ip = ? ORDER BY p.number LIMIT 100
  SEARCH p USING INDEX idx_pk_number (analysis_id=?)               ← the 12th index, chosen only because it is ordered by number
SELECT … WHERE p.analysis_id=? AND (p.src_ip=? OR p.dst_ip=?) ORDER BY p.number LIMIT 100
  SEARCH p USING INDEX idx_pk_number (analysis_id=?)
SELECT … WHERE p.analysis_id=? AND (p.tcp_stream=? OR p.udp_stream=?) ORDER BY p.number LIMIT 100
  SEARCH p USING INDEX idx_pk_number (analysis_id=?)
```

Measured on 1M rows, **before** `ANALYZE` (i.e. the state the shipped DB is in — no `sqlite_stat1`).
The four rows below use an address that does **not** occur in the synthetic capture, which is the
worst case for the scan path and the best case for the index path — it isolates the cost of the
plan choice itself from the cost of returning rows:

| query (all with `ORDER BY p.number LIMIT 100`) | plan | time |
|---|---|---|
| `src_ip = ?` (0 matches) | `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` | **768.9 ms** |
| `dst_ip = ?` (0 matches) | same | **690.8 ms** |
| `src_ip = ?` **without** `ORDER BY` | `SEARCH p USING INDEX idx_pk_src (analysis_id=? AND src_ip=?)` | **0.0 ms** |
| `transport = ?` (rare value) | `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` | **706.0 ms** |
| `search` (4× `LIKE '%…%'`, no match) | `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` | **1010.0 ms** |
| `tcp_flags LIKE '%SYN%'` | `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` | **1055.9 ms** |

After `ANALYZE` (same data, same queries):

| query | plan after ANALYZE | time |
|---|---|---|
| `src_ip = ? ORDER BY number` | `SEARCH p USING INDEX idx_pk_src (analysis_id=? AND src_ip=?) \| USE TEMP B-TREE FOR ORDER BY` | 197–238 ms |
| `(src_ip=? OR dst_ip=?) ORDER BY number` | `MULTI-INDEX OR \| INDEX 1 SEARCH … idx_pk_src \| INDEX 2 SEARCH … idx_pk_dst \| USE TEMP B-TREE FOR ORDER BY` | 392–443 ms |
| `COUNT(*) WHERE (src_ip=? OR dst_ip=?)` | `MULTI-INDEX OR …` | 101–105 ms |
| `transport = 'sctp'` (still bad) | `SEARCH p USING INDEX idx_pk_number (analysis_id=?)` | 623–663 ms |

With the composite index added (measured on the same 1M-row file, each index built and the
query re-run):

| candidate index | before | after | plan after | build | size |
|---|---|---|---|---|---|
| `idx_pk_src_number ON packets(analysis_id, src_ip, number)` | 203 ms | **0.6 ms** | `SEARCH p USING INDEX idx_pk_src_number (analysis_id=? AND src_ip=?)` (no sort) | 6.5 s | +59.5 MB |
| `idx_pk_dst_number ON packets(analysis_id, dst_ip, number)` | 132 ms | **0.7 ms** | `SEARCH … idx_pk_dst_number (analysis_id=? AND dst_ip=?)` | 6.0 s | +59.3 MB |
| `idx_pk_transport_number ON packets(analysis_id, transport, number)` | 630 ms | **0.0 ms** | `SEARCH … idx_pk_transport_number (analysis_id=? AND transport=?)` | 5.8 s | +49.4 MB |
| `idx_pk_dstport_number ON packets(analysis_id, dst_port, number)` | 426 ms | **0.7 ms** | `SEARCH … idx_pk_dstport_number (analysis_id=? AND dst_port=?)` | 6.1 s | +49.1 MB |
| `idx_pk_time_number ON packets(analysis_id, time_epoch, number)` | 0.0 ms | 0.0 ms | unchanged (`idx_pk_time` + temp sort) | 7.3 s | +54.6 MB |

**Why that column order, not the obvious one:** `(analysis_id, <filter column>, number)` puts
the equality term second (so the index can be searched for it) and the sort key third (so the
`ORDER BY number` is satisfied by the index scan itself — the `USE TEMP B-TREE FOR ORDER BY`
disappears, which is worth 200 ms on the `src_ip` case even after `ANALYZE`). The existing
indexes stop at the filter column, which is exactly why they lose to `idx_pk_number`.
Adding `number` costs ~11 B/row (measured: `index(number)` alone = 11.0 B/row vs 44.3 B/row
for `(analysis_id, number)`), i.e. ~5 MB at 1M rows per index — cheap for what it buys.

**Secondary, orthogonal finding in the same queries:** the text filters are structurally
unindexable — `search` is `p.info LIKE ? OR p.protocol LIKE ? OR p.src_ip LIKE ? OR p.dst_ip LIKE ?`
with `%…%` (`routes_packets.py:201-203`), and `tcp_flags` is wrapped in `REPLACE(...) LIKE`
(`routes_packets.py:182`). Both force a full evaluation over the analysis: **1.0 s per
keystroke at 1M rows**. Fix: an FTS5 table (or a single normalised `search_text` column with a
trigram index) fed at insert time, and an INTEGER bitmask column for TCP flags (the indexer
already parses `tcp.flags` into `tcp_flags_raw` — see finding 4) so `flags & 2 = 2` can use an
index. **Verified** (plans and timings quoted; the FTS/bitmask fixes are inferred, not built).

---

### 4. HIGH — list endpoints: `LIMIT/OFFSET` with a *non-aligned* `ORDER BY`, plus 1–3 extra aggregate queries per request

*One-line:* every list page is `COUNT(*)` + `LIMIT/OFFSET` + drop-down aggregates, and in four
of the six lists the sort key is not fully covered by an index.

Where `OFFSET` is used (all of them — `Pagination.offset`, `deps.py:29`): `/packets`
(`routes_packets.py:252,255`), `/conversations` (`routes_conversations.py:103`), `/findings`
(`routes_findings.py:175`), `/dns` (`routes_dns.py:135`), `/http` (`routes_http.py:176`),
`/tls` (`routes_tls.py:122`), `/hosts` (`routes_hosts.py:139`), `/analyses`
(`routes_analyses.py:202`), `/objects`.

`COUNT(*)` per request: `/packets` (247), `/conversations` (93-96), `/findings` (166),
`/dns` (128), `/http` (167), `/tls` (115), `/hosts` (129), `/analyses` (192) — all of them.
Extra aggregates per request: `/conversations` also runs `SELECT COUNT(*), SUM(bytes_total)`
(109-115); `/hosts` runs `SUM(bytes_sent), COUNT(*)` (144-150); `/dns` runs `_distinct` twice
plus `top_clients` (141-153); `/http` runs `_distinct` twice plus `_status_classes` (182-184);
`/tls` runs `_distinct` twice (128-129); `/findings` runs `GROUP BY severity` (181).

Good news, verified: the DNS/HTTP/TLS lists use `ORDER BY <sort>, id` where `id` is the INTEGER
PRIMARY KEY, and the index is `(analysis_id, time_epoch)` — SQLite treats the index as
`(analysis_id, time_epoch, rowid)`, so **no sort step appears at all**:

```
SELECT * FROM dns_queries  WHERE analysis_id=? ORDER BY time_epoch ASC, id ASC LIMIT 100 OFFSET 0
  SEARCH dns_queries USING INDEX idx_dns_analysis (analysis_id=?)
SELECT * FROM http_transactions WHERE analysis_id=? ORDER BY time_epoch ASC, id ASC LIMIT 100 OFFSET 0
  SEARCH http_transactions USING INDEX idx_http_analysis (analysis_id=?)
SELECT * FROM tls_sessions WHERE analysis_id=? ORDER BY time_epoch ASC, id ASC LIMIT 100 OFFSET 0
  SEARCH tls_sessions USING INDEX idx_tls_analysis (analysis_id=?)
```

At the scaled side-table sizes those are cheap (DNS page 0.6 ms, OFFSET 24900 3.5 ms; TLS page
0.8 ms, OFFSET 19900 5.1 ms; HTTP page 15.2 ms because the rows carry bodies).

The bad ones (measured on `side2.db`, 50k/25k/12k/20k/3k/800 rows — note the synthetic DB holds
a *single* analysis, so `analysis_id = ?` is estimated at 100% selectivity and SQLite sometimes
prefers a scan; the real multi-analysis DB produced `SEARCH … USING INDEX idx_conv_bytes (analysis_id=?) | USE TEMP B-TREE FOR RIGHT PART OF ORDER BY` for the same query, quoted from the real DB plan dump):

| query | plan | time |
|---|---|---|
| `conversations ORDER BY bytes_total DESC, conv_id ASC LIMIT 100 OFFSET 0` | `SCAN conversations \| USE TEMP B-TREE FOR ORDER BY` (real DB: `SEARCH … idx_conv_bytes (analysis_id=?) \| USE TEMP B-TREE FOR RIGHT PART OF ORDER BY`) | 29–31 ms |
| same, `OFFSET 49000` | same | **1476 ms** |
| `conversations ORDER BY start_time DESC, conv_id ASC OFFSET 49000` | `SCAN … TEMP B-TREE FOR ORDER BY` (no index on `start_time` at all) | **1461 ms** |
| `conversations … AND (ip_a=? OR ip_b=?)` (host detail, `routes_hosts.py:314-322`) | `SCAN conversations …` — **no index contains `ip_a`/`ip_b`** | 31 ms @50k (real DB: full `SEARCH … idx_conv_bytes (analysis_id=?)`) |
| `hosts ORDER BY packets_sent DESC, ip` | `SCAN hosts \| USE TEMP B-TREE FOR ORDER BY` | 3.7 ms @3k |
| `hosts ORDER BY peer_count DESC, ip` | `SCAN hosts \| USE TEMP B-TREE FOR ORDER BY` | 3.3 ms @3k |
| `hosts … bytes_received>0 ORDER BY bytes_received DESC LIMIT 1` (`routes_analyses.py:522-535`) | `SCAN hosts \| TEMP B-TREE FOR ORDER BY` | 0.6 ms @3k |
| `findings ORDER BY CASE severity … , rule_id, id` (default, `routes_findings.py:74`) | `SEARCH findings USING INDEX idx_findings_rule (analysis_id=?) \| USE TEMP B-TREE FOR ORDER BY` | 3.3 ms @800 |
| `tls_sessions GROUP BY ja3` (`/tls/fingerprints`) | `SCAN tls_sessions \| TEMP B-TREE FOR GROUP BY \| TEMP B-TREE FOR group_concat(DISTINCT) \| TEMP B-TREE FOR ORDER BY` | 31.6 ms @20k |

Two concrete index mistakes are visible here:

* `idx_conv_a(analysis_id, endpoint_a)` (`schema.sql:132`) indexes the **display string**
  `endpoint_a` — used only as a `SORTABLE` key (`routes_conversations.py:37`). Every query that
  actually needs an index on conversations filters **`ip_a` / `ip_b`** (`routes_hosts.py:317`,
  `routes_hosts.py:171` for the graph, `routes_findings.py:404-416`). Those columns have no index
  at all, so `(ip_a = ? OR ip_b = ?)` is *always* a scan of every conversation in the analysis.
* `hosts` gets one sort index (`bytes_sent DESC`) but the UI offers seven sorts
  (`routes_hosts.py:32-40`); the other six sort the whole host set.

Fix:
```sql
-- packets (see finding 3)
CREATE INDEX idx_pk_src_number       ON packets(analysis_id, src_ip,  number);
CREATE INDEX idx_pk_dst_number       ON packets(analysis_id, dst_ip,  number);
CREATE INDEX idx_pk_srcport_number   ON packets(analysis_id, src_port, number);
CREATE INDEX idx_pk_dstport_number   ON packets(analysis_id, dst_port, number);
CREATE INDEX idx_pk_transport_number ON packets(analysis_id, transport, number);
-- conversations
CREATE INDEX idx_conv_bytes_id ON conversations(analysis_id, bytes_total DESC, conv_id ASC); -- kills "RIGHT PART OF ORDER BY"
CREATE INDEX idx_conv_ip_a     ON conversations(analysis_id, ip_a, bytes_total DESC, conv_id);
CREATE INDEX idx_conv_ip_b     ON conversations(analysis_id, ip_b, bytes_total DESC, conv_id);
CREATE INDEX idx_conv_start    ON conversations(analysis_id, start_time DESC, conv_id);
-- hosts
CREATE INDEX idx_hosts_packets_sent   ON hosts(analysis_id, packets_sent DESC, ip);
CREATE INDEX idx_hosts_packets_recv   ON hosts(analysis_id, packets_received DESC, ip);
CREATE INDEX idx_hosts_bytes_received ON hosts(analysis_id, bytes_received DESC, ip);
CREATE INDEX idx_hosts_peer_count     ON hosts(analysis_id, peer_count DESC, ip);
-- findings: store the rank (see finding 5) or index the expression outcome
CREATE INDEX idx_findings_sev_rank ON findings(analysis_id, severity, rule_id, id);
```
And replace the per-request aggregates with stored counters (`analyses.*_count`) and/or cached
dropdown values (`_distinct` returns **every** distinct host/SNI unbounded —
`routes_http.py:204-213`, `routes_tls.py:206-214` — so a big capture inflates the JSON of every
list response, not just its query cost).

**Verified** for the plans and timings; the index statements themselves are the fix, not measured
in full (only the packets composites were measured, in finding 3).

---

### 5. HIGH — `client_ip = ? OR server_ip = ?` is unindexed on the server side in every protocol table

*One-line:* the per-host detail view scans every DNS/HTTP/TLS row of the analysis.

Evidence — `backend/app/api/routes_hosts.py:323-349`:

```sql
SELECT * FROM dns_queries     WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?) ORDER BY time_epoch ASC LIMIT 50
SELECT * FROM http_transactions WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?) ORDER BY time_epoch ASC LIMIT 50
SELECT * FROM tls_sessions     WHERE analysis_id = ? AND (client_ip = ? OR server_ip = ?) ORDER BY time_epoch ASC LIMIT 50
```

Plans and timings (scaled side tables):

```
DNS  SEARCH dns_queries      USING INDEX idx_dns_analysis  (analysis_id=?)   → 34.7 ms
HTTP SEARCH http_transactions USING INDEX idx_http_analysis (analysis_id=?)   → 67.5 ms
TLS  SEARCH tls_sessions     USING INDEX idx_tls_analysis  (analysis_id=?)   → 39.8 ms
```

`idx_dns_client` exists (`schema.sql:220`) but covers only `client_ip`; `server_ip` is indexed
nowhere, and `http_transactions` / `tls_sessions` have no `client_ip`/`server_ip` index at all.
Because the predicate is an `OR`, SQLite cannot use a single-column index even where one exists —
verified: the plan for the DNS query ignores `idx_dns_client` entirely.

Also in the same handler (`routes_hosts.py:350-353`):
`SELECT COUNT(*) FROM packets WHERE analysis_id = ? AND (src_ip = ? OR dst_ip = ?)` —
**885 ms** at 1M rows (`SEARCH packets USING INDEX idx_pk_udpstream (analysis_id=?)`), i.e. the
host page's packet counter alone is close to a second.

Fix:
```sql
CREATE INDEX idx_dns_client_time  ON dns_queries(analysis_id, client_ip, time_epoch);
CREATE INDEX idx_dns_server_time  ON dns_queries(analysis_id, server_ip, time_epoch);
CREATE INDEX idx_http_client_time ON http_transactions(analysis_id, client_ip, time_epoch);
CREATE INDEX idx_http_server_time ON http_transactions(analysis_id, server_ip, time_epoch);
CREATE INDEX idx_tls_client_time  ON tls_sessions(analysis_id, client_ip, time_epoch);
CREATE INDEX idx_tls_server_time  ON tls_sessions(analysis_id, server_ip, time_epoch);
```
(so the plan becomes `MULTI-INDEX OR`, as verified for `packets`), and take the packet count for
a host from `hosts.packets_sent + hosts.packets_received`, which the host stage already computes
(`hosts` table, `schema.sql:267-268`).

**Verified** (plans/timings); fix inferred.

---

### 6. HIGH — the write path maintains **12 indexes per inserted packet**: 5.8× slower inserts, 574 MB of index for 1M packets

*One-line:* `packet_indexer.py` inserts 1,000 rows per transaction into a table with a PK
autoindex plus 11 explicit indexes, so every row costs 12 b-tree insertions.

Evidence — `backend/app/services/packet_indexer.py:109-114, 286-329`:

```python
109  INSERT_SQL = (f"INSERT OR REPLACE INTO packets ({', '.join(COLUMNS)}) "
110                 f"VALUES ({', '.join('?' for _ in COLUMNS)})")
114  BATCH_SIZE = 1000
...
292      conn = db.connect()
294      conn.execute("BEGIN")
307          if len(buffer) >= BATCH_SIZE:
308              conn.executemany(INSERT_SQL, buffer)
310              conn.commit()
311              conn.execute("BEGIN")
```

Pragmas actually in force — `backend/app/db/database.py:29-35` (not defaults):

```python
29  conn = sqlite3.connect(str(path), timeout=30.0, isolation_level="DEFERRED")
31  conn.execute("PRAGMA journal_mode=WAL")
32  conn.execute("PRAGMA foreign_keys=ON")
33  conn.execute("PRAGMA busy_timeout=10000")
34  conn.execute("PRAGMA synchronous=NORMAL")
```

So: **journal_mode=WAL, synchronous=NORMAL, foreign_keys=ON, busy_timeout=10000 ms**. No
`cache_size`, no `mmap_size`, no `wal_autocheckpoint`, no `temp_store` are set anywhere
(`grep PRAGMA` over `backend/app` returns only these four).

Measured, identical rows and identical batching (`executemany` of 1,000, `BEGIN`/`commit` per
batch), 1,000,000 rows:

| build | wall time | rows/s | file size |
|---|---|---|---|
| PK only (`lean.db`) | **11.7 s** | 85,215 | 318.7 MB (after VACUUM) |
| PK + 11 indexes (`full.db`) | **67.7 s** | 14,770 | 899.7 MB |
| index maintenance overhead | **+56.0 s (5.8×)** | | **+574 MB of index** |

One batch transaction (`1000` rows, 11 indexes) holds the write lock for **~40 ms**.

Per-row footprint measured on the real data (74,012 rows, isolated file, `VACUUM`ed):

| object | bytes/row |
|---|---|
| `packets` table | 320.9 |
| `idx_pk_number` | 44.3 |
| `idx_pk_src` / `idx_pk_dst` | 54.9 / 54.8 |
| `idx_pk_time` | 50.2 |
| `idx_pk_srcport` / `idx_pk_dstport` | 44.2 / 44.8 |
| `idx_pk_proto` / `idx_pk_transport` | 46.2 / 45.2 |
| `idx_pk_len` / `idx_pk_tcpstream` / `idx_pk_udpstream` | 43.7 / 42.9 / 42.2 |
| **all 11 indexes** | **513.5** |
| **total** | **834.2 B per packet** |

Cross-check at 1M rows: `1,000,000 × 834 B ≈ 834 MB`, measured 899.7 MB. **64% of the packets
footprint is index**, and every one of those 11 indexes must be updated on every insert.

Additional write-path costs, measured:

* The `DELETE FROM packets WHERE analysis_id = ?` that opens every indexing run
  (`packet_indexer.py:286-287`) removes 143,086 rows **out of 12 indexes in 248 ms** (~1.7 s
  for 1M rows) and does **not** return the pages to the OS (`freelist` grows; the file stays
  141.7 MB).
* `_aggregate()` (`packet_indexer.py:348-374`) runs one 11-aggregate query over `packets`
  immediately after the load — `USE TEMP B-TREE FOR count(DISTINCT)` ×2 plus
  `SEARCH packets USING INDEX idx_pk_udpstream (analysis_id=?)` — at 1M rows that is the same
  10–12 s class of scan as finding 1, on the critical path of every analysis.

Fixes worth making:
1. **Drop `idx_pk_number`** (`schema.sql:94`) — it is an exact duplicate of the PRIMARY KEY's
   autoindex `sqlite_autoindex_packets_1 (analysis_id, number)` (`schema.sql:92`), which SQLite
   happily uses for the same lookups (verified: `SELECT * FROM packets WHERE analysis_id=? AND number=?`
   plans as `SEARCH packets USING INDEX sqlite_autoindex_packets_1 (analysis_id=? AND number=?)`).
   That is one less index update per row and ~44 MB at 1M rows.
2. **Insert first, index after.** Create the `packets` indexes after the bulk load (or create them
   only for the columns this analysis actually uses). Measured ceiling: 11.7 s instead of 67.7 s
   for 1M rows. The schema comment says the DDL is frozen (`schema.sql:1`, `docs/CONTRACT.md §3`),
   so this is a design decision, not a one-line change — but dropping indexes that nothing uses
   (see the priority list) is a strictly good trade.
3. **Do not open a second connection for progress.** `JobContext.set_stage`
   (`services/jobs.py:48-78`) does `with db.get_conn() as conn:` — a brand-new connection issuing
   two UPDATEs — and `packet_indexer.py:313-322` calls it *from inside the insert loop*. Measured:
   while a 1,000-row batch transaction is open, such a write takes **340 ms** to land (it queues
   behind the writer), and two worker threads (`worker_threads = 2`, `core/config.py:41`) mean two
   analyses can contend. Pass the indexer's own `conn` into the progress update, or buffer progress
   in memory and write it once per stage.
4. Keep `synchronous=NORMAL` (correct for WAL). Consider `journal_size_limit` and a
   `wal_checkpoint(TRUNCATE)` at the end of each stage — see finding 7.

**Verified** (timings, sizes, pragma values, plans).

---

### 7. MEDIUM — contention: readers never block, but one long reader pins the WAL to >1 GB while the writer runs

*One-line:* WAL gives the UI non-blocking reads (verified), but the app's own multi-second
dashboard queries hold a snapshot that prevents checkpointing, and the WAL grows to the size of
the whole insert.

Measured with the app's exact pragmas (`wal_test` databases, 1,000-row batches):

```
1000-row batch over 11 indexes: 39.9 ms      → writer holds the write lock ~40 ms per 1000 packets

while that transaction is open:
  reader SELECT (COUNT(*))      :   1.2 ms    → WAL readers do not block on the writer
  UPDATE jobs/analyses (progress): 340.1 ms   → queued behind the indexing transaction

200,000-packet load, writer alone            : 33.7 s | WAL peak   8.1 MB | main db 141.7 MB
200,000-packet load, one open read snapshot  : 18.8 s | WAL peak 1114.0 MB | main db   0.1 MB
```

That second row is the whole point: with a single reader holding a snapshot (a 12-second
`/summary`, a 6-second packet filter, or a long CSV export), `wal_autocheckpoint=1000` pages can
never complete, so **every committed page stays in the WAL** — the main database file does not
grow at all and the WAL becomes the database. Readers then resolve pages through the WAL index
for the rest of the run, and the analysis's disk footprint momentarily doubles.

Does any write hold a transaction open for a whole stage? **No** — every writer commits per
1,000-row batch: `packet_indexer.py:307-311`, `conversation_analyzer.py:597-602`,
`dns_analyzer.py:454-465`, `http_analyzer.py:751-761`, `tls_analyzer.py:537-547`,
`host_analyzer.py:521-524` all use `BATCH_SIZE = 1000` with `commit()`/`BEGIN` per batch. The
long-lived transactions are elsewhere:

* `database.query_all`/`query_one` (`database.py:69-82`) open a **new connection per call** and
  close it. `count()` (109-112) does the same. The measured cost is **1.00 ms per connection**
  versus 0.36 ms bare, i.e. 0.64 ms of `PRAGMA journal_mode=WAL` + `foreign_keys` +
  `busy_timeout` + `synchronous` per call. `/summary` makes ~26 such calls (**178 ms of pure
  connection overhead**); `/dns/domains` makes up to 2 × 500 = 1,000 (`routes_dns.py:193-214`) —
  measured **1,470 ms vs 818 ms** for the identical queries on one reused connection
  (**652 ms of overhead** on a 345-domain response).
* `delete_analysis` (`routes_analyses.py:286-293`) deletes from 12 tables inside one
  `get_conn()` transaction — at 1M packets that is a multi-second write transaction that blocks
  every other writer.
* `_filter_numbers` (`routes_packets.py:237-244`) creates a TEMP table and `executemany`s up to
  `MAX_FILTER_ROWS = 500_000` rows on the **request's connection**; measured 47.9 ms for
  `COUNT(*)` with 50,000 frames, and the tshark pass that produces those numbers runs
  synchronously inside the request (`routes_packets.py:100`).

Fixes: batch the DNS domain loop into two `GROUP BY` queries; cache the drop-down/`_distinct`
results per analysis; use one connection per request (a `get_conn()` dependency) instead of one
per query; give `/summary` its own precomputed row (finding 1) so no request holds a snapshot
for 12 s; run `PRAGMA wal_checkpoint(TRUNCATE)` (and set `journal_size_limit`) at the end of each
pipeline stage.

**Verified.**

---

### 8. MEDIUM — schema choices that scale badly

All sizes below are measured on the real rows (isolated files, `VACUUM`ed) and projected to 1M.

**8a. The 32-character TEXT `analysis_id` is repeated in every index and is ~93% of each index entry.**
`analyses.id TEXT PRIMARY KEY` (`schema.sql:7`) is a 32-char hex string and every child table
stores it as `TEXT NOT NULL`. Measured on the real 74,012 packet rows:

```
index(analysis_id)          = 41.0 B/row
index(analysis_id, number)  = 44.3 B/row      ← only 3.3 B of that is the actual packet number
index(number)               = 11.0 B/row
```

So ~451 B of the 513 B/row of packet index is `analysis_id` duplication (11 indexes × 41 B), i.e.
**~451 MB of the ~574 MB index at 1M rows is the same 32-character string written 11 times per
row.** Fix: an `INTEGER` surrogate key on `analyses` (or a 16-byte BLOB) referenced by the child
tables, or one SQLite file per analysis (the app already has a per-analysis directory,
`storage.analysis_dir`). This single change shrinks the database by roughly a third and speeds up
every index scan, because fewer index pages are read.

**8b. Wide rows: `packets` is 38 columns, and the list endpoint selects 26 of them.**
`SUMMARY_COLUMNS` (`routes_packets.py:44-49`) pulls `protocols` (22.5 B/row), `info` (42.3 B/row),
`eth_src` + `eth_dst` (17 B each) and more out of the table page for every row of every page.
Per-column text bytes at 1M rows (measured over all 74,012 real rows):

```
info 42.3 MB · protocols 22.5 MB · eth_src 17.0 MB · eth_dst 17.0 MB ·
src_ip 12.8 MB · dst_ip 12.7 MB · tcp_flags 8.6 MB · transport 3.0 MB · protocol 4.0 MB
```

`eth_src`/`eth_dst` (34 MB at 1M) are used only by the CSV export and the detail panel, and
`protocols` duplicates information already in `protocol` + `transport` + ports. A narrower
"list row" (or a covering index for the list projection) would cut page reads — but note that a
26-column covering index would be enormous; the cheaper win is to drop `eth_*`/`protocols` from
`SUMMARY_COLUMNS`.

**8c. `TEXT` columns that actually hold numbers — and one that silently converts.**
`tcp_flags_raw TEXT` (`schema.sql:73`) receives `_int(tcp_flags_raw)` from the indexer
(`packet_indexer.py:252`), so SQLite's TEXT affinity converts the integer to text. Verified on
the real DB:

```
tcp_flags_raw   declared=TEXT     stored_type=text     sample='2'   (1.4 B/row)
dns_qtype       declared=TEXT     stored_type=text     sample='1'   (numeric code as text)
dns_rcode       declared=TEXT     stored_type=text     sample='0'   (numeric code as text)
http_status     declared=INTEGER  stored_type=integer  sample=200   (correct)
```

`tcp_flags_raw` is a boolean-ish 0–255 value stored as text: any query written as
`WHERE tcp_flags_raw = 18` will never match, and the column cannot be used for the
bitmask flag filter that finding 3 needs. `dns_qtype`/`dns_rcode` store small integers as text
(code 1, type 1) and are also duplicated by the redundant `rcode`/`query_type`-by-name columns.

**8d. JSON stored as text and parsed per row, per request.**
`hosts.ports/protocols/dns_names/tls_sni/peers` (`schema.sql:271-278`) are parsed by
`routes_hosts.py:60-77` on every host list page (100 rows) and for **all** hosts in
`/hosts/graph` (`routes_hosts.py:175-178`); `dns_queries.answers/flags` by `routes_dns.py:49-54`;
`tls_sessions.flags` by `routes_tls.py:51-55`; `findings.evidence/entities/packet_numbers` by
`routes_findings.py:99-119`, which additionally **de-duplicates and sorts the `packet_numbers`
array for every row of every page**. Measured JSON/text widths in the real DB:
`hosts` JSON 71,240 B over 299 rows (238 B/row, `ports` up to 685 B,
`dns_names` up to 2,319 B, `tls_sni` up to 2,343 B); `dns_queries` JSON 49,718 B over 497 rows
(100 B/row); `findings` text 472,359 B over 312 rows (**1,514 B/row**, `evidence` up to 2,624 B).
At scale these are payload and CPU costs, not query-plan costs, but they are paid on every page.

**8e. Columns only ever used in `WHERE` but unindexed.**
`conversations.ip_a` / `ip_b` (finding 4 — `endpoint_a` is indexed instead), `dns_queries.server_ip`,
`http_transactions.client_ip`/`server_ip`/`uri`/`user_agent`/`full_uri`, `tls_sessions.client_ip`/
`server_ip`/`ja3`/`ja4`, `hosts.packets_sent`/`bytes_received`/`peer_count`, `packets.tcp_flags`.
Also `packets.protocol` is filtered through `UPPER(p.protocol) = UPPER(?)`
(`routes_packets.py:174`), which cannot use `idx_pk_proto(analysis_id, protocol)` at all —
verified: the plan falls back to `SEARCH p USING INDEX idx_pk_number (analysis_id=?)`. Normalising
`protocol` to one case at insert time would make that index usable.

**8f. Redundant / denormalised columns.**
`packets.protocols` vs `protocol`; `dns_queries` carries both `rcode` (INTEGER) and `rcode_name`
(TEXT) and both `query_type` and (in `packets`) `dns_qtype`; `tls_sessions` carries
`client_version`, `server_version` **and** `version`; `conversations` carries
`packets_a_to_b`/`packets_b_to_a`/`packets_total` and the same for bytes. Only the derived
duplicates that are indexed or stored per-row matter for size: `idx_dns_rcode` indexes the
TEXT name while queries filter the INTEGER `rcode` (`routes_dns.py:112-114`) — so **the index is
on the column the queries do not use**.

**8g. `WITHOUT ROWID` / composite PK.** `packets PRIMARY KEY (analysis_id, number)`
(`schema.sql:92`) is already the right composite key and its autoindex is used for
`analysis_id=? AND number=?` lookups for free. `WITHOUT ROWID` would fold the PK index into the
table and save ~44 B/row (44 MB at 1M) but would make every secondary-index lookup slower (no
rowid indirection) and moves the 320 B/row payload into the PK b-tree — for a 38-column table
that is a net loss. Small key-value tables (`settings`, `stats_cache`) would benefit trivially
and are irrelevant at this scale. The genuinely missing structural change is 8a (a small integer
`analysis_id`), which is a surrogate-key decision, not a `WITHOUT ROWID` one.

**8h. HTTP bodies stored inline in the row that the list endpoint reads.**
`http_analyzer.py:509` sets `limit = settings.body_preview_bytes` (**256 KB**,
`core/config.py:45`) and both `request_body` and `response_body` are stored decoded
(`http_analyzer.py:558-567`). Measured on the real DB: 155 transactions hold **1,432,175 bytes of
body text** (avg **9,240 B per transaction overall**, avg 12,871 B for the 111 that have a body,
and **3 rows sit exactly at the 262,144-byte cap**, i.e. truncated bodies are stored at full
cap). Projected to 12,000 HTTP transactions from that same distribution: **111 MB of body text**
in `http_transactions`, which is the reason my scaled side-table file measured **358.6 MB**.
Worse, `SELECT * FROM http_transactions` (the list path, `routes_http.py:174-178`) drags those
bodies out of the b-tree for every page; only 26 of the 32 columns are ever used by the list.
Fix: store bodies in the `objects` table / on disk (the extractor already does this for
files) and keep only a size + hash + `body_preview_len` in `http_transactions`, or at minimum
drop `request_body`/`response_body` from the list `SELECT`.

**Verified** (affinity, widths, body totals, per-index byte costs). The projections to 1M rows
are arithmetic on measured per-row costs.

---

### 9. LOW — nice-to-haves, verified

* `PRAGMA cache_size` is left at the default (2 MB). Raising it helps the big aggregates only
  modestly: `top_talkers` 3,539 ms → 2,869 ms and `COUNT(*)` 124 ms → 67 ms with a 256 MB cache
  (measured, warm OS cache). Not a fix for finding 1. Note the variance in that query across runs:
  the same `top_talkers` measured 6,435 ms in the first pass and 3,539 ms in the cache test, so
  treat the multi-second dashboard figures as ±40% depending on cache state.
* `/api/analyses` calls `pipeline.analysis_disk_usage` per row (`routes_analyses.py:63-71`),
  which is `rglob("*")` + `stat()` over the analysis directory plus a glob of the uploads
  directory (`storage.py:148-155, 202`). The frontend polls this endpoint **every 2 s** while any
  analysis is in flight (`frontend/src/hooks/useAnalysis.tsx:46-52`, `page_size: 200`) — 200
  filesystem walks every 2 seconds. Cache it or store it in `analyses`.
* `analyses` and `jobs` are the only tables with a foreign key, so `foreign_keys=ON` costs
  nothing per packet row — worth stating because it is a common wrong assumption about this
  schema.
* `objects` (129 rows, ~667 B/row + 95 B/row index) and `indicators` are negligible.

---

## Prioritised index list (in the order I would add them)

| # | statement | query it fixes | evidence |
|---|---|---|---|
| 1 | `CREATE INDEX idx_pk_src_number ON packets(analysis_id, src_ip, number);` | `/packets?ip=…` / `src_ip=…` with the default `ORDER BY number` — the single most-used analyst filter | 203 ms → **0.6 ms** (322×), no sort step; **verified** |
| 2 | `CREATE INDEX idx_pk_dst_number ON packets(analysis_id, dst_ip, number);` | `dst_ip=…` and the `ip=` `MULTI-INDEX OR` | 132 ms → **0.7 ms**; **verified** |
| 3 | `CREATE INDEX idx_pk_dstport_number ON packets(analysis_id, dst_port, number);` | `port=`/`dst_port=`; also helps `_top_ports` | 426 ms → **0.7 ms**; **verified** |
| 4 | `CREATE INDEX idx_pk_srcport_number ON packets(analysis_id, src_port, number);` | the other half of `port=` | same shape as #3 (not separately measured) |
| 5 | `CREATE INDEX idx_pk_transport_number ON packets(analysis_id, transport, number);` | `transport=tcp|udp` in the packet explorer | 630 ms → **0.0 ms**; **verified** |
| 6 | `CREATE INDEX idx_conv_ip_a ON conversations(analysis_id, ip_a, bytes_total DESC, conv_id);` + the `ip_b` twin | host detail (`routes_hosts.py:317`) and `/hosts/graph` — today a scan of every conversation | plan is `SCAN conversations` at 50k; **verified** |
| 7 | `CREATE INDEX idx_conv_bytes_id ON conversations(analysis_id, bytes_total DESC, conv_id ASC);` | the default conversations list (`ORDER BY bytes_total DESC, conv_id ASC`) — removes `USE TEMP B-TREE FOR RIGHT PART OF ORDER BY` | real-DB plan quoted; **verified** |
| 8 | `CREATE INDEX idx_dns_client_time ON dns_queries(analysis_id, client_ip, time_epoch);` + `idx_dns_server_time`, `idx_http_client_time`, `idx_http_server_time`, `idx_tls_client_time`, `idx_tls_server_time` | the DNS/HTTP/TLS blocks of `/hosts/{ip}` and the `COUNT(*)` in `routes_hosts.py:351` | 34.7 / 67.5 / 39.8 ms scans; `MULTI-INDEX OR` is the verified end state for the same shape on `packets`; **verified** |
| 9 | `CREATE INDEX idx_pk_tcpstream_number ON packets(analysis_id, tcp_stream, number);` (+ udp twin) | `stream_id=` in the packet explorer (it currently works only by luck of `MULTI-INDEX OR` once statistics exist) | plan without stats: full `idx_pk_number` scan; **verified** |
| 10 | `CREATE INDEX idx_hosts_packets_sent ON hosts(analysis_id, packets_sent DESC, ip);` + `packets_received`, `bytes_received`, `peer_count` | the six host sorts that currently `SCAN hosts \| TEMP B-TREE FOR ORDER BY` | **verified** |
| 11 | `CREATE INDEX idx_conv_start ON conversations(analysis_id, start_time DESC, conv_id);` and `idx_conv_duration` | `sort=start_time|duration` on the conversations list — **1,461 ms at OFFSET 49000** today | **verified** |
| 12 | `CREATE INDEX idx_findings_sev_rank ON findings(analysis_id, severity, rule_id, id);` (or store a numeric rank column and index it) | the findings default order, `ORDER BY CASE severity …` — an expression sort that can never use `idx_findings_analysis` | **verified** |
| 13 | `DROP INDEX idx_pk_number;` | not an addition — a duplicate of the PK autoindex; removing it saves one index update per inserted packet and ~44 MB at 1M rows | `sqlite_autoindex_packets_1` and `idx_pk_number` have identical columns; **verified** |
| 14 | `ANALYZE;` after a bulk load (and periodically) | flips `src_ip=? ORDER BY number` from a 1M-entry index scan to `idx_pk_src` + sort (768 ms → 197 ms) and enables `MULTI-INDEX OR` for the `OR` predicates | **verified**, but it is a partial mitigation and the statistics go stale; the indexes above are the robust fix |

(Not on the list, deliberately: `idx_pk_time_number` measured **zero** benefit — the existing
`idx_pk_time` already serves the time-range predicate, and the extra 54.6 MB was not earned.
`idx_pk_len` and `idx_pk_proto` earn their keep only for the dashboard aggregates, which should
be precomputed instead.)

---

## Write-path changes worth making

1. **Insert first, index afterwards.** Measured ceiling **67.7 s → 11.7 s** for 1M rows
   (5.8×) by moving 11 index builds after the load. If the frozen-schema constraint
   (`schema.sql:1`) forbids per-analysis DDL, the same effect is achieved by shrinking the
   index set to the ones actually used.
2. **Drop `idx_pk_number`** — duplicate of the composite PK; one fewer b-tree per row and
   ~44 MB at 1M rows.
3. **Stop using a second connection for progress.** `JobContext.set_stage` (`jobs.py:63`) opens a
   new connection inside the insert loop (`packet_indexer.py:313-322`); measured **340 ms** queued
   behind a 1,000-row transaction, with `worker_threads = 2` (`config.py:41`). Use the indexer's
   connection or buffer in memory.
4. **Keep the 1,000-row commit cadence** — 40 ms of held write lock is a good number; do not
   enlarge batches to "reduce fsyncs", because WAL + `synchronous=NORMAL` already avoids most of
   that cost and larger batches only lengthen the window other writers must wait.
5. **Add `PRAGMA journal_size_limit` and a `wal_checkpoint(TRUNCATE)` at the end of each stage.**
   Without a checkpoint the WAL reached **1,114 MB** in the presence of one open reader snapshot,
   and `PRAGMA page_count`-based tooling reports a nearly empty main file. This is the one
   *production* risk in the write path: a 12-second dashboard query running during an analysis can
   pin a gigabyte of WAL.
6. **`_aggregate()` after the load** (`packet_indexer.py:348-374`) is an 11-aggregate scan on the
   critical path; compute `bytes_total`/`start_time`/`end_time` from a single pass with a windowed
   scan, or maintain them incrementally while streaming (the indexer already sees every row).
7. Replace `INSERT OR REPLACE` (`packet_indexer.py:110`) with plain `INSERT` after the leading
   `DELETE` (`packet_indexer.py:287`): on a fresh analysis there are no PK collisions to replace,
   and `OR REPLACE` pays a delete+insert per colliding row.
8. Do not add `PRAGMA synchronous=FULL` or `fullfsync`; `NORMAL` in WAL is correct and any change
   would multiply commit cost by 1,000 batches per million packets.

---

## What a 1M-packet database looks like, and where the limit bites first

| component | size |
|---|---|
| `packets` table (320.9 B/row measured on real rows) | ~320 MB |
| the 11 explicit indexes on `packets` (513.5 B/row) | ~514 MB |
| PK autoindex (included above; `idx_pk_number` is a 44 MB duplicate) | — |
| **measured build of 1M packets with the shipped schema** | **899.7 MB** (318.7 MB without the 11 indexes) |
| `conversations` 50,000 (471 B/row measured) | ~24 MB |
| `streams` 50,000 (156 B/row) | ~8 MB |
| `dns_queries` 25,000 (585 B/row) | ~15 MB |
| `http_transactions` 12,000 (dominated by bodies: 111 MB of measured body text) | ~130–300 MB |
| `tls_sessions` 20,000 (771 B/row) | ~15 MB |
| `hosts` 3,000 (520 B/row) | ~2 MB |
| `findings` 800 (2,651 B/row) | ~2 MB |
| **scaled side tables, measured together** | **358.6 MB** |
| **total, one 1M-packet capture** | **≈ 1.2 GB**, of which **~64% is index** and **~30–40% of that index is the repeated 32-character `analysis_id`** |

**`packets` dominates the database by an order of magnitude** (≈900 MB vs ≈360 MB for everything
else), and inside `packets` the indexes dominate the table. The second-largest contributor is
`http_transactions`, and it is large *only* because response bodies are stored inline.

**Where the limit bites first, in order:**

1. **`/summary` (Dashboard and Info)** — 12.3 s of packet aggregates at 1M rows, plus a
   `_top_domains` nested loop that projects to ~114 s at 8,000 domains × 50,000 conversations.
   This is the first thing that becomes unusable, and both pages auto-refresh it.
2. **The packet explorer** — ~150 ms per page just for `COUNT(*)`, 180 ms at `OFFSET 900000`,
   and **200 ms–1.1 s** for any filtered view that keeps the default `ORDER BY number`
   (source/destination IP, port, transport, or any text search).
3. **The pipeline's own write stage** — 67.7 s to insert 1M packets because 12 b-trees are
   updated per row (11.7 s without them), plus a 1.7 s re-index `DELETE`, plus the post-load
   aggregate scan.
4. **The WAL under concurrent reads** — a single long read snapshot during an analysis took the
   WAL from 8.1 MB to 1,114 MB (measured), i.e. disk usage doubles and every reader then resolves
   pages through the WAL.
5. **Per-host detail** (`/hosts/{ip}`) — 35–70 ms per protocol table plus an **885 ms**
   `COUNT(*)` on `packets`, i.e. ~1 s, growing linearly with the capture.
6. Everything else (conversations/DNS/HTTP/TLS lists, findings, objects) stays in the
   tens of milliseconds at these row counts; the conversations list only becomes slow at deep
   pages (1,476 ms at `OFFSET 49000`) or when sorted by a key with no index.

---

## Could not determine

* **The real row-count ratios for a 1M-packet capture.** The 22 completed analyses in the real DB
  are small and unusual (5–55,434 packets, and their `conversations/packets` ratio ranges from
  0.24% to 43%). My side-table counts (50,000 conversations, 25,000 DNS, 12,000 HTTP, 20,000 TLS,
  3,000 hosts, 800 findings) are *assumptions* derived from the most network-like of those
  captures, and they move the total size between ~1.0 GB and ~1.3 GB. The `http_transactions`
  figure is the least certain and the most consequential.
* **Conversations-list plan in production.** My scaled database contains one analysis, so
  `analysis_id = ?` is estimated at 100% selectivity and SQLite chose `SCAN conversations` for the
  default page; the real 23-analysis DB chose
  `SEARCH conversations USING INDEX idx_conv_bytes (analysis_id=?) | USE TEMP B-TREE FOR RIGHT PART OF ORDER BY`
  for the identical SQL. I report both, but the timings (29–31 ms page, 1,476 ms at OFFSET 49000)
  come from the single-analysis file.
* **IP cardinality effects.** The synthetic packets inherit the real capture's address set
  (~340 distinct `src_ip` values), which makes `COUNT(DISTINCT src_ip)` (0.2 ms with statistics,
  237 ms without) cheaper than a real 1M-packet capture with thousands of hosts would be.
* **`tcp_flags_raw` byte savings.** I verified it is stored as text; I did not measure how much
  changing the declared type saves (it is ~1.4 B/row of a 320 B/row table — small).
* **Cold-cache and disk-bound numbers.** All timings are warm-OS-cache on the local NVMe. Every
  I/O-bound figure here (the 12.3 s summary, the 180 ms OFFSET, the 67.7 s load) would be worse
  on a cold cache; the ratios would hold.
* **Real multi-user concurrency.** I measured a single writer plus one reader/progress writer.
  With `worker_threads = 2` (`config.py:41`) two analyses can index simultaneously; I did not run
  that scenario end to end.
* **Whether the detection/Suricata stages add their own scale failures.** They are outside the
  files I was asked to review; `detection_engine.analyze` runs in-request from
  `/findings/rescan` (`routes_findings.py:224-233`) and reads `packets` in chunks
  (`routes_findings.py:1211-1218`), which looks fine, but I did not profile it at 1M rows.
