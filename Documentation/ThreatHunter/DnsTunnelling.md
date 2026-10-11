# Possible DNS Tunnelling (`dns_tunnelling`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is one domain answering many machine-generated subdomains from a single client?**

## 2. How to read the card

The headline counts *client/domain pairs above every tunnelling threshold*: pairs of
(one client address, one base domain) where the client asked at least
`TUNNEL_MIN_NAMES` distinct names under that domain, with at least
`TUNNEL_MIN_QUERIES` queries in total, a mean longest label of at least
`TUNNEL_MIN_LABEL` characters, and a mean entropy of at least `TUNNEL_MIN_ENTROPY`.
All four conditions must hold together. It is a count of client/domain pairs.

Two visuals are drawn:

* a **scatter** of mean longest label against query count, one point per client/domain
  pair, with `x` the mean longest label in characters and `y` the number of queries.
  The threshold box described in the note is `≥10` label characters, `≥5` distinct
  names and `≥10` queries; the entropy condition has no axis and cannot be seen on the
  chart. Up to `SCATTER_CAP = 200` pairs are drawn, ranked by distinct name count;
* a **table** of the pairs that passed all four conditions, capped at
  `TABLE_CAP = 50` rows: the domain (linked to the DNS page for that domain and
  client), the client (linked to the host), distinct names, queries, mean longest label
  and mean entropy.

A **high** reading is a pair far to the right of the scatter, or a table with several
rows, which usually means one client asking a great many long random names under one
domain. A **low** reading is a single pair just over the line, which is very often a
CDN or a telemetry domain. A zero headline with `availability: "empty"` means no pair
satisfied all four conditions; the scatter still shows every pair observed and where
they sat relative to the thresholds, and the reason reports how many pairs there were.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_dns_tunnelling(index)` with the helper `_base_domain(name)` in
`backend/app/services/threat_hunt.py`.

1. If the DNS index holds no rows, return `not_applicable` with
   `the capture recorded no DNS queries`.
2. Read up to `PACKET_SCAN_CAP` query rows that have a `query_name`, taking the client
   address, the name, the name's longest label and the name's entropy.
3. Group the rows by `(client, base domain)` where the base domain is
   `_base_domain(query_name)`: the **last two labels** of the name, or the whole name
   when it has fewer than two labels.
4. Per group, count the distinct names (a set, so repeats do not count), count the
   queries, and take the mean of the per-row `longest_label` and `entropy` values with
   `statistics.fmean`.
5. Rank groups by distinct names, then queries, then domain.
6. A group is a suspect when **all four** hold: distinct names ≥ `TUNNEL_MIN_NAMES`,
   queries ≥ `TUNNEL_MIN_QUERIES`, mean longest label ≥ `TUNNEL_MIN_LABEL`, and mean
   entropy ≥ `TUNNEL_MIN_ENTROPY`.
7. The headline is the number of suspects; the scatter draws the first
   `SCATTER_CAP = 200` ranked pairs whether or not they are suspects; the table draws
   the first `TABLE_CAP = 50` suspects; the links name up to five domains.

Note what the detection does **not** read: the query type, the response code, the lead
flags, the timestamps and the answers. A TXT-based tunnel and a tunnel built from
A records are treated identically, and the rate of queries over time plays no part.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `TUNNEL_MIN_NAMES` | `5` | Distinct names under one domain, from one client, before the pair can be a suspect. |
| `TUNNEL_MIN_QUERIES` | `10` | Total queries in the pair before it can be a suspect. |
| `TUNNEL_MIN_LABEL` | `10.0` | Minimum **mean** longest label, in characters. The note and the empty reason render it as `10`. |
| `TUNNEL_MIN_ENTROPY` | `3.6` | Minimum **mean** entropy over the pair's rows. Rendered as `3.6`. |
| `SCATTER_CAP` | `200` | Maximum points in the scatter. |
| `TABLE_CAP` | `50` | Maximum rows in the suspect table. |
| `PACKET_SCAN_CAP` | `20000` | Maximum DNS rows read. |
| `top` | `12` (1–50) | **Not used by this detection**: there is no ranked bars chart, so the rows-per-visual control does nothing here. |
| `TIMELINE_CAP` | `240` | Not used by this detection. |

The truthiness of the entropy column is worth being precise about. The value compared
against `TUNNEL_MIN_ENTROPY = 3.6` is the **mean of `dns_queries.entropy`** for every
row in the pair. That column is written by `backend/app/services/dns_analyzer.py`,
whose own flag threshold is `HIGH_ENTROPY = 3.8` — a different constant, used for a
different purpose (raising the per-row `high_entropy` flag, which also requires at
least three labels). The two numbers are not interchangeable: a domain whose names
average 3.7 entropy passes this detection while raising no per-row flag, and a single
very high-entropy name inside an otherwise ordinary domain raises a flag without
lifting the mean to 3.6.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `dns_queries.client_ip` | Half the grouping key; `NULL` becomes the literal client `unknown`. |
| `dns_queries.query_name` | The other half of the grouping key, via its last two labels, and the distinct-name count. |
| `dns_queries.longest_label` | The per-row label length, averaged into the pair's mean label (the scatter's `x`). |
| `dns_queries.entropy` | The per-row entropy, averaged into the pair's mean entropy. |

`dns_queries.query_type`, `rcode`, `rcode_name`, `flags`, `time_epoch`, `answers`,
`answer_ips`, `cnames`, `name_length` and `label_count` are all indexed and none of
them is read by this detection.

## 6. Fields the analyst brief asks for but the index does not hold

* **`dns.qry.len`.** No raw query-length field exists. The workaround is the
  analyser's derived `longest_label` (and `name_length`, which this detection does not
  read). The cost is that "long name" here means "longest single label", so a tunnel
  that spreads its payload across many medium labels scores lower than one that packs
  it into one long label.
* **Query type and record content.** `query_type` is indexed and unread; TXT record
  text is not stored at all (`answers`, `answer_ips` and `cnames` hold resolved
  addresses and CNAME chains, and the DNS page's own documentation says TXT text is
  not kept). A tunnel that encodes data in the *answers* rather than the questions is
  therefore invisible to this detection.
* **Response size.** There is no column for the size of a DNS response, so the
  asymmetry a tunnel usually shows — small queries out, larger responses in — cannot
  be measured.
* **Rate and timing.** `time_epoch` and `response_delay` are indexed and unread, so
  the detection cannot measure queries per second or spot a steady machine-like cadence.
  The complaint that a real tunnel "is usually long-lived enough to be obvious only in
  a longer capture", which the card's caveat makes, follows directly from this.
* **Public-suffix awareness.** `_base_domain` takes the last two labels, so
  `shop.example.co.uk` and `mail.other.co.uk` both collapse to the base domain
  `co.uk` and are grouped together, while `a1b2.tunnel.example` gives
  `tunnel.example`. The index holds no public-suffix list and there is no workaround in
  this detection: the grouping is a two-label heuristic, and multi-part suffixes can
  merge unrelated traffic into one pair or split a real tunnel across two.
* **Client identity.** `client_ip` only, so several machines behind one address are one
  client and can push each other over the thresholds.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The domain and client together | `/dns?domain=<domain>&client_ip=<client>` | The actual names. Real tunnelling shows a run of distinct random-looking subdomains under one domain; a CDN shows a small set of host patterns. |
| The client's DNS behaviour | `/dns?client_ip=<client>` | Whether the domain is one of many or the client's whole reason for existing. |
| Only TXT queries | `/dns?qtype=TXT` | The classic tunnelling record type; the card cannot distinguish it, so this filter has to be applied by hand. |
| Only flagged rows | `/dns?suspicious=true` | The names the DNS analyser flagged, which is a second opinion on the same traffic. |
| The client host | `/hosts?ip=<client>` | Whether the client is an endpoint that has no business making thousands of lookups. |
| The resolver | `/dns?server_ip=<resolver>` | Whether the queries went to the expected resolver. |
| The frames | `/packets?ip=<client>&protocol=udp` | Query size and timing, in the raw traffic. |
| One name's answers | `/dns?domain=<one of the subdomains>` | The merged answers for a single name, which may show whether anything resolved back. |

## 8. What it does not prove

A domain answering many long, high-entropy subdomains does not establish a tunnel. It
establishes that one client asked many distinct, machine-looking names under one
domain, which is what modern content delivery, telemetry and anti-tracking
infrastructure does by design. The card's own caveat says the same thing:

> Name shape does not establish a tunnel. Content delivery networks, anti-tracking and
> telemetry hostnames, and marketing redirect domains all generate high-entropy
> subdomains at volume, and a real tunnel is usually long-lived enough to be obvious
> only in a longer capture.

## 9. Known limits and false positives

* **CDNs and cloud platforms.** Any large provider hands out random-looking subdomains
  at volume; these are the single most common source of pairs that pass all four
  thresholds.
* **Telemetry and anti-tracking.** Analytics, crash reporting and anti-tracking
  domains generate long, high-entropy names precisely so they cannot be guessed.
* **Advertising and redirect domains.** Marketing redirects use long opaque subdomains
  by design.
* **The two-label grouping.** Multi-part public suffixes (`co.uk`, `com.au`, `co.jp`)
  are collapsed, so unrelated traffic can be merged into one suspicious-looking pair —
  and a tunnel under a multi-label suffix can be split across two pairs, each below
  `TUNNEL_MIN_NAMES`.
* **The mean hides the shape.** A pair with 90 ordinary names and 10 random ones has a
  mean label and mean entropy that may or may not clear the threshold; a pair with 10
  names that are all random and one that is not will average differently again. The
  scatter shows the mean, not the spread.
* **No timing, no types, no answers.** A slow tunnel, a TXT tunnel and a tunnel that
  carries its data in responses are all under-represented or invisible, and nothing on
  the card reports the query rate.
* **Structural caps.** At most `PACKET_SCAN_CAP = 20000` DNS rows are read, in index
  order rather than time order, so on a large capture the pairs are computed from a
  subset of the traffic and the scatter shows only the first `SCATTER_CAP = 200`
  ranked pairs.
* **An empty card is not a quiet resolver.** It means no client/domain pair reached
  five distinct names, ten queries, a mean longest label of ten characters and a mean
  entropy of 3.6 at the same time.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [DNS](../DNS.md) · [Hosts](../Hosts.md) · [DnsAnomalies](DnsAnomalies.md) · [DataExfiltration](DataExfiltration.md)
