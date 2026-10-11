# DNS Anomalies (`dns_anomalies`)

Part of the **Threat Map** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Are lookups failing, or do names look machine-generated?**

## 2. How to read the card

The headline counts *clients with anomalous DNS behaviour*: clients that asked at
least `DNS_NXDOMAIN_MIN` names that do not exist, or at least `DNS_VOLUME_MIN`
queries in total, or at least `DNS_FLAGGED_MIN` names carrying a machine-looking
lead flag. It is a count of clients, not of queries.

Two visuals are drawn:

* **bars** of anomalous DNS activity per client, where the bar length is
  `NXDOMAIN count + flagged count` for that client — failed or machine-looking
  lookups, not total lookups. The note states the three flags the client had to
  trip to get into the chart;
* a **scatter** of query-name length against query count, one point per query name:
  `x` is the longest label observed for that name, `y` is how many times the name
  was asked. Names to the right are long-labelled; names high up are frequently
  asked. Up to `SCATTER_CAP` names are drawn, and each point links to that name on
  the DNS page.

A **high** reading is several clients with many NXDOMAIN answers, or a client whose
names sit far to the right of the scatter. A **low** reading is a single client
over the NXDOMAIN threshold — usually one misconfigured machine or a typo-happy
resolver. A zero headline with `availability: "empty"` means no client tripped any
of the three conditions; both charts still carry the real measurements, and the
reason states how many clients were observed.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_dns_anomalies(index)` in `backend/app/services/threat_hunt.py`.

1. If the DNS index holds no rows, return `not_applicable` with
   `the capture recorded no DNS queries`.
2. Build a SQL `LIKE` clause over the `flags` JSON column for the six tokens of
   `STRONG_DNS_FLAGS`, and treat a row as failing when `rcode_name = 'NXDOMAIN'` or
   `rcode = 3`.
3. Aggregate `dns_queries` per client (`COALESCE(client_ip, 'unknown')`) into three
   numbers: total queries, NXDOMAIN count, and flagged count (rows whose `flags`
   JSON contains any of those six tokens).
4. Keep a client as anomalous when NXDOMAIN count is at least `DNS_NXDOMAIN_MIN`,
   **or** total queries are at least `DNS_VOLUME_MIN`, **or** flagged count is at
   least `DNS_FLAGGED_MIN`. The three tests are alternatives, not a conjunction.
5. Rank the anomalous clients by `NXDOMAIN + flagged` (descending), then by query
   count, then by name. The headline is how many there are.
6. Separately aggregate `dns_queries` per `query_name`, taking `MAX(longest_label)`,
   `MAX(entropy)` and the flagged count, ordered by flagged count then query count
   and limited to `SCATTER_CAP` names. That is the scatter's data, drawn for the top
   `SCATTER_CAP` names regardless of whether their client is anomalous.

The two halves of the card answer different questions: the bars are per client, the
scatter is per name, and a name in the scatter does not have to belong to an
anomalous client.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `DNS_NXDOMAIN_MIN` | `5` | NXDOMAIN answers from one client before that client is anomalous. Matches the `dns_nxdomain_burst` rule in `docs/CONTRACT.md` §8. |
| `DNS_VOLUME_MIN` | `100` | Total queries from one client before that client is anomalous. Matches the `dns_high_volume` rule in `docs/CONTRACT.md` §8. |
| `DNS_FLAGGED_MIN` | `3` | Rows from one client carrying any strong DNS lead flag. |
| `STRONG_DNS_FLAGS` | `nxdomain`, `servfail`, `long_label`, `long_name`, `high_entropy`, `txt_record` (6 tokens) | The flag tokens that count towards the flagged total. |
| `SCATTER_CAP` | `200` | Maximum number of query names drawn in the scatter. |
| `top` | `12` (1–50) | Rows in the bars chart; number of links. |
| `TABLE_CAP` | `50` | Not used by this detection. |
| `TIMELINE_CAP` | `240` | Not used by this detection. |

The flags themselves are written by `backend/app/services/dns_analyzer.py`, so their
conditions are that module's constants, not this one's:

| Constant (in `dns_analyzer.py`) | Value | Flag it raises |
|---|---|---|
| `LONG_LABEL` | `40` | `long_label` — longest label of 40 characters or more |
| `LONG_NAME` | `100` | `long_name` — query name of 100 characters or more |
| `HIGH_ENTROPY` | `3.8` | `high_entropy` — Shannon entropy above 3.8 with at least 3 labels |

Two flags the DNS analyser writes are deliberately **not** in `STRONG_DNS_FLAGS`:
`unanswered` and `many_ips`. A client with hundreds of unanswered lookups does not
become anomalous through that flag alone, although the lookups still raise the
client's total query count towards `DNS_VOLUME_MIN`.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `dns_queries.client_ip` | The grouping key for the bars; `NULL` becomes the literal client `unknown`. Also the `/dns?client_ip=` link. |
| `dns_queries.rcode_name`, `dns_queries.rcode` | The NXDOMAIN test (`'NXDOMAIN'` or `3`). |
| `dns_queries.flags` | The JSON lead-flag array used for the flagged count and the strong-flag SQL clause. |
| `dns_queries.query_name` | The scatter's point label and its `/dns?domain=` link, and the grouping key for the name aggregate. |
| `dns_queries.longest_label` | The scatter's `x` value, taken as the maximum for that name. |
| `dns_queries.entropy` | Read in the name aggregate (`MAX(entropy)`) but not rendered on the card. |

## 6. Fields the analyst brief asks for but the index does not hold

* **`dns.qry.len`.** There is no raw query-length field in `dns_queries`, and no
  column in `packets` for it either. The workaround is the derived trio the DNS
  analyser computes from the name — `name_length`, `label_count`, `longest_label` —
  plus `entropy`; the engine reads `longest_label` and `entropy`. The cost is that
  the numbers are the analyser's own definition of name shape (labels split on `.`,
  Shannon entropy over the concatenated labels), not TShark's, and the scatter's
  `x` is the longest label rather than the whole name.
* **Response content.** `dns_queries.answers`, `answer_ips` and `cnames` are
  indexed, and TXT record text is not stored at all, so the content of an answer is
  never inspected. A `txt_record` flag says a TXT query was made, not what it asked
  for. A DGA that resolves successfully to a CNAME chain looks nothing like a
  failure here.
* **Resolver side.** `dns_queries.server_ip` exists and is not read, so the card
  cannot say which resolver produced the failures, nor spot one client talking to
  many resolvers.
* **Timing.** `response_time` and `response_delay` exist and are not read, so a
  burst of slow failures is not distinguished from instant ones.
* **`dns.flags.recursion_desired`, `dns.flags.authoritative` as a signal.** The
  `authoritative` and `truncated` columns exist and are unused by this detection.
* **Encrypted DNS.** DNS over HTTPS or TLS produces no `dns_queries` rows at all, so
  a host using an encrypted resolver contributes nothing to this card. There is no
  workaround in the index; the traffic appears only as HTTP or TLS.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| All queries from a client | `/dns?client_ip=<client>` | Whether the failures are one bad suffix (`foo.local`) or genuinely random names. |
| One name | `/dns?domain=<name>` | Its answers, rcodes, and whether the same name was asked repeatedly. |
| Only the rows with lead flags | `/dns?suspicious=true` | The names the analyser itself considered worth flagging, across all clients. |
| Only the failures | `/dns?nxdomain=true` | The full set of names that do not exist, which is where a DGA lives. |
| By record type | `/dns?qtype=TXT` | TXT-heavy traffic in a capture that has no business using it. |
| The client itself | `/hosts?ip=<client>` | Whether the client is a workstation, a resolver, or a gateway; a resolver legitimately asks a great deal. |
| What happened next | `/conversations?ip=<client>` | Whether the client then connected to anything, which is what turns a failed lookup into a lead. |

Note that `/dns` has no parameter for a minimum query count, so the ranked list is
the place to judge volume.

## 8. What it does not prove

NXDOMAIN answers and long, high-entropy names do not establish malicious activity.
They establish that lookups failed or that names look mechanical, both of which
have ordinary explanations. The card's own caveat says the same thing:

> NXDOMAIN and high-entropy names do not establish malicious activity.
> Typographical errors, search-domain suffixes, content delivery hostnames and
> captures that copied most of their answers from cache all look the same here.

## 9. Known limits and false positives

* **Typographical errors and search suffixes.** A single machine with a wrong search
  domain generates constant NXDOMAIN traffic — the classic false positive for this
  threshold.
* **Content delivery and anti-tracking hostnames.** CDNs, ad networks, telemetry
  endpoints and anti-tracking domains are full of long random-looking labels and
  are usually the largest source of high-entropy names in a capture.
* **High-volume resolvers.** A local resolver, a mail gateway or a monitoring
  server will exceed `DNS_VOLUME_MIN = 100` queries without anything being wrong.
  The bars chart shows volume, not impropriety.
* **Captures that start mid-conversation.** Cached answers are not in the capture,
  so a host that is behaving normally can look like it asks many names that it never
  resolves.
* **The three tests are alternatives.** A client with 100 ordinary queries is
  anomalous by this definition, which is why the two charts matter more than the
  headline.
* **Scatter cap.** Only the `SCATTER_CAP = 200` names with the most flags and the
  most queries are drawn, so a rare name with two lookups may not appear at all.
* **An empty card is not clean DNS.** It means no client reached 5 NXDOMAIN answers,
  100 queries, or 3 machine-looking names.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [DNS](../DNS.md) · [Packets](../Packets.md) · [DnsTunnelling](DnsTunnelling.md) · [UnusualEgress](UnusualEgress.md)
