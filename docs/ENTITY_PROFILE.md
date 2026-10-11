# Entity profile contract (Investigate)

**Status:** normative for the `Investigate` section. `docs/CONTRACT.md` governs the
analysis contract; `docs/THREAT_HUNT.md` governs the seventeen detections. This file
governs the per-entity answers — the "everything we know about this address, name or
URL" surface.

Everything here is computed from the analysis index with SQL. **No endpoint in this
document runs TShark, and none of them adds work to the import pipeline.**

---

## 1. What the section is for

The seventeen detections in `docs/THREAT_HUNT.md` ask fixed questions of a whole
capture. This section asks *about one thing*: an address, a domain name, or a URL that
appears in the capture. It answers with the same vocabulary — a headline count, a
chart drawn from real rows, an interpretation, a caveat, and links into the pages that
own the underlying data — so a reader who has learned the Threat Hunt cards can read
these immediately.

It is a reading of the index, not a verdict, and not a risk score. There is no
scoring, no ranking by danger, and no inference beyond what the rows say.

---

## 2. Endpoints

### `GET /api/analyses/{analysis_id}/profile?q=<query>&limit=<n>`

Resolves one free-text query to the entities that match it. This is what the page's
search box calls as the reader types.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `q` | string | required | The query. Trimmed; 1–200 characters after trimming; empty is `422`. |
| `limit` | int | `25` | Maximum matches returned, 1–100. |

```jsonc
{
  "analysis_id": "…",
  "query": "3.173.21",
  "matches": [
    {
      "kind": "ip",              // "ip" | "domain" | "url"
      "entity": "3.173.21.63",   // the exact value to pass to the profile endpoint
      "label": "3.173.21.63",    // what to show; same as entity except for URLs
      "hint": "public address · 12 conversations",   // one short line, never a verdict
      "count": 12,               // rows behind this match, for ordering
      "to": "/investigate?kind=ip&entity=3.173.21.63"
    }
  ],
  "truncated": false
}
```

**Matching rules.** Matching is a case-insensitive substring on the indexed value:

* `ip` — `hosts.ip`. Also matched when the query looks like a prefix of an address
  (`3.173.21` matches `3.173.21.63`). Ordered by `bytes_sent + bytes_received` desc.
* `domain` — the distinct union of `dns_queries.query_name`, `http_transactions.host`
  and `tls_sessions.sni`. Ordered by occurrence count desc.
* `url` — `http_transactions.uri`. Ordered by occurrence count desc, then by URI.

A query that looks like an address returns only `ip` matches; one containing `://` or
starting with `/` returns only `url` matches; otherwise all three kinds are searched.
`matches` is empty when nothing matches — the page says so rather than showing a
placeholder entity.

### `GET /api/analyses/{analysis_id}/profile/{kind}/{entity}`

The profile itself. `{kind}` is `ip`, `domain` or `url`; `{entity}` is the value from a
search match (URL-encoded). An unknown entity is not an error: it returns every
question with `availability: "not_applicable"` and a reason, so a stale link explains
itself instead of 404ing.

```jsonc
{
  "analysis_id": "…",
  "kind": "ip",
  "entity": "10.4.10.132",
  "generated_at": 1791750782.4,
  "summary": {
    "label": "10.4.10.132",
    "scope": "private",            // address_scope(): private/public/multicast/loopback/link_local/…
    "mac": "00:08:02:1c:47:ae",    // null when the capture recorded none
    "hostnames": ["Beijing-5cd1-PC"],
    "first_seen": 1547317408.5,    // null when the entity has no timestamped frames
    "last_seen": 1547317440.3,
    "packets": 1204,
    "bytes": 862341,
    "note": null                   // optional one-line honesty note, or null
  },
  "questions": [ /* see §3 */ ],
  "truncated": { "connections": false, "domains": true, "…": false }
}
```

---

## 3. A question

Every entry in `questions` uses the Threat Hunt card vocabulary verbatim, so the same
visual renderers draw both:

```jsonc
{
  "id": "ports_offered",
  "title": "Ports offered",
  "question": "Which ports did this address listen on?",
  "availability": "ok",              // "ok" | "empty" | "not_applicable"
  "availability_reason": null,       // required when availability is not "ok"
  "headline": { "value": 4, "label": "port(s) accepted traffic", "tone": "info" },
  "visuals": [ /* bars | timeline | histogram | scatter | heatmap | table */ ],
  "interpretation": "…",             // what the numbers mean, in one or two sentences
  "caveat": "…",                     // what this does not prove — always present
  "links": [ { "to": "/packets?ip=…", "label": "packets on this port" } ]
}
```

**Availability is not decoration.** `empty` means the question was computable and
nothing matched — the reader must see the threshold or the reason it is empty.
`not_applicable` means this capture cannot answer it at all (a table has no rows for
this analysis, the entity never appeared in that layer, or the needed column is null
throughout). A question is **never** answered with an invented zero.

**Caps.** Every list and visual is capped, and the cap is stated in the visual's
`note` as `showing <returned> of <total>`.

| Cap | Value | Applies to |
|---|---|---|
| `PROFILE_CAP` | `50` | rows in any `table` visual |
| `BARS_CAP` | `12` | bars in any `bars` visual |
| `TIMELINE_CAP` | `240` | buckets in a `timeline` |
| `SCATTER_CAP` | `200` | points in a `scatter` |
| `HEATMAP_CAP` | `15` | rows and columns in a `heatmap` |
| `MATCH_CAP` | `25` | search matches (the `limit` parameter) |

---

## 4. The questions

### 4.1 `ip`

| id | Question | Answers from |
|---|---|---|
| `volume_by_direction` | How much did it send, and how much did it receive? | `hosts` totals, `packets.frame_len` |
| `activity_over_time` | When was it active, and was the traffic steady or bursty? | `packets.time_epoch` |
| `connections` | How many conversations did it take part in, and with whom? | `conversations` |
| `peer_fanout` | How many distinct peers did it talk to? | `conversations` peers |
| `ports_offered` | Which ports did it listen on (traffic it accepted)? | `conversations` as responder |
| `ports_contacted` | Which ports did it reach out to? | `conversations` as initiator |
| `protocol_mix` | Which protocols did it speak, and in what proportion? | `packets.protocol/transport` |
| `domains_resolved` | Which names did it ask a resolver for? | `dns_queries.query_name` where it is the client |
| `domains_contacted` | Which names did it contact over TLS? | `tls_sessions.sni` where it is an endpoint |
| `dns_health` | How many of its queries went unanswered, and which resolvers did it use? | `dns_queries.rcode/server_ip` |
| `http_activity` | Which HTTP hosts and paths did it use? | `http_transactions` |
| `clear_text_credentials` | Did anything it sent carry a credential in clear text? | `http_transactions` flags |
| `files` | Which files did it transfer, and what are their hashes? | `objects` via `stream_id` / recorded frames |
| `tls_fingerprints` | Which JA3/JA4 fingerprints did it present? | `tls_sessions.ja3/ja4` |
| `fingerprint_peers` | Which other addresses present the same fingerprints? | `tls_sessions` cross-join |
| `findings` | Which detections and Suricata signatures name it? | `findings.entities/packet_numbers` |

### 4.2 `domain`

| id | Question | Answers from |
|---|---|---|
| `clients` | Which addresses asked for this name? | `dns_queries.client_ip` |
| `answers` | Which addresses did it resolve to in this capture? | `dns_queries.answer_ips` |
| `rcodes` | How did the resolver answer? | `dns_queries.rcode_name` |
| `activity_over_time` | When was it asked for? | `dns_queries.time_epoch` |
| `tls_sessions` | Which handshakes carried it as SNI? | `tls_sessions.sni` |
| `http_transactions` | Which HTTP requests were addressed to it? | `http_transactions.host` |
| `files` | Which files were fetched from it? | `objects` via those transactions |
| `findings` | Which detections name it? | `findings.entities` |

### 4.3 `url`

| id | Question | Answers from |
|---|---|---|
| `clients` | Which addresses requested this URL? | `http_transactions` + `conversations` |
| `status_codes` | How did the server answer? | `http_transactions.status_code` |
| `methods` | Which methods were used? | `http_transactions.method` |
| `activity_over_time` | When was it requested? | `http_transactions.time_epoch` |
| `request_shape` | What did the requests look like — user agent, referer, content type? | `http_transactions` |
| `files` | Which files came back from it? | `objects` via `stream_id` |
| `findings` | Which detections name it? | `findings.entities` |

---

## 5. Links

`links` and the `to` on a bar, scatter point or table row may only point at a route
that exists, with the parameters that page actually reads. The vocabulary is the same
one `docs/THREAT_HUNT.md` §5 fixes:

* `/packets?ip=<ip>`, `/packets?ip=<ip>&port=<port>`, `/packets?sel=<frame>`,
  `/packets?stream_id=<id>&transport=<tcp|udp>`, `/packets?search=<text>`
* `/conversations?stream=<transport>:<id>`, `/conversations?ip=<ip>&tab=info`
* `/http?host=<host>&search=<text>`, `/dns?domain=<name>`, `/tls?sni=<name>`
* `/objects?search=<name>`, `/hosts?ip=<ip>`, `/findings/<id>?tab=overview`

A link that would need a parameter the target page does not read must be dropped, not
approximated.

---

## 6. Honest limits, stated on the page

* **Attribution is by what the capture recorded.** A file is tied to an address only
  when its `stream_id` or its recorded frames do; an object with neither
  (`objects.stream_id IS NULL` and no packet numbers) is counted in the page's
  `unattributed` note rather than silently dropped or attributed to a guess.
* **Encrypted payloads are not decrypted**, so "domains contacted" for an address is
  SNI and DNS, never the content of a TLS session.
* **A capture with no HTTP rows cannot answer the HTTP questions**, and says
  `not_applicable` rather than showing zero.
* **The profile describes this capture only.** Nothing is looked up externally, and
  nothing is inferred from another analysis.
