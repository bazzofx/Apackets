# Threat Hunt — implementation contract

Normative spec for the **Threat Hunt** section (`/threat-hunt`). Two implementations
build against this document: the backend indicator engine and the frontend page. The
shapes below are the interface between them and must match exactly.

Source of truth for *which* detections exist and *how* they are computed is the
analyst brief in §1; this document fixes the wire format so the two halves cannot
drift.

---

## 0. Non-negotiables

1. **Every number comes from the analysis index.** No placeholder, no sample, no
   estimate, no interpolation. If a detection cannot be computed, it says so
   (`availability`), it does not render zeroes that look like a real reading.
2. **An indicator is a lead, not a verdict.** Every indicator carries a `caveat`
   naming what it does *not* prove. This is the whole point of the section.
3. **Bounded output, reported caps.** Every list is capped and the cap is stated in
   `note` when it bites.
4. **No TShark re-dissection.** Read the indexed tables only, so the section stays
   fast and works after an upload has been purged.
5. **Links are real.** Only the query parameters listed in §5 may be used, because
   those are the ones the target pages actually read.

---

## 1. The detections

Each row of the brief becomes one indicator. The `id` is stable and is what the
frontend switches on.

| id | title | compute from | visuals |
|---|---|---|---|
| `c2_beaconing` | Potential C2 Beaconing | `conversations` | `histogram`, `table` |
| `network_scanning` | Network Scanning | `packets` (tcp, icmp, arp) | `heatmap`, `bars`, `table` |
| `dns_anomalies` | DNS Anomalies | `dns_queries` | `bars`, `scatter` |
| `data_exfiltration` | Potential Data Exfiltration | `conversations`, `hosts` | `bars`, `timeline` |
| `lateral_movement` | Lateral Movement Indicators | `packets` | `bars`, `table` |
| `suspicious_http` | Suspicious HTTP Activity | `http_transactions` | `timeline`, `histogram`, `table` |
| `suspicious_tls` | Suspicious TLS Connections | `tls_sessions` | `bars`, `table` |
| `unusual_ports` | Unusual Port Usage | `packets` | `bars` |
| `high_fan_out` | High-Fan-Out Hosts | `hosts` | `bars` |
| `rare_pairs` | Rare Communication Pairs | `conversations` | `table` |
| `malware_download` | Possible Malware Download | `http_transactions`, `objects`, `findings` | `timeline`, `table` |
| `dns_tunnelling` | Possible DNS Tunnelling | `dns_queries` | `scatter`, `table` |
| `ids_matches` | IDS Signature Matches | `findings` | `table` |
| `traffic_bursts` | Suspicious Traffic Bursts | `packets` | `timeline` |
| `unusual_egress` | Unusual Egress | `hosts`, `conversations` | `bars` |
| `data_staging` | Potential Data Staging | `conversations` | `timeline`, `histogram` |
| `failed_connections` | Repeated Failed Connections | `packets` | `timeline`, `bars` |

Titles, questions and interpretation text come from the brief and must be worded as
the brief words them in substance: the interpretation says what the pattern *may*
indicate, and the caveat says what it does not establish.

---

## 2. Endpoint

```
GET /api/analyses/{analysis_id}/threat-hunt
```

Query parameters (all optional):

| param | default | meaning |
|---|---|---|
| `window` | `60` | seconds per bucket for every time series |
| `top` | `12` | rows per ranked visual (1–50) |

Errors follow the existing envelope: 404 `analysis_not_found` for an unknown id,
409 for an analysis that is not finished — reuse `deps.get_ready_analysis`.

---

## 3. Response envelope

```jsonc
{
  "analysis_id": "9e2e…",
  "generated_at": 1760000000.0,      // server clock, float seconds
  "packets_scanned": 4003,           // rows in the packet index for this analysis
  "window": 60,
  "top": 12,
  "note": "…",                       // what the whole page is (and is not)
  "indicators": [ /* 17 objects, in the order of §1 */ ]
}
```

### 3.1 Indicator

```jsonc
{
  "id": "c2_beaconing",
  "title": "Potential C2 Beaconing",
  "question": "Is anything contacting the same destination on a regular schedule?",
  "availability": "ok" | "empty" | "not_applicable",
  "availability_reason": null,        // required string when availability != "ok"
  "headline": { "value": 3, "label": "flow(s) with a regular interval", "tone": "info" },
  "visuals": [ /* 1..n, shapes in §4 */ ],
  "interpretation": "…",
  "caveat": "…",
  "links": [ { "to": "/conversations?ip=10.0.0.5", "label": "10.0.0.5" } ]   // 0..n
}
```

* `availability: "ok"` — computed, and there is at least one item worth showing.
* `availability: "empty"` — computable, and the honest answer is "nothing matched".
  `availability_reason` states the threshold that was applied.
* `availability: "not_applicable"` — the capture cannot answer it at all, e.g. no
  HTTP transactions for an HTTP detection. `availability_reason` says why.
* `headline.tone` is `"info" | "watch" | "warn"` — presentation only, never a verdict.
* `headline.value` is a real count/measure. It is `0` only when `availability` is not
  `"ok"`, so a zero on screen always means "nothing matched", never "not computed".

---

## 4. Visual shapes

`visuals[]` entries are tagged by `kind`. Each carries an optional `note` (rendered
under the chart) and an optional `title`.

```jsonc
// Ranked horizontal bars. items are already sorted, largest first, and capped.
{ "kind": "bars", "title": "Outbound volume by destination",
  "items": [ { "label": "example.com", "value": 123456, "to": "/http?host=example.com" } ],
  "unit": "bytes", "note": "top 12 of 40" }

// Time series. t is epoch seconds (bucket start). marker highlights a bucket.
{ "kind": "timeline", "title": "Requests per minute",
  "points": [ { "t": 1760000000.0, "value": 12, "marker": false } ],
  "unit": "requests", "note": "" }

// Distribution. label is the bucket's own description, e.g. "30-60 s".
{ "kind": "histogram", "title": "Interval between connections",
  "buckets": [ { "label": "30-60 s", "value": 4 } ], "unit": "flows", "note": "" }

// Scatter. label names the point; to links it.
{ "kind": "scatter", "title": "Query-name length against query count",
  "points": [ { "x": 78, "y": 240, "label": "a1b2.tunnel.example", "to": "/dns?domain=…" } ],
  "x_label": "longest label", "y_label": "queries", "note": "" }

// Matrix. cells[i] lines up with columns[i]; a missing column is 0.
{ "kind": "heatmap", "title": "Source against destination port",
  "columns": ["22", "80", "443"], "rows": [ { "label": "10.0.0.5", "cells": [0, 3, 1] } ],
  "unit": "attempts", "note": "" }

// Table. Every cell may carry a link; tone is optional emphasis.
{ "kind": "table", "title": "Matched alerts",
  "columns": ["severity", "rule", "endpoints", "packets"],
  "rows": [ { "cells": [ { "text": "high", "tone": "warn" },
                         { "text": "suricata:51000006", "to": "/findings/…" } ] } ],
  "note": "" }
```

Rules:

Colour: the plots colour their items from the active theme's own palette
(`ThemeTokens.chart`, eight hues chosen to stay distinguishable and free of the
severity ambers and reds) rather than one flat accent — a ranked chart of twelve rows
or a scatter of two hundred points is far easier to read when each item is its own
colour. No colour literal may appear in the components.

* A visual is **omitted entirely** when it has nothing to draw, rather than sent with
  empty arrays alongside an `"ok"` indication: `network_scanning` draws the
  source-against-port matrix only when something actually opened ports, and the
  hosts-probed bars only when something actually swept hosts. An `"ok"` indicator
  therefore always carries at least one non-empty visual, and the frontend never
  renders an empty frame.

* `bars` and `heatmap` cap rows at `top`; `timeline` caps points at 240 buckets;
  `table` caps rows at 50 and `scatter` at 200 points. A cap that bites is stated
  in `note` as `top N of M`.
* Empty `items`/`points`/`buckets`/`rows` are allowed only when `availability` is not
  `"ok"`; otherwise the indicator must use `availability: "empty"`.

---

## 5. Allowed link targets

Only these query parameters are read by the target pages. Anything else produces a
link that silently does nothing.

| page | parameters |
|---|---|
| `/packets` | `mode`, `search`, `ip`, `src_ip`, `dst_ip`, `port`, `src_port`, `dst_port`, `protocol`, `transport`, `tcp_flags`, `min_length`, `max_length`, `start_time`, `end_time`, `filter`, `stream_id`, `sel`, `sort`, `order`, `page`, `page_size` |
| `/conversations` | `transport`, `ip`, `port`, `search`, `stream`, `smode`, `alerts`, `tab` (`flow`/`info`/`timeline`), `node`, `expand` |
| `/dns` | `view`, `domain`, `client_ip`, `server_ip`, `qtype`, `rcode`, `search`, `unanswered`, `nxdomain`, `suspicious`, `sel` |
| `/http` | `method`, `host`, `uri`, `status`, `client_ip`, `server_ip`, `user_agent`, `search`, `interesting`, `tx` |
| `/tls` | `view`, `sni`, `version`, `ip`, `port`, `alpn`, `ja3`, `has_cert`, `sel` |
| `/hosts` | `view` (`graph`/`inventory`), `ip`, `search`, `protocol`, `is_private` (`true`/`false`) |
| `/findings`, `/findings/{id}` | path only; the id is `encodeURIComponent`d |
| `/objects` | none |

**A packet is opened with `sel`, not `number`:** the packets page reads
`?sel=<frame number>`. To open one frame inside its conversation use
`/packets?mode=basic&stream_id=<id>&sel=<n>`; for a UDP stream add
`&transport=udp`.

Every value interpolated into a URL must be `encodeURIComponent`d. Ids that already
contain `:` (conversation keys, finding ids) must be encoded.

---

## 6. Backend files

* **New** `backend/app/services/threat_hunt.py` — all computation. One entry point:
  `analyze(analysis_id: str, *, window: int, top: int) -> dict` returning the
  envelope of §3. Pure SQL over `packets`, `conversations`, `dns_queries`,
  `http_transactions`, `tls_sessions`, `hosts`, `findings`. Reuse
  `app.db.database` (`query_all` / `query_one`) and
  `app.services.host_analyzer.is_private_address` for internal/external decisions —
  do not re-implement address classification.
* **New** `backend/app/api/routes_threat_hunt.py` — the route, delegating to the
  service. Prefix `/api/analyses/{analysis_id}`, tag `threat-hunt`. Validate `window`
  (5–3600) and `top` (1–50) with `Query`, and call `deps.get_ready_analysis`.
* **Edit** `backend/app/main.py` — add `("app.api.routes_threat_hunt", "router")` to
  `ROUTER_SPECS`.
* **New** `backend/tests/test_threat_hunt.py` — see §8.
* **Edit** `docs/CONTRACT.md` — add the endpoint to the API index, matching the file's
  existing style.

## 7. Frontend files

* **New** `frontend/src/pages/ThreatHuntPage.tsx` — the page.
* **New** `frontend/src/components/threat/*.tsx` — one component per visual kind plus
  the indicator card.
* **Edit** `frontend/src/App.tsx` — `<Route path="/threat-hunt" …/>`.
* **Edit** `frontend/src/layouts/AppLayout.tsx` — a `Threat Hunt` nav entry, using the
  existing `NavItem` shape. Place it directly after `Findings`.
* **Edit** `frontend/src/types/index.ts` — types mirroring §3/§4 exactly.
* **Edit** `frontend/src/services/api.ts` — `threatHuntApi.get(analysisId, params)` in
  the file's existing style.

The page groups the detections into tabs rather than stacking all seventeen cards on
one page: an **Overview** tab listing every indicator's availability and headline
number, then four phase groups (recon and movement, C2 and name resolution,
exfiltration and staging, web and alerts). The tab lives in the URL (`?tab=`) so a
group is shareable, and the overview row for an indicator opens the tab that owns it.
**Every indicator of §1 must remain reachable**, and an id no group claims must still
be shown — a layout grouping may never hide a detection. The grouping is presentation
only and does not change the payload.

Within a tab, the page must render, for each indicator: its title, the question it
answers, the headline, every visual that carries data, the interpretation, the caveat
as visibly secondary text, and its links as `Link` elements. The page must use the analysis from
`useAnalysis()` and render the shared loading/error/empty states, so it behaves like
every other page.

**`availability` governs the reason, not whether data is drawn.** An indicator that is
not `"ok"` must render its `availability_reason`, and must *also* draw any visual that
carries data, captioned so the reader knows those numbers stayed under the threshold.
"Empty" means nothing crossed the threshold, not that nothing was measured: the
distribution that fell short — the best observed scan, the largest transfer — is
usually the most useful number on the card. An empty chart frame must never be drawn,
because that reads as "nothing found", which is a different claim from "not
computed". A visual with no data is simply not drawn, whatever the availability.

---

## 8. Verification required before either half is called done

Backend, against the **real** analyses in `data/apackets.db`, not only fixtures:

* the endpoint returns 17 indicators, ids in the order of §1;
* every indicator validates against §3/§4 — in particular `availability_reason` is
  present whenever `availability != "ok"`, and no `visuals` array is empty when
  `availability == "ok"`;
* no visual exceeds its cap, and any cap that bit is reported in `note`;
* every `to` in the response parses as a path with only the parameters of §5;
* the numbers are cross-checked against a direct SQL query for at least three
  indicators, and the measured values are reported.

Frontend:

* `npx tsc --noEmit` exits 0 (the project runs `noUnusedLocals`/`noUnusedParameters`);
* the page renders all 17 cards against a real API response captured to a fixture,
  with each visual kind actually drawn, verified by rendering the component tree and
  reading the markup — not by inspection.

Report the **measured** values you observed. If something in this spec is wrong or
impossible, say so explicitly rather than silently deviating.
