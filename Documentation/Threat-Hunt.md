# Threat Map

The investigative front page of an analysis: seventeen fixed questions asked of
the capture's index — is anything beaconing, scanning, tunnelling, staging or
exfiltrating — each with the threshold it applied, the chart behind the number,
links to the rows themselves, and a statement of what the pattern does *not*
prove.

It is reachable at `/threat-hunt`, in the left-hand navigation directly after
**Findings**. The detections are defined by two documents outside this set:
[`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) is the normative contract for the
section (indicator ids, envelope, visual shapes, caps, allowed link parameters),
and [`docs/CONTRACT.md`](../docs/CONTRACT.md) §8 covers the recorded detection
rules. This document explains the section as it runs; the
[overview of the detections](ThreatHunter/ThreatHunter.md) and
[the template every per-detection page follows](ThreatHunter/EachFeature.md) live
in [ThreatHunter/](ThreatHunter/ThreatHunter.md).

---

## 1. What the section is for

An analyst starting on an unfamiliar capture has to answer a small set of
questions before anything else is worth doing. Threat Map answers them with
numbers measured from this analysis's own index, and puts the evidence one click
away.

It is a **triage surface, not a detection engine**: it raises no findings, writes
nothing to the database and changes nothing about the analysis. Everything it
shows is an aggregate over rows that already exist — `packets`, `conversations`,
`dns_queries`, `http_transactions`, `tls_sessions`, `hosts`, `findings` and
`objects`. Because it reads the index and never the capture, it is fast, it keeps
working after the upload has been purged, and it can never report anything the
analysis did not index. See [Architecture.md](Architecture.md) §3 for how those
tables get filled and [Architecture.md](Architecture.md) §6 for why the section
never invokes TShark.

---

## 2. The endpoint

```
GET /api/analyses/{analysis_id}/threat-hunt
```

Implemented in `backend/app/api/routes_threat_hunt.py`, which validates the two
query parameters and applies the shared readiness gate
(`deps.get_ready_analysis`), then delegates all computation to `analyze()` in
`backend/app/services/threat_hunt.py`. An unknown id is `404 analysis_not_found`;
an analysis that has not finished is `409 analysis_not_ready`.

### `window` and `top`

| Parameter | Default | Range | Meaning |
|---|---|---|---|
| `window` | `60` | 5–3600 (seconds) | Seconds per bucket for every time series. The page always sends `60`. |
| `top` | `12` | 1–50 (rows) | Rows returned per ranked visual (bars and heatmap). The page always sends `12`. |

Both are declared with `Query` bounds (`MIN_WINDOW = 5`, `MAX_WINDOW = 3600`,
`MIN_TOP = 1`, `MAX_TOP = 50`), so a value outside the range is
`422 validation_error` before the handler runs. The service also clamps both
(`max(5, min(3600, …))` and `max(1, min(50, …))`) so calling it directly from a
script or a test cannot produce an unbounded response.

The page offers no controls at all, because it reads an indexed capture rather than a
live feed: `window` is fixed at 60 seconds and `top` at 12, so there is nothing to tune
and nothing to refresh. Both stay endpoint parameters, and the API accepts any value
inside 5–3600 for `window` and 1–50 for `top`, so a saved request can choose
different ones.

The response envelope (`analysis_id`, `generated_at`, `packets_scanned`,
`window`, `top`, `note`, and `indicators[]`) is fixed by
[`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §3, and mirrored in
`frontend/src/types/index.ts`. All seventeen indicators are always returned, in
the contract's order; a missing indicator is a contract violation and the page
reports it in a warning banner rather than pretending the card does not exist.

---

## 3. The three `availability` values

`availability` says whether the capture could **answer the question at all** —
not whether the answer was reassuring.

| Value | What it means | What the reader does |
|---|---|---|
| `ok` | The indicator was computed and there is at least one item worth showing. `headline.value` is the real count of those items and is never 0. `availability_reason` is `null`. | Read the headline, then the chart, then decide. The number counted something. |
| `empty` | The indicator is computable and the honest answer is "nothing matched". `availability_reason` states the threshold that was applied, and usually the best value that stayed under it. | Read the reason: it names the threshold and the nearest miss. Anything the card still draws is captioned as below the threshold. |
| `not_applicable` | The capture cannot answer the question at all — no HTTP transactions, no DNS queries, no host rows. `availability_reason` says which table was empty and why. | Nothing is claimed. This is **not** a clean bill of health; it is a question this capture cannot answer. |

Two consequences matter on screen:

* `headline.value` is `0` only when `availability` is not `"ok"`. A zero always
  means "nothing matched" or "not computable", never a measured zero.
* `empty` is not the same as "nothing was measured". The distribution that fell
  short — the best observed scan, the largest transfer — is still drawn, and it is
  usually the most useful number on the card. An empty chart frame is never drawn,
  because that reads as "nothing found", which is a different claim from "not
  computed".

Availability on real captures is genuinely mixed rather than uniformly green.
Running the engine with `window=60, top=12` over the 22 analyses indexed in
`data/apackets.db` (measured, read-only), the count of `ok` indicators per
analysis ranged from **0 of 17** on the empty fixture capture `edge_empty.pcap` to
**11 of 17** on `sf19us-MTA-lab-09.pcap`; `sf19us-MTA-lab-01.pcap` returned 8,
`sf19us-MTA-lab-07.pcap` and `SpaceX_111025.pcapng` 7 each, and
`sf19us-MTA-lab-11.pcap` and `sf19us-MTA-lab-12.pcap` 2 and 1. Per indicator,
`unusual_ports` was `ok` for 12 of the 22 analyses, `rare_pairs` and
`unusual_egress` for 9 each, while `data_staging` was never `ok` (17 `empty`, 5
`not_applicable`) and `c2_beaconing`, `dns_tunnelling`, `failed_connections` and
`malware_download` were `ok` for exactly 1 each. The bulk transfer in these
captures runs *inbound*, which is why `malware_download` fires where
`data_staging` never does — an empty card here is a correct answer about a
capture, not a defect.

---

## 4. The tabs

Seventeen cards is too many to stack, so the page groups them into the phases an
analyst actually works in. The grouping is **presentation only** — it does not
change the payload — and it may never hide a detection: an id no group claims is
shown under *Other*, and an id the response omits is reported in a banner.

| Tab (`?tab=`) | Label | Detections it owns | Count |
|---|---|---|---|
| `overview` | Overview | — (one compact row per detection) | 17 rows |
| `recon` | Recon and movement | `network_scanning`, `high_fan_out`, `rare_pairs`, `unusual_ports`, `failed_connections`, `lateral_movement` | 6 |
| `c2` | C2 and name resolution | `c2_beaconing`, `dns_anomalies`, `dns_tunnelling`, `suspicious_tls` | 4 |
| `exfil` | Exfiltration and staging | `data_exfiltration`, `unusual_egress`, `data_staging`, `malware_download` | 4 |
| `web` | Web and alerts | `suspicious_http`, `traffic_bursts`, `ids_matches` | 3 |

The active tab lives in the URL (`?tab=…`), so a group is shareable and survives
a reload; an unknown value falls back to `overview`. Each non-overview tab shows
an `n/m` count of how many of its detections computed something for this capture.

**Overview** is one compact line per detection: the availability chip, the title,
the headline label and the headline number. Clicking a row opens the tab that owns
that detection — it is a routing surface, not a summary you are meant to read in
full.

Above the tabs sits the header: the scope note, stating what the section can and
cannot say. It starts collapsed — the section is seventeen answers, not a primer —
and opens from the *show* toggle in its own header. No other control sits above the
tabs, and the page does not report a generated-at time.

---

## 5. How to read a card

Each card is the same object rendered the same way, so one reading order works
everywhere:

1. **Title and availability chip** — the indicator's title and one of `computed`,
   `nothing matched` or `not applicable`, plus the stable indicator id with a copy
   button so it can be quoted in notes or re-queried.
2. **The question** — the sentence the endpoint returns as `question`, worded as
   the analyst's question, not as the implementation.
3. **Headline** — one number, its label, in a tone colour. The tone (`info`,
   `watch`, `warn`) is **presentation only, never a verdict**; `warn` is used by
   `malware_download`, and by `ids_matches` when a high-severity signature
   matched.
4. **The chart** — whichever visuals the visual builders produced for this
   capture. The six shapes are bars, timeline, histogram, scatter, heatmap and
   table, each defined in [`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §4. Every
   list is capped (`top` rows for bars and heatmap, 240 timeline buckets, 200
   scatter points, 50 table rows) and a cap that bites says `top N of M` in the
   visual's `note`, so a cut list is never mistaken for a complete one. A visual
   with nothing to draw is omitted entirely rather than drawn empty.
5. **The availability notice** — when the indicator is not `ok`, the reason is
   shown here: the threshold that was applied, or the table that was empty.
6. **"What it may indicate"** — the interpretation: what a pattern like this is
   usually associated with. It is deliberately worded as *may*, because it is a
   reading of the pattern, not a conclusion about the traffic.
7. **The caveat** — visibly secondary italic text, on every card without
   exception, naming what the pattern does not prove. It is what stops a lead
   from reading as a verdict.
8. **The links** — the same values the card is showing, as links into the pages
   that hold the rows behind them: a destination address to `/conversations?ip=…`,
   a conversation to `/conversations?stream=<transport>:<stream_id>`, a host to
   `/hosts?ip=…`, a frame to `/packets?sel=…`, a port to `/packets?dst_port=…`, a
   DNS name to `/dns?domain=…`, a request to `/http?tx=…`, a TLS session to
   `/tls?sni=…` (or `/tls?ip=…` when there is no server name), a signature match
   to `/findings/{id}`, and an extracted file to `/objects`.

Two linking conventions are worth knowing: **a frame is opened with `sel`, not
`number`** (`/packets?mode=basic&stream_id=<id>&sel=<n>`, plus `&transport=udp`
for UDP), and every interpolated value is `encodeURIComponent`d, because
conversation keys and finding ids contain `:`. Only the query parameters listed in
[`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §5 are used — the ones the target
pages actually read — because a parameter no page reads would produce a link that
silently does nothing.

---

## 6. The seventeen detections

Ids are stable and are what the front end switches on. The question is the one the
endpoint returns and the card shows. The principal visual is the first of the
visuals that indicator declares in [`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md)
§1; most indicators draw more than one.

| id | Detection | Question it answers | Principal visual | Page |
|---|---|---|---|---|
| `c2_beaconing` | Potential C2 Beaconing | Is anything contacting the same destination on a regular schedule? | Histogram of intervals between connections | [ThreatHunter/C2Beaconing.md](ThreatHunter/C2Beaconing.md) |
| `network_scanning` | Network Scanning | Is one host probing many ports or hosts in a short time? | Source-against-port heatmap, plus hosts probed with no answer | [ThreatHunter/NetworkScanning.md](ThreatHunter/NetworkScanning.md) |
| `dns_anomalies` | DNS Anomalies | Are lookups failing, or do names look machine-generated? | Bars of anomalous DNS activity per client | [ThreatHunter/DnsAnomalies.md](ThreatHunter/DnsAnomalies.md) |
| `data_exfiltration` | Potential Data Exfiltration | Is an internal host sending more to a public peer than its traffic explains? | Bars of outbound volume by destination | [ThreatHunter/DataExfiltration.md](ThreatHunter/DataExfiltration.md) |
| `lateral_movement` | Lateral Movement Indicators | Is an internal host reaching other internal hosts on remote-administration services? | Bars of internal hosts reached on administration services | [ThreatHunter/LateralMovement.md](ThreatHunter/LateralMovement.md) |
| `suspicious_http` | Suspicious HTTP Activity | Do requests carry paths, credentials or payload types a normal client would not send? | Timeline of HTTP requests per bucket, plus the flagged transactions | [ThreatHunter/SuspiciousHttp.md](ThreatHunter/SuspiciousHttp.md) |
| `suspicious_tls` | Suspicious TLS Connections | Do TLS sessions lack identity, use obsolete versions, or fail mid-handshake? | Bars of sessions by observation | [ThreatHunter/SuspiciousTls.md](ThreatHunter/SuspiciousTls.md) |
| `unusual_ports` | Unusual Port Usage | Which destination ports fall outside the capture's ordinary service set? | Bars of uncommon destination ports by packets | [ThreatHunter/UnusualPorts.md](ThreatHunter/UnusualPorts.md) |
| `high_fan_out` | High-Fan-Out Hosts | Which host is talking to the most distinct peers? | Bars of distinct peers per host | [ThreatHunter/HighFanOut.md](ThreatHunter/HighFanOut.md) |
| `rare_pairs` | Rare Communication Pairs | Which address pairs appear in a single, tiny exchange? | Table of pairs seen in exactly one conversation | [ThreatHunter/RareCommunicationPairs.md](ThreatHunter/RareCommunicationPairs.md) |
| `malware_download` | Possible Malware Download | Was an executable or script payload pulled over HTTP? | Timeline of HTTP response bytes per bucket | [ThreatHunter/PossibleMalwareDownload.md](ThreatHunter/PossibleMalwareDownload.md) |
| `dns_tunnelling` | Possible DNS Tunnelling | Is one domain answering many machine-generated subdomains from a single client? | Scatter of mean longest label against query count | [ThreatHunter/DnsTunnelling.md](ThreatHunter/DnsTunnelling.md) |
| `ids_matches` | IDS Signature Matches | Which recorded IDS signatures fired in this capture? | Table of signature matches | [ThreatHunter/IdsSignatureMatches.md](ThreatHunter/IdsSignatureMatches.md) |
| `traffic_bursts` | Suspicious Traffic Bursts | When does packet volume depart sharply from the capture's own baseline? | Timeline of packets per bucket against the baseline | [ThreatHunter/TrafficBursts.md](ThreatHunter/TrafficBursts.md) |
| `unusual_egress` | Unusual Egress | Is an internal host reaching out on ports or to addresses the rest of the capture never uses? | Bars of outbound volume to non-standard destinations | [ThreatHunter/UnusualEgress.md](ThreatHunter/UnusualEgress.md) |
| `data_staging` | Potential Data Staging | Is a large volume moving between two internal hosts? | Timeline of internal transfer bytes per bucket | [ThreatHunter/DataStaging.md](ThreatHunter/DataStaging.md) |
| `failed_connections` | Repeated Failed Connections | What is repeatedly trying to connect and never being answered? | Timeline of unanswered attempts per bucket | [ThreatHunter/FailedConnections.md](ThreatHunter/FailedConnections.md) |

Every one of those documents follows the same structure, described in
[ThreatHunter/EachFeature.md](ThreatHunter/EachFeature.md): what it answers, how
to read the card, the detection logic with the function that implements it, every
threshold with its exact constant name and value, the indexed fields used, the
fields the brief asks for that the index does not hold, how to investigate
further, what it does not prove, and its known limits and false positives.

---

## 7. Thresholds, caps and honesty rules

* **Thresholds are fixed, not configurable.** Every constant in
  `backend/app/services/threat_hunt.py` — for example `BEACON_MIN_FLOWS = 4`,
  `SCAN_MIN_PORTS = 20`, `DNS_NXDOMAIN_MIN = 5`, `EXFIL_MIN_BYTES = 1_000_000`,
  `FAN_OUT_MIN_PEERS = 10`, `RARE_PAIR_MAX_PACKETS = 2`, `BURST_SIGMAS = 3.0`,
  `FAILED_MIN_ATTEMPTS = 10`, `TUNNEL_MIN_ENTROPY = 3.6` — is a module-level
  constant with no settings key, no per-analysis override and no environment
  variable. The only things a caller can change are `window` and `top`. A capture
  whose normal traffic sits above or below a fixed threshold needs a different
  tool, not a different setting.
* **Caps apply to every list.** `TIMELINE_CAP = 240` points, `TABLE_CAP = 50`
  rows, `SCATTER_CAP = 200` points, `PACKET_SCAN_CAP = 20000` rows read by any
  packet- or conversation-level query, `ROW_SCAN_CAP = 500` rows returned by any
  grouping query, and `top` (default 12) for bars and heatmap. A cap that bit is
  reported as `top N of M`.
* **One bad indicator cannot sink the page.** `analyze()` catches per-indicator
  exceptions, logs them, and returns that indicator as `not_applicable` with the
  reason `"internal error while computing this indicator from the index"`
  (`FAILED_REASON`).
* **No baseline across captures.** `traffic_bursts` compares each bucket against
  the mean of the same capture's buckets, and the relative exfiltration threshold
  comes from the median of this capture's own destinations. Nothing is compared
  with a previous analysis or a stored profile.
* **No payload inspection.** TLS and HTTPS are not decrypted, HTTP bodies are not
  examined (the engine reads the transaction's lead flags, URI, content type and
  sizes), DNS record contents are not read, and no file is opened to identify what
  it really is. A "payload" here means a declared content type or a filename
  extension, not bytes.
* **No re-dissection.** The section inherits every gap in the index: traffic
  TShark did not dissect, columns an analyser left NULL, and protocols no analyser
  covers. A filtered or truncated capture shows up as an `empty` or
  `not_applicable` card, which is a statement about the index, not about the
  network.

---

## Related

[README.md](README.md) · [Architecture.md](Architecture.md) ·
[Findings.md](Findings.md) · [Dashboard.md](Dashboard.md) ·
[Conversations.md](Conversations.md) · [Hosts.md](Hosts.md) · [DNS.md](DNS.md) ·
[HTTP.md](HTTP.md) · [TLS.md](TLS.md) · [Packets.md](Packets.md) ·
[Reference/API.md](Reference/API.md) · [ThreatHunter/](ThreatHunter/ThreatHunter.md) ·
[docs/THREAT_HUNT.md](../docs/THREAT_HUNT.md) ·
[docs/CONTRACT.md](../docs/CONTRACT.md)
