# Threat Map

The Threat Map section is the investigative front page of an analysis. It asks
seventeen fixed questions of the capture — the ones an analyst asks first — and
answers each one from the tables APackets already indexed, with the threshold it
applied, the chart behind the number, links to the rows themselves, and a
statement of what the pattern does *not* prove.

It is reachable at `/threat-hunt`, and in the sidebar directly after **Findings**.

The section is defined by two documents that are not in this folder:

* [`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md) — the normative contract: the
  seventeen indicator ids, the response envelope, the six visual shapes, the caps,
  and the only link parameters that may be used.
* [`docs/CONTRACT.md`](../../docs/CONTRACT.md) — the frozen schema (§3), the API
  conventions (§2), the detection rules and their thresholds (§8).

This folder documents the implementation as it stands. [EachFeature.md](EachFeature.md)
is the template every per-detection document follows; the seventeen documents
below it describe one indicator each.

---

## 1. What the section is for

An analyst starting on an unfamiliar capture has to answer a small set of
questions before anything else is worth doing: is anything beaconing, is anything
scanning, is anything moving data out, is anything talking to a destination it has
no business talking to. Threat Map answers those questions with numbers measured
from this capture's own index, and puts the evidence one click away.

It is a triage surface, not a detection engine of its own. It does not raise
findings, it does not write to the database, and it does not change the analysis.
Everything it shows is an aggregate over rows that already exist:

| Table | What it supplies |
|---|---|
| `packets` | Addresses, ports, transport, TCP flags, frame length, timestamps |
| `conversations` | Per-stream endpoints, directional packets and bytes, start and end times |
| `dns_queries` | Query names, rcodes, name shape (`longest_label`, `entropy`), lead flags |
| `http_transactions` | Method, host, URI, status, user agent, content type, sizes, lead flags |
| `tls_sessions` | SNI, version, ALPN, cipher, JA3/JA4, certificate fields, handshake status, lead flags |
| `hosts` | Per-host packet and byte counters, peer count, DNS names, TLS SNI seen |
| `findings` | The recorded detections, including Suricata signature matches |
| `objects` | Files extracted from the capture, with type and size |

Because the section reads the index rather than the capture, it stays fast and it
keeps working after the uploaded PCAP has been purged. It also means the section
can never report anything the analysis did not index: a detection whose source
table is empty says so instead of showing a zero.

---

## 2. The seventeen detections

Ids are stable and are what the frontend switches on. The question is returned by
the endpoint and shown on the card. The principal visual is the first of the
visuals that indicator declares in the contract (§1 of `docs/THREAT_HUNT.md`).

| id | Question | Principal visual |
|---|---|---|
| `c2_beaconing` | Is anything contacting the same destination on a regular schedule? | Histogram of intervals between connections |
| `network_scanning` | Is one host probing many ports or hosts in a short time? | Source-against-port heatmap, plus hosts probed with no answer |
| `dns_anomalies` | Are lookups failing, or do names look machine-generated? | Bars of anomalous DNS activity per client |
| `data_exfiltration` | Is an internal host sending more to a public peer than its traffic explains? | Bars of outbound volume by destination |
| `lateral_movement` | Is an internal host reaching other internal hosts on remote-administration services? | Bars of internal hosts reached on administration services |
| `suspicious_http` | Do requests carry paths, credentials or payload types a normal client would not send? | Timeline of HTTP requests per bucket, plus the flagged transactions |
| `suspicious_tls` | Do TLS sessions lack identity, use obsolete versions, or fail mid-handshake? | Bars of sessions by observation |
| `unusual_ports` | Which destination ports fall outside the capture's ordinary service set? | Bars of uncommon destination ports by packets |
| `high_fan_out` | Which host is talking to the most distinct peers? | Bars of distinct peers per host |
| `rare_pairs` | Which address pairs appear in a single, tiny exchange? | Table of pairs seen in exactly one conversation |
| `malware_download` | Was an executable or script payload pulled over HTTP? | Timeline of HTTP response bytes per bucket |
| `dns_tunnelling` | Is one domain answering many machine-generated subdomains from a single client? | Scatter of mean longest label against query count |
| `ids_matches` | Which recorded IDS signatures fired in this capture? | Table of signature matches |
| `traffic_bursts` | When does packet volume depart sharply from the capture's own baseline? | Timeline of packets per bucket against the baseline |
| `unusual_egress` | Is an internal host reaching out on ports or to addresses the rest of the capture never uses? | Bars of outbound volume to non-standard destinations |
| `data_staging` | Is a large volume moving between two internal hosts? | Timeline of internal transfer bytes per bucket |
| `failed_connections` | What is repeatedly trying to connect and never being answered? | Timeline of unanswered attempts per bucket |

The endpoint always returns all seventeen, in this order. A missing indicator is a
contract violation, and the page reports it as one rather than omitting the row
(see §6).

---

## 3. How the endpoint works

```
GET /api/analyses/{analysis_id}/threat-hunt
```

Implemented in `backend/app/api/routes_threat_hunt.py`, which validates the two
query parameters and applies the shared readiness gate, then delegates all
computation to `analyze()` in `backend/app/services/threat_hunt.py`. The service is
pure SQL over the indexed tables; it never invokes TShark and never re-reads the
capture.

| Parameter | Default | Range | Meaning |
|---|---|---|---|
| `window` | `60` | 5–3600 (seconds) | Seconds per bucket for every time series on the page |
| `top` | `12` | 1–50 (rows) | Rows returned per ranked visual (bars and heatmap) |

Both are validated with `Query` bounds, so an out-of-range value is
`422 validation_error`. The service also clamps both values
(`max(5, min(3600, …))`, `max(1, min(50, …))`) so it can be called directly from a
script or a test without producing an unbounded response. An unknown analysis id is
`404 analysis_not_found`; an analysis that has not finished is
`409 analysis_not_ready`, because the detections need tables a running analysis has
not filled yet.

Response envelope:

```jsonc
{
  "analysis_id": "9e2e…",
  "generated_at": 1760000000.0,   // server clock, float seconds
  "packets_scanned": 4003,        // rows in the packet index for this analysis
  "window": 60,
  "top": 12,
  "note": "…",                    // what the whole page is, and is not
  "indicators": [ /* 17 objects, in the order of §2 */ ]
}
```

Each indicator carries `id`, `title`, `question`, `availability`,
`availability_reason`, `headline` (`value`, `label`, `tone`), `visuals[]`,
`interpretation`, `caveat` and `links[]`. The shapes are fixed by §3 and §4 of
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md) and are mirrored in
`frontend/src/types/index.ts`.

### Caps

Every list is bounded, and a cap that bites is reported in the visual's `note` as
`top N of M`:

| Constant | Value | Applies to |
|---|---|---|
| `TIMELINE_CAP` | `240` | Points in a timeline (the earliest 240 buckets) |
| `TABLE_CAP` | `50` | Rows in a table, and buckets in a histogram |
| `SCATTER_CAP` | `200` | Points in a scatter |
| `PACKET_SCAN_CAP` | `20000` | Rows any packet-level or conversation-level query will read |
| `ROW_SCAN_CAP` | `500` | Rows any grouping query will return |
| `top` | `12` (1–50) | Rows in a bars or heatmap visual |

One bad indicator cannot sink the page: `analyze()` catches per-indicator
exceptions, logs them, and returns that indicator as `not_applicable` with the
reason `"internal error while computing this indicator from the index"`
(`FAILED_REASON`).

---

## 4. The three availability values

`availability` says whether the capture could answer the question at all — not
whether the answer was reassuring.

| Value | What it means | What the reader should do |
|---|---|---|
| `ok` | The indicator was computed and there is at least one item worth showing. `headline.value` is the real count of those items and is never 0. `availability_reason` is `null`. | Read the headline, then the chart, then decide. The number counted something. |
| `empty` | The indicator is computable, and the honest answer is "nothing matched". `availability_reason` states the threshold that was applied and usually the best value that stayed under it. | Read the reason: it names the threshold and the nearest miss. The card still draws any visual that carries data, captioned as below the threshold. |
| `not_applicable` | The capture cannot answer the question at all, for example because it recorded no HTTP transactions or no DNS queries. `availability_reason` says why. | Nothing is claimed. This is not a clean bill of health — it is a question this capture cannot answer, and the reason says which table was empty. |

Two consequences matter on screen:

* `headline.value` is `0` only when `availability` is not `"ok"`. A zero therefore
  always means "nothing matched" or "not computable", never a measured zero.
* `empty` is not the same as "nothing was measured". The distribution that fell
  short — the best observed scan, the largest transfer — is still drawn, and it is
  usually the most useful number on the card.

`headline.tone` (`info`, `watch`, `warn`) is presentation only. The tone colours
the headline; it is never a verdict. `warn` is used by `malware_download` and by
`ids_matches` when a high-severity signature matched; everything else is `info` or
`watch`.

---

## 5. How to read the page

* **Header.** The scope note alone, collapsed by default and opened from the *show*
  toggle in its header. The page has no other controls: it reads an indexed capture,
  not a live feed, so `window` is fixed at 60 seconds and `top` at 12. Both remain
  endpoint parameters — the API accepts 5–3600 and 1–50 — so a saved
  request can still choose different ones.
* **Tabs.** The seventeen detections are grouped into the phases an analyst works
  in — *Overview*, *Recon and movement*, *C2 and name resolution*, *Exfiltration
  and staging*, *Web and alerts* — with a `n/m` count of how many detections in
  that tab computed something. The active tab lives in the URL (`?tab=…`), so a
  group is shareable and survives a reload. The grouping is presentation only; an
  id that no group claims is shown under *Other* rather than dropped, and an
  indicator the response omits is reported in a warning banner rather than
  silently skipped.
* **Overview.** One compact row per detection: the availability chip, the title,
  the headline label, and the headline number. Clicking a row opens the tab that
  owns that detection.
* **A card.** Title and availability chip (`computed`, `nothing matched`, `not
  applicable`), the question, the stable indicator id with a copy button, the
  headline number in its tone colour, then the availability notice when the
  indicator is not `ok`, then the visuals, then "What it may indicate" (the
  interpretation), then the caveat as visibly secondary italic text, then the links.
  The caveat is deliberately quiet and always present: it is what stops a lead
  reading as a verdict.

Each card documents itself: its thresholds, its evidence, its limits. The
per-detection documents in this folder are the long form of the same thing —
[C2Beaconing.md](C2Beaconing.md), [NetworkScanning.md](NetworkScanning.md) and so
on, one file per id in §2.

---

## 6. How the links connect the section to the rest of the app

Every card ends with links built from the same values the card is showing, so the
reader can move from an aggregate to the rows behind it. Only the query parameters
listed in §5 of [`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md) are used, because
those are the ones the target pages actually read; anything else would produce a
link that silently does nothing.

| Page | Parameters the page reads |
|---|---|
| `/packets` | `mode`, `search`, `ip`, `src_ip`, `dst_ip`, `port`, `src_port`, `dst_port`, `protocol`, `transport`, `tcp_flags`, `min_length`, `max_length`, `start_time`, `end_time`, `filter`, `stream_id`, `sel`, `sort`, `order`, `page`, `page_size` |
| `/conversations` | `transport`, `ip`, `port`, `search`, `stream`, `smode`, `alerts`, `tab` (`flow`/`info`/`timeline`), `node`, `expand` |
| `/dns` | `view`, `domain`, `client_ip`, `server_ip`, `qtype`, `rcode`, `search`, `unanswered`, `nxdomain`, `suspicious`, `sel` |
| `/http` | `method`, `host`, `uri`, `status`, `client_ip`, `server_ip`, `user_agent`, `search`, `interesting`, `tx` |
| `/tls` | `view`, `sni`, `version`, `ip`, `port`, `alpn`, `ja3`, `has_cert`, `sel` |
| `/hosts` | `view` (`graph`/`inventory`), `ip`, `search`, `protocol`, `is_private` (`true`/`false`) |
| `/findings`, `/findings/{id}` | path only; the id is percent-encoded |
| `/objects` | none |

Two conventions matter when following a link:

* **A frame is opened with `sel`, not `number`.** The packets page reads
  `?sel=<frame number>`. To open one frame inside its conversation use
  `/packets?mode=basic&stream_id=<id>&sel=<n>`; for a UDP stream add
  `&transport=udp`.
* **Values are percent-encoded.** Conversation keys and finding ids contain `:`
  and are quoted before they go into a path, so a link always lands on the row it
  names.

In practice the links are: a destination address to `/conversations?ip=…`, a
conversation to `/conversations?stream=<transport>:<stream_id>`, a host to `/hosts?ip=…`,
a frame to `/packets?sel=…`, a port to `/packets?dst_port=…`, a DNS name to
`/dns?domain=…` (with `&client_ip=…` where the client matters), a request to
`/http?tx=…`, a TLS session to `/tls?sni=…` (or `/tls?ip=…` when there is no
server name), a signature match to `/findings/{id}`, and an extracted file to
`/objects`.

---

## 7. Honesty rules

These are the rules the section is built to, and they are the reason it is worth
reading:

1. **Every number comes from this analysis's index.** No placeholder, no sample, no
   extrapolation, no interpolation. If a detection cannot be computed it says so
   through `availability` and `availability_reason` instead of rendering zeroes
   that look like a real reading.
2. **Nothing is fabricated to fill a chart.** A visual that carries no data is not
   drawn at all; an empty axis is never drawn, because it reads as "nothing found",
   which is a different claim from "not computed".
3. **An empty indicator is a real result.** `empty` means nothing crossed the
   threshold for this capture, and the reason states the threshold. It is not an
   error and it is not a clean bill of health either.
4. **Every indicator carries a caveat** naming what its pattern does not prove. An
   indicator is a lead, not a verdict.
5. **Every cap is reported.** A list that was cut short says `top N of M` in its
   note, so the reader knows the page is not showing everything.
6. **Failures are visible.** A per-indicator exception becomes
   `not_applicable` with an explicit reason, and an indicator the response omits is
   reported in a banner on the page.

On the lab captures used during development, between 1 and 11 of the seventeen
indicators returned `ok` for a given analysis; `data_staging` and
`data_exfiltration` are typically empty on those captures because their bulk
transfer runs *inbound* and therefore surfaces as `malware_download` instead. An
empty card there is a correct answer about a capture, not a defect.

---

## 8. Limitations

* **Thresholds are fixed, not configurable.** Every constant in
  `backend/app/services/threat_hunt.py` — `BEACON_MIN_FLOWS = 4`,
  `SCAN_MIN_PORTS = 20`, `DNS_NXDOMAIN_MIN = 5`, `EXFIL_MIN_BYTES = 1_000_000`,
  `FAN_OUT_MIN_PEERS = 10`, `RARE_PAIR_MAX_PACKETS = 2`, `BURST_SIGMAS = 3.0`,
  `FAILED_MIN_ATTEMPTS = 10`, `TUNNEL_MIN_ENTROPY = 3.6` and the rest — is a
  module-level constant. There is no settings key, no per-analysis override and no
  environment variable that changes them, unlike the detection rules of
  `docs/CONTRACT.md` §8, whose thresholds *are* configurable. The only things a
  caller can change are `window` and `top`. A capture whose normal traffic sits
  above or below a fixed threshold needs a different tool, not a different setting.
* **There is no baseline across captures and no history.** Every baseline is this
  capture's own: `traffic_bursts` compares each bucket against the mean of the same
  capture's buckets, and the relative exfiltration threshold is derived from the
  median of this capture's own destinations. Nothing is compared with the same host
  last week, with another analysis, or with a stored profile. A capture that is
  already busy, or short, will not show a burst at all; a host that always talks to
  a peer will not show as unusual, because there is nothing to compare it with.
* **No payload inspection.** The section reads metadata only. TLS and HTTPS are not
  decrypted, HTTP bodies are not examined (the engine reads the transaction's lead
  flags, URI, content type and sizes rather than the stored body preview), DNS
  record contents are not read, and no file is opened to identify what it really is.
  A "payload" here means a declared content type or a filename extension, not bytes.
* **No re-dissection.** Because the section reads the index and never the capture,
  it inherits every gap in the index: traffic TShark did not dissect, columns the
  analysers leave NULL, and protocols no analyser covers. A filtered or truncated
  capture shows up as an `empty` or `not_applicable` card, which is a statement
  about the index, not about the network.

---

## 9. Per-detection documents

| Detection | Document |
|---|---|
| `c2_beaconing` | [C2Beaconing.md](C2Beaconing.md) |
| `network_scanning` | [NetworkScanning.md](NetworkScanning.md) |
| `dns_anomalies` | [DnsAnomalies.md](DnsAnomalies.md) |
| `data_exfiltration` | [DataExfiltration.md](DataExfiltration.md) |
| `lateral_movement` | [LateralMovement.md](LateralMovement.md) |
| `suspicious_http` | [SuspiciousHttp.md](SuspiciousHttp.md) |
| `suspicious_tls` | [SuspiciousTls.md](SuspiciousTls.md) |
| `unusual_ports` | [UnusualPorts.md](UnusualPorts.md) |
| `high_fan_out` | [HighFanOut.md](HighFanOut.md) |
| `rare_pairs` | [RareCommunicationPairs.md](RareCommunicationPairs.md) |
| `malware_download` | [PossibleMalwareDownload.md](PossibleMalwareDownload.md) |
| `dns_tunnelling` | [DnsTunnelling.md](DnsTunnelling.md) |
| `ids_matches` | [IdsSignatureMatches.md](IdsSignatureMatches.md) |
| `traffic_bursts` | [TrafficBursts.md](TrafficBursts.md) |
| `unusual_egress` | [UnusualEgress.md](UnusualEgress.md) |
| `data_staging` | [DataStaging.md](DataStaging.md) |
| `failed_connections` | [FailedConnections.md](FailedConnections.md) |

Each of those documents follows the same structure, described in
[EachFeature.md](EachFeature.md): what it answers, how to read the card, the
detection logic with the function that implements it, every threshold with its
exact constant name and value, the indexed fields used, the fields the brief asks
for that the index does not hold, how to investigate further, what it does not
prove, and its known limits and false positives.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [Architecture](../Architecture.md) · [Findings](../Findings.md)
