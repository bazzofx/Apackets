# Suspicious Traffic Bursts (`traffic_bursts`)

Part of the **Threat Map** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**When does packet volume depart sharply from the capture's own baseline?**

## 2. How to read the card

The headline counts *burst buckets*: `window`-second buckets whose packet count is
both above the capture's own baseline by more than three standard deviations **and**
at least `BURST_MIN_PACKETS` packets in its own right. It is a count of time buckets,
not of packets.

One visual is drawn: a **timeline** of packets per `window`-second bucket against the
capture's own baseline, with the burst buckets marked as vertical highlights. The
caption reports the span of the drawn buckets, the tallest bucket's value, and how
many buckets are highlighted; the note reports the baseline, the computed threshold and
the floor. Reading the line without the marks tells you the shape of the capture;
reading the marks tells you where the engine thinks something happened.

A **high** reading is many marked buckets, which on a chatty capture usually means the
traffic is inherently bursty rather than that anything happened. A **low** reading is
one or two marked buckets, and those are worth opening. A zero headline with
`availability: "empty"` means no bucket cleared both tests; the line is still drawn
with the baseline and threshold in the note, so the reader can see how close it came.

This is the only indicator on the page with **no links at all**: the burst is a
capture-wide aggregate with no address or frame attached, so the card offers nothing to
click. The reader has to take the marked bucket's time and open the packets page with a
time range (see §7).

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_traffic_bursts(index)` in `backend/app/services/threat_hunt.py`.

1. Aggregate the packet index into buckets: `CAST(time_epoch / window AS INTEGER)`,
   counting packets per bucket, in ascending bucket order. Frames with no timestamp are
   excluded. Buckets are aligned to the epoch rather than to the start of the capture,
   so a bucket boundary is a multiple of `window` seconds since 1970.
2. If no bucket exists at all, return `not_applicable` with the reason that the packet
   index holds no timestamped frames and no baseline can be measured.
3. Compute the mean packet count per bucket and the **population** standard deviation
   (`statistics.pstdev`), which is 0 when there is only one bucket.
4. Compute `threshold = mean + BURST_SIGMAS * spread`.
5. A bucket is a burst when its packet count is at least `BURST_MIN_PACKETS` **and**
   strictly greater than the threshold. Both conditions must hold, so on a capture
   whose buckets are uniformly tiny nothing is ever marked, however many standard
   deviations above the mean a bucket sits.
6. The headline is the number of burst buckets across the whole capture. The timeline
   draws the earliest `TIMELINE_CAP = 240` buckets, marking those that are bursts, and
   reports `top 240 of N bucket(s)` in its note when there were more.

Because the bucket size is the only variable, the `window` a caller passes changes
the detection itself and not just its presentation: a 15-second window will mark
different buckets from a 300-second window on the same capture, and a short window
makes the `BURST_MIN_PACKETS = 20` floor harder to reach. The page sends the
default `window = 60` and no longer exposes it as a control.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `BURST_SIGMAS` | `3.0` | How many population standard deviations above the sample mean a bucket must sit. Rendered in the note as `mean + 3σ`. |
| `BURST_MIN_PACKETS` | `20` | Absolute floor: a bucket with fewer than 20 packets is never a burst, however far above the baseline it sits. |
| `TIMELINE_CAP` | `240` | Maximum buckets drawn (the earliest 240). |
| `window` | `60` (5–3600) | The bucket size, from the endpoint's query parameter. It defines the buckets, the mean, the spread and the threshold. |
| `top` | `12` (1–50) | **Not used by this detection**: there is no ranked chart. |
| `PACKET_SCAN_CAP`, `ROW_SCAN_CAP`, `TABLE_CAP`, `SCATTER_CAP` | `20000`, `500`, `50`, `200` | Not used by this detection. |

The burst query itself carries no `LIMIT`: it is a `GROUP BY` over the packet index for
the analysis. Its result is bounded by the capture's duration divided by `window`
rather than by a fixed constant, which is why the timeline cap exists at all — the
headline and the note can describe more buckets than the chart can draw.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `packets.time_epoch` | The bucket each frame falls into; frames with no timestamp are excluded. |
| `packets.number` | Not read; the count is `COUNT(*)` over the grouped rows, so every indexed frame in a bucket contributes 1. |

Nothing else is read. `packets.frame_len`, `packets.cap_len`, `packets.protocol`,
`packets.src_ip` and the rest of the packet row take no part, so the burst is a count
of frames and nothing finer.

## 6. Fields the analyst brief asks for but the index does not hold

* **Bytes per bucket.** `packets.frame_len` and `packets.cap_len` are indexed and not
  read, so the baseline is measured in frames rather than in volume. A bucket of 500
  full-size frames and a bucket of 500 acknowledgements are the same reading. This is a
  gap in the query rather than in the index, and it is the single biggest reason a
  large transfer can pass unmarked.
* **Attribution.** The burst has no address, port or protocol: the query discards
  everything except the timestamp. `packets.src_ip` and `packets.protocol` are indexed
  and could attribute a burst to a talker, but this detection does not, so the card
  cannot say what burst.
* **A baseline beyond this capture.** There is no stored profile and no cross-capture
  history, so the mean comes from this capture only. A capture that is already busy has
  a high mean and a high threshold; a capture that is uniformly quiet has a floor of 20
  packets per bucket that it may never reach.
* **`icmp.type` and other protocol detail.** Not indexed; a flood of ICMP frames is
  counted as frames like any other traffic.
* **Sub-bucket structure.** Nothing is stored per shorter interval, so with a 300-second
  window a five-second spike inside it is invisible — the only remedy is to re-run the
  endpoint with a smaller `window`.

## 7. How to investigate further

The card has no links, so the investigation starts from the time axis of the marked
bucket. A bucket starts at a multiple of `window` seconds since the epoch, and the
timeline's caption shows the clocks of the first and last buckets drawn.

| Step | Link | What to look for |
|---|---|---|
| The burst's frames | `/packets?start_time=<bucket start>&end_time=<bucket end>` | What the bucket actually contained. Both parameters accept epoch seconds or an ISO-8601 timestamp. |
| Narrowed to one talker | add `&src_ip=<host>` to the above | Which host caused the burst; the packets page accepts `ip`, `src_ip` and `dst_ip` alongside the time range. |
| Narrowed to one protocol | add `&protocol=<protocol>` | Whether the burst is a protocol the capture otherwise talks. |
| Large frames only | add `&min_length=500` | Whether the burst was real payload rather than a storm of small frames. |
| Conversations in that period | `/conversations?ip=<host>` then `tab=timeline` | Which streams were busy around the burst. |
| Exfiltration view | [`data_exfiltration`](DataExfiltration.md) and [`data_staging`](DataStaging.md) | Whether the burst coincides with a large transfer the other cards found. |
| Scanning view | [`network_scanning`](NetworkScanning.md) | Whether the burst coincides with a sweep. |

## 8. What it does not prove

A burst is not itself suspicious, and it is not even a measurement of volume. It
establishes only that one bucket of time held more frames than the rest of the capture
did, by the capture's own standard. The card's own caveat says the same thing:

> A burst is not itself suspicious. Bursty traffic is normal for web browsing, backups
> and streaming, and the baseline is this capture's own — a capture that is short or
> already busy will not show one.

## 9. Known limits and false positives

* **Ordinary bursty traffic.** Page loads, video buffering, backups, software updates
  and scheduled jobs all produce short bursts against a quiet baseline.
* **The baseline is self-referential.** Three standard deviations of a capture's own
  buckets is not a statement about normal network behaviour. A capture containing only
  a large transfer has no baseline to depart from, and a capture of almost nothing has
  a floor of 20 packets that nothing will reach.
* **Frames, not bytes.** Because `frame_len` is not summed, a burst of small frames
  outranks a steadier stream of large ones. A quiet exfiltration may never be marked.
* **Bucket size is the detection.** The `window` a caller passes changes which buckets
  are bursts; two readings of the same capture at different windows are not comparable,
  and neither is more correct than the other. The page always sends 60.
* **The floor can hide a real burst.** On a capture whose busiest bucket holds 15
  packets, no bucket can be a burst at all.
* **Structural cap.** Only the earliest `TIMELINE_CAP = 240` buckets are drawn. The
  headline counts bursts in every bucket, so on a capture longer than
  240 × `window` seconds a burst can be counted without being marked on the chart. The
  note reports the truncation as `top 240 of N bucket(s)`.
* **No links.** The reader must build the time-range link by hand; the section's own
  links do not exist for this indicator.
* **An empty card is not a flat capture.** It means no bucket held at least 20 packets
  while also exceeding the mean by more than three standard deviations — with the
  active bucket size.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [Packets](../Packets.md) · [Conversations](../Conversations.md) · [C2Beaconing](C2Beaconing.md) · [DataStaging](DataStaging.md)
