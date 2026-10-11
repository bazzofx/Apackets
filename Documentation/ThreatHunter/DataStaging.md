# Potential Data Staging (`data_staging`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is a large volume moving between two internal hosts?**

## 2. How to read the card

The headline counts *internal transfers above the threshold*: conversations between two
private addresses whose total byte count is at least `STAGING_MIN_BYTES`. It is a count
of conversations, not of host pairs and not of files.

Two visuals are drawn:

* a **timeline** of internal transfer bytes per `window`-second bucket, built from
  every internal conversation's start time and byte total, so a single large transfer
  and a steady internal flow look different;
* a **histogram** of internal transfer sizes, using the backend's own bucket labels
  (`under 10 KB`, `10-100 KB`, `100 KB-1 MB`, `1-10 MB`, `10 MB and over`) and counting
  **conversations**, not bytes. This is the shape of the whole internal picture, not
  just the part above the line, and its note reports how many internal conversations
  there were and what the threshold is.

A **high** reading is several conversations over a million bytes, especially between
hosts that do not normally exchange anything. A **low** reading is a capture whose
internal histogram is dominated by the two smallest buckets. A zero headline with
`availability: "empty"` means no internal conversation reached a million bytes; the
histogram and timeline still show the largest transfer that did happen and the reason
names it.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_data_staging(index)` in `backend/app/services/threat_hunt.py`.

1. If the conversation index holds no rows, return `not_applicable` with
   `the conversation index holds no rows for this capture`.
2. Read up to `PACKET_SCAN_CAP` conversations ordered by `bytes_total` **descending**,
   taking both addresses, the transport, stream, packet total, byte total and start
   time. Ordering by size means the largest conversations are the ones read when the
   cap bites.
3. Keep the conversations whose two addresses are **both private**, using
   `is_private_address` from `backend/app/services/host_analyzer.py`. Everything else —
   internal to public, public to internal, multicast, loopback — is discarded.
4. If nothing is left, return `empty` with the reason that the capture records no
   conversation between two private addresses, and two empty visual frames.
5. Order the surviving conversations by byte total and keep those at or above
   `STAGING_MIN_BYTES`. The headline is how many there are.
6. Build the timeline from every internal conversation's start time and byte total, and
   the histogram from every internal conversation's size, bucketed by `_STAGING_BUCKETS`.
7. Link up to five addresses, taking the source and destination of the largest
   conversations in turn.

Direction is not considered: `bytes_total` covers both directions of the conversation,
so an internal host receiving a large transfer is counted exactly like one sending it.
Nor is the protocol considered, although `conversations.protocols` records what the
stream carried.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `STAGING_MIN_BYTES` | `1_000_000` | Bytes in one internal conversation before it counts as staging. Rendered on the card as `1,000,000` (and the histogram note uses the same value). |
| `_STAGING_BUCKETS` | `(10_240, "under 10 KB")`, `(102_400, "10-100 KB")`, `(1_048_576, "100 KB-1 MB")`, `(10_485_760, "1-10 MB")`, `(inf, "10 MB and over")` | The histogram's bucket edges and labels. Note the units: these edges are binary (10,240 = 10 KiB) while the label says KB. |
| `PACKET_SCAN_CAP` | `20000` | Maximum conversation rows read, largest first. |
| `TIMELINE_CAP` | `240` | Maximum points in the timeline (the earliest 240 buckets). |
| `TABLE_CAP` | `50` | Caps the histogram at 50 buckets; there are five, so it never bites. |
| `top` | `12` (1–50) | **Not used by this detection**: there is no ranked chart, so the rows-per-visual control does nothing here. |
| `ROW_SCAN_CAP`, `SCATTER_CAP` | `500`, `200` | Not used by this detection. |

The threshold is per **conversation**, not per host pair and not per host. Two hosts
that exchanged 600,000 bytes in each of four separate conversations stay below it,
whereas one 1,000,000-byte conversation qualifies.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `conversations.ip_a`, `conversations.ip_b` | The private/private test, and the `/hosts?ip=` links. |
| `conversations.bytes_total` | The threshold test, the bar-equivalent values in the timeline, and the histogram bucket. |
| `conversations.start_time` | The timeline bucket. |
| `conversations.transport`, `conversations.stream_id` | Selected by the query and **not rendered**; there is no link to the stream from this card. |
| `conversations.packets_total` | Selected by the query and **not rendered**. |

Note that `conversations.bytes_a_to_b` and `bytes_b_to_a` — the directional counts —
are not read at all, which is why direction cannot appear on this card.

## 6. Fields the analyst brief asks for but the index does not hold

* **Direction.** The directional byte columns exist and are not read, so the card cannot
  say whether data was pushed to another host (staging outward) or pulled from one. It
  also means an internal host receiving a large download counts exactly as one
  collecting data, which is the single most important interpretive limit of this card.
* **What was transferred.** No payload column exists and no file is joined in:
  `objects` holds extracted files with sizes, source and destination, and this detection
  does not read it. A 5 MB object extracted from an internal stream and a 5 MB stream
  that produced no object are the same row.
* **The protocol.** `conversations.protocols` (for example `http,smb`) is indexed and
  unread, so a backup, a file share copy and an archive upload cannot be told apart.
* **A per-pair aggregate.** The unit is the conversation, and there is no host-pair
  roll-up, so a slow drip stage across many small conversations is invisible.
* **A baseline or expected volume.** There is no record of how much these two hosts
  normally exchange, and no cross-capture history; a million bytes is judged against a
  constant.
* **A time window for staging.** The threshold has no time component, so bytes spread
  over an hour and bytes in ten seconds are equivalent.
* **Host roles.** `hosts.is_private` is implied by the address test, but nothing records
  whether a host is a file server or a workstation, which is what would make the
  transfer unremarkable or not.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The two hosts | `/hosts?ip=<host>&view=inventory` | Whether the pair is a file server and a workstation, or two workstations that never otherwise speak. |
| The conversations | `/conversations?ip=<host>` | Which streams carry the volume and, in the directional columns, which way it moved. |
| The stream itself | `/conversations?stream=<transport>:<stream_id>` | The reassembled bytes, where the protocol is not encrypted, and the `smode` control for a hex or raw view. |
| The frames | `/packets?ip=<host>&min_length=500` | Whether the volume is real payload rather than many small frames. |
| What was extracted | `/objects` | Whether the analysis pulled a file out of this traffic, which is the strongest available evidence about what moved. |
| The outbound side | [`data_exfiltration`](DataExfiltration.md) and [`unusual_egress`](UnusualEgress.md) | Whether the same host then sent the same volume outside, which is the sequence staging is supposed to precede. |
| The inbound side | [`malware_download`](PossibleMalwareDownload.md) | Whether the large transfer was incoming, which is what an empty staging card with a busy download card usually means. |

## 8. What it does not prove

Internal bulk transfer does not establish staging. It establishes that two private
addresses exchanged at least a million bytes in one conversation, which is what file
servers, backups and media shares do constantly. The card's own caveat says the same
thing:

> Internal bulk transfer does not establish staging. File servers, backups, imaging,
> virtual-machine migration and media shares move far more data than this threshold
> between internal hosts every day.

## 9. Known limits and false positives

* **File servers and backups.** Any SMB or NFS share, any backup job and any imaging or
  virtual-machine migration moves far more than a million bytes between internal hosts.
  On an enterprise capture this card is expected to be `ok` for entirely ordinary
  reasons.
* **A structural blind spot: inbound bulk traffic.** Because direction is not
  considered and `bytes_total` is used, this card cannot be read as "data being
  collected". On the lab captures used during development it is typically `empty`
  because their bulk transfer is *inbound* to internal hosts and is better explained by
  [`malware_download`](PossibleMalwareDownload.md). An empty staging card beside a busy
  download card is that pattern, not a contradiction.
* **The unit is the conversation.** A pair exchanging a large volume in many small
  conversations is not counted, and a single large conversation between hosts that talk
  constantly is.
* **Encrypted transfers.** A large TLS session between internal hosts is a byte count
  with no content, so "what was staged" cannot be answered from this card.
* **Ordering and cap.** The query takes the largest `PACKET_SCAN_CAP = 20000`
  conversations, which is the right end of the distribution for this detection, but
  means a capture with more than 20,000 conversations is measured against its own
  largest ones only.
* **Timeline truncation.** Only the earliest `TIMELINE_CAP = 240` buckets are drawn, so a
  late transfer counts in the headline and the histogram but may not appear on the line.
  The note reports `top 240 of N bucket(s)`.
* **Histogram units.** The bucket edges are binary sizes (10,240; 102,400; 1,048,576;
  10,485,760) labelled as KB and MB, so the boundaries sit slightly above the decimal
  values a reader will assume.
* **`top` does nothing here.** Reducing rows per visual will not change this card.
* **An empty card is not a quiet internal network.** It means no single conversation
  between two private addresses carried a million bytes.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Conversations](../Conversations.md) · [Hosts](../Hosts.md) · [DataExfiltration](DataExfiltration.md) · [UnusualEgress](UnusualEgress.md)
