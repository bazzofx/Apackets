# Potential Data Exfiltration (`data_exfiltration`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is an internal host sending more to a public peer than its traffic explains?**

## 2. How to read the card

The headline counts *internal-to-public destinations above the threshold*: pairs of
(a private source address, a public destination address) where the bytes the private
address **sent** to that destination cross either the absolute floor or a threshold
relative to the capture's own median. It is a count of address pairs, not of hosts
and not of transfers.

Two visuals are drawn:

* **bars** of outbound volume by destination — one bar per destination address, in
  bytes, labelled with the destination and the number of packets sent in that
  direction. The bar chart is drawn for the largest destinations in the capture
  whether or not they crossed the threshold, so a capture with nothing above the
  line still shows what the biggest transfers were. Its note states the two
  thresholds and the median they were derived from;
* a **timeline** of outbound bytes per `window`-second bucket, so a single large
  transfer and a steady trickle over the whole capture look different.

A **high** reading is one or more destinations with a large bar relative to the rest,
combined with a timeline that shows the volume arriving in one or two buckets. A
**low** reading is a flat set of small bars, which is what a normal capture of web
traffic looks like. A zero headline with `availability: "empty"` means no pair
crossed either threshold: the reason names the largest observed transfer, and the
bars and timeline are still drawn.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_data_exfiltration(index)` with the helper `_outbound_pairs(analysis_id)`
in `backend/app/services/threat_hunt.py`.

1. If the conversation index holds no rows, return `not_applicable` with
   `the conversation index holds no rows for this capture`.
2. `_outbound_pairs` reads up to `PACKET_SCAN_CAP` conversation rows and decides the
   direction of each one from its endpoints:
   * if `ip_a` is private and `ip_b` is a public unicast address, the pair is
     (`ip_a`, `ip_b`) and the *sent* bytes are `bytes_a_to_b`;
   * if `ip_b` is private and `ip_a` is a public unicast address, the pair is
     (`ip_b`, `ip_a`) and the *sent* bytes are `bytes_b_to_a`;
   * anything else — private to private, public to public, or a multicast,
     broadcast or loopback address on either side — is discarded.
3. Accumulate per pair: bytes sent, bytes received, packets in the sent direction,
   the number of conversations, and the earliest `start_time` seen.
4. If no pair survived, return `empty` with the reason about there being no
   private-to-public conversation, and empty visuals.
5. Take the median of all pairs' sent volumes and compute
   `relative_floor = max(EXFIL_RELATIVE_BYTES, median * EXFIL_RELATIVE_FACTOR)`.
6. A pair is a candidate when its sent volume is at least `EXFIL_MIN_BYTES` **or** at
   least the relative floor. The two tests are alternatives.
7. Rank candidates by sent volume; the headline is how many there are. The bars chart
   ranks all pairs (not only candidates) by sent volume and takes the first `top`.

Two things this detection deliberately does not do: it does not aggregate a host's
sending across destinations, and it does not consider the protocol, the port, or
whether the destination is one the host has ever used before.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `EXFIL_MIN_BYTES` | `1_000_000` | Absolute floor: one million bytes sent from a private address to one public address makes that pair a candidate. Rendered on the card as `1,000,000`. |
| `EXFIL_RELATIVE_BYTES` | `100_000` | Lower bound of the relative floor, so a capture whose median is tiny cannot set a threshold of a few kilobytes. |
| `EXFIL_RELATIVE_FACTOR` | `10` | Multiplier applied to the median sent volume of all internal-to-public pairs; the floor is the larger of this product and `EXFIL_RELATIVE_BYTES`. |
| `PACKET_SCAN_CAP` | `20000` | Maximum conversation rows read by `_outbound_pairs`. |
| `TIMELINE_CAP` | `240` | Maximum points in the byte timeline; the earliest 240 buckets are drawn, and the note says `top 240 of N` if more existed. |
| `top` | `12` (1–50) | Bars in the volume chart; number of links. |
| `ROW_SCAN_CAP` | `500` | Not used by this detection. |
| `TABLE_CAP` | `50` | Not used by this detection. |

Note the deliberate difference from the detection engine: `docs/CONTRACT.md` §8
defines the `outbound_volume` rule as ≥50 MB from one host, or ≥10× the median
**sender**. This detection uses a 1 MB absolute floor and 10× the median
**destination pair**. The two use the same factor and disagree by a factor of fifty
on the absolute floor, so a capture can produce an `outbound_volume` finding with no
`data_exfiltration` candidate underneath it.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `conversations.ip_a`, `conversations.ip_b` | The endpoints of each conversation; the direction decision and the pair key. |
| `conversations.bytes_a_to_b`, `conversations.bytes_b_to_a` | The sent and received volumes; only the direction from the private address counts towards the threshold. |
| `conversations.packets_a_to_b`, `conversations.packets_b_to_a` | The word `pkt` in each bar label. |
| `conversations.start_time` | The bucket each pair is placed in for the timeline; the earliest of a pair's conversations wins. |
| `conversations.stream_id`, `conversations.transport` | Read into the pair record but not rendered on the card. |

The private/public decision is not made here: `is_private_address` and
`address_scope` from `backend/app/services/host_analyzer.py` are reused so the
section cannot drift from the rest of the app.

## 6. Fields the analyst brief asks for but the index does not hold

* **Direction of the payload beyond byte totals.** The index holds
  `bytes_a_to_b`/`bytes_b_to_a` per conversation, which is what makes direction
  possible at all, but nothing below that: there is no per-packet payload size
  column for a specific transfer, and `packets.frame_len` includes headers.
  Retransmissions are counted, so a lossy transfer inflates its own number.
* **`http.request_in` / `response_in`.** There is no column linking an HTTP
  transaction to the frame that carried it beyond
  `http_transactions.request_packet` and `response_packet`, and this detection does
  not read the HTTP index at all. It therefore cannot say what was uploaded: no file
  name, no URI, no content type, no status code. Uploading a 5 MB PDF and downloading
  a 5 MB video look identical here except for direction.
* **TLS plaintext.** Nothing is decrypted, so a transfer inside a TLS session is a
  byte count and nothing more. `tls_sessions.sni` exists, but the conversation is not
  joined to the TLS session to give the destination a name on this card.
* **Application identity.** `conversations.protocols` (a comma-separated list such as
  `http,tls`) is indexed and is not read, so a bulk transfer cannot be labelled as a
  backup, an upload or a video call from this card alone.
* **A per-host baseline.** There is no column holding how much this host usually
  sends, and no cross-capture history; the relative threshold is computed against
  the median of *all* pairs in the same capture, which one very large transfer can
  drag upwards.
* **Objects transferred.** The `objects` table holds extracted files with sizes and
  endpoints, but only the malware-download detection consults it, so an extraction
  that produced a 2 MB object does not appear as evidence here.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The conversations to that destination | `/conversations?ip=<peer>` | Directional byte counts per stream: whether one stream carries the volume or many small ones do. |
| One stream in full | `/conversations?stream=<transport>:<stream_id>` | The reassembled bytes, where the protocol is not encrypted. |
| The peer's view | `/hosts?ip=<peer>&view=inventory` | Everything exchanged with that address, not just the one pair. |
| Is it a named service | `/tls?ip=<peer>`, `/http?server_ip=<peer>` | Whether the destination is a known cloud service, backup target or upload endpoint. |
| Was there a name | `/dns?domain=<name>` and `/hosts?ip=<peer>` | Whether the destination was resolved by this capture, or reached by bare address. |
| The sending host | `/hosts?ip=<source>` | What else it sends and to how many peers; a workstation that talks to nothing else is a different case from a backup server. |
| The frames | `/packets?ip=<peer>&transport=tcp` | The shape of the transfer: many full-size frames in one direction is a bulk send. |

## 8. What it does not prove

Volume does not establish exfiltration. It establishes that a private address sent a
quantity of bytes to a public address, which is what backups, uploads, mail, video
calls and software distribution do as a matter of routine. Nothing here shows what
the bytes were, whether anyone asked for them, or whether the destination is
hostile. The card's own caveat says the same thing:

> Volume does not establish exfiltration. Backups, uploads to cloud services, mail
> attachments and video calls move the same volumes with no malicious intent, and
> bytes counted here include retransmissions and headers.

## 9. Known limits and false positives

* **Backups and cloud sync.** Any workstation with OneDrive, Dropbox, iCloud or a
  backup agent will cross this threshold, repeatedly and legitimately.
* **Mail attachments and file uploads.** A single 5 MB attachment is five times the
  absolute floor. The bars chart cannot tell it from an archive being shipped out.
* **Video calls and streaming.** Large sustained outbound volume is normal for
  conferencing, and shows as one long bar and a broad timeline.
* **A structural blind spot: inbound bulk traffic is invisible here.** Only bytes
  sent *from* a private address *to* a public one are counted. On the lab captures
  used during development, this indicator is typically `empty` because the bulk
  transfer in those captures runs the other way — public server to internal host —
  and therefore surfaces as [`malware_download`](PossibleMalwareDownload.md) instead.
  That is a correct answer about those captures, not a defect, and it is the single
  most likely reason for an empty card on a download-heavy capture.
* **The relative floor is capture-wide.** The median is taken over all
  internal-to-public pairs, so a capture dominated by one huge transfer raises the
  threshold for everything else, and a capture of uniformly small pairs lowers it
  towards the `EXFIL_RELATIVE_BYTES` floor of 100,000 bytes.
* **The unit is a pair, not a host.** A host exfiltrating 400 KB to eight
  destinations may stay under `EXFIL_MIN_BYTES` for every individual pair; it is
  caught only if the relative floor works out at or below 400 KB.
* **Caps.** At most `PACKET_SCAN_CAP = 20000` conversation rows are read, and only
  the earliest `TIMELINE_CAP = 240` buckets are drawn, so on a long capture a late
  transfer is counted in the headline but may fall outside the drawn timeline.
* **An empty card is not a quiet host.** It means no private-to-public pair sent
  one million bytes, and none sent ten times the capture's median pair volume (with a
  100,000-byte floor).

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Conversations](../Conversations.md) · [Hosts](../Hosts.md) · [UnusualEgress](UnusualEgress.md) · [DataStaging](DataStaging.md)
