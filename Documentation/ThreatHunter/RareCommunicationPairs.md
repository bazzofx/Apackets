# Rare Communication Pairs (`rare_pairs`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Which address pairs appear in a single, tiny exchange?**

## 2. How to read the card

The headline counts *rare address pairs*: pairs of addresses that appear in exactly
one conversation in the whole capture, and that conversation carried at most
`RARE_PAIR_MAX_PACKETS` packets. It is a count of address pairs.

One visual is drawn: a **table** of those pairs, capped at `TABLE_CAP = 50` rows and
ordered by the first address of each pair. Columns: the pair itself
(`a ↔ b`, linked to the conversations page for the first address), the transport, the
packet count (linked to the frames for the first address), the total bytes, and the
scope of each address (`private`, `public`, `multicast`, `broadcast`, `loopback` or
`unknown`).

The scope column is the useful one: a `public / public` pair of one packet is usually
background noise, a `private / public` pair is a client that tried something once, and
a `private / private` pair is an internal host that spoke to another host exactly once
— which is worth understanding. A **high** reading is a long table, which on most
captures means lots of short-lived outbound connections rather than anything
suspicious. A **low** reading is a handful of rows and is easier to read properly.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_rare_pairs(index)` in `backend/app/services/threat_hunt.py`.

1. If the conversation index holds no rows, return `not_applicable` with
   `the conversation index holds no rows for this capture`.
2. Read up to `PACKET_SCAN_CAP` conversations in `start_time` order, taking both
   addresses, the transport, the stream, the packet and byte totals, the start time
   and the state.
3. Group conversations into pairs by the **sorted** pair of addresses. Ports and
   transport are part of neither the key nor the test: two conversations between the
   same two addresses on different ports are one pair with two conversations, and
   therefore not rare.
4. Sum the packets and bytes, and count the conversations, per pair. The first
   conversation seen for a pair supplies the row that is displayed.
5. Keep a pair when it has exactly one conversation **and** that conversation's packet
   total is at most `RARE_PAIR_MAX_PACKETS`. It is a conjunction: both tests must
   hold.
6. Order pairs by their first address and then their second, and draw the first
   `TABLE_CAP = 50`. The headline is the total number of rare pairs, which may exceed
   the number of rows drawn.
7. Link up to five addresses from the rare pairs.

The helper `_scope_label(value)` turns an address into its scope word using
`address_scope` from `backend/app/services/host_analyzer.py`, so the wording matches
the rest of the app.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `RARE_PAIR_MAX_PACKETS` | `2` | Maximum packets in the single conversation for a pair to count as rare. Rendered on the card as "at most 2 packets". |
| `PACKET_SCAN_CAP` | `20000` | Maximum conversation rows read. |
| `TABLE_CAP` | `50` | Maximum rows in the table. |
| `top` | `12` (1–50) | **Not used by this detection**: there is no ranked chart, so the rows-per-visual control does nothing on this card. |
| `ROW_SCAN_CAP`, `TIMELINE_CAP`, `SCATTER_CAP` | `500`, `240`, `200` | Not used by this detection. |

The "exactly one conversation" test is written as
`entry["conversations"] == 1`, which is an equality rather than a threshold: a pair
with two conversations of one packet each is not rare, however small they are.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `conversations.ip_a`, `conversations.ip_b` | The pair key (sorted), the pair label, and the links. |
| `conversations.packets_total` | Summed per pair and tested against `RARE_PAIR_MAX_PACKETS`. |
| `conversations.bytes_total` | Summed per pair and shown in the bytes column. |
| `conversations.transport` | The transport column, taken from the first conversation of the pair. |
| `conversations.start_time` | The query's ordering, which decides which conversation for a pair is displayed as the row. |
| `conversations.conv_id` | Tie-break ordering of the query. |
| `conversations.stream_id`, `conversations.state` | Selected by the query and **not rendered**: the table shows neither the stream nor the conversation state. |

The pair's ports are not read from `conversations.port_a`/`port_b` at all, so the
table cannot show which port a rare exchange used.

## 6. Fields the analyst brief asks for but the index does not hold

* **What was exchanged.** No payload column exists, so "a tiny exchange" is a packet
  count and nothing more. The detection cannot tell a TCP SYN that was ignored from a
  DHCP request from a DNS query from an ARP-like announcement. The reader has to open
  the frames.
* **The port.** `conversations.port_a` and `conversations.port_b` are indexed and are
  not read by this detection, so the row is ports-blind even though the data is
  there. That is a gap in the query, not in the index.
* **The direction.** `packets_a_to_b`/`packets_b_to_a` are indexed and not read, so
  the table does not say who initiated.
* **The conversation state.** `conversations.state` is indexed and read into the row
  and never shown, so `half_open` (attempted, never established) is not visible — and
  that is the state that would make a rare pair interesting.
* **A time reference.** The row shows no timestamp, although `start_time` selected the
  row, so a rare pair cannot be placed in the capture's timeline from the card.
* **Sub-second detail.** `conversations.duration` and `end_time` exist and are not
  read.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The pair's conversations | `/conversations?ip=<first address>` | The one conversation, its stream, its state and its byte balance. |
| Its frames | `/packets?ip=<first address>` | What the exchange actually was: flags, sizes, ports, and whether anything came back. |
| The other side | `/hosts?ip=<second address>` | Whether that address is a server, a peer, or something the capture saw only once. |
| If it was a name lookup | `/dns?client_ip=<first address>` | A one-packet pair is often a DNS query whose reply never arrived. |
| If it was HTTP | `/http?client_ip=<first address>` | Whether a request was attempted and what came back. |
| The conversation list around it | `/conversations?ip=<first address>&tab=timeline` | Whether this was the only exchange or the one that failed among many. |

## 8. What it does not prove

A rare pair is not evidence of anything. It establishes that two addresses exchanged
one very small conversation inside this capture's window. The card's own caveat says
the same thing:

> A rare pair is not evidence of anything. Discovery protocols, NTP, DHCP, health
> checks and failed name lookups produce one-packet pairs constantly, and a pair can
> only be rare within the window this capture covers.

## 9. Known limits and false positives

* **Discovery and broadcast protocols.** mDNS, SSDP, LLMNR, NetBIOS name service, DHCP
  and ARP-adjacent chatter produce one- or two-packet pairs continuously; the scope
  column will often read `multicast` or `broadcast` for exactly these.
* **Health checks and keep-alives.** A load balancer's check and a client's first
  packet that went nowhere both appear here.
* **Outbound internet noise.** Any capture with real internet traffic contains
  thousands of short exchanges to CDN and advertising addresses, which is why the
  table is capped and why the scope column matters.
* **Captures that start mid-transfer.** A pair whose other conversations happened
  before the capture began looks rare. This is the most common false positive and no
  filter can remove it.
* **Ports and transport are ignored in the key.** A pair that spoke on three ports in
  three conversations is one pair with three conversations and is not rare, even
  though each exchange was tiny.
* **Structural cap and ordering.** The query takes the earliest `PACKET_SCAN_CAP =
  20000` conversations by `start_time`, so on a very large capture later pairs are not
  examined at all, and the table shows only the first `TABLE_CAP = 50` pairs in
  address order — which is not the "top 50 of anything" and may look arbitrary.
* **`top` does nothing here.** Reducing rows per visual will not shorten this table.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Conversations](../Conversations.md) · [Hosts](../Hosts.md) · [HighFanOut](HighFanOut.md) · [LateralMovement](LateralMovement.md)
