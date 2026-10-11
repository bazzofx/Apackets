# Repeated Failed Connections (`failed_connections`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**What is repeatedly trying to connect and never being answered?**

## 2. How to read the card

The headline counts *destinations with repeated unanswered attempts*: pairs of
(internal or any source, destination) where the source sent at least
`FAILED_MIN_ATTEMPTS` connection attempts to that destination and every one of them
went unanswered. The count is per (source, destination) pair, summed across all
destination ports. `top` ranks those pairs and the card's links name the first five of
them; there is no table on this card.

Two visuals are drawn:

* a **timeline** of unanswered connection attempts per `window`-second bucket, with the
  buckets that contain a repeatedly-failed flow marked. The marks are placed using the
  attempts of one (source, destination, port) flow, so a pair that reached the
  threshold only by summing across ports can count in the headline without marking the
  chart;
* **bars** of unanswered attempts by destination port, one bar per port, ranked by
  attempt count and linked to `/packets?dst_port=<port>`. This is the most useful chart
  on the card: a single port at the top nearly always means one client retrying one
  service, while a spread of ports means something else.

A **high** reading is many destinations with unanswered attempts, or a large bar on one
port. A **low** reading is one destination, which is usually a client whose server is
down. A zero headline with `availability: "empty"` means no source reached ten
unanswered attempts to any one destination; the reason reports the total number of
unanswered attempts in the capture, which is the useful number in that case.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_failed_connections(index)` in `backend/app/services/threat_hunt.py`,
as one SQL statement with two common table expressions.

1. If the packet index holds no rows, return `not_applicable` with
   `the packet index holds no rows for this capture`; if it holds no TCP frames, return
   `not_applicable` with `the packet index holds no TCP frames for this capture`.
2. Build the **attempts** set: TCP frames with both addresses and a destination port
   where the SYN bit is set and the ACK bit is clear
   (`(tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 0`). This is a first connection
   attempt, not a mid-stream frame.
3. Build the **answered** set: distinct (server address, client address, server port)
   triples taken from frames where both SYN and ACK are set
   (`(tcp_flags_raw & 18) = 18`) — that is, a SYN/ACK travelling from the destination
   back to the source, on the port that was attempted.
4. Left-join attempts to answered on exactly those three fields and keep the attempts
   that found no match, grouped by `(source, destination, port)`, with the attempt count,
   first frame number and first timestamp. The query takes the `ROW_SCAN_CAP` busiest
   flows.
5. Sum each flow's attempts into a per `(source, destination)` total, and keep the pairs
   whose total is at least `FAILED_MIN_ATTEMPTS`. The headline is how many there are, and
   the card's links name the first five of the `top`-ranked destinations.
6. Build the timeline from every flow's first timestamp and attempt count, marking the
   buckets that contain a flow with at least `FAILED_MIN_ATTEMPTS` attempts of its own.
7. Build the port bars by summing attempts per destination port across all flows, taking
   the first `top` ports.

Two consequences of this construction matter. Only a SYN/ACK counts as an answer, so a
destination that responds with RST is recorded as unanswered. And because "answered" is
a set built from the whole capture, a single SYN/ACK anywhere in the capture clears every
attempt to that destination and port, so a capture that spans a service going down and
coming back up reports the port as answered.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `FAILED_MIN_ATTEMPTS` | `10` | Unanswered attempts from one source to one destination before the pair is counted. Matches the `repeated_failed_connections` rule in `docs/CONTRACT.md` §8. |
| `ROW_SCAN_CAP` | `500` | Maximum `(source, destination, port)` flows read, busiest first. |
| `top` | `12` (1–50) | Bars in the port chart; number of destination links. |
| `TIMELINE_CAP` | `240` | Maximum points in the timeline (the earliest 240 buckets). |
| `PACKET_SCAN_CAP`, `TABLE_CAP`, `SCATTER_CAP` | `20000`, `50`, `200` | Not used by this detection. |

The bitmasks are literals in the query rather than named constants: `2` is SYN, `16` is
ACK, and `18` is their combination for the answered test. `detection_engine.py` names the
same two bits `TCP_SYN = 0x02` and `TCP_ACK = 0x10`.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `packets.src_ip`, `packets.dst_ip` | The attempt's endpoints; the answered-set join is on the same two fields in reverse roles. |
| `packets.dst_port` | The attempted port, the join key back through the server's `src_port`, the grouping key and the port bars. |
| `packets.src_port` | The server side of an answer: a SYN/ACK from the destination must carry this port to clear the attempt. |
| `packets.tcp_flags_raw` | Both bitwise tests (SYN-without-ACK for attempts, SYN+ACK for answers). |
| `packets.number` | The first frame number of a flow, read as `MIN(number)` and not rendered. |
| `packets.time_epoch` | The timeline bucket, read as `MIN(time_epoch)` per flow. |
| `packets.transport` | Restricts both parts of the query to `transport = 'tcp'`. |

## 6. Fields the analyst brief asks for but the index does not hold

* **`icmp.type`.** There is no ICMP column in the index and no ICMP correlation in this
  detection, so a destination that answered every attempt with an ICMP
  port-unreachable — which is a definitive answer — is recorded here as unanswered.
  This is the largest single over-count in the detection.
* **RST as a reply.** The RST bit is present in `tcp_flags_raw` and the detection does
  not test it, so an actively refused connection and a silently dropped one are
  indistinguishable. The card's caveat talks about a firewall "silently dropping" a
  port, but the data cannot actually tell that from a host refusing it.
* **Why the attempt failed.** Nothing distinguishes "no route", "host up, port closed",
  "filtered" or "server overloaded". `packets.ttl`, `ip_id` and the TCP option fields
  are indexed and unread; there is no ICMP and no route information.
* **Application-level failure.** A TCP connection that opens and then fails is not a
  failed connection here. An HTTP 500, a TLS alert and a refused authentication are all
  successes as far as this detection is concerned, even though
  [`suspicious_http`](SuspiciousHttp.md) and [`suspicious_tls`](SuspiciousTls.md) may
  show them.
* **Retry timing.** The index holds no per-attempt interval and the detection does not
  use one: a client retrying every second for ten seconds and one retrying every ten
  minutes for an hour produce the same count. `retries` and `tcp.analysis.retransmission`
  are not indexed.
* **Capture coverage.** There is no column saying whether the capture was complete, and
  none of the reasoning accounts for it. A capture that starts after a SYN/ACK, or that
  was filtered to one direction, will manufacture unanswered attempts that were in fact
  answered outside the capture window.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The destination | `/hosts?ip=<destination>` | Whether the address exists elsewhere in the capture — a destination that appears only as the target of unanswered attempts is the strongest form of this lead. |
| The attempts themselves | `/packets?dst_port=<port>` | The frames, their spread over time, and whether anything ever came back. |
| One source to one destination | `/packets?src_ip=<source>&dst_ip=<destination>` | The full retry pattern, with flags visible on each frame. |
| The port in context | `/conversations?port=<port>` | Whether any conversation ever opened on that port, which contradicts the "never answered" claim. |
| The client | `/hosts?ip=<source>` | Whether the source is a workstation whose controller should exist. |
| Whether anything answered later | `/packets?ip=<destination>&transport=tcp` | A SYN/ACK late in the capture clears the destination for the whole run, so check the tail. |
| Compare with the scanner | [`network_scanning`](NetworkScanning.md) | A source with many unanswered attempts to one destination and a wide port spread is a sweep, not a client hunting a controller. |

## 8. What it does not prove

Unanswered attempts do not establish malicious intent. They establish that a source sent
at least ten connection attempts to one destination that the capture never saw answered.
The card's own caveat says the same thing:

> Unanswered attempts do not establish malicious intent. The destination may be offline,
> blocked by policy, or answering outside the capture's window, and retries are also what
> a misconfigured client does.

## 9. Known limits and false positives

* **Servers that are simply down.** A client retrying an offline service, a decommissioned
  host, a superseded address and a cloud endpoint that moved all produce this pattern.
* **Blocked destinations by policy.** An egress firewall that drops rather than rejects
  produces unanswered attempts by design.
* **Captures that are partial.** A filtered, one-directional or time-limited capture
  manufactures this pattern: if the SYN/ACK was not captured, the attempt is unanswered.
  This is the most common cause of a false positive here and nothing on the card can
  detect it.
* **Port scans.** A sweep across many ports is counted as unanswered attempts on each
  port; the per-destination total will cross ten quickly. Read together with
  [`network_scanning`](NetworkScanning.md), which is the same traffic seen as a scan.
* **Monitoring and discovery.** Health probes against hosts that no longer exist, and
  discovery tools probing unused addresses, both generate steady unanswered traffic.
* **RST-based refusals count as failures.** Because only SYN/ACK clears an attempt, a
  host that actively refuses connections appears as unanswered and is indistinguishable
  from one that is silent.
* **The marks and the headline group differently.** The timeline is marked from
  per-(source, destination, port) flows and the headline counts per-(source, destination)
  totals, so a pair that reached ten attempts by summing across three ports can be
  counted without any marked bucket.
* **One SYN/ACK clears everything.** `answered` is a set over the whole capture, so a
  single SYN/ACK at any time removes every attempt to that destination and port from the
  analysis.
* **Structural cap.** At most `ROW_SCAN_CAP = 500` flows are read, busiest first, so on a
  busy capture the quietest failure patterns are not examined.
* **An empty card is not a healthy network.** It means no source reached ten unanswered
  attempts against one destination; the reason reports the total number of unanswered
  attempts, which may still be large when spread thinly.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Packets](../Packets.md) · [Conversations](../Conversations.md) · [NetworkScanning](NetworkScanning.md) · [LateralMovement](LateralMovement.md)
