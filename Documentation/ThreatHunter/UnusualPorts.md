# Unusual Port Usage (`unusual_ports`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Which destination ports fall outside the capture's ordinary service set?**

## 2. How to read the card

The headline counts *single-use destination ports outside the common service set*:
destination ports not in the detection engine's `COMMON_PORTS` list that appear in
exactly one packet in the whole capture. It is a count of ports, not of packets and
not of hosts.

One visual is drawn: **bars** of destination ports outside the common service set,
ranked by **packet count** — which is not the same thing the headline counts. The
chart shows the *busiest* uncommon ports (the ones the capture actually uses);
the headline counts the *rarest* ones (used exactly once, which the caveat argues is
usually an ephemeral reply port rather than a service). Read the chart for what the
capture does and the headline for what the capture barely touched. If the chart has
rows and the headline is low, that is the normal shape; both are drawn from the same
port set but ranked for different questions.

A **high** reading is a large number of single-use uncommon ports, which usually
means a lot of short-lived connections on dynamic ports rather than many strange
services. A **low** reading is a capture dominated by the well-known ports. A zero
headline with `availability: "empty"` means no uncommon port was used exactly once;
the chart still shows the uncommon ports that were used more than once, and the
reason states how many uncommon ports were observed in total.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_unusual_ports(index)` in `backend/app/services/threat_hunt.py`.

1. If the packet index holds no rows, return `not_applicable` with
   `the packet index holds no rows for this capture`.
2. Group the packet index by `dst_port` (ignoring frames with no destination port and
   **not** filtering by transport), counting packets and distinct source addresses
   per port. The query is ordered by packet count descending and takes at most
   `ROW_SCAN_CAP * 4` port groups.
3. Discard every port that is present in `COMMON_PORTS`, the detection engine's own
   well-known list, so that this detection cannot drift from the findings beside it.
4. Split the survivors: `uncommon` is everything left, and `single_use` is the
   uncommon ports whose total packet count is exactly 1.
5. The headline is the length of `single_use`. The bars chart draws the first `top`
   of `uncommon` ordered by packet count, and the links name up to five single-use
   ports.
6. Order `single_use` by port number, so the links are stable.

There is no notion of a service, an owner or a port range: a port is judged only by
whether it is in the common list and how often it was seen. Direction is not
considered, so a client's ephemeral source port, seen as the destination port of the
server's reply, is counted as a destination port like any other.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `COMMON_PORTS` | **112** ports, imported from `backend/app/services/detection_engine.py` | The well-known list. A destination port in it is never "uncommon". The same set is used by the `rare_destination_port` rule in `docs/CONTRACT.md` §8. |
| `ROW_SCAN_CAP` | `500` | Multiplied by four for this detection's port query, giving a limit of `2000` port groups ordered by packet count. |
| `ROW_SCAN_CAP * 4` | `2000` | The actual `LIMIT` on distinct destination ports examined. |
| `top` | `12` (1–50) | Bars in the chart; the first `top` busiest uncommon ports. |
| `TABLE_CAP`, `TIMELINE_CAP`, `SCATTER_CAP`, `PACKET_SCAN_CAP` | `50`, `240`, `200`, `20000` | Not used by this detection. |

The single-use test is `COUNT(*) == 1` on the grouped packet count: exactly one frame
in the capture had that destination port. There is no configurable threshold and no
minimum source count, so a single frame from a single host is enough to make a port
count.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `packets.dst_port` | The grouping key, the common-list test, the bar label (`port N`) and the `/packets?dst_port=` link. |
| `packets.src_ip` | Read as `COUNT(DISTINCT src_ip)` for each port and then **never used**. No count of distinct sources appears on the card. |

Nothing else is read. In particular `packets.transport`, `packets.protocol` and the
frame timestamps take no part in this detection, so TCP and UDP ports are pooled and
no time dimension exists.

## 6. Fields the analyst brief asks for but the index does not hold

* **Service names.** There is no `tcp.port`/`udp.port` service-name column and no
  port-to-application mapping in the index, so a row is a number. The mapping the
  card does have is the fixed `COMMON_PORTS` set, which only answers "common or not".
* **Direction of the connection.** The packet index has no session role column
  beyond `tcp_stream`/`udp_stream` and `conversations.endpoint_a`, and this detection
  reads neither. A single-use high-numbered destination port is therefore, as the
  caveat says, usually a client's own ephemeral port seen in the server's reply —
  and the detection cannot tell the two apart from `dst_port` alone.
* **`tcp.flags` as a filter.** The flags are indexed (`tcp_flags_raw`) and not read
  here, so a mid-stream frame's port is counted exactly like a connection's.
* **Application protocol.** `packets.protocol` (`TCP`, `HTTP`, `DNS`) is indexed and
  not read. A port carrying HTTP is not labelled as such.
* **Port ranges.** No column records a configured port range, and there is no notion
  of an ephemeral range (the 112-port common list includes `49152` and `49153` but not
  the surrounding range), so "outside the common set" is a fixed-list test and not a
  range test.
* **Payload and banners.** No payload is inspected, so an unusual port cannot be
  identified by what answered on it.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The frames on that port | `/packets?dst_port=<port>` | How many frames, what transport, and whether they are one connection or many. |
| With a source filter | `/packets?src_ip=<host>&dst_port=<port>` | Which host used it, which turns a number into a candidate. |
| The conversations | `/conversations?port=<port>` | Whether the port belongs to a stream with real payload in both directions, or a single stray frame. |
| The host using it | `/hosts?ip=<host>` | Whether the host is a client with many ephemeral ports or a server offering an unusual service. |
| Both endpoints at once | `/packets?ip=<host>&port=<port>` | Every frame involving that host and port together. |
| What the capture makes of the protocol | `/packets?protocol=<protocol>&dst_port=<port>` | Whether TShark dissected an application protocol on that port, which is stronger than the port number alone. |

## 8. What it does not prove

An uncommon port is not a malicious port. It establishes that a destination port is
outside a fixed list of well-known ports and was used rarely or once. The card's own
caveat says the same thing:

> An uncommon port is not a malicious port. A single-use high-numbered destination
> port is usually a client's own ephemeral port seen in a server-to-client reply, and
> peers, games and appliances use fixed non-standard ports legitimately.

## 9. Known limits and false positives

* **Ephemeral reply ports.** This is the dominant source of single-use entries: the
  server's reply has the client's dynamic port as its destination. On a capture of
  ordinary internet traffic the headline is effectively a count of short-lived
  connections.
* **Consumers of the same list.** The detection engine's `rare_destination_port` rule
  uses `COMMON_PORTS` too, so the two agree; a port absent from the list shows up in
  both places.
* **Legitimate non-standard services.** Peer-to-peer clients, games, voice and video
  platforms, appliances, printers and management agents all use fixed high ports that
  are not in the common list.
* **The chart and the headline answer different questions.** The bars rank by volume
  and the headline counts single-use ports, so a card can show a loud chart with a
  zero headline or the reverse. Neither number is a verdict on its own.
* **Structural cap that hits the headline exactly.** The port query is ordered by
  packet count descending and limited to `ROW_SCAN_CAP * 4 = 2000` groups. On a
  capture with more than 2000 distinct destination ports, the groups beyond the 2000
  busiest are never returned — and those are precisely the single-use ports the
  headline counts. On such a capture the headline is an undercount of an unknown
  size, and nothing on the card says so.
* **TCP and UDP are pooled.** A UDP source port and a TCP source port with the same
  number are the same row.
* **An empty card is not a tidy capture.** It means no destination port outside the
  112-port common list was seen exactly once, and the reason reports how many uncommon
  ports there were in total.
