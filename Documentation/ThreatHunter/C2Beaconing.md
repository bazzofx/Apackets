# Potential C2 Beaconing (`c2_beaconing`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is anything contacting the same destination on a regular schedule?**

## 2. How to read the card

The headline is the number of *flows with a regular interval*: groups of
conversations — same source, same destination, same destination port, same
transport — whose spacing is steady enough to look scheduled. It is a count of
groups, not of packets.

Two visuals are drawn:

* a **histogram** of the interval between consecutive connections to the same
  destination, with the backend's own bucket labels (`under 1 s`, `1-5 s`,
  `5-30 s`, `30-60 s`, `1-5 min`, `5-30 min`, `30 min and over`). It is built from
  every repeated group in the capture, including those that failed the regularity
  test, so it shows the whole distribution and not only the suspicious part;
* a **table** of the groups that passed, with one row each: the destination
  (`source → destination:port`, linked to the conversation), how many flows over
  how many seconds, the mean interval in seconds, and the coefficient of variation
  that decided it. The table is capped at `top` rows and says `top N of M` when it
  bites.

A **high** reading is a non-trivial count of groups with low coefficients of
variation — several distinct destinations being polled on a schedule. A **low**
reading is one or two, which is what mail clients, NTP and update checks usually
produce. A zero headline with `availability: "empty"` means nothing was regular
enough; the histogram is still drawn and the reason names the threshold and how
many repeated flows were measurable.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_c2_beaconing(index)` in `backend/app/services/threat_hunt.py`.

1. If the conversation index holds no rows, return `not_applicable` with the
   reason `the conversation index holds no rows for this capture`.
2. Group `conversations` by `(ip_a, ip_b, port_b, transport)` where both addresses
   and `start_time` are present, keeping only groups with at least
   `BEACON_MIN_FLOWS` conversations. Groups are ordered by flow count descending
   and the query takes at most `ROW_SCAN_CAP` of them.
3. For each group, read that group's conversation `start_time` values in ascending
   order (again limited to `ROW_SCAN_CAP`), and take the difference between
   consecutive values. Non-positive intervals are discarded.
4. Add every positive interval to the interval histogram, whether or not the group
   qualifies.
5. Keep the group only if it has at least `BEACON_MIN_FLOWS - 1` positive intervals
   (that is, at least three gaps from four connections), its **mean** interval is at
   least `BEACON_MIN_INTERVAL`, and its **coefficient of variation**
   (`statistics.pstdev(intervals) / mean`) is at most `BEACON_MAX_CV`.
6. Rank the survivors by coefficient of variation (most regular first), then by
   flow count, then by destination.
7. The headline is the number of survivors; the table shows the first `top` of
   them; the links name up to five distinct destination addresses.

Note what is *not* checked: payload size, response size, connection duration, or
whether the destination has a name or a certificate. Regularity is the only signal.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `BEACON_MIN_FLOWS` | `4` | Minimum conversations to one destination before a group is measured at all (`HAVING COUNT(*) >= 4`). |
| `BEACON_MIN_FLOWS - 1` | `3` | Minimum number of positive intervals a group must have to be judged (`if len(positive) < BEACON_MIN_FLOWS - 1: continue`). |
| `BEACON_MIN_INTERVAL` | `5.0` | Minimum mean interval in seconds; anything faster is not treated as a schedule. |
| `BEACON_MAX_CV` | `0.35` | Maximum coefficient of variation (`pstdev / mean`). This is the regularity test; a group must be at or below it. |
| `ROW_SCAN_CAP` | `500` | Caps both the number of groups examined and the number of start times read per group. |
| `TIMELINE_CAP` | `240` | Not used by this detection (it draws no timeline). |
| `TABLE_CAP` | `50` | Caps histogram buckets (`_histogram`) — there are only seven interval buckets, so it never bites here. |
| `top` | `12` (1–50) | Caps the table's rows and the number of links. |

`BEACON_MIN_INTERVAL` is formatted as `{BEACON_MIN_INTERVAL:.0f}` in the empty
reason, so the card reads `5 s`.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `conversations.ip_a`, `conversations.ip_b` | The address pair that forms a group, and the destination for the link. |
| `conversations.port_b` | Part of the grouping key, so one peer on two ports is two groups. May be NULL, and NULL is matched as NULL. |
| `conversations.transport` | Part of the grouping key, and passed to the conversation link. |
| `conversations.start_time` | The timestamp of each connection; the interval series is built from these. |
| `conversations.stream_id` | The stream opened by the conversation link (`MIN(stream_id)` for the group). |

## 6. Fields the analyst brief asks for but the index does not hold

* **Channel content.** There is no payload column anywhere in the index, and the
  engine reads none. A beacon is identified by timing alone; nothing here says
  whether the traffic carried commands, a heartbeat, or an empty keep-alive.
* **Per-beacon payload size.** `conversations.bytes_a_to_b` and `bytes_b_to_a`
  exist and the query does not read them, so the card cannot show whether each
  check-in carries bytes or is a bare connection. The workaround is not there
  because the detection never needed it; adding it would be a change to the code,
  not to the data.
* **Connection duration.** `conversations.duration` exists (as do `end_time`) and is
  not read. The detection therefore cannot tell a client that reconnects every
  60 seconds from one that holds a connection open and exchanges traffic inside it —
  the second case produces a single conversation and is invisible here.
* **Inter-packet timing.** `packets.time_epoch` exists per frame, but the detection
  works at conversation-start granularity only. A beacon that reuses one long-lived
  TLS connection, or one DNS name, is not seen.
* **`jitter` or `interval` columns.** No such columns exist; `interval`, `mean` and
  `cv` are computed in Python from `start_time` and never stored.
* **Host names for the destination.** The card shows the address. Turning it into a
  name needs `/hosts?ip=…` or `/dns?domain=…`, not this table.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| Read the conversation | `/conversations?ip=<destination>` | Every stream to that peer, with byte counts in each direction and the stream state. |
| Open one stream | `/conversations?stream=<transport>:<stream_id>` | The reassembled bytes (`smode` picks the rendering) — for plain protocols this shows the exchange itself. |
| See the pattern over time | `/conversations?ip=<destination>&tab=timeline` | Whether the connections really are evenly spaced, and whether they continue throughout the capture. |
| Look at the frames | `/packets?ip=<destination>&protocol=tcp` | Frame sizes and flags; a beacon of equal-sized empty connections is visible as such. |
| Open a single frame in its stream | `/packets?mode=basic&stream_id=<stream_id>&sel=<frame>` | The exact frame of a suspect check-in. |
| Who is behind the address | `/hosts?ip=<source>` | What else that host does; a poller on a workstation with no other traffic is more interesting than one on a management server. |
| What the name is | `/dns?domain=<name>` | If the destination has a name, whether it was resolved here and what else resolved with it. |

Values must be percent-encoded; the section already does this in the links it
generates.

## 8. What it does not prove

A regular interval does not establish command-and-control. It establishes that
something connected to the same destination on a schedule, which is what a great
deal of ordinary software does. It says nothing about who or what is on the other
end, nothing about the content of the exchange, and nothing about whether the host
is compromised. The card's own caveat says the same thing:

> A regular interval does not establish command-and-control. Mail clients, NTP,
> monitoring agents, licence checks and software updates all poll on a schedule,
> and a jittered beacon can hide below this threshold.

## 9. Known limits and false positives

* **Legitimate pollers.** Mail clients checking IMAP, NTP time sync, monitoring
  agents (Zabbix, Nagios, Prometheus scrape intervals), licence servers, MDM
  check-ins, software update checks, and cloud agents all reconnect on a fixed
  interval and pass `BEACON_MAX_CV = 0.35` easily.
* **Load balancers and NAT.** Many clients behind one address, or one client across
  several backends that share a virtual address, can look like a single regular
  pair, because the grouping key is the address, not the process.
* **A chatty service on one port.** A service that polls every 30 seconds for hours
  produces both a high flow count and a low coefficient of variation.
* **Jittered beacons evade it.** Real implants often randomise their interval; a
  beacon with enough jitter exceeds `BEACON_MAX_CV` and never appears.
* **Only reconnecting traffic is measured.** Beacons carried inside a single
  long-lived connection, inside DNS, or inside an existing session produce one
  conversation and are invisible.
* **Structural caps.** At most `ROW_SCAN_CAP = 500` groups are examined and at most
  500 start times per group, so on a very large capture the busiest 500 groups are
  the only ones considered, and a group with more than 500 connections has only its
  earliest 500 timestamps measured.
* **An empty card is not a clean capture.** It means no group of four or more
  connections to one destination and port had a mean interval of at least 5 seconds
  with a coefficient of variation at or below 0.35.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Conversations](../Conversations.md) · [Packets](../Packets.md) · [TrafficBursts](TrafficBursts.md) · [RareCommunicationPairs](RareCommunicationPairs.md)
