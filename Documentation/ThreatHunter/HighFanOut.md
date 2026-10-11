# High-Fan-Out Hosts (`high_fan_out`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Which host is talking to the most distinct peers?**

## 2. How to read the card

The headline counts *hosts with 10 or more peers*: hosts whose `hosts.peer_count` —
the number of distinct addresses it exchanged at least one conversation with — is at
least `FAN_OUT_MIN_PEERS`. It is a count of hosts.

One visual is drawn: **bars** of distinct conversation peers per host, one bar per
qualifying host, ranked by peer count, each label linked to that host. The chart
contains only hosts at or above the threshold, so hosts below it are not drawn and
the chart is not drawn at all when none qualifies. The bar chart therefore shows the
shape of the fan-out at the top of the distribution, not the distribution itself.

A **high** reading is one host far above the rest — a bar twice the height of its
neighbour is worth a look, and a host with hundreds of peers is usually
infrastructure. A **low** reading is a couple of hosts just over ten, which a busy
workstation can reach in an afternoon. A zero headline with
`availability: "empty"` means no host reached ten distinct peers; the reason reports
the highest observed count and the median, which is where the real information is on
a quiet capture.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_high_fan_out(index)` in `backend/app/services/threat_hunt.py`.

1. If the host index holds no rows, return `not_applicable` with
   `the host index holds no rows for this capture`.
2. Read up to `ROW_SCAN_CAP` hosts ordered by `peer_count` descending, taking the
   address, MAC, private flag, packet and byte counters, the peer count and the DNS
   names.
3. Keep every host whose `peer_count` is at least `FAN_OUT_MIN_PEERS`. The headline is
   how many there are, labelled `host(s) with 10+ peers`.
4. Compute the median peer count of all hosts read, for the empty-case reason only.
5. Draw bars for the first `top` qualifying hosts, and link up to five of them.

The number the detection ranks on is not computed here. `hosts.peer_count` is written
by `backend/app/services/host_analyzer.py` as the count of distinct peers in the
conversation index, taken from both directions of every conversation and excluding
the host itself. So a peer counts only if it appears in at least one indexed
conversation, and the count says nothing about how much was exchanged with each peer
or in which direction.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `FAN_OUT_MIN_PEERS` | `10` | Distinct peers a host must have before it is counted. The headline label is built from this value (`host(s) with 10+ peers`). |
| `ROW_SCAN_CAP` | `500` | Maximum hosts read, ordered by peer count descending, so the 500 hosts with the most peers are the ones examined. |
| `top` | `12` (1–50) | Bars in the chart; number of links. |
| `PACKET_SCAN_CAP` | `20000` | Not used by this detection. |
| `TABLE_CAP`, `TIMELINE_CAP`, `SCATTER_CAP` | `50`, `240`, `200` | Not used by this detection. |

There is no minimum packet count or byte volume, and no ratio test against the rest
of the capture: a host with exactly ten peers, each seen in one packet, qualifies
exactly as a host with ten busy peers does.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `hosts.ip` | The bar label, the `/hosts?ip=` link, and the identity of the host. |
| `hosts.peer_count` | The value ranked and charted, and the threshold test. |

The query also selects `hosts.mac`, `hosts.is_private`, `hosts.packets_sent`,
`hosts.packets_received`, `hosts.bytes_sent`, `hosts.bytes_received` and
`hosts.dns_names`, and **none of them is rendered** on the card. That means the card
cannot tell a host that is fanning out because it is a gateway from one that is
fanning out because it is an infected client, even though the private flag and the
byte counters are already in the row.

## 6. Fields the analyst brief asks for but the index does not hold

* **The peer list itself.** `hosts.peers` is a JSON array of the distinct peers and
  is not read, so the card shows a count without the names behind it. The workaround
  available to the reader is `/hosts?ip=<host>&view=inventory` or
  `/conversations?ip=<host>`, which is a different page rather than part of the
  indicator.
* **Per-peer volume or direction.** `hosts.peers` is not read, and the per-peer byte
  counts that would rank one peer above another exist only inside `conversations`.
  The detection therefore cannot distinguish a host with ten silent peers from a host
  moving data to all ten.
* **A baseline.** There is no stored per-host history and no cross-capture
  comparison, so "far more peers than the rest of the capture" is judged against the
  capture's own top-500 host list and nothing else.
* **Protocol identity.** `hosts.protocols` (a JSON object of protocol counts) and
  `conversations.protocols` exist and are not read, so a host with many peers because
  it speaks DNS to everyone looks the same as one speaking SMB to everyone.
* **`dns.names` as evidence.** `hosts.dns_names` is read into the row and unused, so
  the card does not show whether the peers are named or bare addresses.
* **Purpose.** No column records a host's role (client, server, gateway, resolver),
  so the detection cannot exclude infrastructure from the count.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The host in full | `/hosts?ip=<host>&view=inventory` | Counters, protocols and names for that one address. |
| The host in context | `/hosts?view=graph` | Where the host sits in the capture's connectivity graph, which separates a gateway from a leaf. |
| Its conversations | `/conversations?ip=<host>` | Each peer as a stream, with directional byte counts: ten peers with one packet each is a different finding from ten busy peers. |
| Only internal peers | `/hosts?is_private=true` | Whether the fan-out is inside the estate or towards the internet. |
| Its DNS behaviour | `/dns?client_ip=<host>` | Whether many peers were reached by name and in quick succession. |
| Look for a scanner pattern | [NetworkScanning.md](NetworkScanning.md) and `/packets?src_ip=<host>` | High fan-out and scanning frequently come from the same host; the two cards should be read together. |
| What it established | `/conversations?ip=<host>&tab=info` | Which of the peers actually opened a stream, and the state of each. |

## 8. What it does not prove

Talking to many peers does not establish malicious activity. It establishes that the
host appeared in conversations with at least ten distinct addresses. The card's own
caveat says the same thing:

> Fan-out does not establish malicious activity. Network gateways, resolvers, update
> servers, proxies and monitoring platforms legitimately talk to everything, and peer
> counts come from observed conversations alone.

## 9. Known limits and false positives

* **Gateways, proxies and resolvers.** A NAT device, a web proxy or a DNS resolver
  appears as a host with enormous fan-out and is doing its job.
* **Update and telemetry servers.** Anything that distributes content to many clients
  has thousands of peers.
* **Monitoring and discovery.** A monitoring platform checking every host, or a
  discovery tool enumerating the estate, produces exactly this pattern — and the same
  host will usually also appear on [`network_scanning`](NetworkScanning.md).
* **Peer-to-peer clients.** BitTorrent and similar protocols open conversations with
  large numbers of peers by design.
* **Conversations only.** The count comes from the conversation index, so peers
  present only as single frames that produced no conversation are not counted, and a
  capture that was truncated will undercount.
* **The chart only shows hosts over the line.** Hosts below ten peers are invisible on
  this card, so a capture with one host at nine peers shows an empty chart and an
  empty headline, even though the distribution is interesting.
* **Structural cap.** At most `ROW_SCAN_CAP = 500` hosts are read, ordered by peer
  count, so on a large capture only the busiest 500 hosts are considered — which for
  this detection is the right end of the distribution, but means the median reported
  in the empty reason is the median of the top 500 hosts, not of all hosts.
* **An empty card is not a quiet capture.** It means no host reached ten distinct
  peers in the conversation index.
