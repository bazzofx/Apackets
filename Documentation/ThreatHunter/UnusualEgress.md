# Unusual Egress (`unusual_egress`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is an internal host reaching out on ports or to addresses the rest of the capture
never uses?**

## 2. How to read the card

The headline counts *unusual egress destinations*: pairs of (internal address, public
destination) where at least one of two things is true — the port used is outside the
fixed `STANDARD_EGRESS_PORTS` set, or the capture holds no name for the destination
address. It is a count of destination addresses, not of connections and not of bytes.

There is no volume threshold anywhere in this detection: a destination qualifies on
the port it used or on the absence of a name, however little was sent to it.

One visual is drawn: **bars** of outbound volume to public destinations outside the
standard egress set, one bar per destination, in bytes sent, ranked by volume. Each
label reads `<destination> port <up to three ports by count> (reason)`, where the
reason is either `non-standard port` or `no name evidence`. The note states the
qualifying rule, and the chart is capped at `top` rows with the cap reported.

A **high** reading is many destinations, especially ones carrying real volume. A
**low** reading is one or two, which is what a capture containing a peer-to-peer
client or a VPN endpoint looks like. A zero headline with `availability: "empty"`
means every public destination from a private address used a standard port **and** had
a name in the capture; the reason lists those standard ports so the reader can see
which rule was applied.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_unusual_egress(index)`, with the helpers `_host_names(analysis_id)`
and `_outbound_pairs(analysis_id)` (the latter shared with
[`data_exfiltration`](DataExfiltration.md)), in `backend/app/services/threat_hunt.py`.

1. If the conversation index holds no rows, return `not_applicable` with
   `the conversation index holds no rows for this capture`.
2. Build a map of address to known names: for every host row, collect the JSON arrays
   `hosts.dns_names` and `hosts.tls_sni` into a set per address. That is the only
   evidence of a name the detection has.
3. Read up to `PACKET_SCAN_CAP` conversation rows, taking both addresses, both ports,
   both directional byte counts and the packet total.
4. Decide the direction of each conversation: private to public-unicast gives
   (internal source, public peer) and the bytes sent are `bytes_a_to_b`; the reverse
   arrangement gives `bytes_b_to_a`. Anything else — private to private, public to
   public, or a multicast, broadcast or loopback address — is discarded.
5. Take the destination port of the **outbound** direction: `port_b` when the source is
   `ip_a`, otherwise `port_a`. A conversation with no port on that side is skipped.
6. Test the two conditions: the port is not in `STANDARD_EGRESS_PORTS`, and the peer
   address has no names in the map. A conversation with neither condition is dropped;
   either condition alone is enough.
7. Accumulate per `(source, peer)`: bytes sent, conversation count, a per-port counter,
   and the two condition flags combined with OR, so a pair that was unusual on any one
   conversation stays unusual.
8. Rank the destinations by bytes sent, then by address. The headline is how many
   there are; the bars draw the first `top`, each labelled with up to three ports by
   frequency and one reason string.
9. Link up to five destination addresses.

The reason string is coarse by construction: a destination that used both a
non-standard port and had no name is labelled `non-standard port`, because the code
prefers that branch.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `STANDARD_EGRESS_PORTS` | **19** ports: `20`, `21`, `25`, `53`, `80`, `110`, `123`, `143`, `389`, `443`, `465`, `587`, `636`, `993`, `995`, `8080`, `8443`, `5222`, `5228` | A destination port outside this set makes the conversation unusual. It is a fixed set, hard-coded in the module. |
| name evidence | `hosts.dns_names` + `hosts.tls_sni` | A public destination with at least one name from either array is considered named; an empty set makes the conversation unusual. |
| `PACKET_SCAN_CAP` | `20000` | Used twice: the limit on host rows when building the name map, and the limit on conversation rows when measuring egress. |
| `top` | `12` (1–50) | Bars in the chart; number of links. |
| `ROW_SCAN_CAP`, `TABLE_CAP`, `TIMELINE_CAP`, `SCATTER_CAP` | `500`, `50`, `240`, `200` | Not used by this detection. |

Note that this standard-egress list is **not** the detection engine's `COMMON_PORTS`
(112 ports) used by [`unusual_ports`](UnusualPorts.md). The two disagree in both
directions: `51820` (WireGuard) and `8883` (MQTT over TLS) are in `COMMON_PORTS` but
not in `STANDARD_EGRESS_PORTS`, so egress to them is unusual here and common there;
`5222` and `5228` are in both. A port can be unremarkable on one card and unusual on
the other, and that is a property of the two lists, not of the traffic.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `conversations.ip_a`, `conversations.ip_b` | The direction decision and the (source, peer) key. |
| `conversations.port_a`, `conversations.port_b` | The port actually used towards the peer, which is the standard-egress test and part of the bar label. |
| `conversations.bytes_a_to_b`, `conversations.bytes_b_to_a` | The byte volume in the outbound direction: the bar length and the rank order. |
| `conversations.packets_total` | Selected by the query and **not used**. |
| `hosts.ip` | The key of the name map. |
| `hosts.dns_names`, `hosts.tls_sni` | The name evidence for a destination address. If either holds a value for the peer, the destination is considered named. |

## 6. Fields the analyst brief asks for but the index does not hold

* **A name for the destination that is not in `hosts`.** Name evidence comes only from
  `hosts.dns_names` and `hosts.tls_sni`, both written by the host analyser from names
  it saw in this capture. There is no reverse DNS, no ASN or organisation lookup, no
  certificate-subject lookup and no geo-IP: an address that was never resolved inside
  the capture is permanently "unnamed", however well known it is in reality. The cost
  is that hard-coded endpoints and ordinary CDN addresses are treated identically.
* **A prior-traffic baseline.** Nothing records which destinations a host *usually*
  uses, so "the rest of the capture never uses it" is judged only by the two fixed
  tests — port set membership and the presence of a name — and not by comparing the
  destination with anything.
* **TLS and HTTP identity on this card.** `tls_sessions.sni` and
  `http_transactions.host` exist and are not read here; the name evidence is taken from
  the host roll-up, so the card shows that a destination is named but not by which
  name, and does not show which SNI or Host header was used.
* **Ports on other transports.** UDP and TCP conversations are treated the same, and
  the port is taken from whichever side is the internal one; there is no protocol
  qualification, so a UDP conversation on a port that is standard for TCP is judged
  against the same list.
* **Payload or protocol identity.** No payload inspection and no `conversations.protocols`
  read, so a QUIC session, a VPN and a tunnelled protocol on the same port are
  indistinguishable.
* **`icmp.type`.** Not indexed, so ICMP-based egress (tunnels over echo requests, for
  example) produces no conversation and cannot appear.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The destination's traffic | `/conversations?ip=<peer>` | Ports used, byte balance and stream states for every conversation with that address. |
| Every conversation on that port | `/conversations?port=<port>` | Whether the port is one internal host talking out, or a pattern across the estate. |
| The frames | `/packets?ip=<peer>` | What the traffic looks like on the wire. |
| The client | `/hosts?ip=<source>` | Whether the host is expected to reach the internet at all. |
| Is it really unnamed | `/dns?domain=<name>` and `/tls?ip=<peer>` | Whether anything in the capture ever associated a name with that address; an SNI or a DNS answer that the host roll-up did not carry would explain it. |
| Encrypted traffic to it | `/tls?ip=<peer>` | Whether the sessions to that address have a server name, version and fingerprint. |
| Standard-port comparison | `/packets?ip=<peer>&dst_port=<port>` | Whether the same port is used elsewhere in the capture, which weakens the "unusual" claim. |
| Volume in context | [`data_exfiltration`](DataExfiltration.md) | Whether this destination also crossed the exfiltration thresholds. |

## 8. What it does not prove

An unnamed destination is not a hidden one, and a non-standard port is not a tunnel.
The card's own caveat says the same thing:

> An unnamed destination is not a hidden one. Addresses are often cached from before
> the capture started or reused across connections, and reachable non-standard ports
> are ordinary in peer-to-peer, gaming and remote-access traffic.

Nothing here says what was sent, who operated the destination, or whether the traffic
was expected.

## 9. Known limits and false positives

* **Ordinary services on ports outside the list.** WireGuard (`51820`), MQTT over TLS
  (`8883`), DNS over TLS (`853`), IPsec (`500`, `4500`), OpenVPN (`1194`), STUN
  (`3478`), SIP over TLS (`5061`) and countless vendor agents all use ports this list
  does not contain, so they appear as unusual egress on the first capture taken.
* **Unnamed destinations by construction.** Any address whose name was resolved before
  the capture started, or that is reached by a hard-coded address, has no name evidence
  and lands in this chart. On a capture of ordinary browsing that is a large fraction
  of the internet.
* **One bar per destination, ranked by volume.** A destination that was touched once is
  in the chart if it qualifies, but it will be at the bottom and may be cut off by
  `top` without any cap note if the number of qualifying destinations is under the
  limit.
* **No volume threshold.** The card cannot distinguish a 200-byte probe from a 200 MB
  transfer except by bar length.
* **The reason label hides the other condition.** A destination that failed both tests
  is reported as `non-standard port`, which understates why it qualified.
* **Two different port lists in one section.** This card's list is
  `STANDARD_EGRESS_PORTS`; [`unusual_ports`](UnusualPorts.md) uses `COMMON_PORTS`. A
  reader comparing the two should not expect them to agree.
* **Structural caps.** `PACKET_SCAN_CAP = 20000` bounds both the host rows read for
  the name map and the conversation rows measured, so on a large capture the name map
  may be built from only part of the host index — which makes more destinations look
  unnamed — and the egress measurement from only part of the conversation index.
* **An empty card is not a closed network.** It means every public destination reached
  from a private address used one of those 19 ports and already had a name in this
  capture.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Hosts](../Hosts.md) · [Conversations](../Conversations.md) · [DataExfiltration](DataExfiltration.md) · [DataStaging](DataStaging.md)
