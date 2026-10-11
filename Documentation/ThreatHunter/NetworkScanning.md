# Network Scanning (`network_scanning`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is one host probing many ports or many hosts in a short time?**

## 2. How to read the card

The headline counts **sources that scanned**, in either of the two shapes the brief
distinguishes, and it is a count of sources — not of ports, hosts or packets:

* **vertical** — one host opening connections to many distinct destination ports;
* **horizontal** — one host probing many distinct addresses that never answered it.
  A local `nmap -sn` sweep is this shape, and it opens no port at all: it asks the
  link who holds each address in the range.

Up to three visuals are drawn, and **each one appears only when it has something to
show**, so an ARP sweep carries no empty port matrix:

* a **heatmap** of source against destination port, drawn only when something opened
  ports. Rows are the busiest sources by attempt count, columns the busiest
  destination ports, each cell the attempts that source made to that port. A measured
  zero is drawn as a zero, because a blank cell would be indistinguishable from "not
  measured";
* **bars** of hosts probed with no answer per source, drawn only when some source
  swept hosts. The bar's length is the largest number of unanswered addresses that
  source probed inside one window;
* a **table** of the qualifying sources: the source (linked to the host), the
  unanswered hosts in its best window, the ports in its best window, the TCP
  destination pairs it touched, and its total TCP attempts. A zero is shown as `0`
  rather than left blank: an ARP sweep genuinely opened no ports.

A **high** reading is one or a few sources with a large number in either column. A
**low** reading is one source just over a threshold with the rest of the capture
focused on a handful of services. A zero headline with `availability: "empty"` means
nothing crossed either threshold, and the reason names the best observed value for
both shapes.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_network_scanning(index)` with the helper `_host_probes(index)`, in
`backend/app/services/threat_hunt.py`. The sliding window itself is
`_best_scan_window(events, span)`, which returns the largest number of **distinct**
values inside any window of `span` seconds.

### 3.1 Vertical: many ports on one host

1. If the packet index holds no rows at all, return `not_applicable` with
   `the packet index holds no rows for this capture`.
2. Read up to `PACKET_SCAN_CAP` frames that are TCP, carry both addresses and a
   destination port, and are **connection attempts**: SYN set, ACK clear
   (`(tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 0`). If the query returned
   exactly the cap, the heatmap note says `capped at 20000 attempts`.
3. Group the attempts by source, and for each source run the sliding window over
   destination ports in time order. Distinct ports are counted, so repeating one port
   does not advance the score.
4. A source qualifies at `SCAN_MIN_PORTS` distinct ports inside `SCAN_PORT_SPAN`.

### 3.2 Horizontal: many hosts probed that never answered

5. `_host_probes` collects the probes of every protocol that can discover a host, and
   the addresses that ever answered:
   * **ARP** — for rows with `protocol = 'ARP'`, the summary line is parsed:
     `Who has <ip>? Tell <ip>` is a request, and the prober is the *Tell* address;
     `<ip> is at <mac>` is a reply, and marks that address as live. This parsing is
     unavoidable: an ARP frame carries no IP layer, so `packets.dst_ip` is NULL for
     every ARP row and the probed address exists nowhere else in the index.
   * **ICMP echo** — for rows with `protocol = 'ICMP'`, an `info` beginning
     `Echo (ping) request` is a probe from `src_ip` to `dst_ip`; an
     `Echo (ping) reply` marks `src_ip` live. This is the remote-sweep case, where ARP
     is not used because the targets are not on the local link.
   * **TCP** — SYN-without-ACK frames are probes; a SYN+ACK
     (`(tcp_flags_raw & 2) = 2 AND (tcp_flags_raw & 16) = 16`) marks `src_ip` live.
6. For each source, the probes whose target is **not** in the live set are kept, and
   the sliding window is run over those destinations. A source qualifies at
   `SCAN_HOST_MIN` unanswered addresses inside `SCAN_HOST_SPAN`.
7. The result is the union of the sources from 4 and 6, sorted by unanswered hosts,
   then ports, then attempts, then address. The headline is how many there are, and
   the table shows the first `top`. The heatmap is built from the busiest `top`
   sources and ports; the bars from the qualifying sources.

### 3.3 Why "never answered" is the test

Counting probed hosts alone does not separate a sweep from ordinary traffic. Measured
on the captures in this library, the busiest normal source reached 43 distinct
destinations inside ten seconds — and **every one of the 43 answered** with a
SYN+ACK. A discovery sweep is defined by the opposite: the addresses it probes mostly
do not exist or do not reply. Requiring the probes to be unanswered keeps the 43-host
case off the card while catching a sweep of a mostly-empty range.

There is no SYN-to-SYN/ACK ratio check, no TCP reply correlation beyond the live-set
test, no destination reachability test beyond it, and no exclusion of an internal
source probing another internal host.

## 4. Thresholds

| Constant | Value | What it does |
|---|---|---|
| `SCAN_MIN_PORTS` | `20` | Distinct destination ports a single source must reach inside one window before it counts as a scanning source. Matches the documented `tcp_syn_scan` threshold in `docs/CONTRACT.md` §8. |
| `SCAN_PORT_SPAN` | `10.0` | Length of the port window in seconds. The table renders it as `10 s`. |
| `SCAN_HOST_MIN` | `20` | Distinct probed addresses a single source must leave **unanswered** inside one window before it counts as a host sweep. |
| `SCAN_HOST_SPAN` | `10.0` | Length of the host window in seconds. |
| `PACKET_SCAN_CAP` | `20000` | Maximum frames each probe query will read; when it bites, the heatmap note says so. |
| `top` | `12` (1–50) | Rows and columns in the heatmap; bars; rows in the table; number of links. |
| `ROW_SCAN_CAP` | `500` | Not used by this detection. |
| `TABLE_CAP` | `50` | Not used directly: the table is capped at `top`, which is at most 50. |
| `TIMELINE_CAP` | `240` | Not used by this detection (it draws no timeline). |

The port threshold matches the detection engine's `tcp_syn_scan` on the port count and
the window, but **not** on its second condition: `docs/CONTRACT.md` §8 also requires
that at least 80% of the frames be SYN-only, whereas this detection filters its input
to SYN-without-ACK frames and applies no ratio test. The two therefore disagree on a
source whose traffic mixes new connections with mid-stream frames.

### How `SCAN_HOST_MIN = 20` was chosen

From measurement, not taste. Across every completed analysis in this library:

| capture | addresses a source probed in one 10 s window | of which answered |
|---|---|---|
| a local `nmap -sn` sweep of a /24 | **255** | 11 |
| the busiest ordinary capture (`sf19us-MTA-lab-01`) | 43 | **43** |
| every other capture | 1–3 | — |

Twenty sits an order of magnitude above normal ARP behaviour (which peaks at **one**
target per prober per ten seconds across the whole library) and far below a real
sweep, while the answered-address test keeps the 43-host case out.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `packets.src_ip` | The scanning source for TCP and ICMP; also the bar and table label and the `/hosts?ip=` link. |
| `packets.dst_ip` | The probed address for TCP and ICMP; counted as distinct destinations per source. |
| `packets.dst_port` | The port counted by the port window, and the heatmap column. |
| `packets.time_epoch` | The timestamp used to order probes and to measure both windows. |
| `packets.number` | Tie-break ordering of attempts at the same timestamp, and the frame ordering of the query. |
| `packets.transport` | Restricts the port query to `transport = 'tcp'`. |
| `packets.tcp_flags_raw` | The bitwise tests that select probes (`& 2`, not `& 16`) and answers (both bits). |
| `packets.protocol` | Selects the `ARP` and `ICMP` rows. |
| `packets.info` | The **only** source of the probed address in an ARP request, and of the prober in it; also distinguishes an ICMP echo request from a reply. |

Note that `packets.dst_ip` is NULL for every ARP row, which is why the summary line
has to be parsed rather than a column read. `packets.dst_port` is likewise NULL for
ARP and ICMP, so a host sweep contributes nothing to the port matrix by construction.

## 6. Fields the analyst brief asks for but the index does not hold

* **`icmp.type` and `icmp.code`.** There is no ICMP column in `packets`. The workaround
  is the summary line: `info` beginning `Echo (ping) request` is treated as a probe and
  `Echo (ping) reply` as an answer. That covers echo sweeps — including the remote case
  `nmap -sn` uses — but **not** ICMP timestamp requests, address-mask requests or
  unreachable replies, which produce no distinguishable summary here. Precision cost:
  a sweep built from a non-echo ICMP type is invisible, and an ICMP unreachable is not
  counted as an answer, so a filtered address can look unanswered.
* **The ARP target as a field.** There is no ARP column at all. The probed address is
  read from `Who has <ip>? Tell <ip>` in the summary line, which is TShark's wording
  and could change with a future dissector version; if it did, the host-sweep branch
  would silently find nothing rather than error. The generated fixture
  (`tests/generators.py::arp_sweep_capture`) exists so that change fails a test
  instead of passing unnoticed.
* **Which prober an ARP reply belongs to.** A reply carries the answering address and
  the requester's MAC but not the requester's IP, so a reply is used only to mark the
  answering address as live, for every source. An address that answered somebody
  else's probe is therefore not counted as unanswered for this one.
* **`tcp.scan`-style summary fields.** TShark's own scan detection and its `tcp.flags`
  string are not indexed as such. The workaround is the bitwise test on
  `tcp_flags_raw` (`& 2` for SYN, `& 16` for ACK), which is precise but limited to what
  those two bits say.
* **UDP scans and non-SYN probes.** Only TCP frames with a destination port and the SYN
  bit set are read, so UDP sweeps, FIN/NULL/XMAS scans and RST scans are invisible.
* **Protocol identity beyond the port.** `packets.protocol` is read only to select ARP
  and ICMP rows; the TCP branch works from ports and flags alone.
* **`dcerpc.*`, `smb.*`.** Not indexed. A scan that enumerated SMB shares or RPC
  endpoints inside an otherwise permitted session produces no unusual port pattern.
* **Frame-level rate.** Both windows count distinct values, not rate, so a 10,000-port
  sweep in one second and 20 ports spread over ten seconds score the same if both stay
  under the threshold.
* **A cross-capture baseline.** There is none. Every threshold is absolute and fixed,
  so "many" means the same number whatever the network normally does.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The scanning host | `/hosts?ip=<source>` | Whether this is a server that legitimately has many peers, or a workstation that should not be probing anything. |
| The attempts themselves | `/packets?src_ip=<source>&transport=tcp` | Frame sizes, flags and timing; a uniform run of 60-byte SYNs is a scan, a mixture is not. |
| The ports probed | `/packets?src_ip=<source>&dst_port=<port>` | What the source was looking for, and whether anything was sent back. |
| Who answered | `/conversations?ip=<source>&tab=info` | Which of the probed destinations opened a stream, and the state of that stream. |
| The destination side | `/packets?ip=<destination>` | One destination's view: were the probes answered, refused, or ignored? |
| An ARP sweep on the wire | `/packets?ip=<source>` | The prober's other traffic. ARP frames carry no IP address, so they are **not** selectable by `ip=`; the probes themselves are visible in the packet browser unfiltered, where `Who has …` reads as the Info column. |
| Is it a known scanner | `/hosts?search=<source>` and `/findings` | Whether a vulnerability-scanner finding or an asset record already explains the host. |

The engine does not link to `tcp_flags=SYN`. As the note in `_failed_connections`
records, `packets.tcp_flags` holds TShark's `tcp.flags.str` — the dotted string such as
`···A··S·` — so that filter matches nothing; the port and address filters are the ones
that land on these frames. The bitwise tests in this detection read
`packets.tcp_flags_raw`, which holds `tcp.flags` as a number.

## 8. What it does not prove

A source reaching many ports or probing many addresses does not establish intent, and
does not establish that anything was found. Scanning is equally what an inventory
tool, a vulnerability scanner, a load balancer health check or a misconfigured client
does. The card's own caveat says the same thing:

> Scanning does not establish intent or success. Vulnerability scanners, inventory
> tools, load balancers and NAT devices produce the same pattern, and a scan the
> capture never shows a reply to may simply have been dropped.

## 9. Known limits and false positives

* **Vulnerability scanners and inventory tools.** Nessus, OpenVAS, Qualys, network
  discovery appliances and asset-inventory agents exist to do exactly this, and they
  do it on a schedule.
* **Health checks and load balancers.** A device probing a pool of ports across a pool
  of backends can fill the heatmap without any hostile intent.
* **NAT and aggregating devices.** Many internal hosts behind one address look like one
  source scanning, because the source is an address and not a host.
* **Ascending-connect clients.** Some applications — and some P2P clients — try a range
  of ports in order, which is indistinguishable here from a scan.
* **A ping sweep of a mostly-live subnet.** Because the test is *unanswered* addresses,
  sweeping a range where nearly everything answers can stay under the threshold. That
  is deliberate: "talked to many hosts and they all replied" is also what the busiest
  normal capture does, and it is not evidence of discovery.
* **Sweeps that avoid the local link and use no echo request.** A remote sweep built
  from ICMP timestamp or address-mask requests, or from UDP probes, produces nothing
  here.
* **Slow sweeps.** A source that spreads its probes beyond the ten-second window keeps
  every window under the threshold. `window` changes the *display* bucket size and does
  not affect these two spans.
* **Structural cap.** At most `PACKET_SCAN_CAP = 20000` frames are read per probe
  query, in address-then-time order, so on a very large capture later sources may not
  be examined at all. The heatmap note says `capped at 20000 attempts` when this
  happens, but the table and the headline give no indication that the scan was
  incomplete.
* **ARP summary parsing is wording-dependent.** If TShark changes the phrasing of
  `Who has …? Tell …` or `… is at …`, the host-sweep branch finds nothing and reports
  `empty`. The fixture in `tests/generators.py` guards this.
* **The ICMP branch is not exercised by any capture in this library.** No analysis in
  the library contains ICMP echo traffic, so that path is verified structurally (and by
  the code's own tests) but never against real capture data.
* **An empty card is not a quiet network.** It means no source reached 20 distinct
  destination ports, or probed 20 unanswered addresses, inside ten seconds.

---

**Related:** [Threat Hunt](../Threat-Hunt.md) · [Packets](../Packets.md) · [Hosts](../Hosts.md) · [HighFanOut](HighFanOut.md) · [FailedConnections](FailedConnections.md)
