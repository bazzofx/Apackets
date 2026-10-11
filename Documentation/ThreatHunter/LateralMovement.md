# Lateral Movement Indicators (`lateral_movement`)

Part of the **Threat Hunt** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Is an internal host reaching other internal hosts on remote-administration
services?**

## 2. How to read the card

The headline counts *internal-to-internal administration flows*: distinct
(source address, destination address, destination port) triples where both
addresses are private and the destination port is in the fixed
`LATERAL_PORTS` portfolio (SSH, Telnet, NetBIOS, SMB, RDP, MSSQL, Oracle TNS, NFS,
MySQL, PostgreSQL, VNC, WinRM, Redis, MongoDB, rpcbind, MS RPC, rexec, rlogin, rsh).
It is a count of flows — that is, of *kinds* of internal connection — not of packets
and not of hosts.

This is the one detection on the page with **no minimum-count threshold**: a single
packet between two private addresses on one of those twenty ports is enough to make
the indicator `ok`. The card answers "does the capture contain any internal
administration traffic at all", and the ranking tells you where it is. Read the
table, not the headline.

Two visuals are drawn:

* **bars** of internal hosts reached on administration services, one bar per
  (destination host, port) pair, showing the packets sent to it, labelled with the
  service name. This is the "who is being administered" view;
* a **table** of the flows themselves, capped at `TABLE_CAP = 50` rows: source
  (linked to the host), destination (linked to the host), the service, the packet
  count (linked to the frames), and the byte total. It is ordered by packet count,
  so a long-lived session is at the top and a one-packet touch is at the bottom.

A **high** reading is a large number of distinct internal flows spread across many
hosts and several services, or a long list of hosts all being touched on one
administration port. A **low** reading is the handful of SSH or SMB flows a normal
internal capture contains. A zero headline with `availability: "empty"` means no
internal-to-internal TCP flow was seen on any of the twenty ports at all.

Because there is no threshold to cross, this indicator is `ok` on almost any capture
that contains internal traffic. That is deliberate — the value is in the table — but
it means the headline should never be read as a score.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_lateral_movement(index)` in `backend/app/services/threat_hunt.py`.

1. If the packet index holds no rows, return `not_applicable` with
   `the packet index holds no rows for this capture`; if it holds no TCP frames,
   return `not_applicable` with `the packet index holds no TCP frames for this
   capture`.
2. Read TCP frames whose destination port is in `LATERAL_PORTS` and where both
   addresses are present, grouping by `(src_ip, dst_ip, dst_port)` and taking the
   packet count, the sum of `frame_len`, the first frame number and the first
   timestamp. The query takes at most `ROW_SCAN_CAP` groups, ordered by packet count.
3. Discard every group where either address is not private, using
   `is_private_address` from `backend/app/services/host_analyzer.py`. Only
   private-to-private flows survive; a private host reaching an *external* address on
   RDP is not lateral movement and is not counted here.
4. Re-sort by packet count, then by source and destination address.
5. The headline is the number of surviving flows. The table draws the first
   `TABLE_CAP = 50`; the bars aggregate the same flows by `(destination, port)` and
   draw the top `top`.
6. Links name up to five destination hosts.

Direction is taken from the frame itself: `src_ip` is the initiator as observed, so
the bars and the table show who connected to whom. There is no check of session
success, authentication, or whether the destination is a server that offers the
service.

## 4. Thresholds

This detection has no numeric threshold. Its gate is set membership plus an address
classification, and both are fixed:

| Constant | Value | What it does |
|---|---|---|
| `LATERAL_PORTS` | a dict of **20** ports: `22` SSH, `23` Telnet, `111` rpcbind, `135` MS RPC, `139` NetBIOS session, `445` SMB, `512` rexec, `513` rlogin, `514` rsh, `1433` MSSQL, `1521` Oracle TNS, `2049` NFS, `3306` MySQL, `3389` RDP, `5432` PostgreSQL, `5900` VNC, `5985` WinRM HTTP, `5986` WinRM HTTPS, `6379` Redis, `27017` MongoDB | The destination ports that count as administration services. Membership alone qualifies a flow. |
| `ROW_SCAN_CAP` | `500` | Maximum number of `(source, destination, port)` groups read from the packet index. |
| `TABLE_CAP` | `50` | Maximum rows in the flow table. |
| `top` | `12` (1–50) | Bars in the service chart; number of links. |
| `PACKET_SCAN_CAP` | `20000` | Not used by this detection. |
| `TIMELINE_CAP` | `240` | Not used by this detection. |

There is no minimum packet count, no minimum number of hosts, and no minimum number
of distinct services. If you need one, add it in code; the page cannot express it.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `packets.src_ip`, `packets.dst_ip` | The flow key, the address classification, and both `/hosts?ip=` links. |
| `packets.dst_port` | Membership of `LATERAL_PORTS`, the service label, and the `/packets?dst_port=` link. |
| `packets.transport` | Restricts the query to `transport = 'tcp'`. |
| `packets.frame_len` | Summed into the flow's byte total. |
| `packets.number` | Read as `MIN(number)` (`first_frame`) but not rendered on the card. |
| `packets.time_epoch` | Read as `MIN(time_epoch)` (`first_time`) but not rendered on the card. |

## 6. Fields the analyst brief asks for but the index does not hold

* **`smb.*`.** There is no SMB column group in `packets` and no SMB analyser: no
  share name, no path, no command, no service name beyond port 445. An SMB session
  to a file server and an SMB session used to move an implant are the same row.
* **`dcerpc.*`.** Not indexed at all. No interface UUID, no operation number, so an
  RPC call that changed a service configuration cannot be told from a routine one.
* **`rdp.*`.** Not indexed: no RDP cookie, no requested user name, no negotiated
  security layer. RDP appears only as TCP port 3389.
* **`wmi.*` and `kerberos.*`.** Not indexed. WMI is reachable only through the port
  135/5985 entries if it happens to use them, and Kerberos tickets, service names and
  user names are not present, so the detection cannot say who authenticated or
  whether authentication succeeded.
* **Authentication outcome.** There is no success/failure column for any of these
  services. An SMB session that was refused produces the same flow as one that
  succeeded.
* **Direction of administration.** The flow records who sent the first frame; the
  index holds no notion of which side was the administrator and which the target.
* **Payload.** No payload column exists anywhere, so no command, file or credential
  carried over these services can be read here.

The practical cost of these gaps is that this card is a map of *where internal
administration traffic is*, not an indicator of intrusion. It cannot rank one
administration flow above another beyond packet count.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The initiator | `/hosts?ip=<source>` | Whether that host is an administrator workstation, a management server or a user's laptop. |
| The target | `/hosts?ip=<destination>` | Whether the destination is a server that offers the service, and how many other hosts reach it. |
| The conversations to it | `/conversations?ip=<destination>&port=<port>` | Which streams exist, their byte balance, and their state. |
| The frames | `/packets?ip=<destination>&dst_port=<port>&transport=tcp` | Session shape and duration; a one-packet touch is different from a long session. |
| One stream in full | `/conversations?stream=tcp:<stream_id>` | The reassembled bytes, which for unencrypted SMB or Telnet may show what was done. |
| Any recorded findings | `/findings` | Whether the analysis already raised a rule about this pair. |
| The whole internal picture | `/hosts?view=graph` | The shape of internal-to-internal connectivity, which puts one flow in context. |

## 8. What it does not prove

Internal traffic on an administration port does not establish lateral movement. It
establishes that one private address sent TCP frames to another private address on a
port that is commonly used for administration. Nothing here says who authenticated,
what was done, or whether anyone unauthorised was involved. The card's own caveat says
the same thing:

> Administrative services are used administratively. Management platforms, backup
> jobs, domain controllers and help-desk tools produce the same flows, and a captured
> session says nothing about who authenticated.

## 9. Known limits and false positives

* **Management platforms.** Configuration management, inventory and monitoring
  systems reach every host on SSH, WinRM or SMB on a schedule; on a managed estate
  this chart is full of them by design.
* **Backup jobs and file shares.** SMB and NFS traffic between servers is ordinary
  and produces long flows with high packet counts at the top of the table.
* **Domain controllers.** Kerberos and RPC-adjacent traffic means domain controllers
  legitimately dominate the 135/139/445 rows.
* **Help-desk and remote-support tools.** VNC, RDP and WinRM sessions from a support
  workstation are the intended use of those ports.
* **No threshold means no signal in the headline.** The count is deliberately
  unfiltered, so a low number is not reassurance and a high number is not evidence.
  This is the card most likely to be `ok` when nothing is wrong.
* **Structural blind spots.** Only TCP is read, so UDP-based administration and
  discovery are invisible; only the twenty listed ports count, so a service moved to
  a non-standard port does not appear; and a flow whose addresses are not both
  private — an internal host reaching a cloud management endpoint — is discarded
  rather than shown.
* **Caps.** At most `ROW_SCAN_CAP = 500` flows are read, ordered by packet count, so
  on a busy internal capture the quietest flows are not examined at all, and the
  table shows only the first `TABLE_CAP = 50`.
* **Direction from one frame.** The source is whoever sent the first captured frame,
  so a capture that starts mid-session can attribute a reply to the wrong side.
