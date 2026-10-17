# Baseline network

One capture is designated as *the network*: every other analysis is compared against it,
and the entities it never contained are reported as findings. The mode is global — one
baseline for the whole application, on or off, with a persistent indicator on every page.

Its service is `backend/app/services/baseline.py`, its router
`backend/app/api/routes_baseline.py`, its seven rules live in
`backend/app/services/detection_engine.py`, and the two interface surfaces are
[PCAP Files](PCAP-Files.md) (choose it, switch it) and the top bar of every page (show it).
The normative API and rule text is [`docs/CONTRACT.md`](../docs/CONTRACT.md) §8.

---

## 1. What it is for

A single capture answers "what was on this network while it was running". A second capture
from the same network answers a different question — "what is on it now" — and the
difference between the two is one of the few claims a forensics tool can make that is
>*about* a network rather than about a file. The baseline is that reference capture:

* it is an ordinary analysed capture that has been marked as the reference;
* comparing is a **set difference**, not a statistical model — an address, a
  destination, a service, a name or a TLS fingerprint that occurs in this capture and not
  in the reference;
* every finding it produces names the reference it was measured against, so it still
  reads correctly months later when the baseline has changed.

Nothing is inferred about intent. Novelty is the fact; whether a new address is a rogue
device or a laptop on a new DHCP lease is the analyst's question, and the rule text says
so in every finding (see §6).

---

## 2. The configuration

One row in `settings` under key `baseline_config` holds the whole state:

```
{"analysis_id": "74a7aa01ef2f48cc958c250a24a1706e", "enabled": true,
 "label": null, "created_at": 1792249966.27}
```

| Field | Meaning |
|---|---|
| `analysis_id` | The reference capture, or `null`. Only a `completed` analysis with at least one packet may be chosen — a baseline that cannot be compared against fails silently, which is the one failure mode nobody notices. |
| `enabled` | Baseline mode. Forced to `false` whenever `analysis_id` becomes `null`. |
| `label` | Optional analyst name for the reference (for example `office-2025-11`), used in every reason string in place of the file name. Capped at 120 characters. |
| `created_at` | When the baseline was chosen, not when the capture was taken. |

`status()` resolves that row against the `analyses` table and returns one of five states,
each with a `reason` the interface prints verbatim:

| State | `configured` | `active` | `reason` |
|---|---|---|---|
| No baseline set | `false` | `false` | `no baseline is configured` |
| Baseline capture deleted | `false` | `false` | `the capture this baseline pointed at has been deleted` |
| Baseline not `completed` | `true` | `false` | `the baseline capture is '<status>', so it cannot be compared against` |
| Baseline set, mode off | `true` | `false` | `baseline mode is off` |
| Baseline set, mode on | `true` | `true` | `null` |

`active` is the only flag the rules and the top-bar indicator read. A configured baseline
with the mode off compares nothing and reports nothing.

---

## 3. The profile — what a capture is reduced to

Both captures are reduced to seven sets before they are compared (`PROFILE_KINDS`). The
sets, and where each comes from:

| Kind | Read from | How it is built |
|---|---|---|
| `hosts` | `packets` | Every distinct `src_ip` and `dst_ip`. |
| `peers` | `packets` | Every distinct `src_ip|dst_ip` ordered pair — "who talked to whom". |
| `services` | `packets` | Every distinct `dst_ip|port|transport` on a **listening-looking** port: `dst_port < 49152`, and for TCP only the frames whose flags are exactly `SYN` (`tcp_flags_raw = 2`). |
| `dns_names` | `dns_queries` | Every distinct `query_name`, lower-cased. |
| `http_hosts` | `http_transactions` | Every distinct `host`, lower-cased. |
| `sni` | `tls_sessions` | Every distinct `sni`, lower-cased. |
| `ja3` | `tls_sessions` | Every distinct `ja3`, lower-cased. |

Two filters in that table are the difference between a usable rule and a noisy one, and
both were put there after measuring:

* **`dst_port < 49152` and `SYN`-only for TCP.** Counting every `dst_port` made a
  single HTTPS client look like it offered dozens of new "services": on
  `SpaceX_loads_of_tabs.pcapng` the unfiltered set held **59** entries that a later capture
  on the same network lacked, all of them ephemeral client ports. With the listener filter
  the same comparison reports **4**. A service is a port something listens on, and a SYN is
  the only frame that says so.
* **Lower-casing names.** DNS is case-insensitive and captures do not preserve a case
  convention, so `Example.COM` and `example.com` are one name, not two.

The profile is memoised per analysis (`CACHE_LIMIT = 4`, least-recently-added evicted) and
the caches are dropped whenever the configuration is written. A `completed` analysis is
immutable — re-uploading the file produces a new id — so a memo cannot go stale the way a
cached `findings` row can.

---

## 4. Comparability — the one rule that keeps this honest

Novelty is only computed when the two captures **demonstrably belong to the same
network**:

```
comparable = the captures share at least one PRIVATE address
```

Public sharing does not count. Two captures from different sites both contacting
`142.250.x.x` share a Google edge; treating that as the same network would report an
entire foreign network as novel, produce hundreds of findings, and mean nothing. This was
found the same way: `sf19us-MTA-lab-07.pcap` compared against a SpaceX baseline shares
public resolvers with it, and the first version of `compare()` called it comparable. It is
now `comparable: false`.

When the captures do not overlap, the novelty rules stay **silent** and one rule says why:

> This capture shares no local address with the baseline network

which names the baseline, states how many addresses it holds, how many this capture holds,
and how many of them are local — and then says plainly that this is a statement about the
two captures, not about the traffic.

`compare()` therefore has five honest "nothing was compared" answers, all reported as
`active: false` with a `reason`, never as an empty novelty list: no baseline is configured,
baseline mode is off, this capture *is* the baseline, and the baseline indexed no
addresses. Callers never have to guess whether an empty list means "nothing new" or
"nothing compared".

---

## 5. The seven rules

Every rule is an ordinary detection rule: severity, an on/off switch, a threshold sentence,
stored findings, the Findings page filter and the Alert Settings editor. They are silent
whenever `compare()` is not active (mode off, or this capture is the baseline).

| Rule id | Severity | Reports | Cap |
|---|---|---|---|
| `baseline_new_host` | high | One finding per **private** address in this capture that the baseline never held. Public novelty is not reported: a new CDN edge is not a new device. | 40 |
| `baseline_new_destination` | medium | One finding per source, listing the **global unicast** destinations it reached that the baseline never recorded. | 40 sources |
| `baseline_new_service` | medium | One finding per private host, listing the `port/transport` pairs it answered on that the baseline never held. | 40 hosts |
| `baseline_new_dns` | low | One finding per client, listing the names it resolved that the baseline never queried. | 40 clients, 200 names resolved back to their clients |
| `baseline_new_sni` | low | One finding per TLS server name not in the baseline. | 40 |
| `baseline_new_ja3` | medium | One finding per TLS client fingerprint not in the baseline. | 40 |
| `baseline_no_overlap` | medium | The single finding that explains why the other six are silent, when the two captures share no private address. | 1 |

Excluded from `new_destination` on purpose: multicast, broadcast and reserved addresses
(`224.0.0.0/4`, `203.0.113.0/24`-style documentation ranges, `255.255.255.255`) are not
destinations anyone chose to contact. Excluded from `new_host` on purpose: public
addresses, which the baseline cannot vouch for either way.

Each finding carries:

* a `reason` that names the baseline (label or file name), its frame count, how many
  addresses it recorded, and how many of this capture's addresses it shares;
* `evidence` with the baseline block, the capture block, the overlap counts, the novelty
  kind and a capped `sample` of the entities;
* up to 10 `packet_numbers` — the first matching frames in frame order, so the finding
  opens on the traffic rather than on an aggregate;
* `entities` (`ips`, `hostnames`, `ports`, `uris`) for the finding's own links.

### Recalculating the findings after a change

A baseline change is not a local edit: it changes what all seven rules would say about
**every** analysis. Leaving the stored findings alone would make the findings pages
describe a reference that is no longer the one configured, so choosing, switching or
clearing a baseline schedules a sweep:

* **Scope.** Only the `baseline_*` rows are replaced - the other built-in findings and
  every `suricata:` match keep the rows they have. This is why the sweep calls
  `detection_engine.rerun_rules` rather than `analyze()`, which erases every finding
  (Suricata's included) and re-runs seventeen rules to answer a question about seven.
* **Off the request path.** `PUT /api/baseline` and `DELETE /api/baseline` return as soon as
  the configuration is written; the sweep runs in a daemon thread and reports itself
  under `recalc` on `GET /api/baseline`. Measured on the 13-capture library in
  `data/` (read-only copy of the same database): **13 analyses in 3.8 s**, 157 baseline
  findings, no errors. For comparison, the full `analyze()`+`suricata` path that the
  Findings page's **Re-run rules** performs took **34.7 s** over the same library.
* **Single-flight.** A second change during a sweep does not start a second thread; it
  marks the sweep to run again, so the last write always wins and the database never has
  two sweeps competing for the write lock.
* **Only where there is something to compute.** Only `completed` analyses with at least
  one indexed packet are swept. The analysis that *is* the baseline is swept too: its
  rules are silent by definition, so the sweep simply removes rows it should not have.
* **Manual repeat.** `POST /api/baseline/recalculate` runs the same sweep on demand -
  useful after re-enabling a baseline rule in [Alert Settings](Alert-Settings.md) - and the
  PCAP Files strip carries it as a **Recalculate** button.
* **Switched off.** `APACKETS_BASELINE_AUTO_RECALC=false` leaves the stored findings alone
  until someone asks: the sweep reports `auto: false` and the endpoints never schedule
  one. The test suite runs with it off, so a sweep can never write while a test asserts.

The interface draws the sweep while it runs: PCAP Files polls `GET /api/baseline` once a
second and shows `N of M analyses done` with the capture in flight, then the finding
counts and lists on every page are invalidated when it finishes.
---

## 6. The interface

### Where the baseline is chosen — [PCAP Files](PCAP-Files.md) (`/files`)

The Analyses table gains a **Baseline** column between File and Size:

* a checkbox on every row, enabled only for a `completed` analysis (the tooltip on a
  disabled checkbox says *A baseline must be a completed analysis*);
* ticking one **replaces** any previous baseline and switches baseline mode on in the same
  call — there is one baseline, so ticking a second row moves it;
* unticking the ticked row clears the baseline entirely;
* the ticked row also shows a `baseline` chip with a scale icon, whose tooltip
  distinguishes "being compared against" from "selected but mode off".

The panel header carries the mode switch: a **Baseline mode** checkbox with an `on`/`off`
chip, disabled until a baseline exists. A strip under the header states the reference, its
frame count and what the mode currently does, or — when nothing is set — explains that
ticking a completed capture makes every later analysis comparable. The panel subtitle gains
` · baseline mode on` while the mode is active.

### Where the difference is read — [Baseline Check](Baseline-Check.md) (`/baseline-check`)

A page of its own, under **Investigate** in the sidebar: the same comparison as counts and
capped samples, one panel per novelty kind, with every entity linking into [Hunt](Investigate.md)
or [Packets](Packets.md). The top bar's chip opens it. It draws no findings and writes
nothing — it is the report behind the seven rules, so a reader can see *what* is novel
without first looking at *what fired*. Its own document is [Baseline-Check.md](Baseline-Check.md).

### Where the mode is visible — the top bar, on every page

While `active` is true, the top bar shows a warning-coloured chip reading
**Baseline mode : enabled** (13 px), linking to `/baseline-check`, with a tooltip naming the
reference capture. It is deliberately on every page and not only on the two that configure
it: a global comparison that changes what the Findings page contains must be visible from
the Findings page. When the mode is off the chip is absent rather than greyed out — an
"off" chip that is always there is furniture, and nobody reads furniture.

---

## 7. Where the data comes from

| Action | Call | Route module |
|---|---|---|
| Read the state (top bar, PCAP Files) | `GET /api/baseline` | `routes_baseline.py` → `baseline.status()` |
| Choose / switch / relabel | `PUT /api/baseline` | `routes_baseline.py` → `baseline.save_config()` |
| Clear it | `DELETE /api/baseline` | `routes_baseline.py` → `baseline.clear_config()` |
| Per-capture comparison (counts and samples) | `GET /api/analyses/{id}/baseline` | `routes_baseline.py` → `baseline.summary()` |

`PUT /api/baseline` rejects, with `400`, an id that does not exist
(`analysis_not_found`), one that has not finished (`analysis_not_ready`, carrying the
status) and one that indexed nothing (`analysis_empty`). The body merges over the current
configuration, so `{"enabled": false}` alone turns the mode off without moving the
reference.

The per-capture endpoint is the read-only view: `active`, `comparable`, the baseline and
capture blocks, the overlap counts and `novel_counts`, with each novelty list capped to 40
samples. It applies the shared readiness gate, so an unfinished analysis is `409`.

---

## 8. Limits and honest caveats

* **One capture is a reference, not a baseline in the statistical sense.** There is no
  averaging, no time-of-day model, no confidence interval. A capture taken during an
  incident describes the incident as normal.
* **Novelty is silent, never wrong-but-loud.** When the two captures share no private
  address you get `baseline_no_overlap` and nothing else. That is deliberate: hundreds of
  findings about a foreign network would be worse than one honest sentence.
* **A service needs an observed SYN.** A capture that begins mid-flow, or a service only
  ever reached over UDP, is only in the profile if a frame recorded it. `SpaceX_ssh.pcapng`
  against `SpaceX_loads_of_tabs.pcapng` reports 4 novel services; a mid-flow capture would
  report fewer, and the difference is the capture's, not the network's.
* **UDP listeners are a heuristic.** For UDP the profile keeps every `dst_port < 49152`,
  because UDP has no handshake to observe. A client that happens to use a low source port
  is counted as a destination port.
* **A change recalculates the findings, but nothing else.** The sweep rewrites only the
  `baseline_*` rows (§5.1); the other built-in findings and every Suricata match keep
  the rows they already had, including their `created_at`. An analysis that was never
  scanned for findings stays unscanned - the sweep does not invent them.
* **The profile is memoised in process.** Four profiles and four comparisons are cached, and
  the caches are dropped on every configuration write. A baseline edited by two processes at
  once is last-writer-wins, because the store is a single `settings` row.
* **A deleted baseline silently stops everything.** `status()` reports it as
  `configured: false` with a reason, and deleting the capture that is the baseline removes
  the comparison for every later analysis until a new one is chosen. There is no "choose the
  nearest surviving capture" fallback.
* **Novelty is order-insensitive and time-blind.** The sets have no timestamps, so "new"
  means "absent from the reference", never "first seen at 14:32". A host that was present
  and silent in the baseline and loud here is not novel.
* **`http_hosts` is profiled but not reported.** The set is built and counted, and no rule
  fires on it yet; a new HTTP `Host:` header is currently only visible through
  `baseline_new_dns` and `baseline_new_sni` when the name is also resolved or presented in
  TLS. That is a gap, kept rather than filled with a noisy rule.

---

## 9. Related

The capture the baseline points at is chosen on [PCAP Files](PCAP-Files.md); the findings
it produces are listed, filtered and opened on [Findings](Findings.md), and the rules
themselves are switched and tuned on [Alert Settings](Alert-Settings.md) beside the other
built-in rules. The measurement behind the seven rules and the rule text they must carry is
[`docs/CONTRACT.md`](../docs/CONTRACT.md) §8; the index the profile is read from is
described in [Architecture.md](Architecture.md) §3.
