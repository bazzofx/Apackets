# Baseline Check

The report page of the [baseline network](Baseline.md): everything this capture holds —
addresses, source/destination pairs, services, DNS names, TLS names and TLS client
fingerprints — that one reference capture never did, with the overlap the two were measured
on. It is the readable form of the comparison the seven `baseline_*` detection rules turn
into findings.

It is reachable at `/baseline-check`, in the left-hand navigation under **Investigate**,
directly after **Threat Map**. The component is `frontend/src/pages/BaselineCheckPage.tsx`;
the comparison itself is `backend/app/services/baseline.py`, and the normative API and rule
text is [`docs/CONTRACT.md`](../docs/CONTRACT.md) §8.

---

## 1. What it is for

The [Findings](Findings.md) page answers "what fired". This page answers the question
underneath it: **what does this capture have that the reference did not?** Findings are
capped, one per host or per source, and they are written in the language of an alert; the
comparison behind them is a set difference with counts and samples, and it is worth being
able to read it directly.

Three consequences shape the page:

* it draws **one** request and nothing else — no re-dissection, no re-run of rules, no
  writes;
* it is honest about non-comparison: with no baseline, with baseline mode off, with this
  capture *being* the baseline, or with a capture from another network, it says which and
  draws no novelty list;
* every count is stated as a count, never as a verdict.

---

## 2. The one request

```
GET /api/analyses/{analysis_id}/baseline
```

React Query key `['baseline-compare', analysisId]`, refetched when the analysis changes. The
envelope is `BaselineSummary` in `frontend/src/types/index.ts`: `active`, a
`reason` when it is not, `comparable`, the `baseline` and `capture` blocks, the
`overlap` counts, `novel_counts` (full totals) and `novel` (capped samples, 40 per
kind).

The page also reads `GET /api/baseline` through the same `['baseline']` query the top bar
uses, so the mode chip and the reference name in the headline are the same data the rest of
the application shows. Both requests are served from a memoised profile of each capture, so
the page costs two SQL passes over the index, not a scan of the pcap.

---

## 3. The four states the page can be in

| State | What the page draws |
|---|---|
| `active: false` — no baseline, or mode off | A panel named *Baseline mode is not in force* carrying the backend's own `reason` (for example *baseline mode is off*), plus a line pointing at [PCAP Files](PCAP-Files.md), where the reference and the switch live. |
| `reason` = *this capture is the baseline itself* | A panel saying a reference cannot be compared with itself, why its own novelty list would be empty by construction, and where to choose another capture or another reference. |
| `comparable: false` | A panel named *This capture and the baseline are different networks*: how many addresses each side holds, that none of them are local to both, and that novelty is withheld **because** reporting a foreign network as new would mean nothing. It names the `baseline_no_overlap` rule that records the same fact. |
| `comparable: true` | The report, below. |

A page that cannot compare never shows an empty difference list: an empty list and a
comparison that never happened look identical, and only one of them is reassuring.

---

## 4. What the report draws

### 4.1 The measurement panel

Four `KpiTile` figures — new addresses, new pairs, new services, new names (DNS +
TLS) — then four label/value rows: this capture's file name, the frames compared on both
sides, the shared addresses (`shared of capture`, and how many are local), and the shared
pairs and DNS names. The reference's own identity, frame count and address count are in the
panel subtitle.

Beneath them, one sentence: either *Nothing novel…* or `<N> differences across X of the six
novelty kinds` naming the kinds that are empty, and always the caveat that novelty is a
fact about two captures and not intent.

### 4.2 The six novelty panels

A panel appears only when its count is non-zero, so the page shortens as the capture looks
more like the reference. Each header carries the kind's **full total**, and a strip appears
when the payload carried fewer rows than the total (the endpoint caps every list at 40
samples) so a truncated list is never mistaken for the whole picture.

| Panel | Rows | Links |
|---|---|---|
| **New addresses** | One row per novel address: the address, whether it is on the local side, how many novel pairs involve it, and a Packets action. | The address opens its [Hunt](Investigate.md) profile (`/investigate?kind=ip&entity=…`); **Packets** opens `/packets?ip=…`. |
| **New pairs** | One row per source address, with its novel destinations as chips (first 8, the rest counted with a tooltip listing them). | Each chip opens that destination's Hunt profile. |
| **New services** | One row per address answering on novel ports, as `port/transport` chips. | Each chip opens `/packets?ip=<host>&port=<port>`. |
| **New DNS names** | One row per name this capture resolved that the reference never queried. | The name and its **Hunt** action open a domain profile. |
| **New TLS server names** | The names as chips. | Each opens a domain profile. |
| **New TLS client fingerprints** | The JA3 strings, with a copy button each. | — (the TLS page has no per-fingerprint route; the string is copyable instead of being made a dead link). |

Two of the panels carry the rule's own scoping as a note rather than as a hidden filter:
`new_host` reports only the private addresses, so a public address in the address list is
explained as a CDN edge or resolver the reference never contacted, and `new_destination` excludes
multicast, broadcast and documentation addresses, so those never appear as reach.

### 4.3 The closing line

*These differences are also written to Findings by the seven `baseline_*` rules.* It also says
that changing the baseline does not rewrite stored findings, and links to
[Findings](Findings.md) — the page where they are recorded.

---

## 5. The headline and the scope note

Under the page title, the meta line carries three chips: the mode (**Baseline mode :
enabled** in the warning tone, or *off* in the quiet one), the reference capture's file name
(a link to PCAP Files), and **findings**. The chip in the top bar across the whole
application opens this page.

Above the body, a collapsible *How to read this section* note lists what the page can and
cannot say: it can report novelty from the index and the overlap it was measured on; it
cannot call novelty a verdict, cannot compare two different networks, and cannot place
anything in time — the profile is a set, so "new" means absent from the reference, never
first seen at a particular moment.

---

## 6. Limits and honest caveats

* **It is the same comparison the rules run, not a second opinion.** If the rules are
  disabled, this page still shows the difference; if the rules are enabled, the page and
  the findings cannot disagree except where a finding is capped at 40 rows.
* **Samples are capped at 40 per kind.** The counts in the panel headers are the true
  totals; the rows are the first 40 in set order, and the page says so when it truncates.
* **Grouping is computed from the capped sample.** The pairs and services panels group
  what the payload carried, so with more than 40 novel entities the panel rows can hold
  fewer chips than the totals suggest.
* **A capture that is the baseline has nothing to show here**, and the page says that
  instead of drawing a zero-filled report.
* **A different network is not a long list.** No baseline overlap means no novelty list at
  all — one honest panel instead of hundreds of meaningless rows.
* **Nothing here re-runs or stores anything.** Changing the baseline, the mode or the
  capture refreshes this page immediately; it does not update the findings already stored
  for the analysis.
* **No per-fingerprint route exists for JA3.** The TLS page lists fingerprints but cannot
  be opened at one, so the strings are copyable rather than linked.

---

## 7. Related

The reference capture, the mode switch and the acceptance rules are [Baseline.md](Baseline.md);
the findings the seven rules write are [Findings](Findings.md); the per-entity lookups the
links open are [Investigate.md](Investigate.md); the other front page of an analysis is
[Threat-Hunt.md](Threat-Hunt.md). The API and the rule text are
[`docs/CONTRACT.md`](../docs/CONTRACT.md) §8.
