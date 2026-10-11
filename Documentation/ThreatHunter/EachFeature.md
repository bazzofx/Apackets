# Per-feature document template

**This file is a template, not a description of a detection.** Every per-feature
document in this folder — the seventeen files that document one Threat Hunt
indicator each — follows the structure below, in this order, with these headings.
Nothing here is filled in: the headings and the note under each one say what
belongs there.

The section itself is documented in [ThreatHunter.md](ThreatHunter.md). The
normative contract for the section is [`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md);
where this template and the code disagree, the code in
`backend/app/services/threat_hunt.py` wins, and the disagreement should be
written down rather than smoothed over.

---

## 1. What it answers

One sentence, phrased as the analyst's question. It is the `question` the
endpoint returns for the indicator and the line the card shows under its title,
so it must be the same claim the code actually computes — not a broader one.

## 2. How to read the card

What the headline number counts, which visual(s) the card draws and what each
axis or column means, and what a high reading looks like against a low one. State
plainly that the headline is `0` only when `availability` is not `"ok"`, so a
zero on screen means "nothing matched" rather than "not computed". Also say what
the card shows when the count is zero — the below-threshold measurements that are
still drawn.

## 3. Detection logic

The correlation as implemented, step by step, in the order the function performs
it. Name the builder function in `backend/app/services/threat_hunt.py` (for
example `_c2_beaconing(index)`) and say which tables each step reads. Mention
where a step is a filter, where it is an aggregate, and where it is a threshold
test, and note anything that is deliberately *not* checked.

## 4. Thresholds

A table of every constant that governs the detection, with its **exact name and
value as written in the code** and one line on what it does. This is the most
important section of the document: if the code says `SCAN_MIN_PORTS = 20`, the
document says `SCAN_MIN_PORTS` and `20`. Include the shared caps
(`TIMELINE_CAP`, `TABLE_CAP`, `SCATTER_CAP`, `PACKET_SCAN_CAP`, `ROW_SCAN_CAP`)
where they bite, and any lookup set the detection consults. Where a threshold
lives in another module (the HTTP analyser's flags, the DNS analyser's name
shape), name that module and its constant too, so a reader can find it.

## 5. Indexed fields used

The columns actually read, named exactly as the schema names them, with the table
prefix (`conversations.start_time`, `dns_queries.entropy`, `tls_sessions.ja3`).
Say what each column supplies to the detection. Where the query reads columns it
never renders, say so.

## 6. Fields the analyst brief asks for but the index does not hold

Be specific and honest about the gap between the question and the data. Name the
missing field as it would appear in a TShark dissection (`icmp.type`, `smb.*`,
`dcerpc.*`, `rdp.*`, `dns.qry.len`, `http.request_in`), state that
`backend/app/db/schema.sql` has no column for it, and describe the workaround the
implementation uses and what that workaround costs in precision. If there is no
workaround, say that the detection is simply blind to that case.

## 7. How to investigate further

Which page to open and with which query parameters, using only the parameters
listed in `docs/THREAT_HUNT.md` §5 — the ones the target pages actually read. A
parameter that no page reads produces a link that silently does nothing. Give the
route and the parameters that land on the rows behind the card, and say what to
look for once there. Use `/packets?mode=basic&sel=<frame>` to open a single
frame, and add `&stream_id=<id>` plus `&transport=udp` where relevant.

## 8. What it does not prove

The caveat in plain language, in the document's own words as well as the wording
the card carries. Every detection is a lead to check, not a verdict: say what an
analyst may reasonably conclude and what they may not.

## 9. Known limits and false positives

The specific legitimate things that look like this — CDNs, telemetry, software
updates, vulnerability scanners, backup jobs, monitoring agents — and any
structural blind spot in the implementation, such as a cap that drops later
buckets, a direction assumption that fails when the capture's bulk transfer runs
inbound, or a detection that is empty because the stage that would populate its
source table never ran.

---

## Conventions for every document in this folder

* Link to other documents in this folder by file name
  (`RareCommunicationPairs.md`) and to the contract as
  [`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md), so every link resolves
  inside the repository.
* Quote constants and column names exactly. Never round a threshold to a
  friendlier number and never invent a field.
* Where a behaviour could not be established from the code — because the column
  does not exist, or the branch was not found — write that it is not established
  rather than guessing.
* Tables where a table helps; prose otherwise. No marketing language.
