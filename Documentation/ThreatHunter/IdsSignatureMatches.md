# IDS Signature Matches (`ids_matches`)

Part of the **Threat Map** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Which recorded IDS signatures fired in this capture?**

## 2. How to read the card

The headline counts *IDS signature matches*: findings recorded for this analysis whose
rule id begins with `suricata:` — that is, one row per signature match the IDS stage
produced. It is a count of findings, so one rule that fired on twelve frames is either
one row or twelve rows depending on how the analyser recorded it, and the packet-count
column is what tells the reader which.

One visual is drawn: a **table** of the matches, capped at `TABLE_CAP = 50` rows and
ordered by severity (high, medium, low, informational), then by signature id. Columns:
the severity (drawn with the application's severity badge, so the card reads like the
Findings page), the rule as `suricata:<sid>`, the alert title (linked to the finding
itself), the endpoints — up to four addresses, or up to three hostnames when there are
no addresses — and the number of frames the finding recorded (linked to the first of
them).

A **high** reading is a long table with several high-severity rules, and the card's
headline tone turns to `warn` when any match is high severity. A **low** reading is one
or two informational matches. A zero headline with `availability: "empty"` means the
findings index has rows, but none of them carries a `suricata:` rule id.

This card lists only Suricata-rule findings. The built-in detection engine's findings
(`tcp_syn_scan`, `dns_nxdomain_burst`, `http_suspicious_path`, `outbound_volume`,
`rare_destination_port`, `repeated_failed_connections`, `indicator_match` — see
`docs/CONTRACT.md` §8) live in the same table and are deliberately excluded. An empty
card therefore means "no IDS signature matched, or the IDS stage did not run", and the
rest of the findings are on the Findings page.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_ids_matches(index)` in `backend/app/services/threat_hunt.py`.

1. If the findings index holds no rows for the capture, return `not_applicable` with
   the reason that a signature match cannot be told apart from a detection stage that
   did not run. That is the single most careful decision on the page: an empty
   findings table is ambiguous, so the indicator refuses to call it "nothing matched".
2. Read up to `ROW_SCAN_CAP` findings whose `rule_id` matches `suricata:%`, taking the
   id, rule id, severity, title, reason, packet numbers and entities.
3. Parse the `entities` JSON object, take up to four addresses from its `ips` array and
   up to three names from its `hostnames` array, and parse `packet_numbers` into a list
   of frame numbers.
4. Strip the `suricata:` prefix from the rule id so the table shows the signature id
   alone. A severity that is missing or empty becomes `informational`.
5. Order the matches by severity rank (`high` 0, `medium` 1, `low` 2, `informational`
   3, anything else 4), then by signature id, then by finding id.
6. The headline is the number of matches; the table draws the first `TABLE_CAP = 50`;
   the links name the first five findings. The headline tone is `warn` when any match
   is high severity, otherwise `watch`.

Nothing is re-evaluated and no signature is re-run: the card reports what the analysis
recorded and nothing more.

## 4. Thresholds

This detection has no numeric threshold of its own. Its gates are a rule-id pattern and
two ordering tables.

| Constant | Value | What it does |
|---|---|---|
| `'suricata:%'` | the SQL `LIKE` pattern in the query | Selects the findings that count. Findings from the built-in detection engine are excluded by this pattern. |
| `_SEVERITY_RANK` | `{"high": 0, "medium": 1, "low": 2, "informational": 3}` | Sort order of the table; any other value ranks 4 and sorts last. |
| `_SEVERITY_TONE` | `{"high": "warn", "medium": "watch", "low": "info", "informational": "info"}` | The emphasis colour of the severity cell. |
| `ROW_SCAN_CAP` | `500` | Maximum findings rows read. |
| `TABLE_CAP` | `50` | Maximum rows in the table. |
| `top` | `12` (1–50) | **Not used by this detection**: there is no ranked chart, so the rows-per-visual control does nothing here. |
| `PACKET_SCAN_CAP`, `TIMELINE_CAP`, `SCATTER_CAP` | `20000`, `240`, `200` | Not used by this detection. |

The severity vocabulary (`informational`, `low`, `medium`, `high`) is fixed by
`docs/CONTRACT.md` §3 for the `findings` table; this detection does not invent one.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `findings.rule_id` | The `suricata:%` selection, and the signature id shown in the rule column. |
| `findings.severity` | The sort order and the badge. |
| `findings.title` | The linked alert title, and the label of the card's links. |
| `findings.id` | The `/findings/{id}` link target, percent-encoded. |
| `findings.entities` | The endpoints column: the `ips` array (first four) and the `hostnames` array (first three). |
| `findings.packet_numbers` | The count in the packets column, and the first frame for the `/packets?sel=` link. |
| `findings.reason` | Selected by the query and **not rendered**. The reason string — which by contract states the observed numbers and the threshold — is therefore not on the card, even though it is the most useful text the finding holds. |

## 6. Fields the analyst brief asks for but the index does not hold

* **The signature's provenance.** There is no column for the rule file, revision,
  category or source, and the section does not read the `suricata_rules` table, so the
  card cannot say whether a signature is a curated community rule or a locally written
  one. Every match is presented with the same weight.
* **The event's time.** `findings` has `created_at` — when the finding was recorded —
  and no event timestamp at all, and this detection reads neither. The card therefore
  puts every alert in a flat, severity-ordered list with no time dimension, and an
  alert cannot be placed against the traffic around it.
* **What the signature matched on.** `findings.evidence` is a JSON blob and is not
  read; `findings.description` and `findings.recommendation` are not read either. The
  card shows the title, the endpoints and a frame count, and sends the reader to the
  finding for the rest.
* **The flow.** No column links a finding to a conversation or a stream, so the card
  links to individual frames (`/packets?sel=`) rather than to the conversation the
  alert belongs to.
* **`icmp.type`, `smb.*`, `dcerpc.*`, `rdp.*`.** Not indexed. A signature that depends
  on those fields — which is most of any modern rule set — cannot have matched during
  indexing if the analyser could not evaluate it, and the card can only report what was
  recorded.
* **Direction and outcome.** No column records whether the matched traffic was inbound
  or outbound beyond the endpoint lists, nor whether an attempted exploit succeeded.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The finding itself | `/findings/{id}` | The evidence, reason and recommendation recorded with the alert — the detail this card deliberately leaves out. |
| The first matched frame | `/packets?sel=<first packet number>` | The bytes the signature fired on. |
| The endpoint host | `/hosts?ip=<endpoint>` | Whether the endpoint is the source or the target, and what else it did. |
| Conversations carrying alerts | `/conversations?alerts=1` | The same alerts in conversational context, with byte counts and stream state. |
| Flagged HTTP | `/http?interesting=true` | If the signature was an HTTP rule, whether the transaction is also flagged there. |
| All findings | `/findings` | The built-in detection engine's findings, which this card excludes, plus any severity filter the Findings page offers. |
| The indicators on this page | [`suspicious_http`](SuspiciousHttp.md), [`c2_beaconing`](C2Beaconing.md), [`network_scanning`](NetworkScanning.md) | Whether an alert is corroborated by an independently computed pattern. |

## 8. What it does not prove

A signature match is the most specific evidence on the Threat Map page — a rule
written for a known technique matched frames that were actually captured — and it is
still not a confirmed compromise. It says nothing about whether the attempt succeeded,
and a rule with a loose pattern can fire on ordinary traffic. The card's own caveat
says the same thing:

> A signature match is not a confirmed compromise. Rules trade false negatives for
> false positives, the alert says nothing about whether the attempt succeeded, and an
> empty list only means no rule matched this capture.

## 9. Known limits and false positives

* **False positives are inherent to signatures.** Rules are written to be sensitive;
  any rule set produces alerts on legitimate traffic, and the card gives no way to
  judge a rule's quality beyond its severity and its title.
* **The empty list is ambiguous.** This card reports no matches both when the IDS
  stage ran and found nothing and when the IDS stage never ran with a usable rule set.
  The `not_applicable` case covers an entirely empty findings table, but a capture whose
  findings table holds only built-in-engine findings lands in `empty` with no
  indication that the signature stage produced nothing.
* **Built-in findings are excluded.** Every rule listed in `docs/CONTRACT.md` §8 other
  than the Suricata ones is absent from this table by design. Readers who expect the
  Findings page's list and this card to agree will be surprised.
* **No time, no flow, no evidence on the card.** An alert is a row with a link; the
  context lives on the Findings page and in the frames.
* **Severity is the only ordering.** Two rules of the same severity are ordered by
  signature id, which is arbitrary from an analyst's point of view.
* **Caps.** At most `ROW_SCAN_CAP = 500` findings are read and the table shows the
  first `TABLE_CAP = 50`, so on a capture with many alerts the low-severity matches
  are cut off first — the sort order means the omissions are the ones least likely to
  matter, but the card does not say it truncated. The endpoints column is also
  truncated to four addresses and three hostnames per finding without saying so.
* **An empty card is not a clean capture.** It means no finding in this analysis has a
  rule id beginning `suricata:`.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [Findings](../Findings.md) · [Packets](../Packets.md) · [SuspiciousHttp](SuspiciousHttp.md) · [PossibleMalwareDownload](PossibleMalwareDownload.md)
