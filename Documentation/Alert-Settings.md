# Alert Settings

The rule-management page (`/alert-settings`): the two families of rule that decide what a
capture flags, each showing whether it is still running what shipped, and each restorable to its
default.

The component is `frontend/src/pages/AlertSettingsPage.tsx`, which renders
`frontend/src/components/AlertRulesSection.tsx` - the tab bar and the shared explanation -
around `frontend/src/components/DetectionRulesPanel.tsx` and
`frontend/src/components/SuricataRulesPanel.tsx`. Like [Settings](Settings.md) it is **not**
wrapped in `AnalysisGuard`: the rules are configuration, so the page is fully readable with no
capture selected; only the per-capture features (hit counts, **Re-run on capture**) need one.

It belongs beside Settings rather than inside it because it is not configuration in the same
sense: Settings holds the knobs of this installation, while these two tables *are* the detector,
and reading them is how anyone checks that what shipped is what is running. The section lived on
`/settings` until it was given its own page and its own sidebar entry.

---

## 1. What it is for

It answers the question that comes before trusting any finding: *what is this installation
actually looking for, and is it still what it shipped with?* Every rule is shown with its current
state, the page's verdict on whether that state is the default one, and a way back to the default
when it is not.

Two conventions hold across the whole page:

* **Amber means "not at its defaults"** - a tinted row, a `modified` chip naming what moved, and
  a count on the family's tab. It is the only amber on the page and it means nothing else.
* **Restore is one click away, and only offered where a default exists.** A signature that was
  uploaded has no vendored file to go back to, so its Restore button says so and stays disabled
  instead of inventing one.

## 2. What is on the screen

A page headline (the sidebar group *Settings*, the title *Alert Settings*, the one-line purpose
and the local-only note the shell draws), then one panel holding a two-tab section.

### 2.1 The two rule families

The two rule panels are **tabs of one section**, not two stacked cards. The section header reads
*Alert rules* - *everything the analyser flags - rows tinted amber are not running their
defaults* - and carries one button per family:

| Tab | Panel | Subtitle of the panel below it |
|---|---|---|
| **Detection rules** | The ten built-in heuristics (2.2) | *built-in heuristics run over every capture - view, enable/disable and tune thresholds* |
| **Suricata rules** | The imported signature set (2.3) | *signature-based detections evaluated against this capture's indexed fields* |

Each tab button shows the family's rule count in muted monospace and, **when any rule in that
family is not at its default**, an amber chip with that count and the tooltip *N rule(s) in this
family are not at their defaults*. So the state of both families is visible without opening
either tab - which is the point: the panels used to be stacked, and a tuned detection threshold
sat above a 1,600-row signature table that nobody scrolled to.

The tab is in the URL as `rules=detection` or `rules=suricata`, so a reload or a copied link
keeps the tab. It also settles the two deep links the Findings page uses: `sid=<n>` opens the
**Suricata rules** tab and `rule=<rule_id>` the **Detection rules** tab, because a finding's own
link always means that rule rather than whichever tab was open last. Switching tabs by hand drops
the other family's deep link from the URL, so the address bar never describes a rule that is not
on screen.

Under the tabs sits one explanatory line, identical for both families: both are decisions this
installation makes about your traffic, each panel states what it can change and what it cannot,
and **Restore** puts a rule back to its default - the vendored text for a signature, the
documented thresholds for a heuristic.

**Amber is the "not at defaults" signal, in both tabs.** A row is tinted (`bg-warn/[0.07]`) and
carries a `modified` chip whose tooltip names exactly what moved, and each panel's header reports
how many rules are in that state. The colour is only ever this one and only ever means this one
thing - *this row is not what shipped* - so it cannot be confused with severity, with the
`disabled` styling (60% opacity), or with the `skipped by the matcher` chip.

### 2.2 Detection rules

Subtitle: *built-in heuristics run over every capture - view, enable/disable and tune
thresholds*.

These are the ten rules in `backend/app/services/detection_engine.py` that produce most findings in
a capture. They run first in the pipeline and they are the ones an analyst most often needs to
re-tune: the NXDOMAIN burst, the outbound-volume and the repeated-failed-connection rules are all
threshold rules, and every finding they produce is a comparison against a number that used to be
visible only in this documentation.

**The rules are code, and the panel says so.** Each rule is a Python function; nothing here
can rewrite its matching logic. What the panel changes is the configuration that function
reads - whether it runs, and the thresholds it compares against - and the *Fires when*
sentence is regenerated by the backend from whatever those are set to, so the page can never
describe a threshold the engine is not using.

**Header actions**:

| Button | Call | Notes |
|---|---|---|
| **Refresh** | `GET /api/detection/rules` | Reloads the configuration. |
| **Re-run on capture** | `POST /api/analyses/{id}/findings/rescan` then `POST /api/analyses/{id}/suricata/run` | Disabled until an analysis is selected. The built-in engine deletes every finding row for the analysis, Suricata ones included, so the Suricata matcher is run again immediately after - the same two-step the Findings page uses. |

**Stats strip** (from `GET /api/detection/rules`): how many rules, how many enabled, four severity
count badges, how many rules are **not at defaults** (amber, with a tooltip; the figure is absent
when every rule is at its default), and which capture the hit counts refer to. Measured in this
library: **10 rules**, all enabled, **3 high / 5 medium / 1 low / 1 informational**, none modified.

**Explanation strip**: that the rules are code rather than signatures, and that a change
applies to the next analysis - and to an existing one only after **Re-run on capture**,
because stored findings keep the thresholds they ran with.

**Toolbar**: a search box (*search rule id, title or threshold…*, matching the id, the title,
the threshold sentence and the description), a severity select (`all severities`, `high`,
`medium`, `low`, `informational`), an enabled-state select (`enabled + disabled`,
`enabled only`, `disabled only`), and a count of how many rules the filters are showing.

**The table**:

| Column | Content |
|---|---|
| Severity | A badge, labelled. |
| Rule | The rule's title and, underneath, the `rule_id` in monospace. A rule that is disabled or whose thresholds differ from the defaults also carries an amber `modified` chip whose tooltip lists what moved (`enabled`, `min_nxdomain`, …), and the whole row is tinted amber. |
| Fires when | The threshold sentence, truncated to 460 px with the full text in the tooltip. |
| Hits | Findings this rule produced in the selected analysis; `0` without one. |
| State | A button that toggles the rule between enabled and disabled. Disabled rows are drawn at 60% opacity. |
| Actions | **Edit**, which opens the threshold editor, and **Restore**, which is enabled only while the rule is modified and puts every threshold back to its default and re-enables the rule — the same `{"reset": true}` call the editor's own button makes. |

**The threshold editor** is a modal titled with the rule's title and its `rule_id` and severity,
containing:

* the *Fires when* sentence, so the effect of the numbers below is visible next to them;
* a **Run this rule during analysis** checkbox;
* one row per threshold, with the key in monospace, its unit underneath (`seconds`, `count`,
  `ratio, 0 to 1`, `times the median sender`, `megabytes`, `ports, comma separated`), the
  input, and the documented default beside it;
* the rule's own note, when it has one (*long labels are also common in legitimate CDN, DKIM
  and telemetry domains*, for example).

Values are checked in the browser against the same rules the API applies, so a rejected value
is explained in place rather than only after a round trip. **Save rule** stays disabled until
something actually differs, and **Restore defaults** issues `{"reset": true}` — available from
the editor and from the row's own **Restore** button, so a rule can be put back without opening
the editor at all.

Two keys are deliberately not editable as such:

* `enabled` is the switch above the table, not a threshold; the API refuses it inside
  `thresholds`.
* `max_mb` is a mirror of `max_bytes` that the engine always derives, so the outbound-volume
  rule's byte limit is edited in **megabytes** under the `max_bytes` row and sent as `max_mb`; the
  API converts it and the stored value stays bytes.

Three rules (`http_suspicious_path`, `http_cleartext_credentials`, `indicator_match`) have no tunable
threshold at all - they are pattern and indicator driven - so their editor offers only the
enable/disable switch and says so.

### 2.3 Suricata rules

Subtitle: *signature-based detections evaluated against this capture's indexed fields*.

**Header actions**, left to right:

| Button | Call | Notes |
|---|---|---|
| **Import bundled** | `POST /api/suricata/rules/seed` | Imports the rule sets vendored under `backend/rules/`. Reports how many were new and how many refreshed, and from how many files. |
| **Upload .rules** | `POST /api/suricata/rules/import?enabled=true` | A multiple-file picker (`accept=".rules,.txt"`). The panel keeps only names ending `.rules` and shows a notice naming the rest; the API itself also accepts `.txt` and `.rule`, at most 25 files per request and 16 MiB per file. Upload progress is reported as a percentage bar. |
| **Run on capture** | `POST /api/analyses/{id}/suricata/run` | Disabled until an analysis is selected. The endpoint requires that analysis to be `completed`. |

**Stats strip** (from `GET /api/suricata/rules/stats`): total rules, rules enabled, rules
`evaluable` by the matcher, rules `skipped by the matcher` (in the warning colour, with a
tooltip naming the reasons — flowbits, thresholds, raw payload buffers, undissected
protocols), rules **not at defaults** (amber, shown only when the count is non-zero), four
severity count badges, and up to four sources as `source (N)` joined by `|`.

Measured in this library: **1,615 rules** from **286** `.rules` files, all enabled, **1,115
evaluable** and **500 skipped by the matcher**, **0 not at defaults**; sources
`bundled:daffainfo` (1,150), `bundled:oisf` (448) and `bundled:local` (17).

**Not at defaults** is one API field, not a UI guess: `GET /api/suricata/rules` and
`GET /api/suricata/rules/stats` report `modified` (and, per rule, `restorable` and `differs`),
computed by comparing the stored row with the definition in the vendored rule tree — the text,
the `rev`, and the enabled flag. A rule whose vendored file was corrected in
`backend/rules/local/` is compared against the **local** file, so the 17 corrected rules sit at
their defaults rather than showing as edited.

When at least one rule is not at its default, an amber strip appears above the toolbar: *N
rule(s) are not running their vendored default - their text, revision or enabled state differs
from the file under the bundled rule tree. They are tinted below; Restore puts one back.*

**Engine note**, from `GET /api/suricata/config`: *Engine: `apackets-native-matcher` — Rules
are matched against TShark-extracted fields. The Suricata binary is not required and is not
used. Patterns are matched against TShark-extracted fields (URI, host, method, headers,
bodies, DNS name, TLS SNI); rules that need raw packet payloads are skipped rather than
approximated.*

**Run summary**, drawn after a run completes: how many rules matched, against which capture,
in how long, how many findings that produced, how many rules were evaluated and how many of
those were packet-scope versus HTTP-scope, the four severity counts for this run, and an
**Open findings** button.

**Toolbar**: a search box (*search message, sid or rule text…*, matching `msg`, `raw` or the
`sid` as text), a severity select, an enabled-state select (`enabled + disabled`,
`enabled only`, `disabled only`), a support select (`all rules`, `evaluable by the matcher`,
`skipped by the matcher`), a source select built from the stats (only when at least one
source exists), and a **Refresh** button.

**The rule table** is sorted by severity with high first (`sort=severity&order=asc`) and
paged at 25, 50, 100 or 250 rows.

| Column | Content |
|---|---|
| SID | The rule's signature id. |
| Severity | A badge, labelled. |
| Proto | The rule's protocol. |
| Action | Usually `alert`. |
| Message | The `msg`, truncated to 420 px with the full text in the tooltip. A warning `skipped` chip appears on rules the matcher cannot evaluate (its tooltip lists the unsupported options), a `field match` chip appears on rules matched against extracted fields rather than raw payload bytes, and an amber `modified` chip appears on a rule that is not at its vendored default — its tooltip names what moved (`text`, `revision`, `disabled`) and says whether a default exists to restore. Such a row is also tinted amber. |
| Category | The rule's category, truncated to 170 px; `-` when absent. |
| Source | `bundled:daffainfo`, `bundled:oisf`, `upload:<file>` or `manual`, truncated to 150 px. |
| Hits | How many findings for the currently selected analysis carry `rule_id = 'suricata:<sid>'`. Shows `-` when no analysis is selected and `0` when one is selected but the rule never matched. |
| State | A button that toggles the rule between enabled and disabled. Disabled rows are drawn at 60% opacity. |
| Actions | **Edit** (opens the rule text editor), **Restore** and **Delete** (opens a confirmation dialog). **Restore** is enabled only for a modified rule that has a vendored default; it issues `POST /api/suricata/rules/{sid}/restore`, which rewrites the row from the bundled file — text, `msg`, severity, options, source and category — and re-enables it. Uploaded and hand-written rules have no default, so their Restore button is disabled with a tooltip saying so. |

**The rule editor** is a modal with the rule text verbatim in a monospace textarea, a
character count, and a note: *The rule is stored verbatim. The sid must stay `<sid>` — a rule
cannot be moved to another sid. Saving re-parses the signature and recalculates what the
matcher can evaluate.* **Save rule** stays disabled until the text actually differs from
what was loaded. Editing recalculates `supported`, so a rule can become skippable — or become
evaluable — by an edit.

**The delete dialog** names the rule's `msg` and says: *Imported `<timestamp>` from
`<source>`. Deleting removes the rule and its stored text; findings already produced by it
stay in the analysis.* That last clause is exact: the rule row is removed, the findings
already in `findings` are not.

**Matcher scope** panel, below the table. Read-only, from `GET /api/suricata/config`:

| Row | Content |
|---|---|
| HOME_NET | The configured address ranges. Seven by default: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`. |
| Bundled rule files | `N file(s) in <backend/rules>`. |
| Findings per rule | *at most `25` grouped findings per rule per capture* — the `max_findings_per_rule` default. |
| Suricata binary | `not used - matches run in-process over TShark output`, because the engine reports a null binary. |
| Unsupported options | *rules needing them are skipped and flagged in the table* — the `include_unsupported: false` default. |

`PUT /api/suricata/config` exists and can change `home_net`, `max_findings_per_rule`
(`1`–`1000`) and `include_unsupported`, but **this panel has no controls**, so those values
can only be changed by calling the API directly.

---

## 3. Where the data comes from

| Panel | Call | Route module |
|---|---|---|
| Detection rules tab, stats strip, Hits column | `GET /api/detection/rules` (with optional `analysis_id`) | `backend/app/api/routes_detection.py` |
| Enable/disable, tune, restore a built-in rule | `PUT /api/detection/rules/{rule_id}` (restore is `reset: true`) | `routes_detection.py` |
| Suricata rules tab, stats strip, Matcher scope | `GET /api/suricata/rules`, `GET /api/suricata/rules/stats`, `GET /api/suricata/config` | `backend/app/api/routes_suricata.py` |
| Import / upload / edit / toggle / delete / **restore** a signature | `POST /api/suricata/rules/seed`, `POST /api/suricata/rules/import`, `PUT /api/suricata/rules/{sid}`, `DELETE /api/suricata/rules/{sid}`, `POST /api/suricata/rules/{sid}/restore` | `routes_suricata.py` |
| **Run on capture** | `POST /api/analyses/{id}/suricata/run` | `routes_suricata.py` |
| **Re-run on capture** (detection half) | `POST /api/analyses/{id}/findings/rescan`, then `POST /api/analyses/{id}/suricata/run` | `routes_findings.py`, `routes_suricata.py` |

The client wrappers are `detectionApi` and `suricataApi` in
`frontend/src/services/api.ts`; `importSuricataRules` uses `XMLHttpRequest` rather than `fetch`,
purely so a large rule file can report upload progress.

Tables behind the page:

| Table | Supplies |
|---|---|
| `settings` | The detection configuration under `detection_config` (each rule's `enabled` and thresholds, read through `detection_engine.load_config()`) and the matcher configuration under `suricata_config` (HOME_NET, `max_findings_per_rule`, `include_unsupported`). |
| `suricata_rules` | Everything in the signature table and every figure in its stats strip. `modified`, `restorable` and `differs` are **not** stored: they are computed per request by comparing the row with the vendored rule tree. |
| `findings` | The Hits column only: a correlated subquery counting `rule_id = 'suricata:' || sid` for the selected analysis, and a plain `GROUP BY rule_id` count for each built-in rule id. |
| `analyses` | Whether the per-capture buttons are available, through the top bar's shared selection. |

## 4. Links into the rest of the app

The page is a leaf: nothing here opens another page except **Open findings**, which returns to
[Findings](Findings.md) (`/findings`).

Two inbound links matter, because they are how the page is reached in practice:

* `/alert-settings?sid=<n>` opens the **Suricata rules** tab with its search box seeded with that
  sid, so the table opens filtered to that rule. The Findings workbench uses it: the *Suricata
  rule behind this alert* panel has an **edit in Alert Settings** button.
* `/alert-settings?rule=<rule_id>` does the same for the **Detection rules** tab. The *Detection
  rule behind this alert* panel - shown for every finding whose `rule_id` is not a
  `suricata:<sid>` - links here.

The sidebar entry carries the count of rules that are not at their defaults, in the same amber, so
the state of both families is visible from any page without opening this one.

## 5. Limits and honest caveats

* **A built-in rule's logic is not editable here.** These are Python functions; the page changes
  only whether they run and the numbers they compare against, and says so.
* **A restored signature goes back to the text on disk**, which for the 17 rules corrected in
  `backend/rules/local/` is the *corrected* rule, not the upstream one. That is the point of
  writing corrections as same-SID overrides.
* **Editing a rule does not rewrite findings already stored** for an analysis: they keep the
  thresholds they ran with until the analysis is re-run, which is what **Re-run on capture** does -
  for both engines, because the built-in one clears every finding row.
* **A restored or edited rule is only evaluated on the next run.** A rule that is enabled and
  supported here can still be the reason an analysis was or was not flagged, depending on what was
  in force when it ran.
* **The count only knows about rules that exist.** A deleted signature has no row to report, so it
  is neither modified nor restorable; **Import bundled** brings it back as a new rule.
* **Rule evaluation runs over the index, not the wire.** The matcher reads TShark-extracted
  fields, never raw payload bytes: a signature that depends on a buffer APackets does not extract
  - a raw payload, a flowbit, a threshold across a stream - is either skipped outright or matched
  on its remaining options, and `field match` chips mark the rules evaluated against fields
  rather than payload. As shipped, **1,115 of the 1,615** rules are evaluable and **500** are
  skipped; the stats strip reports the live pair, so editing a rule into an option the matcher
  cannot honour moves it from one figure to the other. A rule being enabled does not mean it is
  being evaluated.
* **Re-running the signatures is idempotent; re-running the built-in engine is not, for Suricata
  findings.** `suricata_engine.run_rules()` deletes only `rule_id LIKE 'suricata:%'` before
  rewriting them, so **Run on capture** can be pressed repeatedly. But
  `detection_engine.analyze()` - **Re-run on capture**, and the rescan on the Findings page -
  deletes **every** finding for the analysis, Suricata ones included. That is why this page runs
  both engines back to back; run only the first and the signature findings are gone until
  **Run on capture** is pressed again, with the Hits column reading `0` in the meantime.
* **Per-rule findings are capped twice, and neither cap is shown as a number.** A signature's
  matches are grouped by a key - the endpoint pair for packet-scope rules, the host and URI for
  HTTP-scope rules - and only the first `max_findings_per_rule` groups (default `25`) become
  findings; a rule that exceeded that has the extras dropped and is counted in `capped_rules`,
  which the run summary on screen does not display. Within one group only the first **10** hits
  are kept and the rest are folded into an `extra` counter on the first hit. A rule that matched
  a thousand times can therefore be represented by twenty-five findings that each stand for more
  than they show.
* **Deleting a signature does not delete its findings.** The dialog says so, and it means the
  findings table can contain alerts whose rule no longer exists anywhere in the interface - only
  the raw `rule_id` string survives, on the Findings page. A deleted rule also has no row here,
  so it is neither counted as modified nor restorable; **Import bundled** brings it back as new.
* **The Matcher scope panel is read-only even though the API is not.** HOME_NET,
  `max_findings_per_rule` and `include_unsupported` can be changed only through
  `PUT /api/suricata/config`. Until then the default HOME_NET is the seven RFC1918, loopback
  and link-local ranges - a configuration choice about the deployment, not a measurement of the
  capture, so a capture from a different address plan is matched with the wrong inside/outside
  assumption.
* **Nothing here validates a rule file against reality.** There is no check that an imported file
  is a newer revision of the one it duplicates, and no warning when two sources ship the same sid
  - the later import silently wins that sid.
* **Re-importing a rule set deliberately does not re-enable it.** `import_rules` upserts by sid
  and leaves the `enabled` column of an existing row alone, so a rule an analyst disabled stays
  disabled after **Import bundled** or after uploading the same file again. That is the useful
  behaviour, and it also means a rule file cannot be used to switch a hundred disabled rules back
  on: they have to be toggled one row at a time. Restore is the exception that does re-enable, and
  it does so one rule at a time.
* **The page works without a capture, but its per-capture half is inert.** With no analysis
  selected, **Run on capture** and **Re-run on capture** are disabled and every Hits column reads
  `0`; the rules, the stats and the matcher scope still load, because they are global.
## 6. Related

[Findings](Findings.md) for what these rules produced; [Settings](Settings.md) for the rest of the
configuration; and [Architecture](Architecture.md) for where the rules sit in the pipeline.
