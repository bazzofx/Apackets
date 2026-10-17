# Settings

The configuration and rule-management page (`/settings`): what the backend is actually
running with, the handful of values an analyst may change, the **Users & Passwords**
discovery switch and its protocol selection, the indicators the detection engine matches
against, the **Alert rules** section (the built-in detection rules and the imported Suricata
signatures, as two tabs of one section), and the four colour themes.

The component is `frontend/src/pages/SettingsPage.tsx`, with
`frontend/src/components/ThemePanel.tsx`,
`frontend/src/components/AlertRulesSection.tsx` (which holds
`frontend/src/components/DetectionRulesPanel.tsx` and
`frontend/src/components/SuricataRulesPanel.tsx`) as its large pieces. Like
[PCAP Files](PCAP-Files.md) it is **not** wrapped in `AnalysisGuard`: most of the page makes
sense with no capture selected, and only the rule panels' per-capture features need one.

---

## 1. What it is for

It answers three questions an analyst has to be able to answer before trusting a figure
elsewhere in the application: *what is this build configured to do?*, *what does the
detector treat as suspicious?*, and *which threshold am I looking at?* It is also the only
place where configuration can be changed without editing files, and the only place where
analyst-supplied indicators are entered.

## 2. What is on the screen

Seven panels, in this order.

### 2.1 Theme

The first panel, above everything else. Four palette cards in a
`grid-cols-1 sm:grid-cols-2 xl:grid-cols-4` grid. Each card shows the theme's label, a strip
of five representative swatches, its description, and three chips: `accent`, `accent 2` and
`8 series`. The active card carries a check-marked `active` chip and an accent border; the
others read `select`. Clicking anywhere on a card switches the theme immediately — no save
step, no page reload — and the choice is written to this browser's `localStorage`.

Panel subtitle: *applies immediately across the app and is remembered in this browser*. The
panel's footnote says the palette drives interface colours, charts and the network map, that
severity colours keep the same meaning in every theme, and that every combination is
checked for text contrast.

The four themes, with the values read out of `frontend/src/theme/themes.ts`:

| Internal id | Label | Description (as written in the code) | `accent` | `accent2` |
|---|---|---|---|---|
| `steel-blue` | Steel Blue | The original restrained analyst palette: deep navy, a single blue accent, quiet greys. | `#3b82f6` | `#60a5fa` |
| `cyber-punk` | Cyber Punk | Neon magenta and cyan on purple-black. The boldest and highest-contrast of the four. | `#ff2d95` | `#22d3ee` |
| `cyber-samurai` | Cyber Samurai | Crimson and gold on ink-black with warm paper text. Muted, print-like series colours. | `#d7263d` | `#e8b04b` |
| `soc` | SOC | Security-operations cyan on navy-black, with green reserved for healthy status. | `#06b6d4` | `#22d3ee` |

Steel Blue is the default (`DEFAULT_THEME_ID = 'steel-blue'`) and is what an unknown or
unreadable stored value falls back to.

**What a theme actually changes.** Every colour in the interface comes from one place —
`frontend/src/theme/themes.ts` is the only file in `src/**` allowed to contain a colour
literal. Each theme supplies 23 named tokens:

| Group | Tokens |
|---|---|
| Surfaces | `bg`, `surface`, `surface2`, `border`, `border2` |
| Brand | `accent`, `accent2` |
| Type | `text`, `muted`, `faint` |
| Accent bloom | `glow` — drawn behind the KPI row and the map |
| Severity | `sevInformational`, `sevLow`, `sevMedium`, `sevHigh` |
| Status | `ok`, `warn`, `danger` |
| Chart series | `chart` — exactly eight hues, chosen to avoid the amber and red severity hues |
| Map classification | `mapPrivate`, `mapPublic`, `mapMulticast`, `mapLocal`, `mapUnclassified` |

Those 23 tokens are published as CSS custom properties on `<html>` as `r g b` channel
triples (`rgb(var(--c-…) / <alpha-value>)` is what Tailwind's opacity syntax needs), which
is why ordinary Tailwind classes such as `bg-surface` and `border-danger/50` re-theme
without any component knowing about the theme. `--c-glow` is published whole instead,
because it always carries alpha. The eight chart hues are also published as
`--c-chart-1` … `--c-chart-8`. `applyTheme` additionally sets `data-theme` and
`data-theme-ready` on `<html>` and pins `color-scheme: dark`.

Charts and inline SVG cannot use CSS classes for a concrete colour, so they read
`useThemeTokens()` and get the same values as plain strings — which is how the protocol
donut, the traffic charts and the network map follow the palette.

`frontend/index.html` carries a small pre-paint script so a stored theme never flashes
Steel Blue. It mirrors **only** `bg`, `surface` and `surface2` for the four ids, sets
`data-theme`, and falls through to `steel-blue` when storage is unavailable or the stored
value is not one of the four. The full palette is deliberately not duplicated there;
`ThemeProvider` replaces the hints on mount.

Because the preference lives in `localStorage['apackets.theme']`, it is per browser and per
machine. It is not sent to the backend, not stored in the database, and not shared with
anyone else looking at the same capture.

### 2.2 Effective settings

A read-only definition list, subtitle *read from the backend configuration and the persisted
settings table*.

| Row | Source |
|---|---|
| Data directory | `settings.data_dir` |
| Uploads directory | `settings.uploads_dir` |
| Analyses directory | `settings.analyses_dir` |
| Exports directory | *not returned by the API — always `—`* |
| Max upload | `max_upload_mb`, rendered as `N MB` |
| Retain uploads | `yes — captures kept on disk` or `no — captures discarded` |
| Max object size | `max_object_bytes`, byte size |
| Body preview limit | `body_preview_bytes`, byte size |
| TShark timeout | `tshark_timeout_s`, formatted as a duration |
| Max packet rows | *not returned by the API — always `—`* |
| Max DNS rows | *not returned by the API — always `—`* |
| Worker threads | `worker_threads` |
| Bind address | `host:port` |
| Log level | `log_level` |
| Backend version | `version` from `app.__version__` |
| TShark | A green `available <version>` chip or a red `unavailable` chip, then the resolved binary path, or *not resolved — set a path or add tshark to PATH* |

Three rows are permanently blank, and that is worth knowing before reading anything into
them:

* **Exports directory** — `Settings.exports_dir` exists and `ensure_dirs()` creates it, but
  `runtime_settings.effective()` does not include it in the payload the endpoint returns.
* **Max packet rows** — `settings.max_packet_rows` exists (default `0`, meaning "index every
  packet") but is not in the effective payload, and nothing in the pipeline reads it.
* **Max DNS rows** — the DNS analyser reads it as
  `getattr(settings, "max_dns_rows", 0) or None`, but no such field is declared on
  `Settings` and the model is configured `extra="ignore"`, so the attribute is always
  absent and the cap is never applied.

The endpoint returns three fields this panel does not show: `db_path`, `allowed_extensions`
and `max_export_rows` (default `200,000`, the hard cap on rows in a single CSV export).

### 2.3 Editable settings

Subtitle: *PUT /api/settings — persisted to the settings table and applied to new
analyses*. A **Save settings** button sits in the panel header and stays disabled only while
a save is in flight.

| Control | Unit | Hint shown under it | Default | Accepted range |
|---|---|---|---|---|
| Max upload | MB | larger uploads are rejected with 413 | `512` | `1` … `10240` |
| Max object size | bytes | bigger objects are recorded as partial | `52428800` (50 MiB) | `1024` … `2147483648` (2 GiB) |
| Body preview | bytes | HTTP body preview kept per transaction | `262144` (256 KiB) | `1024` … `8388608` (8 MiB) |
| TShark timeout | seconds | a slower TShark call returns 504 | `300` | `10` … `7200` |
| Retain uploads | — | *keep capture files after analysis* (checkbox) | checked | — |

Defaults and ranges are the ones in `backend/app/core/config.py` and
`backend/app/core/runtime_settings.py`; the range table is `INT_BOUNDS`. The ranges are
enforced **by the server**, not by the browser: the page only checks that each field parses
as a positive whole number and refuses to send otherwise (message: *X must be a positive
whole number (no decimals, no units).*). A value outside a range comes back as a `400`
`invalid_setting` naming the bounds and is displayed as a **Save failed** panel under the
form. On success the form is re-filled from the response and *Saved at
`YYYY-MM-DD HH:MM:SS.mmm`* appears in the success colour.

The five keys are the complete set the endpoint accepts. A request carrying none of them is
rejected as `400 no_changes`. The response shape is `{ ok, changed, settings }`, where
`settings` is the whole effective settings view again — so the Effective settings panel
above refreshes with the same values the save wrote.

They are persisted as one JSON object under the `settings` table key `app_settings`, and
`runtime_settings` caches that object in-process, replacing the cache on every write. The
Settings page also invalidates its `settings` and `health` queries after a save.

**Which of these five are honoured without a restart.** This is the most misleading thing on
the page, so it is worth stating exactly:

| Key | Who reads it | Does an edit take effect immediately? |
|---|---|---|
| `max_upload_mb` | `routes_analyses.upload_analysis()` via `runtime_settings.max_upload_bytes()` | **Yes.** The next upload is checked against the new value. |
| `max_object_bytes` | `app/services/object_extractor.py` reads `settings.max_object_bytes` from `app.core.config` | **No.** The extractor reads the environment-derived value captured at import. |
| `body_preview_bytes` | `app/services/http_analyzer.py` reads `settings.body_preview_bytes` from `app.core.config` | **No**, same reason. |
| `tshark_timeout_s` | `app/services/tshark.py` reads `settings.tshark_timeout_s` from `app.core.config` | **No**, same reason. |
| `retain_uploads` | Stored, returned as `retain_uploads` in `GET /api/settings`, echoed per analysis as `upload_retained` — and read by nothing else | The label changes; no behaviour changes, because no code purges an upload. `.env.example` describes the flag as controlling whether packet detail and stream views work, which is not what the code does. |

So four of the five fields behave as documentation of intent rather than as controls: the
value is saved, echoed back into the Effective settings panel as though it were live, and
ignored by the analysers. Changing object size, body preview or the TShark timeout for real
means setting `APACKETS_MAX_OBJECT_BYTES`, `APACKETS_BODY_PREVIEW_BYTES` or
`APACKETS_TSHARK_TIMEOUT_S` in the environment (or `.env`) and restarting the backend — the
mechanism documented in [Getting-Started.md](Getting-Started.md). See §5 for the rest of the
start-up-only settings.

### 2.4 Users & Passwords discovery

Panel title *Users & Passwords discovery* — the visible name matches the sidebar entry, which is
the [Users & Passwords](Credentials.md) page. Subtitle: *the cleartext credential stage's own
switch and protocol selection (docs/CREDENTIALS.md §7)*. A **Save Users & Passwords settings**
button sits in the panel header and is enabled only while the block differs from what the settings
payload currently holds.

| Control | Setting | Default | Meaning |
|---|---|---|---|
| *search new analyses for cleartext credentials* (checkbox) | `credential_scan_enabled` | checked | With it off, the pipeline **skips the stage** and writes no rows at all |
| Protocol checkboxes: HTTP, FTP, SMTP, POP3 and IMAP | `credential_protocols` | all five | Which protocols' locations the scanner reads. An empty selection means **none**, not "all" |

Both live in the `settings` table under `credential_config` and are saved through the same
`PUT /api/settings` the Editable settings panel uses, but in **their own request**: the save
sends only the two credential keys, so editing one block can never submit the other's fields.
What the controls show is read from `GET /api/settings` on every render, and an unsaved edit
is held beside it — so the block draws the real configuration on the first frame, and a change
that is toggled back by hand leaves the form clean again (the save button is enabled only while
the edit differs from the payload). An unsaved change is labelled *Unsaved change — the pipeline
keeps using the settings below until Save Users & Passwords settings is pressed*, and a successful
save writes the response's settings view into the page's settings query and reads *Saved at
`YYYY-MM-DD HH:MM:SS.mmm` — applied to analyses started after the save; what was already found is
untouched*.

If the settings API returns neither `credential_scan_enabled` nor `credential_protocols`, the
panel says so instead of drawing the controls: showing the contract's defaults would describe
the contract rather than this installation. When exactly one of the two keys is missing, the
other is shown and the missing one falls back to its documented default. The list of protocol
checkboxes is `credential_protocols_available` from the same payload — the protocols this backend
will accept — falling back to the contract's five when the payload does not carry it, so the
block cannot offer a protocol the server would reject.

Directly under the panel, the block's explanation is a **collapsed help card**
(`ScopeNote`, the same component the protocol pages and the Users & Passwords page use), titled
*What switching Users & Passwords discovery off does, and does not do*. It states that the switch
governs future analyses, that the protocol selection narrows where the scanner looks, and
three things it is not: **nothing is deleted** (the rows an earlier run found stay in the
analysis and stay readable on the [Users & Passwords](Credentials.md) page, which reports the
setting's state beside them so the two cannot be confused), it cannot read anything encrypted
— not with the scan on — and it is not a new capture pass, because the scanner reads the rows
the other analysers already stored.

### 2.5 Indicators

Subtitle: *analyst-supplied indicators matched by the indicator_match rule (global scope)*,
with the total indicator count as a chip in the header.

The entry row is a toolbar of four controls:

| Control | Notes |
|---|---|
| Type select | `ip`, `domain`, `port`, `ja3`, `ja4`, `ua`, `sha256` — in that order. |
| Value input | Placeholder changes with the type: `10.0.0.9`, `c2.example.net`, `4444`, a full `771,4865-4866-4867,0-23-65281-10-11,29-23-24,0` JA3 string, a `t13d1516h2_8daaf6152771_b186095e22b6` JA4 string, `Mozilla/5.0 (compatible; suspicious-agent)`, or a 64-character SHA-256. |
| Note input | *note (optional, shown in the finding)* |
| Add indicator | Sends the indicator; disabled while the request is in flight. |

Validation happens in two places. The browser refuses an empty value (*An indicator needs a
value.*), a `port` that is not an integer between `1` and `65535`, and an `ip` containing a
space. The server enforces the same type list, a non-empty value, and a port between `0` and
`65535` — so a port of `0` is refused by the page but would be accepted by the API.

The indicator table:

| Column | Content |
|---|---|
| Type | An accent chip with the type as stored (lower-cased). |
| Value | Truncated to 360 px, full value in the tooltip. |
| Note | Clamped to a fixed width and truncated, with the full note in the tooltip; `—` when absent. |
| Scope | The row's `analysis_id`, or the word `global` when it is null. |
| Added | `created_at` as `YYYY-MM-DD HH:MM:SS.mmm`. |
| Actions | **Delete**, which removes the row with no confirmation. |

There is no edit: an indicator is added and deleted, never amended. When the table is empty
the panel reads *No indicators defined. Indicators you add here are matched against every
analysis.*

Where indicators are consumed: the built-in detection engine's rule 10, `indicator_match`,
reads `WHERE analysis_id IS NULL OR analysis_id = ?` — every global indicator plus the ones
scoped to the capture being analysed — caps the loop at
`MAX_FINDINGS_PER_RULE = 60` indicators per analysis, and skips any row whose type is not in
`{"ip", "domain", "port", "ja3", "ja4", "ua", "sha256"}`. Each match becomes a finding whose
reason text names the indicator's id, scope, type and value, and whose evidence carries the
indicator's note, the table it matched in, the number of matching rows and the earliest
match's timestamp.

Measured on the library in `data/`: **6 indicators** — three global (`ip 192.168.1.50`,
`ip 203.0.113.250`, a `sha256`) and three scoped to the fixture analysis
`detect_verify.pcap` (`port 8443`, `domain nope3.example.com`, `ua sqlmap/1.7`).

Important: `GET /api/indicators` is called with no `analysis_id`, which returns **every** row
in the table. The three analysis-scoped indicators therefore appear in this list labelled
with their analysis id, even though `indicator_match` will never apply them to any other
capture. There is no control on this page to choose the scope, so anything added here is
always global.

### 2.6 Alert rules

The two rule panels are **tabs of one section**, not two stacked cards. The section header reads
*Alert rules* - *everything the analyser flags - rows tinted amber are not running their
defaults* - and carries one button per family:

| Tab | Panel | Subtitle of the panel below it |
|---|---|---|
| **Detection rules** | The ten built-in heuristics (2.7) | *built-in heuristics run over every capture - view, enable/disable and tune thresholds* |
| **Suricata rules** | The imported signature set (2.8) | *signature-based detections evaluated against this capture's indexed fields* |

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

### 2.7 Detection rules

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

### 2.8 Suricata rules

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

### 2.9 Local-only operation

Four static statements, not data read from the backend: that capture files, decoded packets,
extracted objects, hashes and findings never leave the machine and that the frontend talks
only to the local backend on `127.0.0.1` through `/api`; that there is no telemetry, no
analytics and no update check, the only outbound behaviour being whatever the local TShark
configuration does; that derived data is stored in SQLite under the data directory shown
above and can be removed per analysis from [PCAP Files](PCAP-Files.md); and that TShark is
invoked with an argument list (`shell=False`) so capture content is never interpolated into
a command line.

## 3. Where the data comes from

| Panel | Call | Route module |
|---|---|---|
| Effective settings, Editable settings | `GET /api/settings`, `PUT /api/settings` | `backend/app/api/routes_settings.py` |
| Users & Passwords discovery | `GET /api/settings`, `PUT /api/settings` (only `credential_scan_enabled` and `credential_protocols`) | `routes_settings.py`; the stage itself is `backend/app/services/credential_analyzer.py` |
| Indicators | `GET /api/indicators`, `POST /api/indicators`, `DELETE /api/indicators/{id}` | `routes_settings.py` |
| Detection rules table, stats strip, Hits column | `GET /api/detection/rules` (with optional `analysis_id`) | `backend/app/api/routes_detection.py` |
| Enable/disable, tune or reset a detection rule | `PUT /api/detection/rules/{rule_id}` | `routes_detection.py` |
| Re-run on capture (detection half) | `POST /api/analyses/{id}/findings/rescan`, then `POST /api/analyses/{id}/suricata/run` | `routes_findings.py`, `routes_suricata.py` |
| Suricata rules table, stats strip | `GET /api/suricata/rules`, `GET /api/suricata/rules/stats` | `backend/app/api/routes_suricata.py` |
| Matcher scope | `GET /api/suricata/config` | `routes_suricata.py` |
| Import / upload / toggle / edit / delete a rule | `POST /api/suricata/rules/seed`, `POST /api/suricata/rules/import`, `PUT /api/suricata/rules/{sid}`, `DELETE /api/suricata/rules/{sid}` | `routes_suricata.py` |
| Run on capture | `POST /api/analyses/{id}/suricata/run` | `routes_suricata.py` |
| Hits column | part of `GET /api/suricata/rules`, with `analysis_id` set | `routes_suricata.py` |
| Theme | *no API call at all* — `localStorage` and `frontend/src/theme/themes.ts` | — |

The client wrappers are `settingsApi`, `detectionApi` and `suricataApi` in
`frontend/src/services/api.ts`;
`importSuricataRules` uses `XMLHttpRequest` rather than `fetch`, purely so a large rule file
can report upload progress. The theme needs no endpoint: `ThemeProvider` holds it in React
state, publishes CSS custom properties and mirrors the id into `localStorage`.

Tables behind the page:

| Table | Supplies |
|---|---|
| `settings` | The runtime overrides, under the keys `app_settings` (the five editable values), `credential_config` (`credential_scan_enabled`, `credential_protocols`) and `suricata_config` (HOME_NET, `max_findings_per_rule`, `include_unsupported`, per-variable overrides). All are read through `runtime_settings.load_overrides()`. |
| `indicators` | The whole indicator table: `type`, `value`, `note`, `created_at`, and `analysis_id` which is NULL for global rows. |
| `suricata_rules` | Everything in the rules table and every figure in the stats strip: `sid`, `rev`, `action`, `protocol`, `msg`, `category`, `severity`, `options`, `unsupported`, `supported`, `approximate`, `enabled`, `source`, `raw`, `created_at`, `updated_at`. The `modified` / `restorable` / `differs` columns are **not** stored — they are computed per request by comparing the row with the vendored rule tree. |
| `findings` | The Hits column only: a correlated subquery counting `rule_id = 'suricata:' \|\| sid` for the selected analysis, and a plain `GROUP BY rule_id` count for each built-in rule id. |
| `detection_config` (a `settings` row) | Every detection rule's `enabled` flag and thresholds, read through `detection_engine.load_config()` and written by `PUT /api/detection/rules/{rule_id}`. |
| `analyses` | Whether **Run on capture** is available, through the top bar's shared selection. |

The effective settings view is assembled by `runtime_settings.effective()`, which resolves
each editable key through `_int_value()` — clamp to the key's bound, fall back to the value
from `app.core.config` when the stored value is missing or unparsable — and then merges in
the directories, `allowed_extensions`, `worker_threads`, `max_export_rows`, `host`, `port`
and `db_path`; `routes_settings.effective_settings()` adds `version`, `tshark`, `local_only`
and `telemetry: false`.

## 4. Links into the rest of the app

Settings is mostly a leaf: the theme panel and both configuration panels open nothing, and
the indicator table has no drill-down.

| Element | Opens |
|---|---|
| **Open findings** (in a Suricata run summary) | `/findings` |
| **Run on capture** | Nothing — it evaluates rules against the selected capture and returns counts |
| Import / upload / edit / delete / toggle / **Restore** a rule | Nothing — the table refreshes in place, and the notice names what changed |
| **Detection rules** / **Suricata rules** tabs | Each other — the tab is written to the URL as `?rules=detection` or `?rules=suricata` |
| **Save Users & Passwords settings** | Nothing — it writes the two credential keys and the panel reports the save in place |
| Edit / toggle / **Restore defaults** on a detection rule | Nothing — the table refreshes in place, and the notice reports the regenerated *Fires when* sentence |
| **Re-run on capture** (detection rules) | Nothing — it rewrites the selected analysis's findings and reports both engines' counts |

Three inbound links matter, because they are how this page is reached in practice:

* `/settings?sid=<n>` opens the **Suricata rules** tab and seeds its search box with that
  value, so the table opens filtered to that rule. The Findings workbench uses it: the *Suricata
  rule behind this alert* panel has an **edit in settings** button that navigates to
  `/settings?sid=<sid>`. The search is a
  substring match over message, sid and rule text, so a sid whose digits also occur in another
  rule's text pulls that rule into the list as well — the filter narrows the table, it does
  not prove uniqueness.
* `/settings?rule=<rule_id>` does the same for the **Detection rules** tab: it opens that tab
  and seeds its search box with the id, so the table opens on the one rule. The Findings
  workbench uses it the other way round: the *Detection rule behind this alert* panel, shown for
  every finding whose `rule_id` is not a `suricata:<sid>`, has an **edit in settings** button
  that navigates to `/settings?rule=<rule_id>`.
* The [Users & Passwords](Credentials.md) page links here from its disabled-scan panel and from
  both of its empty states, because the switch this panel edits is the reason those states exist.
* The sidebar's Settings item, which is present on every page.

The capture selector in the top bar decides which analysis **Run on capture** and the Hits
column apply to. With no capture selected the button is disabled and Hits reads `-`.

## 5. Limits and honest caveats

* **A tuned detection threshold does not change findings that already exist.** The numbers are
  read by the detection stage when it runs, so an analysis keeps the findings its thresholds
  produced until it is re-run — and the built-in engine clears every finding row for the
  analysis when it runs, Suricata ones included, which is why **Re-run on capture** runs both
  engines. The panel's explanation strip and the *Fires when* sentence in the finding view say
  so rather than leaving it to be discovered.
* **Only `max_upload_mb` really takes effect without a restart.** See §2.3. The other three
  numeric fields are saved and displayed as effective, while `object_extractor`,
  `http_analyzer` and `tshark` keep using the values `app.core.config.Settings` captured at
  import. `runtime_settings.load_overrides()` is consulted by the settings view, the upload
  route, and the Suricata config — nowhere else.
* **The `retain_uploads` checkbox changes a label and nothing else.** See §2.3. The
  *Effective settings* panel will read `no — captures discarded` and the captures will still
  be on disk, because no code path purges a stored upload; the checkbox's own hint,
  *keep capture files after analysis*, describes a policy the build does not implement.
* **Three rows on the Effective settings panel can never show a value.** Exports directory,
  Max packet rows and Max DNS rows are all `—` by construction: the API does not return the
  first two, and the third does not exist as a setting at all. `max_dns_rows` is read by the
  DNS analyser but never declared, so the cap that field implies is not in force.
* **Other settings are read once, at start-up, and are not editable anywhere in the UI.**
  `data_dir`, `tshark_path`, `capinfos_path`, `max_packet_rows`, `worker_threads`,
  `max_export_rows`, `host`, `port`, `cors_origins`, `log_level` and `allowed_extensions`
  come from the environment or `.env` through a cached `get_settings()`. `worker_threads`
  in particular sizes the job thread pool the first time `JobManager.pool` is touched, so a
  change there needs a restart even to be noticed. The page shows `worker_threads`,
  `host:port` and `log_level`; the rest are visible only in the code or in `.env.example`.
* **The theme is a local preference, not analysis data.** It is stored per browser, is not
  in the database, and is not shared. Two analysts on the same machine can be looking at the
  same capture in different palettes — and a screenshot's colours are therefore not evidence
  of what build was used. The panel's claim that every combination is "checked for text
  contrast" is a statement in the component's own comment; this document did not measure
  contrast ratios.
* **A theme changes the charts, but not what a severity colour means.** The four severity
  hues keep their vocabulary (`informational`, `low`, `medium`, `high`) and their relative
  reading in every palette, but the eight *chart* hues differ per theme — so a series colour
  seen in one palette does not identify the same series in another.
* **Indicators cannot be edited or scoped from this page.** They are added and deleted only,
  every one added here is global, and a delete has no confirmation and no undo. Deleting an
  analysis also deletes the indicators scoped to it — `delete_analysis` clears
  `indicators WHERE analysis_id = ?`, which cannot touch the global rows because NULL never
  matches an equality test.
* **The indicator list mixes scopes.** The panel asks for every indicator and shows each
  row's `analysis_id`. A row scoped to another capture looks like an ordinary entry but will
  never match anything except that capture, and nothing on the screen says so.
* **An indicator match is a lead, not a verdict.** The rule's own reason text says the value
  was supplied by an analyst rather than derived from traffic behaviour, so a match has to be
  confirmed to resolve to the same entity the indicator was collected from before it is acted
  on. A port indicator matches any packet carrying that port as source or destination, which
  is a much weaker statement than "this service was used".
* **Indicator matching is capped.** `indicator_match` evaluates at most
  `MAX_FINDINGS_PER_RULE = 60` indicators per analysis, in `id` order, so on a long indicator
  list later rows are not evaluated at all and the findings give no hint of it.
* **Rule evaluation runs over the index, not the wire.** The matcher reads TShark-extracted
  fields, never raw payload bytes. **501 of the 1,615** rules stored in this library are
  skipped by the matcher because they need options it cannot evaluate — raw payload buffers,
  flowbits, thresholds, undissected protocols — and they are stored, listed and toggled like
  any other. A rule being enabled does not mean it is being evaluated; the stats strip's
  `evaluable` count is the honest number, and every skipped rule carries a `skipped` chip in
  the table.
* **Rules do not create packets.** A rule can only match what the dissectors already
  recorded, so a signature that depends on a buffer APackets does not extract — a raw
  payload, a flowbit, a threshold across a stream — is either skipped or matched on its
  remaining options. `field match` chips mark the rules that were evaluated against fields
  rather than payload.
* **Re-running rules is idempotent; re-running the built-in engine is not, for Suricata
  findings.** `suricata_engine.run_rules()` deletes only `rule_id LIKE 'suricata:%'` before
  rewriting them, so **Run on capture** can be pressed repeatedly. But
  `detection_engine.analyze()` — the rescan on the Findings page — deletes **every** finding
  for the analysis, Suricata ones included. After a built-in rescan the Suricata findings are
  gone until **Run on capture** is pressed again, and the Hits column will read `0` in the
  meantime.
* **Per-rule findings are capped twice, and neither cap is shown as a number.** A rule's
  matches are grouped by a key — the endpoint pair for packet-scope rules, the host and URI
  for HTTP-scope rules — and only the first `max_findings_per_rule` groups (default `25`)
  become findings; a rule that exceeded that has the extras dropped and is counted in
  `capped_rules`, which the run summary on screen does not display. Within one group, only
  the first **10** hits are kept and the rest are folded into an `extra` counter on the first
  hit. A rule that matched a thousand times can therefore be represented by twenty-five
  findings that each stand for more than they show.
* **Deleting a rule does not delete its findings.** The dialog says so, and it means the
  findings table can contain alerts whose rule no longer exists anywhere in the interface —
  only the raw `rule_id` string survives, on the Findings page.
* **The Matcher scope panel is read-only even though the API is not.** HOME_NET,
  `max_findings_per_rule` and `include_unsupported` can be changed only through
  `PUT /api/suricata/config`. Until then, the by-default HOME_NET is the seven RFC1918,
  loopback and link-local ranges — which is a configuration choice about the deployment, not
  a measurement of the capture, and a capture from a different address plan will be matched
  with the wrong inside/outside assumption.
* **Nothing here validates the indicators or the rules against reality.** There is no
  duplicate detection for indicators, no check that a rule file is a newer revision of the one
  it duplicates, and no warning when two sources ship the same sid.
* **Re-importing a rule set deliberately does not re-enable it.** `import_rules` upserts by
  sid and leaves the `enabled` column of an existing row alone, so a rule an analyst disabled
  stays disabled after **Import bundled** or after uploading the same file again. That is the
  useful behaviour, and it also means a rule file cannot be used to switch a hundred disabled
  rules back on: they have to be toggled one row at a time.
* **The page works without a capture, but its Suricata half is partly inert.** With no
  analysis selected, **Run on capture** is disabled and Hits reads `-`; the rules, stats and
  matcher scope still load, because they are global.
* **The Users & Passwords switch is a setting, not a purge.** Turning `credential_scan_enabled`
  off stops the stage in analyses started afterwards; it deletes no row that an earlier run wrote,
  and the [Users & Passwords](Credentials.md) page keeps listing those rows while reporting that
  the setting is off. An empty credentials table for such an analysis is a statement about the
  setting, not about the capture.
* **An empty protocol selection means none, not all.** `credential_protocols` is a positive
  list: unticking all five leaves the scanner with nothing to read, and the Users & Passwords page
  states that as its own case rather than presenting an empty table. The two keys are
  independent — the master switch does not clear the protocol list, and the protocol list does
  not re-enable the switch.
* **Nothing on this panel decrypts anything.** The scanner reads the locations
  [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) §2 defines — cleartext HTTP fields and
  FTP/SMTP/POP3/IMAP authentication commands — and never examines TLS, SSH or SMB-signed
  traffic. Switching discovery on cannot change that, and the panel says so.
* **This panel reports what the settings API exposes.** If the payload carries neither
  `credential_scan_enabled` nor `credential_protocols`, the block states that it can neither
  show nor change them rather than drawing the contract's defaults as this installation's
  configuration. The saved values come from the response's own settings view, so a server that
  stores something other than what was sent is shown as it stored it.

## 6. Related

The upload limit and the retention flag this page edits are consumed by
[PCAP-Files.md](PCAP-Files.md); the indicators feed the `indicator_match` rule documented in
[Findings.md](Findings.md); and the Suricata rule set is the signature half of
[Threat-Hunt.md](Threat-Hunt.md), whose detections are the behavioural half. The credential
switch and protocol list this page edits are the subject of
[Users & Passwords](Credentials.md) and specified in
[`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md). The environment
variables that are the real controls for start-up-only settings are listed in
[Getting-Started.md](Getting-Started.md), and the endpoints this page calls are specified in
[Reference/API.md](Reference/API.md).
