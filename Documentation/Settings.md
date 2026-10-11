# Settings

The configuration and rule-management page (`/settings`): what the backend is actually
running with, the handful of values an analyst may change, the indicators the detection
engine matches against, the Suricata rules panel, and the four colour themes.

The component is `frontend/src/pages/SettingsPage.tsx`, with
`frontend/src/components/ThemePanel.tsx` and
`frontend/src/components/SuricataRulesPanel.tsx` as its two large pieces. Like
[PCAP Files](PCAP-Files.md) it is **not** wrapped in `AnalysisGuard`: most of the page makes
sense with no capture selected, and only the Suricata panel's per-capture features need one.

---

## 1. What it is for

It answers three questions an analyst has to be able to answer before trusting a figure
elsewhere in the application: *what is this build configured to do?*, *what does the
detector treat as suspicious?*, and *which threshold am I looking at?* It is also the only
place where configuration can be changed without editing files, and the only place where
analyst-supplied indicators are entered.

## 2. What is on the screen

Six panels, in this order.

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

### 2.4 Indicators

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

### 2.5 Suricata rules

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
protocols), four severity count badges, and up to four sources as `source (N)` joined by `|`.

Measured in this library: **1,615 rules**, all enabled, **1,114 evaluable** and **501 skipped
by the matcher**; sources `bundled:daffainfo` (1,167) and `bundled:oisf` (448); **284**
`.rules` files vendored under `backend/rules/`.

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
| Message | The `msg`, truncated to 420 px with the full text in the tooltip. A warning `skipped` chip appears on rules the matcher cannot evaluate (its tooltip lists the unsupported options), and a `field match` chip appears on rules matched against extracted fields rather than raw payload bytes. |
| Category | The rule's category, truncated to 170 px; `-` when absent. |
| Source | `bundled:daffainfo`, `bundled:oisf`, `upload:<file>` or `manual`, truncated to 150 px. |
| Hits | How many findings for the currently selected analysis carry `rule_id = 'suricata:<sid>'`. Shows `-` when no analysis is selected and `0` when one is selected but the rule never matched. |
| State | A button that toggles the rule between enabled and disabled. Disabled rows are drawn at 60% opacity. |
| Actions | **Edit** (opens the rule text editor) and **Delete** (opens a confirmation dialog). |

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

### 2.6 Local-only operation

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
| Indicators | `GET /api/indicators`, `POST /api/indicators`, `DELETE /api/indicators/{id}` | `routes_settings.py` |
| Suricata rules table, stats strip | `GET /api/suricata/rules`, `GET /api/suricata/rules/stats` | `backend/app/api/routes_suricata.py` |
| Matcher scope | `GET /api/suricata/config` | `routes_suricata.py` |
| Import / upload / toggle / edit / delete a rule | `POST /api/suricata/rules/seed`, `POST /api/suricata/rules/import`, `PUT /api/suricata/rules/{sid}`, `DELETE /api/suricata/rules/{sid}` | `routes_suricata.py` |
| Run on capture | `POST /api/analyses/{id}/suricata/run` | `routes_suricata.py` |
| Hits column | part of `GET /api/suricata/rules`, with `analysis_id` set | `routes_suricata.py` |
| Theme | *no API call at all* — `localStorage` and `frontend/src/theme/themes.ts` | — |

The client wrappers are `settingsApi` and `suricataApi` in `frontend/src/services/api.ts`;
`importSuricataRules` uses `XMLHttpRequest` rather than `fetch`, purely so a large rule file
can report upload progress. The theme needs no endpoint: `ThemeProvider` holds it in React
state, publishes CSS custom properties and mirrors the id into `localStorage`.

Tables behind the page:

| Table | Supplies |
|---|---|
| `settings` | The runtime overrides, under the keys `app_settings` (the five editable values) and `suricata_config` (HOME_NET, `max_findings_per_rule`, `include_unsupported`, per-variable overrides). Both are read through `runtime_settings.load_overrides()`. |
| `indicators` | The whole indicator table: `type`, `value`, `note`, `created_at`, and `analysis_id` which is NULL for global rows. |
| `suricata_rules` | Everything in the rules table and every figure in the stats strip: `sid`, `rev`, `action`, `protocol`, `msg`, `category`, `severity`, `options`, `unsupported`, `supported`, `approximate`, `enabled`, `source`, `raw`, `created_at`, `updated_at`. |
| `findings` | The Hits column only, via a correlated subquery counting `rule_id = 'suricata:' \|\| sid` for the selected analysis. |
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
| Import / upload / edit / delete / toggle a rule | Nothing — the table refreshes in place |

Two inbound links matter, because they are how this page is reached in practice:

* `/settings?sid=<n>` seeds the rule search box with that value, so the table opens filtered to
  that rule. The Findings workbench uses it: the *Suricata rule behind this alert* panel has
  an **edit in settings** button that navigates to `/settings?sid=<sid>`. The search is a
  substring match over message, sid and rule text, so a sid whose digits also occur in another
  rule's text pulls that rule into the list as well — the filter narrows the table, it does
  not prove uniqueness.
* The sidebar's Settings item, which is present on every page.

The capture selector in the top bar decides which analysis **Run on capture** and the Hits
column apply to. With no capture selected the button is disabled and Hits reads `-`.

## 5. Limits and honest caveats

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

## 6. Related

The upload limit and the retention flag this page edits are consumed by
[PCAP-Files.md](PCAP-Files.md); the indicators feed the `indicator_match` rule documented in
[Findings.md](Findings.md); and the Suricata rule set is the signature half of
[Threat-Hunt.md](Threat-Hunt.md), whose detections are the behavioural half. The environment
variables that are the real controls for start-up-only settings are listed in
[Getting-Started.md](Getting-Started.md), and the endpoints this page calls are specified in
[Reference/API.md](Reference/API.md).
