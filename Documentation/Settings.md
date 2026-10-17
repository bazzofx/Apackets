# Settings

The configuration page (`/settings`): what the backend is actually running with, the handful of
values an analyst may change, and the four colour themes.

Everything to do with detection that used to live here - the built-in rules, the imported
signatures, the Users & Passwords discovery switch and the indicator list - is now its own page,
[Alert Settings](Alert-Settings.md) (`/alert-settings`), with its own sidebar entry. This document
covers what remains: the installation's own configuration.

The component is `frontend/src/pages/SettingsPage.tsx`, with
`frontend/src/components/ThemePanel.tsx` as its large piece. Like
[PCAP Files](PCAP-Files.md) it is **not** wrapped in `AnalysisGuard`: the whole page makes sense
with no capture selected.

---

## 1. What it is for

It answers the question an analyst has to be able to answer before trusting a figure elsewhere
in the application: *what is this build configured to do?* It is also the only place where an
installation setting can be changed without editing files. What the detector treats as
suspicious, and what it is told to watch for, are on [Alert Settings](Alert-Settings.md).

## 2. What is on the screen

Four panels, in this order.

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

### 2.4 Local-only operation

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
| Theme | *no API call at all* — `localStorage` and `frontend/src/theme/themes.ts` | — |

The client wrapper is `settingsApi` in `frontend/src/services/api.ts`. The theme needs no
endpoint: `ThemeProvider` holds it in React state, publishes CSS custom properties and mirrors
the id into `localStorage`.

Tables behind the page:

| Table | Supplies |
|---|---|
| `settings` | The runtime overrides, under the key `app_settings` (the five editable values), read through `runtime_settings.load_overrides()`. The detection, matcher and credential configuration lives in the same table under its own keys and is documented in [Alert Settings](Alert-Settings.md). |

The effective settings view is assembled by `runtime_settings.effective()`, which resolves
each editable key through `_int_value()` — clamp to the key's bound, fall back to the value
from `app.core.config` when the stored value is missing or unparsable — and then merges in
the directories, `allowed_extensions`, `worker_threads`, `max_export_rows`, `host`, `port`
and `db_path`; `routes_settings.effective_settings()` adds `version`, `tshark`, `local_only`
and `telemetry: false`.

## 4. Links into the rest of the app

Settings is a leaf: nothing on it opens another page. Every control writes in place and reports
the save beside itself.

The only inbound link is the sidebar's Settings item, which is present on every page.

Everything that was documented here about the detector - the rule tables, the credential
switch, the indicators and the deep links the Findings workbench uses - has moved to
[Alert Settings](Alert-Settings.md).

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

## 6. Related

The upload limit and the retention flag this page edits are consumed by
[PCAP-Files.md](PCAP-Files.md). Everything about the detector - the built-in rules, the imported
signatures, the credential stage's switch and the indicators - is on
[Alert Settings](Alert-Settings.md); what those produce is documented in [Findings.md](Findings.md)
and [Threat-Hunt.md](Threat-Hunt.md). The environment variables that are the real controls for
start-up-only settings are listed in [Getting-Started.md](Getting-Started.md), and the endpoints
this page calls are specified in [Reference/API.md](Reference/API.md).
