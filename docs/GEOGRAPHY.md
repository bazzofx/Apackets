# Geography contract

**Status:** normative for the geographic view of the Dashboard's map panel — the world map,
the arcs to destination countries, and the country list beneath it. `docs/CONTRACT.md`
governs everything older; where the two touch, that document wins.

---

## 1. What the feature answers

The Dashboard's map panel has always drawn who talked to whom: a force-directed graph of
addresses. That answers *topology*. It cannot answer the question an analyst asks next:
**where in the world is this capture talking to?**

This feature answers it, and nothing more:

> every mode of address classification already exists (§3); this adds **country** to it, and
> draws the capture's public destinations on a world map, one dot per country.

It is a **reading surface**: SQL over tables the analysis already holds, plus a country
lookup that needs no capture data at all. No capture byte is sent anywhere.

## 2. The geolocation source

| | |
|---|---|
| Dataset | **DB-IP Lite — country** (`dbip-country-lite-YYYY-MM.csv.gz`) |
| Licence | **Creative Commons Attribution 4.0** — attribution is required and is shown in the UI and in the section documents |
| Shape | one CSV row per range: `start_ip,end_ip,country_code`, 710,834 ranges and 251 country codes in the 2026-10 file (measured) |
| What it gives | a two-letter country code per address, or `ZZ` for "no country known" |
| Cost | one 4.4 MB download, one file on disk, no account, no API key, no per-query service, no telemetry |
| Refresh | monthly; the app asks for the current month and falls back up to six months, because the file name is dated |

**Nothing is fetched at page render time.** The dataset is downloaded only when a reader
explicitly asks for it — the Dashboard offers to build it, and `POST /api/geoip/refresh` does
the work (§5.2). Until then the map says the dataset is missing and the rest of the page is
unaffected. This keeps the application's promise that a capture never leaves the host: what
leaves is one request for a public dataset, made by the reader.

`ZZ`, an empty code and any code outside the ISO 3166-1 alpha-2 set mean **unknown**, and are
reported as unknown — never guessed, never dropped into a neighbouring country.

There is exactly one exception, and it is named rather than inferred: **`XK`**, the
user-assigned code for Kosovo. The 2026-10 file uses it on 152 rows and the map asset names
and draws it, so calling that traffic unknown while the page could label it would be the worse
error. No other non-ISO code is accepted.

**IPv6 addresses are not looked up by this build.** The dataset itself carries both families —
348,712 of its 710,834 rows are IPv6 — so this is a limit of the extraction here, not of the
source, and the pages and notes say it that way. An IPv4-mapped IPv6 address is unwrapped to
its IPv4 address and answered normally; a native IPv6 address is counted as unknown.

## 3. Addresses that are not geolocated

A country is only recorded for addresses the dataset can answer for. Everything else is
classified from the address itself, using the same vocabulary the rest of the application
uses (`hosts.scope`, `docs/CONTRACT.md` §7):

| Class | Meaning here |
|---|---|
| `local` | the capture's own side: RFC 1918, loopback, link-local, multicast — the origin of the arcs, never a destination dot |
| `public` and located | a destination dot, one per country |
| `public` and unknown | counted under `unknown`, drawn nowhere on the map |
| `reserved` | never geolocated, never drawn |

The origin is **the capture's own network, drawn as one labelled hub**, not a point on the
map: a private address carries no location, and this feature will not invent a home country
from latency, DNS or a guess. The hub's size reflects the local addresses' volume, and every
arc leaves it.

## 4. Storage

```
data/geoip/                # created on the first successful refresh
  dbip-country-lite-YYYY-MM.csv.gz   # the file exactly as downloaded
  source.json                        # provenance, §4.1
```

The table is parsed into memory the first time a lookup is needed and cached for the life of
the process, keyed by the raw file's size and mtime, so a refresh is picked up without a
restart and a page render never parses 710,834 rows twice.

### 4.1 `source.json`

```json
{
  "dataset": "DB-IP Lite — country",
  "url": "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz",
  "licence": "CC BY 4.0",
  "attribution": "IP geolocation by DB-IP (https://db-ip.com)",
  "file": "dbip-country-lite-2026-10.csv.gz",
  "bytes": 4491776,
  "sha256": "…",
  "ranges": 710834,
  "countries": 251,
  "dataset_month": "2026-10",
  "fetched_at": 1791810000.0
}
```

`fetched_at` is this installation's clock; `dataset_month` is the file's own month. Both are
shown, because "the data is from March" and "we downloaded it in July" are different claims.

There is **no fallback dataset**. An installation that has never refreshed reports
`available: false` and the UI says so; a country is never produced from a guess, from the
registry that allocated the block, or from a static list baked into the app.

## 5. Endpoints

### 5.1 `GET /api/geoip/status`

```json
{
  "available": true,
  "source": { "…": "§4.1, or null when unavailable" },
  "reason": null,
  "note": "…"
}
```

`reason` is a sentence a reader can act on when `available` is false (for example: the dataset
has never been downloaded, or the file on disk could not be parsed).

### 5.2 `POST /api/geoip/refresh`

Downloads the newest available monthly file, verifies it parses and that it covers a sane
number of ranges, writes it and `source.json` atomically, and returns `202` with
`{job_id, kind: "geoip_refresh", status}`. It is a job because it is a network download, and
its result is recorded in `source.json` rather than in any analysis.

Failure is reported, never worked around: a partial download is discarded, and the previous
dataset (if any) stays in force. A file that parses to fewer than `MIN_RANGES` (100,000) rows
is rejected as truncated rather than installed.

### 5.3 `GET /api/analyses/{analysis_id}/geography`

```json
{
  "analysis_id": "…",
  "generated_at": 1791810000.0,
  "dataset": {
    "available": true,
    "source": { "…": "§4.1, or null" },
    "reason": null
  },
  "origin": {
    "label": "This capture's own addresses",
    "addresses": 6,
    "packets": 41000,
    "bytes": 24000000
  },
  "countries": [
    {
      "code": "US",
      "name": "United States",
      "addresses": 4,
      "packets": 31000,
      "bytes": 19000000,
      "ips": ["3.173.21.63", "34.160.56.206"],
      "ips_truncated": false
    }
  ],
  "unknown": { "addresses": 2, "packets": 12, "bytes": 900, "ips": ["…"], "ips_truncated": false },
  "counts": { "addresses": 12, "located": 8, "countries": 5, "unknown": 2, "local": 2 },
  "note": "…"
}
```

* `countries` is sorted by `bytes` descending, then by code, and capped by `COUNTRY_CAP`
  (60). A cap that bit is reported in `counts.countries_truncated` and in the `note`.
* A `countries[].ips` list carries at most `GEO_IP_CAP` (50) addresses and sets
  `ips_truncated` when it was cut.
* `name` is the country's English name, resolved from the code by the frontend's map asset
  (§6) or a bundled code list. The API may send `null` when it does not know the name; the
  page then shows the code. It never invents a name from a code by pattern.
* `note` states the section's limits (§7) in one sentence, then one more naming which
  conversation is linked, and one more for each cap that bit. It is never shorter than §7
  requires and never leaves a cut unreported.
* Failure modes follow the rest of the application: unknown analysis `404
  analysis_not_found` (after the id-shape check), unfinished `409 analysis_not_ready`.

### 5.4 `GET /api/analyses/{analysis_id}/geography/{code}`

The **destination panel**: everything a reader opening one dot wants, in one request. The
country list on `/geography` stays light (§5.3) because the map draws every country at once and
almost none of them are opened; this endpoint is fetched only when a dot is clicked.

`{code}` is an ISO 3166-1 alpha-2 code (case-insensitive) **or `ZZ`**, which returns the
*not placed* bucket — those addresses have ports and conversations like any others, so the
panel is the same shape.

* An analysis that has **never been extracted at all** (no `hosts` rows) answers `200` with
  empty buckets for any code: there is nothing to report as missing, which is the same reading
  §5.1 gives `extracted`.
* An extracted capture whose **bucket is empty** — all of its traffic was local — answers
  `404 country_not_found` for that country, because the page that asks has a dot for it and a
  dot with no traffic is a contradiction worth reporting rather than an empty panel.
* `ZZ` is a bucket rather than a country, so it answers `200` whenever the capture has any
  unplaced public address.

```json
{
  "analysis_id": "…",
  "code": "US",
  "generated_at": 1791810000.0,
  "counts": {
    "addresses": 16,
    "packets": 5640,
    "bytes": 9630000,
    "sent": { "packets": 4200, "bytes": 1200000 },
    "received": { "packets": 1440, "bytes": 8430000 }
  },
  "ports": [
    { "port": 443, "side": "remote", "packets": 4000, "bytes": 9000000, "addresses": 12 },
    { "port": 51234, "side": "local", "packets": 900, "bytes": 120000, "addresses": 3 }
  ],
  "ports_truncated": false,
  "targets": [
    {
      "ip": "3.173.21.63",
      "packets": 1200,
      "bytes": 500000,
      "sent": { "packets": 300, "bytes": 40000 },
      "received": { "packets": 900, "bytes": 460000 },
      "ports": [{ "port": 443, "side": "remote", "packets": 1150, "bytes": 498000, "addresses": 1 }],
      "ports_truncated": false,
      "protocols": ["tcp", "tls"],
      "first_conversation": {
        "conv_id": "tcp:36",
        "transport": "tcp",
        "stream_id": 36,
        "packets": 1200,
        "bytes": 500000,
        "start_time": 1554928696.28
      }
    }
  ],
  "targets_truncated": false,
  "note": "…"
}
```

* **Direction** (`sent` / `received`) is from the capture's own side, taken from the `hosts`
  row of each address — and the mapping is the reverse of that row's own columns, because the
  row's perspective is the *address's*, not this side's. `host_analyzer._HOST_SQL` counts
  `bytes_sent` for frames where the address is the **source** and `bytes_received` for frames
  where it is the **destination**. For a destination in this feature:

  | Panel field | `hosts` column | Meaning |
  |---|---|---|
  | `sent` | `bytes_received`, `packets_received` | what **this capture's side** sent, i.e. what the destination received |
  | `received` | `bytes_sent`, `packets_sent` | what **this capture's side** received, i.e. what the destination sent |

  Stated here because the two readings are opposite and nothing in the shape of the data
  distinguishes them, so this is exactly the kind of thing that gets silently inverted. The
  measured case, which is also the test fixture's shape: in
  `SpaceX_Download_sysInternals_curlOutput.pcapng` the **ZA** bucket reads `received 210.27 MB`
  against `sent 0.87 MB`, because Microsoft's `150.171.109.217` sent 209.9 MB in 140,996 frames
  — that is the download — while the **US** bucket reads `sent 8.86 MB` against
  `received 0.81 MB`, because `3.173.21.63` is S3 and this capture uploaded to it (the
  conversations table names `192.168.8.229:59141 → 3.173.21.63:443` at 2.93 MB outbound). Both
  are correct; a reader who assumes "download capture means received is larger" will get the
  second one wrong. The page prints whose side it means next to the two figures.
* **Ports** come from `conversations`, not from per-packet dissection, and carry the side that
  owned the port: `remote` is the port on the destination's address (the service port a reader
  is looking for), `local` is the port on the capture's own side (usually the ephemeral one).
  An entry's `packets` and `bytes` are that port's **conversation totals for that side**, both
  directions together — the direction split belongs to the address row, not the port, and two
  numbers per port would say less than the address's own `sent`/`received` already does.
  `addresses` is how many addresses of the bucket used that port on that side; on a `targets[]`
  entry it is always `1`, because there the port belongs to that one address.
  Both lists are cut by `PORT_CAP` (25) and both say so: `ports_truncated` for the panel's list,
  `targets[].ports_truncated` for an address's own — one address can legitimately have hundreds
  of ports, and a scan's worth of chips is not a panel. Each list keeps the busiest ports.
* **`first_conversation.stream_id` can be `null`**: a conversation exists, but the dissector
  never reassembled it into a stream (a mixed or absent stream id). The contract still returns
  that conversation, because it is the earliest and the counts are real — and the page then
  **cannot** build the conversation link, so it disables the button and says why rather than
  linking to `tcp:null`.
* **`first_conversation`** is the **earliest** conversation involving that address, by
  `start_time` and then `stream_id` — deterministic, and named "first" rather than "biggest"
  because the page links to it as *follow conversation with this address*. `null` means the
  address has no conversation at all (a one-way broadcast, for instance), and the page then
  says so instead of offering a link that would land nowhere. `transport` and `stream_id` are
  exactly the two values the application's existing conversation deep link takes
  (`/conversations?stream=<transport>:<stream_id>&tab=timeline`).
* **Targets** are capped at `GEO_IP_CAP` (50), largest by bytes first, with
  `targets_truncated` when cut. Every address in the bucket is counted in `counts` whether or
  not it is listed.

## 6. The map itself

* The **outline data is Natural Earth 110m admin-0 countries**, public domain, reduced to one
  path per ISO 3166-1 alpha-2 code plus that country's label point, in a single generated
  asset. It ships with the application: no download, no CDN, no runtime fetch, and the
  generator that produced it is kept with the asset so the file can be regenerated and
  re-verified.
* Projection is equirectangular in a fixed view box, so a label point and its outline are
  always in the same space.
* **One dot per country**, sized by bytes and tinted by the theme, with the count of its
  addresses beside it. Nothing is drawn per address: a capture with 400 destinations draws at
  most `COUNTRY_CAP` dots.
* Arcs run from the origin hub to each country's label point, and carry a **slow, low-opacity
  flow** — one travelling dash per arc — to show direction without demanding attention. The
  animation is disabled entirely under `prefers-reduced-motion: reduce`, and it never changes
  its colour, thickness or speed per frame beyond that travel.
* Countries are hoverable and focusable; selecting one highlights it on the map and in the
  list under it, and clicking an address in the list opens that host.
* **The map zooms.** Wheel or pinch zooms about the pointer, dragging pans, and the controls in
  the corner zoom in, zoom out and reset. The scale is clamped to `1 × – 8 ×` and the pan is
  clamped so the world never leaves the frame. Keyboard users get the same three controls, and
  the zoom level is announced in a control's tooltip rather than in a live region that would
  chatter on every wheel tick.
* **Clicking a dot zooms to that country, and half a second later opens its destination panel**
  (§5.4) — the wait (`PANEL_DELAY_MS = 500`) exists because the zoom takes 220 ms, and a card that
  appears mid-movement reads as if it belonged to where the dot *was*. It is skipped under
  `prefers-reduced-motion`, where nothing moves. The card is **docked against the right edge of
  the frame and centred vertically**, so it is in the same place for every country, is always
  inside the frame, and never covers the country it describes: the address
  count, packets and bytes in each direction, the ports used with the side that owned them, and
  one row per address with its own counts, its ports, and a **Follow conversation** button that
  opens the earliest conversation involving that address on the Conversations page's timeline.
  An address with no conversation says so — the button is disabled and its tooltip explains why
  — rather than opening somewhere unrelated. The panel is fetched on the click, so a reader who
  never opens one never pays for it.

## 7. Honest limits, stated on the page

* **A country is where the address block is registered, not where the host is.** Cloud,
  CDN, VPN and satellite space routinely disagrees with the physical machine: the measured
  2026-10 dataset places `150.171.109.213` in South Africa, which is where Microsoft's block
  is allocated, not where the server is. The page says this in one sentence, always.
* **The origin is not on the map.** A private address has no country, and the capture does not
  contain this installation's public address, so the hub is labelled as the capture's own side
  rather than placed anywhere.
* **Unknown is a result.** Addresses the dataset answers `ZZ` for are counted as unknown and
  drawn nowhere. They are never distributed into nearby countries.
* **No city, no coordinates, no confidence.** This is a country code and nothing else: the
  feature does not claim a city, an ASN, an organisation or a coordinate.
* **A dot is a destination, not a person.** One address in a country means one address in a
  country; the country list says how many, so a single CDN edge never reads as a campaign.
* **The dataset ages.** `dataset_month` and `fetched_at` are both shown, because a stale
  country table is a different claim from a fresh one.

## 8. Caps

| Constant | Value | What it limits |
|---|---|---|
| `COUNTRY_CAP` | `60` | Countries in one response, sorted by bytes |
| `GEO_IP_CAP` | `50` | Addresses listed per country and for the unknown bucket |
| `MIN_RANGES` | `100000` | Smallest parsed dataset accepted as complete |
| `REFRESH_MONTHS_BACK` | `6` | Monthly files tried before the refresh gives up |
| `PORT_CAP` | `25` | Ports in one destination panel, largest first |
| `GEO_TARGET_DETAIL_CAP` | `50` | Addresses in one destination panel (the same 50 as `GEO_IP_CAP`) |

## 9. Where the code lives

| Part | File |
|---|---|
| Geolocation service | `backend/app/services/geoip.py` |
| Geography + GeoIP routes | `backend/app/api/routes_geo.py` |
| World outline asset | `frontend/src/theme/worldMap.ts` (generated; generator recorded in the file's header and in this contract) |
| World map component | `frontend/src/components/dashboard/WorldMap.tsx` |
| Country list | `frontend/src/components/dashboard/CountryList.tsx` |
| Dashboard integration | `frontend/src/pages/DashboardPage.tsx`, `frontend/src/components/dashboard/NetworkMap.tsx` |
