# Investigate

One entity, everything the capture recorded about it: search by IP address, domain
name or URL, then read a grid of small coloured widgets — one per question — each
with its own chart, its own number and a link to the rows behind it.

The page is `frontend/src/pages/InvestigatePage.tsx` and its route is
`/investigate`. It sits in the left-hand navigation under **Investigate**, directly
after **Threat Map**, and it is the one page in the application laid out as a lookup
rather than a listing: a centred headline with the search box inside it, then a field
of tiles.

The normative interface for the section is
[`docs/ENTITY_PROFILE.md`](../docs/ENTITY_PROFILE.md) — the two endpoints, the
response envelope, the question ids, the caps and the matching rules. This document
explains the section as it runs. The card contract it draws its widgets with is the
Threat Map's ([`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) §3), which is why
[Threat-Hunt.md](Threat-Hunt.md) and this page share one set of chart renderers.

---

## 1. What the section is for

The other sections answer questions about the capture: what is in it
([Packets.md](Packets.md), [Conversations.md](Conversations.md)), what each address
did on the whole ([Hosts.md](Hosts.md)), what each protocol said
([HTTP.md](HTTP.md), [DNS.md](DNS.md), [TLS.md](TLS.md)), and what the detections
make of it ([Findings.md](Findings.md), [Threat-Hunt.md](Threat-Hunt.md)).

This section answers the question that follows from all of them: **I have one name
in front of me — tell me everything this capture knows about it.** An analyst who
has just read a Suricata alert naming `185.199.110.133`, or a DNS query for
`blog.eskill.com`, or a request URI, should not have to visit six pages and read
six tables to build the picture. They type the value here once and read sixteen
answers.

It is a **reading surface, not an analysis run**: the endpoints issue SQL over the
tables the analysis already indexed (`packets`, `conversations`, `hosts`,
`dns_queries`, `http_transactions`, `tls_sessions`, `findings`, `objects`) and write
nothing. No capture is dissected again, no TShark process is started, and the
section keeps working after an upload has been purged — see
[Architecture.md](Architecture.md) §3 for the pipeline that fills those tables and
[Architecture.md](Architecture.md) §6 for why every section reads the index rather
than the file.

---

## 2. The two endpoints

```
GET /api/analyses/{analysis_id}/profile?q=<query>&limit=<n>
GET /api/analyses/{analysis_id}/profile/{kind}/{entity}
```

Implemented in `backend/app/api/routes_profile.py`, which validates the parameters
and applies the shared readiness gate (`deps.get_ready_analysis`); all computation
is in `backend/app/services/entity_profile.py`. Both are documented in
[Reference/API.md](Reference/API.md).

| Failure | Status | Code |
|---|---|---|
| Unknown analysis | `404` | `analysis_not_found` |
| Analysis not finished | `409` | `analysis_not_ready` |
| `q` empty after trimming, or longer than 200 characters | `422` | `invalid_query` / `validation_error` |
| `limit` outside 1–100 | `422` | `validation_error` |
| `kind` outside `ip`, `domain`, `url` | `422` | `validation_error` |
| **Entity the capture never recorded** | `200` | — |

That last row is the important one. A stale bookmark, a link pasted from another
capture, or a typo produces a **full response** in which every question reports
`not_applicable` with the reason, rather than a `404`. A `404` would say "this
request is wrong"; the truth is usually "this capture never saw it", and only the
second is worth showing an analyst.

### `q` and `limit`

| Parameter | Default | Range | Meaning |
|---|---|---|---|
| `q` | required | 1–200 characters after trimming | An address, part of one, a name, or a URL |
| `limit` | `25` | 1–100 | Maximum matches returned |

The page sends `limit` at its default and debounces typing, so one request is made
per pause rather than per keystroke.

---

## 3. What a query resolves to

Matching is a case-insensitive substring over the indexed value, and **the shape of
the query decides which kinds are searched**:

| Query looks like | Kinds searched | Example |
|---|---|---|
| An address | addresses only | `192.168.8.229`, `192.168` |
| Contains `://` or starts with `/` | URLs only | `https://…`, `/analytics?…` |
| Anything else | all three | `sharethis`, `.com`, `blog` |

A match carries the exact value to pass back (`entity`), a value to show (`label` —
for a URL the capture's host is prefixed), one line of context (`hint`), the number
of rows behind it, and a deep link (`to`). Matches are ordered by that row count,
then by kind, then by value, so the list is stable between calls. If the cap bit,
`truncated` is `true` and the page says so rather than presenting a shorter list as
the whole truth.

The page adds a second way to use the box: pressing Enter opens **exactly what was
typed**, with the kind read off its shape. That row is offered only when no match
equals the text, and it says what kind the value will be read as. It costs nothing —
an entity the capture does not contain answers every question with why — and it is
what makes the box usable for a value copied from outside the capture.

---

## 4. A question

A profile is a list of questions, and every question is the same object the Threat
Map cards use (`docs/THREAT_HUNT.md` §3.1):

| Field | Meaning |
|---|---|
| `id` | Stable question id from §4 of the contract; what the page switches on |
| `title`, `question` | A short name and the sentence the widget answers |
| `availability` | `ok`, `empty`, or `not_applicable` |
| `availability_reason` | Required whenever `availability` is not `ok` |
| `headline` | A real measured number, its label, and a tone |
| `visuals[]` | One or more charts of the six kinds: `bars`, `timeline`, `histogram`, `scatter`, `heatmap`, `table` |
| `interpretation` | What the pattern may indicate |
| `caveat` | What it does not prove |

Three rules make the widgets honest, and the page enforces all three:

1. **`0` means "nothing matched", never "not measured".** A question the capture
   cannot answer is `not_applicable` with a reason, and it is never drawn as a zero.
2. **An empty chart is never drawn.** A visual with no rows is skipped, because an
   empty frame reads as "nothing found here" — a different claim from "this could
   not be computed".
3. **The caveat travels with the number.** What a pattern does not prove is on every
   widget, in a quieter voice, so a lead cannot be read as a verdict.

`truncated` is a map from question id to a flag: a question whose visual was cut to
a contract cap reports it, and the page lists those ids above the grid.

| Cap | Value | What it limits |
|---|---|---|
| `PROFILE_CAP` | `50` | Rows in any `table` visual |
| `BARS_CAP` | `12` | Bars in any `bars` visual |
| `TIMELINE_CAP` | `240` | Points in a `timeline` |
| `SCATTER_CAP` | `200` | Points in a `scatter` |
| `HEATMAP_CAP` | `15` | Rows and columns in a `heatmap` |
| `MATCH_CAP` | `25` | Search matches (the default `limit`) |

Timelines bucket at 60 seconds. The route exposes no override for that, because the
page has no controls: it reads an indexed capture rather than a live feed.

Those are the backend's caps, and they bound the response. The page adds one of its own
on top — a tile draws the first eight rows of a table and the first eight rows and columns
of a heatmap — because sixteen tiles in a grid cannot each hold fifty rows. It states the
difference in a chip (`+33 rows`) rather than quietly showing less, and §7 describes it.

---

## 5. The sixteen questions asked of an address

| # | id | Question | Read from |
|---|---|---|---|
| 01 | `volume_by_direction` | How much did it send, and how much did it receive? | `hosts` totals, `packets.frame_len` |
| 02 | `activity_over_time` | When was it active, and was the traffic steady or bursty? | `packets.time_epoch` |
| 03 | `connections` | How many conversations did it take part in, and with whom? | `conversations` |
| 04 | `peer_fanout` | How many distinct peers did it talk to? | `conversations` peers |
| 05 | `ports_offered` | Which ports did it listen on? | `conversations` as responder |
| 06 | `ports_contacted` | Which ports did it reach out to? | `conversations` as initiator |
| 07 | `protocol_mix` | Which protocols did it speak, and in what proportion? | `packets.protocol/transport` |
| 08 | `domains_resolved` | Which names did it ask a resolver for? | `dns_queries` where it is the client |
| 09 | `domains_contacted` | Which names did it contact over TLS? | `tls_sessions.sni` |
| 10 | `dns_health` | How many of its queries went unanswered, and which resolvers did it use? | `dns_queries.rcode/server_ip` |
| 11 | `http_activity` | Which HTTP hosts and paths did it use? | `http_transactions` |
| 12 | `clear_text_credentials` | Did anything it sent carry a credential in clear text? | `http_transactions` flags |
| 13 | `files` | Which files did it transfer, and what are their hashes? | `objects` via `stream_id` and recorded frames |
| 14 | `tls_fingerprints` | Which JA3/JA4 fingerprints did it present? | `tls_sessions.ja3/ja4` |
| 15 | `fingerprint_peers` | Which other addresses present the same fingerprints? | `tls_sessions`, cross-joined |
| 16 | `findings` | Which detections and Suricata signatures name it? | `findings.entities/packet_numbers` |

The order is the contract's order, the page numbers the widgets in it, and each
widget's hue follows its position, so a question looks the same on every entity.

## 6. The questions asked of a name, and of a URL

A domain name is asked eight questions: `clients`, `answers`, `rcodes`,
`activity_over_time`, `tls_sessions`, `http_transactions`, `files`, `findings`. A
URL is asked seven: `clients`, `status_codes`, `methods`, `activity_over_time`,
`request_shape`, `files`, `findings`.

The count differs by kind because the capture can answer different things about each:
a name has resolvers and answers, a request URI has methods and status codes, and an
address has macro-level behaviour — fan-out, ports, fingerprints — that a name
simply does not have. A question that does not apply is still in the response, marked
`not_applicable` with the reason, so the grid never silently changes shape.

---

## 7. The page

**The search box is the head.** The headline, its purpose line and the field all sit
in one centred block, above the body: the page's single control is at the top of the
page, not buried under a card. The section is styled as the `signal` variant of the
page shell (`frontend/src/theme/sections.ts`) — a centred head with a spectrum
rule drawn from the theme's eight chart hues, which is the one place in the
application where the whole palette appears at once, previewing the colours of the
widgets below.

**Before a lookup, the page shows the question index**: the questions it will ask,
each with its number and its hue, and a row of kind tabs so the list can be read for
addresses, names or URLs. Nothing is fetched until an entity is chosen.

**The selected entity lives in the URL** (`/investigate?kind=ip&entity=10.0.0.5`). A
profile is therefore shareable, survives a reload, and Back leaves it. Clearing the
field, pressing Escape, or closing the strip leaves the page.

**Each question is a widget with its own hue.** The hues cycle the theme's eight
chart hues by position, so a grid of sixteen reads as sixteen measured things rather
than sixteen identical cards, and the colours follow the active theme.

**A widget prints three things, and explains itself on hover.** It shows the
question's title, the sentence it answers, and its data — the headline number and the
charts, drawn larger here than the Threat Map draws them because on a tile the chart
is the content. Everything else is on the tile's tooltip: what the pattern may
indicate, what it does not prove, why a question could not be answered, each chart's
own note, and the question id. A small mark in the tile's header is the affordance, so
the hover is discoverable rather than secret. Nothing is lost — the explanation is
only out of the way, because sixteen paragraphs of caveat is not a dashboard.

**A question the capture could not answer is greyed out, not hidden.** The grid keeps
its shape, so a gap reads as a gap and the coloured tiles are exactly the questions
this capture answered. `not applicable` — the capture holds nothing to measure — is
greyed hardest and loses its hue; `nothing matched` — something was measured and
nothing crossed the threshold — keeps more of its colour, because its numbers are real.
Both carry a chip naming their state, which is the one word a widget in that state
prints.

**Links keep the endpoint's label and add the destination's icon.** The label is what
distinguishes one link from the next — a peer address, a domain, a port, a finding id —
so it is printed and truncated to the chip's width rather than replaced, and it is the
tooltip that spells it out in full alongside the page it opens. Five links to five pages
read alike without the destination, so each chip carries that section's own icon, read
from `sections.ts` and therefore the same icon the sidebar draws.

**A chart too long for a tile is shortened and counted.** The backend caps a table at
fifty rows and a heatmap at fifteen by fifteen, which is the right size for a card in a
column; in a grid of sixteen it is a wall. A tile therefore draws the first eight rows
(and the first eight columns) and prints one chip for what it did not draw — `+33 rows` —
whose tooltip says how many came back and where the rest are. The rows are not hidden
data: they are on the pages the widget links to, and the chip says so.

**The entity strip above the grid** holds the facts that are the same whichever
question is asked: the value, its kind, the label, scope, MAC, packets, bytes, first
and last seen, and the names attributed to it. A fact the capture cannot supply shows an
em dash — nothing on this page is filled in — and the backend's note about the entity is
on the strip's tooltip, since it explains those facts rather than adding to them.

---

## 8. Measured behaviour

Measured on this installation, on the captures in `data/`. Each figure is the
endpoint's own timing, and the question counts are the response's own
`availability` values.

| Capture | Packets | Entity | Questions answered | Seconds |
|---|---|---|---|---|
| `SpaceX_Download_sysInternals_curlOutput.pcapng` | 163,584 | `192.168.8.229` | 14 `ok`, 1 `empty`, 1 `not_applicable` | 0.539 |
| `SpaceX_loads_of_tabs.pcapng` | 55,434 | `192.168.8.229` | 13 `ok`, 3 `not_applicable` | 0.316 |
| `sf19us-MTA-lab-01.pcap` | 4,500 | `blog.eskill.com` | 7 `ok`, 1 `not_applicable` | 0.087 |

Search is cheaper than a profile by an order of magnitude: on the largest capture
above, `192.168` resolves to five addresses in 0.005 s. A profile is a fixed set of
aggregates over tables an address already appears in, which is why it stays under a
second on the largest capture this installation holds while the capture that has no
HTTP at all (`SpaceX_loads_of_tabs.pcapng` contains zero HTTP transactions) returns
three questions as `not_applicable` instead of guessing.

The largest capture returned all six visual kinds in one response (7 `bars`, 11
`table`, 1 `timeline`, 1 `histogram`, 1 `heatmap`, 1 `scatter`) and reported two
questions capped: `connections` and `peer_fanout`. On the 55,434-packet capture,
seven questions reported a cap. A capped question is never silently shortened: the
id appears in `truncated` and the page lists it above the grid.

### A URL is the one entity that needs care in transit

A URL entity is a request URI — `"/bounce?%2Fgetuid%3F%252Fsync…"` — so it contains
`/`, `?`, `&` and `%`. The page percent-encodes it into the path
(`encodeURIComponent`), the endpoint declares the parameter as a path
(`{entity:path}`), and the value that arrives is byte-identical to the one the search
returned. That round trip is checked directly against the live index, because a
client library that normalises the path itself decodes the value twice and makes
every URL lookup look empty — a false negative that would have read as "this capture
never saw this request".

---

## 9. Honest limits, stated on the page

* **A profile is about one capture.** A name seen here on one capture is not a claim
  about any other capture in the library. Nothing is merged across captures.
* **No decryption.** TLS and HTTPS payloads are never decrypted, so `domains_contacted`
  and `tls_fingerprints` read metadata only — SNI, versions, ciphers, JA3/JA4 — and a
  question about what crossed inside a tunnel is `not_applicable`, not empty.
* **Objects that cannot be attributed are not attributed.** An extracted object with
  no stream and no frame cannot be tied to an entity; the strip's note states how many
  such objects the capture holds rather than adding them to whoever looks plausible.
* **A MAC is not an identity.** When the same MAC appears for other addresses the
  note says so, and the strip repeats it, because a shared MAC does not identify a host.
* **A match is a lead, not a verdict.** Every widget carries its caveat and the reason
  behind its state, one hover away, and the page labels the hover rather than leaving it
  to be discovered: read a widget as a direction to look in, then check the rows behind
  it through the links it carries.
* **Nothing is estimated.** Every number is a count over indexed rows; a question that
  cannot be computed says why; a visual cut to its cap says so; an unknown entity is
  answered with sixteen reasons rather than a placeholder.

---

## 10. Where the code lives

| Part | File |
|---|---|
| Page | `frontend/src/pages/InvestigatePage.tsx` |
| Search box | `frontend/src/components/profile/EntitySearch.tsx` |
| Entity strip | `frontend/src/components/profile/EntitySummary.tsx` |
| Widget | `frontend/src/components/profile/QuestionTile.tsx` |
| Chart dispatch | `frontend/src/components/profile/EntityVisual.tsx` |
| Chart renderers | `frontend/src/components/threat/` (shared with the Threat Map) |
| Section identity | `frontend/src/theme/sections.ts` (hue `--c-map-local`, variant `signal`) |
| Stylesheet | `frontend/src/index.css` (the `signal pages` block) |
| Endpoints | `backend/app/api/routes_profile.py` |
| Computation | `backend/app/services/entity_profile.py` |
| Contract | [`docs/ENTITY_PROFILE.md`](../docs/ENTITY_PROFILE.md) |
| Types | `frontend/src/types/index.ts` (`EntityProfile`, `ProfileMatch`, …) |
| Client | `frontend/src/services/api.ts` (`profileApi`) |

**Related:** [Threat-Hunt.md](Threat-Hunt.md) asks the capture-wide questions; this
page asks the same kind of question of one entity. [Hosts.md](Hosts.md),
[DNS.md](DNS.md) and [HTTP.md](HTTP.md) hold the rows each widget links to.
[Findings.md](Findings.md) holds what the last widget names.
[PCAP-Files.md](PCAP-Files.md) manages the captures a profile is read from, and
[Architecture.md](Architecture.md) explains how those tables were built.
