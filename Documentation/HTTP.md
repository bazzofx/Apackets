# HTTP

Every cleartext HTTP request and response TShark dissected from the selected capture, with the
analyser's lead flags beside each transaction.

The page is `frontend/src/pages/HttpPage.tsx` and its route is `/http`. It sits with the other
two protocol pages, [DNS](DNS.md) and [TLS](TLS.md), under **Protocols** in the left-hand
navigation. The normative interface shape is [`docs/CONTRACT.md`](../docs/CONTRACT.md) §5; this
document explains behaviour.

---

## 1. What it is for

**What was requested in the clear, what came back, and which of those requests should I read
first?** HTTP is the one application protocol this app can read end to end: method, host, URI,
status, headers and a body preview are all stored, so this page answers "what did the client ask
for and what did the server say" without any decryption. Everything else on a modern network is
inside TLS and never reaches this table. The page is therefore a starting point for reading
requests and responses in detail, and for triaging which of them the analyser thought were worth
a second look.

## 2. What is on the screen

### Lead flag legend

The first thing on the page, and **collapsed by default**: a **How to read HTTP lead flags** panel
enumerating every flag this page can show, with a short meaning for each. *Show* opens it. It
carries the standing note that status codes are facts about the response while the flags are
patterns matched in request fields — a single 4xx, or a literal-IP Host header on its own,
is not evidence of anything.

There is no scope panel on this page. What HTTP can and cannot show is stated where it matters
instead: an empty table means no cleartext HTTP was found, not that the capture is clean, because
HTTPS payloads are never decrypted.

### Status summary

A row of chips, one per stored status class, labelled `2xx · 123`. The counts are computed over
**every HTTP transaction in the analysis, not the current filter** — the panel subtitle says so.
Clicking a chip sets the `status` filter to that class; clicking it again clears it, and an active
class also appears as a removable `status = 4xx` chip. Beside the chips the panel states how many
distinct methods and hosts were observed, and how many rows **on the current page** carry lead
flags. A refresh button re-reads the list.

### The transaction table

Columns, left to right, exactly as rendered:

| Column | Meaning |
|---|---|
| Time | `frame.time_epoch` of the request frame, as `YYYY-MM-DD HH:MM:SS.mmm` local time. |
| Client | Request source address and port, `ip:port`. |
| Server | Request destination address and port. |
| Method | `http.request.method`, verbatim. `—` on a row built only from a response. |
| Host | `http.host` (the Host header). |
| URI | `http.request.uri` — the path and query as sent, not the absolute URL. |
| Ver | `http.request.version`, e.g. `HTTP/1.1`. |
| Status | `http.response.code`, colour-coded: 5xx red, 4xx amber, 3xx blue, 2xx green, anything else muted. |
| User-Agent | `http.user_agent`. |
| Referer | `http.referer`. |
| Content-Type | `http.content_type` of the response. |
| Req | Total request message length in bytes, `formatBytes`. Empty when the stream was not reassembled. |
| Resp | Total response message length in bytes. Empty for the same reason. |
| Lead flags | One badge per recorded flag; hovering a badge shows the raw flag key and its explanation. `—` when the row carries none. |

Above the table: a **Sort** select (time, method, host, uri, status, response length), a direction
toggle, and **Reset filters**.

### The filters

Every filter lives in the query string, so a view can be copied and shared; the page re-reads the
URL on every render. The complete list of parameters this page owns, transcribed from `URL_KEYS`
in `HttpPage.tsx`, in order:

```ts
const URL_KEYS = [
  'method',
  'host',
  'uri',
  'status',
  'client_ip',
  'server_ip',
  'user_agent',
  'search',
  'interesting',
  'sort',
  'order',
  'page',
  'page_size',
  'tx',
]
```

| Parameter | What it filters |
|---|---|
| `method` | **Exact** method match. The backend upper-cases the value and compares `UPPER(method) = ?`; the dropdown lists only the methods actually stored in this analysis. |
| `host` | **Substring** match on the Host header (`LIKE`; `%` and `_` are escaped so they stay literal). |
| `uri` | **Substring** match on the request URI. |
| `status` | An exact code (`404`) or a class (`4xx`). The backend recognises a three-character `Nxx` and a longer `NNxx` form, otherwise parses an integer. **A value it cannot parse makes the query match nothing at all**, so a typo returns an empty table rather than an error. |
| `client_ip` | **Exact** client address. |
| `server_ip` | **Exact** server address. |
| `user_agent` | **Substring** match on the User-Agent header. |
| `search` | One substring tested against the URI, the Host header, the User-Agent **and** the full URI. |
| `interesting` | `true` — only transactions whose stored `flags` array is non-empty. The checkbox writes `true` only; the API also accepts `false` (rows with no flags), but the page never produces that value. |
| `sort` | Sort column. The UI offers `time_epoch`, `method`, `host`, `uri`, `status_code` and `response_len`; the endpoint also allows `request_packet`. |
| `order` | `asc` (the page's default) or `desc`. |
| `page` | 1-based page number. |
| `page_size` | Rows per page; the page's default is `100` and the API caps it at `MAX_PAGE_SIZE = 1000`. |
| `tx` | The id of the transaction whose detail panel is open. This is selection state, not a filter. |

`page`, `page_size`, `sort`, `order` and `tx` are listed in `NON_FILTER_KEYS`
(`frontend/src/components/protocols/ProtocolFilters.tsx`). They therefore do **not** count towards
"filters active", they survive **Reset filters**, and changing one does not reset the page number.
Changing any other filter resets `page`.

### The detail panel

Selecting a row (click, or Enter/Space) sets `tx` and opens **Transaction detail** below the
table. It re-reads that transaction on its own request and shows:

* the reconstructed request line, the status line, and the **full URI** when one exists, each with
  a copy button, plus a copy-the-whole-transaction-as-text button;
* a detail grid: Time, Response time, Response delay (computed in the browser as
  `response_time - time_epoch`, shown to six decimals), Client, Server, Stream, Method, Host,
  Version, Status code, Status phrase, Content-Type, Full URI, User-Agent, Referer, Server header,
  Request length, Response length, Request body size, Response body size, Response truncated,
  Request packet, Response packet. Every unavailable field renders `—` with a tooltip explaining
  why — for example "No response packet was matched to this request in the capture";
* the full reasoning for each recorded lead flag;
* request and response header tables (duplicate header names are stored suffixed `#2`, `#3` … so
  nothing is silently lost), each with a copy button;
* request and response body previews, with an explicit notice for each of the three real cases:
  the preview is complete, the preview was cut at the configured limit, or no preview is stored
  although a body length was measured. A non-text Content-Type is called out as a printable
  rendering of the captured bytes rather than the original text.

### What the page shows when there is nothing

* **No capture selected** — the shared `AnalysisGuard` shows an empty state pointing at
  [PCAP-Files.md](PCAP-Files.md), because no analysis is chosen in the top bar.
* **Analysis still running** — a progress panel with the current stage, refreshed every two
  seconds; a failed or cancelled analysis shows the backend's reason.
* **No transactions and no filters** — the status summary reads "No transactions stored for this
  analysis." and the table area shows an empty state: *"TShark dissected no cleartext HTTP messages
  in this capture. HTTPS traffic is not decrypted by this app, so an encrypted-only capture
  legitimately shows nothing here."* This is a real state, not a hypothetical one:
  `SpaceX_111025.pcapng` in `data/` holds 20 TLS sessions and 14 DNS rows and **zero** HTTP
  transactions.
* **No rows matching active filters** — a different empty state advises widening or resetting the
  filters and names the "interesting only" toggle as the usual culprit, with a reset button.

## 3. Where the data comes from

| Layer | Name |
|---|---|
| Page component | `frontend/src/pages/HttpPage.tsx` — `HttpPage` (wrapped in `AnalysisGuard`), `HttpContent`, `TransactionDetail`, `TransactionDetailBody` |
| Shared filter state | `useUrlFilters` in `frontend/src/components/protocols/ProtocolFilters.tsx` |
| Flags and legends | `HTTP_FLAG_CATALOG`, `HTTP_FLAG_KEYS` in `frontend/src/components/protocols/ProtocolFlags.tsx` |
| Frontend client | `httpApi.list` / `httpApi.get` in `frontend/src/services/api.ts` |
| Endpoints | `GET /api/analyses/{analysis_id}/http` (list, plus `methods`, `hosts` and `status_classes` blocks) and `GET /api/analyses/{analysis_id}/http/{transaction_id}` (detail) |
| Route module | `backend/app/api/routes_http.py` (router prefix `/api/analyses/{analysis_id}`) |
| Table | `http_transactions` in `backend/app/db/schema.sql` |
| Analysis that fills it | `backend/app/services/http_analyzer.py`, run as the `http` stage of `backend/app/services/pipeline.py` |

The list endpoint serves rows from `http_transactions` only. The three blocks that drive the
dropdowns (`methods`, `hosts`, `status_classes`) are computed from the same table for the whole
analysis, so a filter value can never be offered that does not exist in the capture.

The analyser needs two TShark passes: a field pass over the scalar fields
(`http.request.method`, `http.request.uri`, `http.request.version`, `http.host`,
`http.response.code`, `http.response.phrase`, `http.user_agent`, `http.referer`,
`http.content_type`, `http.server`, `http.content_length`, `http.request.full_uri`), and a second
pass for the multi-valued header lines (`http.request.line` / `http.response.line`) because
TShark's `occurrence` option is global. Bodies come from TShark's stream reassembly
(`-z follow,tcp,raw`), split per message, and are attached **only when the parsed message counts
match the observed transaction counts**; otherwise the length and body columns stay NULL.

Transactions are paired per `tcp.stream`: a request frame opens a pending transaction and the next
response on that stream closes it, so keep-alive streams yield one transaction per request. A
response whose request is not in the capture becomes its own row with no method and no request
fields, rather than being dropped.

## 4. What the flags mean

All of these are computed by `compute_flags(transaction)` in
`backend/app/services/http_analyzer.py` and stored in `http_transactions.flags` at analysis time.
The route neither recomputes nor extends them: `interesting=true` is a test on the stored array.
Changing any constant below therefore requires re-analysing the capture before the page reflects it.

| Flag | Exact condition (as written in the code) | What it does not establish |
|---|---|---|
| `client_error` | `400 <= status <= 499` in `compute_flags`, where `status = response.status_code` | Nothing about intent. Ordinary 404s, 403s and expired-session noise produce it constantly. Volume and repetition against one host or client are the interesting part. |
| `server_error` | `500 <= status <= 599`. Checked **before** `client_error` with `elif`, so a row never carries both, and a status below 400 carries neither. | Nothing about the server being compromised; a healthy service returns 5xx for one malformed request. |
| `unusual_method` | `request.method and request.method not in COMMON_METHODS`, where `COMMON_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}` | Nothing about the client being hostile. WebDAV and REST APIs use `PROPFIND`, `PATCH` and friends legitimately. A response-only row has no method and raises nothing. |
| `suspicious_path` | The first match (`break`, so at most one instance) of any substring in `SUSPICIOUS_PATH_PATTERNS` inside the lower-cased `uri + "\n" + "Name: value\n…"` header text. The 12 substrings are `../`, `/etc/passwd`, `cmd=`, `exec`, `eval`, `.php?`, `union select`, `<script`, `/admin`, `/shell`, `wget `, `curl `. | That a traversal or injection was attempted, or that any of it succeeded. These are plain substrings and they appear in ordinary traffic. Measured: in `sf19us-MTA-lab-01.pcap`, the request `GET /favicon.ico` on `blog.eskill.com` is flagged because its Google Analytics cookie contains `utmcmd=(none)` — which contains `cmd=`. Read the response status and the surrounding session before reading anything into it. |
| `ip_host` | `_is_ip_host(request.host)`: the host is parsed as a literal address after stripping a `:port` suffix or unwrapping `[IPv6]`, using `ipaddress.ip_address`. | That the client is a scanner. Direct-IP testing, internal services and misconfigured clients do the same, and a hostname that simply looks numeric is not flagged. |
| `cleartext_credentials:<keyword>` | The first match (`break`) of any of the 10 `CREDENTIAL_KEYWORDS` (`password`, `passwd`, `pwd`, `pass=`, `token=`, `api_key`, `apikey`, `secret`, `authorization:`, `user=`) in the lower-cased, dash-normalised (`-` → `_`) text of `uri + headers + request_body`. The matched keyword is appended to the flag. | That a secret was present, let alone valid — the test is on **field names**, not values. Measured: four transactions in `sf19us-MTA-lab-01.pcap` are flagged on the keyword `user=` inside tracking query strings (`?newuser=1&dc_rc=1…` on `ps.eyeota.net`), not on any credential. The check does establish that whatever the field did carry travelled unencrypted. |
| `unusual_user_agent:missing` | `not user_agent` — the request carried no User-Agent at all. | Anything on its own. The three User-Agent branches are one `if`/`elif`/`else`, so a row carries exactly one of them. |
| `unusual_user_agent:long` | `len(user_agent) > 200`. The threshold is a literal `200` in `compute_flags`, not a named constant. | Automation. Long legitimate browser and application agents exist. |
| `unusual_user_agent:<signature>` | Otherwise, the first signature in `TOOL_USER_AGENTS` found in the lower-cased agent (`sqlmap`, `nikto`, `nmap`, `masscan`, `curl`, `wget`, `python-requests`, `go-http-client`, `hydra`, `dirbuster`, `gobuster`; `break` after the first). | Malice. Administrators, monitoring agents and software updaters use these tools as well as anyone else. |

A row can carry several flags at once. The status, method, path, host, credential and User-Agent
tests are independent of one another — the only exclusive pair is `client_error` / `server_error` —
while the credential, path and User-Agent tests each stop at their first match, so a row carries at
most one keyword, at most one path-match and exactly one of the three User-Agent forms.

## 5. Links into the rest of the app

The page has no outbound links: rows, flags and detail fields are rendered as text and copy
buttons, and it never navigates to another section. Navigation happens through the parameters
above and through the other sections linking in:

| To get there | Use | What to look for |
|---|---|---|
| One transaction, opened | `/http?tx=<transaction id>` | The header blocks, the body previews and the reasoning for each flag. |
| One host's requests | `/http?host=<host>` | Whether a flagged request is a one-off or part of a pattern. |
| One server address | `/http?server_ip=<address>` | What else was requested from that address, including by other clients. |
| One client's requests | `/http?client_ip=<address>` | Whether the client also did the flagging-worthy things the Threat Map section reports for it. |
| Only flagged rows | `/http?interesting=true` | The whole flagged set at once, rather than page by page. |
| One host's full-text matches | `/http?search=<text>` | The same substring across URIs, hosts, User-Agents and full URIs. |

The packet and stream numbers shown in the detail panel are the hand-off to the raw traffic: open
the frame in [Packets.md](Packets.md) with `/packets?mode=basic&sel=<frame number>`, and reach the
stream itself from [Conversations.md](Conversations.md) with the `stream_id` the detail panel
shows. Bodies that are cut here are complete in the stream view, and files the analyser extracted
are listed in [Files-and-Objects.md](Files-and-Objects.md).

Several Threat Map detections are built on this page's rows and link back into it —
[ThreatHunter/SuspiciousHttp.md](ThreatHunter/SuspiciousHttp.md),
[ThreatHunter/PossibleMalwareDownload.md](ThreatHunter/PossibleMalwareDownload.md),
[ThreatHunter/IdsSignatureMatches.md](ThreatHunter/IdsSignatureMatches.md) and
[ThreatHunter/RareCommunicationPairs.md](ThreatHunter/RareCommunicationPairs.md); the section
overview is [Threat-Hunt.md](Threat-Hunt.md).

## 6. Limits and honest caveats

* **HTTPS is invisible.** TLS payloads are not decrypted anywhere in this app, so no request or
  response inside an encrypted session appears on this page. Most web traffic is HTTPS: an empty
  table is a statement about the capture, not about the network.
* **Only what TShark dissects as HTTP/1.x reaches the table.** The analyser reads `http.*` fields
  only; there is no `http2.*` or QUIC handling in `http_analyzer.py`, so traffic TShark identifies
  as HTTP/2 or HTTP/3 does not produce rows here.
* **Bodies are conditional.** Lengths, sizes and previews are stored only when TShark's stream
  reassembly produced exactly as many parsed messages as there are transaction rows on that
  stream. When it did not — a mid-stream capture, missing packets, an unusual framing — every
  length and body field on those rows stays NULL and the Req/Resp columns show `—`. In
  `sf19us-MTA-lab-01.pcap` all 102 transactions have both lengths; that is not guaranteed in
  general.
* **Previews are capped, and only responses say so.** The limit is the setting
  `body_preview_bytes` — `256 * 1024` bytes by default in `backend/app/core/config.py`,
  adjustable at runtime between `1024` and `8 * 1024 * 1024`. A response whose preview was cut
  carries `response_body_truncated = 1`, which the detail panel renders as "yes" and the body
  notice spells out. There is no equivalent column for the request body, so a truncated request
  preview is not flagged as such. For non-text content types the same limit is applied to the
  hexadecimal rendering rather than to the byte count, so the visible byte count differs.
* **The credential flag reads only what is stored.** It tests the URI, the stored headers and the
  stored (possibly truncated) request body. A credential named deeper in a body larger than the
  preview limit, or in a body that could not be reassembled, is not seen.
* **Flags are a snapshot of the analysis, not a live verdict.** They are written once, when the
  capture is analysed; no page recomputes them, and the API's own `flags` filters test the stored
  text. Nothing on this page changes a flag.
* **A flag is a lead.** The page says it in its own words: the flags "are patterns matched in the
  request fields — a 4xx alone, or a literal IP Host header alone, is not evidence of anything".
  A row with no flags means the analyser saw nothing worth flagging in the fields it reads, which
  is not the same as benign traffic.
* **A status filter typo is silent.** An unparseable `status` value compiles to `0 = 1`: the table
  is empty and no error is shown.
* **Paging is bounded.** `page_size` is capped at `MAX_PAGE_SIZE = 1000`, so a very large capture
  is read a page at a time; the flagged-row count in the status summary describes the current page
  only, while the status-class chips describe the whole analysis.

---

**Related:** [DNS](DNS.md) · [TLS](TLS.md) · [Packets](Packets.md) · [Conversations.md](Conversations.md) · [Files-and-Objects.md](Files-and-Objects.md) · [Threat-Hunt.md](Threat-Hunt.md) · [SuspiciousHttp](ThreatHunter/SuspiciousHttp.md) · [README.md](README.md)
