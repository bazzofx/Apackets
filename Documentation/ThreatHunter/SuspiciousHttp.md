# Suspicious HTTP Activity (`suspicious_http`)

Part of the **Threat Map** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Do requests carry paths, credentials or payload types a normal client would not
send?**

## 2. How to read the card

The headline counts *flagged HTTP transactions*: transactions that carry at least
one lead flag written by the HTTP analyser, or that name an executable or script
payload in their URI extension or declared content type. It is a count of
transactions across the whole capture, not capped by `top`.

Three visuals are drawn:

* a **timeline** of HTTP requests per `window`-second bucket across the whole
  capture, with the buckets that contain at least one flagged transaction marked.
  The line is total request volume; the marks are where the interesting requests
  sit. That distinction is the point of the chart — a burst of scanning looks like a
  spike with every bucket marked, while a single bad request looks like a flat line
  with one mark;
* a **histogram** of flagged transactions by reason: one labelled column per
  category that occurred (`credentials in clear text`, `suspicious request path`,
  `server error response`, `client error response`, `unusual HTTP method`, `address
  used as Host header`, `unusual user agent`, `executable or script payload`). Each
  transaction contributes exactly one category — the first that applies in the
  priority order below — so the columns sum to the headline;
* a **table** of the flagged transactions themselves, most recent first, one row per
  transaction: the reason it was flagged, the method plus host plus path, the status
  code, the client address and the request frame number. Each row links out to the
  transaction on the HTTP page, to the client on the Hosts page and to the frame in
  the packet browser, so every flagged request is one click away from its evidence.

A **high** reading is a broad histogram — several categories with non-trivial counts
— or a timeline where most buckets are marked, which means the suspicious traffic is
the ordinary traffic. A **low** reading is a single category with a handful of
transactions. A zero headline with `availability: "empty"` means nothing in the
capture carried a flag or a dangerous payload type; the timeline is still drawn, with
no marks.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_suspicious_http(index)` with the categoriser `_http_category(row)`
in `backend/app/services/threat_hunt.py`.

1. If the HTTP index holds no rows, return `not_applicable` with
   `the capture recorded no HTTP transactions`.
2. Read up to `PACKET_SCAN_CAP` transactions in time order, taking the id, timestamp,
   request frame, client and server addresses, host, method, URI, status code, user
   agent, content type, response length and the analyser's `flags` JSON.
3. For each transaction, decide a category. The flag tokens in `flags` (each entry
   split at its first `:` so `cleartext_credentials:password` becomes
   `cleartext_credentials`) are tested in this fixed priority order, and the first
   match wins:
   1. `cleartext_credentials` — credentials in clear text
   2. `suspicious_path` — suspicious request path
   3. `server_error` — server error response
   4. `client_error` — client error response
   5. `unusual_method` — unusual HTTP method
   6. `ip_host` — address used as Host header
   7. `unusual_user_agent` — unusual user agent
4. If no flag matched, check the payload: the URI's extension (query string and
   fragment stripped, so `?x=1` cannot fake an extension) against
   `DANGEROUS_EXTENSIONS_STRICT`, or the declared content type against the twelve
   `DANGEROUS_CONTENT_TYPES` markers. A match gives the category
   `dangerous_payload`, `executable or script payload`.
5. If still nothing matched but the transaction has flags whose token is not one of
   the seven above, fall back to that first token, with underscores replaced by
   spaces.
6. Count transactions per category, and record the last label seen per category for
   the histogram's axis.
7. Order the flagged transactions newest first. The headline is how many there are.
8. Build the timeline from **every** transaction in the capture, then mark the
   buckets that contain at least one flagged transaction.
9. Collect up to five distinct `host` values from the flagged transactions as links.

The category is a presentation choice: a transaction with both a clear-text password
and a traversal path is counted once, under credentials, and the traversal is not
visible anywhere on the card.

## 4. Thresholds

This detection is a categoriser rather than a counter, so it has no numeric
threshold of its own. The gates are two fixed sets, plus the flags written by
`backend/app/services/http_analyzer.py`.

| Constant | Value | What it does |
|---|---|---|
| `DANGEROUS_EXTENSIONS_STRICT` | `DANGEROUS_EXTENSIONS` minus `js`, `sh`, `bin` — that is **21** extensions: `exe`, `dll`, `scr`, `com`, `pif`, `bat`, `cmd`, `ps1`, `vbs`, `vbe`, `jse`, `wsf`, `hta`, `cpl`, `jar`, `msi`, `msp`, `apk`, `elf`, `run`, `lnk` | The URI extensions that count as an executable or script payload. `DANGEROUS_EXTENSIONS` itself has 24 entries; the three excluded ones are ubiquitous on the web and would flag ordinary traffic. |
| `DANGEROUS_CONTENT_TYPES` | **12** markers: `application/x-msdownload`, `application/x-msdos-program`, `application/x-dosexec`, `application/vnd.microsoft.portable-executable`, `application/x-executable`, `application/x-elf`, `application/java-archive`, `application/x-msi`, `application/x-sh`, `application/x-bat`, `application/x-powershell`, `application/x-msmetafile` | Substring match against the transaction's lower-cased `content_type`. |
| `PACKET_SCAN_CAP` | `20000` | Maximum transactions read. |
| `TIMELINE_CAP` | `240` | Maximum points in the timeline (the earliest 240 buckets). |
| `TABLE_CAP` | `50` | Caps the flagged-transaction table at 50 rows, most recent first. The histogram is not capped: it counts every flagged transaction, and there are at most eight categories. |
| `top` | `12` (1–50) | **Not used by this detection**: the histogram is not a ranked `bars` visual, so `top` changes nothing on this card. |
| `SCATTER_CAP` | `200` | Not used by this detection. |

The conditions behind the flags live in `http_analyzer.py`, not here:

| Constant (in `http_analyzer.py`) | Value | Flag it raises |
|---|---|---|
| `COMMON_METHODS` | `GET`, `POST`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `PATCH` | `unusual_method` for anything else |
| `SUSPICIOUS_PATH_PATTERNS` | 12 plain substrings: `../`, `/etc/passwd`, `cmd=`, `exec`, `eval`, `.php?`, `union select`, `<script`, `/admin`, `/shell`, `wget `, `curl ` | `suspicious_path` |
| `CREDENTIAL_KEYWORDS` | 10 keywords: `password`, `passwd`, `pwd`, `pass=`, `token=`, `api_key`, `apikey`, `secret`, `authorization:`, `user=` | `cleartext_credentials:<keyword>` |
| `TOOL_USER_AGENTS` | 11 signatures: `sqlmap`, `nikto`, `nmap`, `masscan`, `curl`, `wget`, `python-requests`, `go-http-client`, `hydra`, `dirbuster`, `gobuster` | `unusual_user_agent:<signature>` |
| — | status 500–599 | `server_error` |
| — | status 400–499 | `client_error` |
| — | Host header is an IP address | `ip_host` |
| — | missing user agent / length over 200 characters | `unusual_user_agent:missing` / `unusual_user_agent:long` |

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `http_transactions.flags` | The analyser's JSON lead-flag array; the primary input to the categoriser. |
| `http_transactions.uri` | Tested for a dangerous extension, and part of the request identity. |
| `http_transactions.content_type` | Tested against `DANGEROUS_CONTENT_TYPES`. |
| `http_transactions.host` | The `/http?host=` links, and the first element of a request's display identity. |
| `http_transactions.time_epoch` | The timeline bucket for every transaction, and the sort order of the flagged list. |
| `http_transactions.id` | Tie-break ordering, and the `/http?tx=` link the engine builds for a transaction. |
| `http_transactions.request_packet` | The `/packets?sel=` link the engine builds for a request frame. |
| `http_transactions.method`, `http_transactions.status_code`, `http_transactions.client_ip`, `http_transactions.server_ip`, `http_transactions.user_agent`, `http_transactions.response_len` | Read by the query and used to build the (unattached) transaction table, the links and the run-length figures; `method`, `status_code` and `client_ip` are not otherwise rendered on the card. |

## 6. Fields the analyst brief asks for but the index does not hold

* **`http.request_in` / `http.response_in`.** These TShark fields — the frame number
  in which a request or response was completed within a TCP stream — are not
  columns. `http_transactions.request_packet` and `response_packet` are the
  analyser's own reconstruction of the same idea, and the engine uses
  `request_packet` for the frame link. The cost is that the frame shown is the
  analyser's chosen frame, which may be the first frame of the request rather than
  the one that carried a particular header.
* **Payload content.** `http_transactions.request_body` and `response_body` hold a
  decoded preview, and this detection never reads them. `Cleartext credentials` and
  `suspicious path` are therefore conclusions the *analyser* reached from the URI,
  headers and body preview at index time, and the section only reports the resulting
  flag. If the analyser's body preview was truncated, this detection cannot recover
  the missed content — there is no second pass.
* **`http.file_data`, MIME sniffing, file magic.** Not indexed. A payload's real
  type is never established: `dangerous_payload` means the URI ended in a suspicious
  extension or the server *declared* a suspicious content type. A `.exe` served as
  `text/html` is still caught by the extension; a `.php` beacon served as
  `application/octet-stream` is not.
* **Response bodies as evidence.** `response_body_size` and
  `response_body_truncated` exist and are not read here, so the card cannot show how
  large a flagged response was.
* **`http.request.full_uri`.** `full_uri` is indexed and the engine uses `host` plus
  `uri` instead.
* **Cookie and authorization header contents beyond the flag.** `request_headers`
  holds a JSON object of headers and is not read by this detection, so no evidence
  for a clear-text credential is shown on the card — only the fact that the analyser
  found a keyword.
* **TLS-wrapped HTTP.** HTTP inside TLS produces no `http_transactions` rows, so on
  a modern capture this card is mostly empty for exactly the traffic that matters
  most.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| Everything the flagged hosts did | `/http?host=<host>` | The full request set for one host, which gives a flagged request its context. |
| Only the flagged transactions | `/http?interesting=true` | The HTTP page's own filter for transactions carrying any lead flag. |
| One request in detail | `/http?tx=<transaction id>` | Headers, body preview and timing for a single transaction. |
| The client | `/hosts?ip=<client>` | Whether the client is a tool host, a workstation or a server. |
| The server or address | `/http?server_ip=<server>` | What else was requested from that server. |
| The frames | `/packets?ip=<server>&protocol=tcp` | The raw exchange, and `sel` to open the request frame inside its stream. |
| The extracted payload | `/objects` | Whether the analysis extracted the file, so its type and hash can be checked. |

## 8. What it does not prove

A suspicious-looking request does not establish compromise. It establishes that a
request had a shape that the analyser considered worth flagging — a path that looks
like traversal, a word that looks like a credential, a method no browser sends, a
declared executable type. None of that says the request succeeded, that the server
was vulnerable, or that the client was malicious. The card's own caveat says the same
thing:

> A suspicious-looking request does not establish a compromise. The same patterns
> come from vulnerability scanners, security tooling, application error pages and
> legitimate administrative interfaces.

## 9. Known limits and false positives

* **Vulnerability scanners and security tooling.** The analyser's own
  `TOOL_USER_AGENTS` list (sqlmap, nikto, nmap, masscan, curl, wget, hydra,
  dirbuster, gobuster) exists because these tools are *expected* to appear; a scan of
  your own estate produces a full histogram with nothing wrong.
* **Administrative interfaces.** `/admin`, `/phpmyadmin` and similar paths are in the
  suspicious-path list and are also exactly what an administrator types.
* **Client errors are ordinary.** Any 404 or 401 raises `client_error`, so a web
  application that returns 404 on a favicon fills the histogram's smallest column.
* **Clear-text credentials are often by design.** A legacy internal application that
  posts a form field called `password` over HTTP raises `cleartext_credentials`
  every time. That is a real finding about the application and not an intrusion.
* **One category per transaction.** The priority order means only the highest-priority
  reason is counted, so a request that is both a traversal attempt and a clear-text
  credential is reported only as credentials.
* **The table is capped at `TABLE_CAP = 50` rows**, most recent first, so a capture
  with hundreds of flagged transactions shows the newest fifty and says so in the
  table's note. The headline counts all of them.
* **The `top` parameter does nothing here.** This card is not a ranked visual, so the
  endpoint's `top` parameter does not shorten it.
* **Structural caps.** At most `PACKET_SCAN_CAP = 20000` transactions are read and
  only the earliest `TIMELINE_CAP = 240` buckets are drawn, so a flagged request late
  in a long capture is counted in the headline but may not be marked on the line.
* **An empty card is not clean.** It means no transaction carried one of the
  analyser's flags and none named an executable or script payload type. Requests
  inside TLS are not in the HTTP index at all and cannot appear here.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [HTTP](../HTTP.md) · [Packets](../Packets.md) · [PossibleMalwareDownload](PossibleMalwareDownload.md) · [IdsSignatureMatches](IdsSignatureMatches.md)
