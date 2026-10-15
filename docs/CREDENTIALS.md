# Credential discovery — the normative contract

Visible (cleartext) credentials in a capture: usernames, passwords, API keys, bearer tokens
and other secrets that crossed the wire unencrypted and were therefore recoverable from the
bytes on the wire. This document fixes the interface: where the scanner reads, what it looks
for, how it scores what it finds, what it stores, the endpoints that serve it, and the limits
it states rather than hides. Code and tests must match this document; where this document and
the code disagree, one of them is a bug.

Application code: `backend/app/services/credential_analyzer.py`,
`backend/app/api/routes_credentials.py`, `frontend/src/pages/CredentialsPage.tsx`. In the
interface the feature is called **Users & Passwords** and it sits under **Investigate** at
`/credentials`; the route, the table and the file names keep the word `credentials`, because
that is what the values are.

---

## 1. Scope

**Cleartext only.** A credential is recoverable only if it crossed the wire in a form the
application's own dissectors already decoded:

| In scope | Why |
|---|---|
| HTTP — `Authorization`, `Cookie`, URL query, form body, JSON body | the request is plain text |
| FTP — `USER`, `PASS` on the control channel | the control channel is plain text |
| SMTP — `AUTH LOGIN`, `AUTH PLAIN`, `USER`/`PASS` | plain text on ports 25/587 before STARTTLS |
| POP3 — `USER`, `PASS`, `AUTH` | plain text on 110 |
| IMAP — `LOGIN`, `AUTHENTICATE` | plain text on 143 |

**Out of scope, and the reason is never "nothing there":**

* **Anything encrypted.** TLS, HTTPS, SSH, SMB signing, `AUTH TLS`/STARTTLS/`STLS` sessions,
  and anything on 443/465/993/995/22. This build never decrypts, so a credential inside those
  sessions is unreachable — not absent. The page says so.
* **Telnet.** This build has no Telnet dissector, so there is no location to read: adding it
  means a new capture pass over port-23 streams, which this phase deliberately does not do.
* **DNS labels.** A credential-shaped query label is not a credential until something proves
  it is; without a protocol context there is no such proof, so nothing is reported from DNS.
* **Non-textual bodies.** A gzip or image body is not scanned as text: a request whose own
  `Content-Type` says so is skipped (§3.1.1). A body whose request declared nothing is read
  by its shape, and a body that is neither JSON nor a form is read as free text — a binary
  body that arrived with no declaration at all is therefore read as text, which finds
  nothing unless it happens to contain a labelled or shaped value.
* **What the analysers capped.** The scanner reads the rows the other analysers wrote, so
  anything they truncated (HTTP body previews, the per-session command cap) is beyond reach
  too. This is the price of being lightweight, and §10 states it.

---

## 2. Where it reads from

Two sources, and no third:

**(a) The rows the other analysers already wrote** — free, no dissection:

| Protocol | Source rows | Locations inspected |
|---|---|---|
| HTTP | `http_transactions` | `request_headers` (`Authorization`, `Cookie`, `X-Api-Key` and similar), `uri`/`full_uri` query, `request_body` parsed as form-urlencoded, JSON or free text |
| all five | `protocol_sessions` | `detail.auth_username`, `detail.auth_mechanisms`, and `detail.commands` **verbs** (`USER`, `PASS`, `AUTH`, `LOGIN`, `AUTHENTICATE`) — which say *that* a credential was exchanged, and whose stream is therefore worth reading |

**(b) The control channel of those sessions, reassembled** — for the four command protocols
only, because the value is deliberately not in the database.

`protocol_analyzer` redacts the verbs whose argument *is* a password (`PASS` for FTP and POP3)
and records `password_present: true` instead; SMTP `AUTH` keeps the mechanism but not the
Base64 exchange that follows it. That is a deliberate property of `docs/PROTOCOLS.md`, and this
feature must not undo it by writing values into `detail`: every `/protocols` response sends
`detail` to the browser, so a value there would be served unredacted on a page with no reveal
control. So the credential stage reassembles **only** the control streams of sessions the
analyser already classified as FTP, SMTP, POP3 or IMAP (capped at `MAX_CONTROL_STREAMS` per
protocol), reads the authentication lines out of that reassembled text, and stores the values
in `credentials` and nowhere else — where the redaction and reveal of §5 apply.

That is the one place this stage touches the capture, and it is bounded: mail and FTP control
streams are few even in a large capture, and no HTTP stream is ever reassembled here (HTTP
bodies are already stored with their transactions).

**Protocol confirmation is not optional.** Nothing is reported from a stream that the
analysers did not classify as one of the protocols above: a port number is a hint, not proof,
and the classification already happened upstream. Likewise an empty filter list means **no
restriction**, never "match nothing".

---

## 3. Detector layers

Candidates first, then judgement — never one giant regex over raw bytes.

### 3.1 Format parsers (protocol-aware field extraction)

| Location | Parser |
|---|---|
| `Authorization: Basic <b64>` | strict Base64 decode, split on the **first** `:`, username / password. Invalid Base64 or no colon ⇒ keep the encoded value as one `other_secret` finding at medium confidence, because a malformed Basic header is still an interesting fact |
| `Authorization: Bearer <token>` | scheme-aware: `bearer` ⇒ `bearer_token` |
| `Authorization: <scheme> <value>` (other) | one `other_secret` finding naming the scheme |
| `Cookie: k=v; …` | cookie parser; a cookie whose **name** looks credential-like (`session`, `token`, `auth`, `jwt`, `sid`, `api_key`) becomes a finding, the rest are ignored |
| URL query `?k=v&…` | form-urlencoded parser over the query string |
| `application/x-www-form-urlencoded` body | form-urlencoded parser |
| `application/json` body | JSON parser, walked to a depth of 6; keys are matched by name, values are read as strings only when they are strings, numbers or booleans |
| command protocols | the command verb picks the role: `USER`/`LOGIN` ⇒ username, `PASS` ⇒ password, `AUTH <mechanism> <arg>` ⇒ mechanism-specific (`PLAIN` decodes `\0user\0pass`; `LOGIN` takes the arguments as Base64 username then password) |

Base64 is decoded **only** where a protocol says the field is Base64 (Basic credentials,
`AUTH LOGIN`, `AUTH PLAIN`). A Base64-looking string with no context is reported as *nothing*.

#### 3.1.1 Choosing the reader for a body

`http_transactions.content_type` is the **response's** content type. It can never say how to
read a **request** body, and using it to do so read the most ordinary login on the web — a
form POST to an endpoint that answers JSON — as prose, producing one medium finding whose
value was the whole string `admin&password=secret123` instead of the two `high` fields the
server received. The rule is therefore:

1. **The request's own `Content-Type`** (from `request_headers`) selects the reader. A
   declaration is believed, including `text/*` and a type that says *skip*.
2. **No usable declaration** (the header was absent) ⇒ the body's shape decides, and only
   two shapes are recognised, because each is self-evidencing:
   * a JSON document (starts with `{` or `[` and parses) is read as JSON;
   * a **single line** in which every `&`-separated chunk carries its own `=` and at least
     one chunk has a plausible field name is read as a form.
   Everything else is read as free text, which keeps multi-line labelled prose
   (`password: hunter2`) and sentences (`the user=admin logged in`) in the text reader.
3. **A declared form that parses as JSON** is read as JSON: the parse is proof of what the
   body is, and reading it as a form would find nothing.

Pairs are separated by `&` **and** `;` (the older separator; `parse_qsl` in this Python
takes `separator` as one literal string, so `;` is rewritten to `&` first, and a literal
`;` inside a value must be percent-encoded as `%3B`). Values are percent-decoded, `+`
becomes a space, and a pair of surrounding quotes is removed. A value always ends at the
next pair separator, in the form reader and in the free-text label reader alike.

### 3.2 Field-name matching

A field name is matched case-insensitively, with `_` and `-` treated alike, against:

```
user, username, user_name, login, login_id, logon, email, account, name,
pass, passwd, password, pwd, secret, client_secret, api_key, apikey, access_key,
access_token, auth_token, token, session, sessionid, bearer, authorization
```

A match yields a **candidate**; its value becomes a finding only if it passes §3.4.

This list **contains** `http_analyzer.CREDENTIAL_KEYWORDS` — the application's existing
answer to *"does this request look like it carries a credential"* — reduced to the field
names it implies (`user=`, `authorization:` and the rest are haystack substrings, so the
trailing punctuation is dropped). The two features therefore cannot disagree about a
password form. That keyword list was written to flag a *request*, not to name a *field*, so
it is a floor rather than the whole list: the names above are what this contract adds.
`test_every_name_in_the_shared_keyword_list_is_a_field_kind` fails if the shared list ever
grows a name with no kind here.

### 3.3 Secret shapes (targeted patterns)

Applied only to values that §3.1 or §3.2 already selected — never to whole bodies:

| Kind | Pattern |
|---|---|
| `aws_access_key` | `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b` |
| `jwt` | `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b` |
| `pem_private_key` | `-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----` |
| `github_token` | `\b(?:ghp\|gho\|ghu\|ghs)_[A-Za-z0-9]{36}\b` |
| `slack_token` | `\bxox[baprs]-[A-Za-z0-9-]{10,}\b` |
| `google_api_key` | `\bAIza[0-9A-Za-z_-]{35}\b` |
| `stripe_key` | `\b(?:sk\|pk)_(?:live\|test)_[A-Za-z0-9]{16,}\b` |
| `private_ip_only` | not a secret: never reported |

Each shape is a **shape**, not a validity check. §10 says so on the page.

### 3.4 Value filtering

A candidate is discarded when it is: shorter than `MIN_VALUE_CHARS = 3`; a placeholder
(`password`, `changeme`, `example`, `test`, `xxx…`, `<...>`, `***`, `null`, `undefined`, `true`,
`false`); wholly punctuation or whitespace; longer than `MAX_VALUE_CHARS = 512` (truncated to
it and flagged `value_truncated`); or identical to the field name.

---

## 4. Confidence

| Confidence | Rule |
|---|---|
| **high** | a protocol-confirmed structured location yielded the value: HTTP Basic / Bearer / other `Authorization` scheme, a form or JSON field whose name is credential-like, an FTP/SMTP/POP3/IMAP authentication command, or a §3.3 shape matched inside such a field |
| **medium** | a credential-like field name in a *free-text* body or a URL query, a credential-like cookie name, or a malformed Basic header kept as one opaque value |
| **low** | a §3.3 shape found in a string that no field name vouched for |

Confidence is stored, shown, and never silently upgraded. A finding is a lead, not a verdict.

---

## 5. Redaction and reveal

* List responses **redact by default**: `value_preview` is the value with its middle removed
  (`ab…yz`, first `PREVIEW_HEAD = 3` and last `PREVIEW_TAIL = 2` characters, `•••` between
  them when the value is longer than `2 × (head + tail)`), and the full value is not present
  anywhere in the JSON.
* The full value is served only when the request asks for it: `?reveal=1`. The page holds that
  behind an explicit per-row action and states that revealing shows the wire value. A reveal is
  therefore a **narrowed** list request — the row's own `kind`, `protocol`, `confidence` and
  `stream_id`, with `reveal=1` — whose matching `id` is the row being revealed; the row itself
  says so when the answer did not contain its value, rather than showing a blank as though the
  value were empty.
* **No credential value is ever logged.** The stage logs counts and kinds only.
* The evidence text a finding quotes (for example the header line) is redacted the same way
  before it is stored.

---

## 6. Storage

```sql
CREATE TABLE IF NOT EXISTS credentials (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id   TEXT NOT NULL,
  kind          TEXT NOT NULL,      -- username | password | api_key | bearer_token
                                    -- | other_secret | aws_access_key | jwt
                                    -- | pem_private_key | github_token | slack_token
                                    -- | google_api_key | stripe_key
  value         TEXT NOT NULL,      -- the wire value as recovered
  value_preview TEXT NOT NULL,      -- §5, what every list response shows
  value_length  INTEGER NOT NULL,
  value_truncated INTEGER NOT NULL DEFAULT 0,
  protocol      TEXT NOT NULL,      -- http | ftp | smtp | pop3 | imap
  transport     TEXT,               -- tcp | udp
  stream_id     INTEGER,
  direction     TEXT,               -- 'client_to_server' | 'server_to_client' | NULL
  location      TEXT NOT NULL,      -- e.g. authorization_basic, form_body, url_query,
                                    -- json_body, cookie_header, ftp_user_command,
                                    -- smtp_auth_plain, pop3_pass_command, imap_login_command
  source_field  TEXT,               -- the field name that selected it, when one did
  method        TEXT NOT NULL,      -- how it was derived: basic_decode, bearer_header,
                                    -- form_field, json_field, command_arg, pattern, …
  confidence    TEXT NOT NULL,      -- high | medium | low
  client_ip     TEXT, client_port INTEGER,
  server_ip     TEXT, server_port INTEGER,
  packet_first  INTEGER, packet_last INTEGER,
  evidence      TEXT NOT NULL,      -- one redacted line of context (§5)
  note          TEXT,               -- why it was scored as it was, in one sentence
  created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_analysis ON credentials (analysis_id, kind);
CREATE INDEX IF NOT EXISTS idx_credentials_stream   ON credentials (analysis_id, stream_id);
```

`packet_first` / `packet_last` come from the source row (`request_packet`, `first_frame`) so
the UI can offer the same packet links every other page uses. Rules are deterministic: the
same capture produces the same rows.

---

## 7. The toggle

Two runtime settings, both editable at `/settings` and stored in the `settings` table under
`credential_config`:

| Setting | Default | Meaning |
|---|---|---|
| `credential_scan_enabled` | `true` | when `false` the pipeline **skips the stage** and writes no rows |
| `credential_protocols` | `["http","ftp","smtp","pop3","imap"]` | which protocols to inspect; an empty list means none |

Turning the scan off for an existing analysis does **not** delete what it already found; the
page reports the setting's current state and the time the rows were written, so the two can
never be confused. A rescan (`POST …/credentials/scan`) re-runs the stage on demand.

Both values are read and written through the existing settings endpoints — `GET /api/settings`
returns them beside the other runtime settings, `PUT /api/settings` accepts either or both —
and `GET /api/settings` also returns `credential_protocols_available`, the protocols this build
can scan, so the page never offers a protocol the scanner does not implement. A key the
response omits is reported as unavailable rather than assumed to hold the defaults above.

---

## 8. Endpoints

### 8.1 `GET /api/analyses/{analysis_id}/credentials`

Query: `kind`, `protocol`, `confidence`, `stream_id`, `unique` (default `1`; `0` for every
occurrence), `reveal` (`1` to include `value`), `sort`
(`confidence|kind|protocol|created_at`, default `confidence`), `order`
(`asc|desc`, default `desc`), `page`, `page_size`.

**The default view is one row per distinct value.** A credential is the value; the streams it
crossed are where it was seen. A capture that authenticates seven times with one username and
one password carries **one** username and **one** password, and seven identical rows would say
something untrue about it — so `unique=1` returns one row per distinct `(kind, value)`, and each
row names every occurrence behind it:

| Extra item field | Meaning |
|---|---|
| `occurrences` | how many stored rows this value accounts for |
| `stream_ids` | every stream it was seen in, ascending; the row's own `stream_id` is the first |
| `protocols` | every protocol it was seen in, when more than one |
| `locations` | every location it was read from, when more than one |

The row itself is the **earliest occurrence**, so its value, preview, method, source field and
packet numbers belong to one real stored row rather than to a blend of several. Nothing is
merged into the value: the stored rows are untouched, and `unique=0` returns them one by one for
anyone who wants the per-stream evidence. `counts.total`, `counts.by_kind` and
`counts.by_confidence` count **distinct values** in this view, and `counts.occurrences` reports
the stored rows behind them, so "one credential seen seven times" can never be read as seven.

```json
{
  "items": [
    {
      "id": 12,
      "kind": "password",
      "value_preview": "Exa•••23",
      "value_length": 18,
      "value_truncated": false,
      "protocol": "http",
      "transport": "tcp",
      "stream_id": 36,
      "direction": "client_to_server",
      "location": "authorization_basic",
      "source_field": "authorization",
      "method": "basic_decode",
      "confidence": "high",
      "client_ip": "192.168.1.10", "client_port": 51000,
      "server_ip": "192.168.1.20", "server_port": 80,
      "packet_first": 1450, "packet_last": 1450,
      "evidence": "Authorization: Basic YWxpY2U6RXhh•••23",
      "note": "HTTP Basic credentials, decoded from the request header"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50,
  "reveal": false,
  "unique": true,
  "capped": false,
  "scan": {
    "enabled": true,
    "protocols": ["http","ftp","smtp","pop3","imap"],
    "protocols_scanned": ["http","smtp"],
    "scanned_at": 1791923405.5,
    "stage_ran": true,
    "rows_written_at": 1791923405.5,
    "findings": 1,
    "seconds": 0.4
  },
  "counts": { "total": 1, "by_kind": { "username": 0, "password": 1 }, "by_confidence": { "high": 1 }, "occurrences": 7 },
  "note": "…"
}
```

`capped` is `true` when `MAX_FINDINGS` (§9) stopped the stage storing everything it matched, so
a reader can tell "this capture carried one credential" from "this capture carried more than
the cap allows and the rest was not kept". `stage_ran` distinguishes *never scanned* from
*scanned and found nothing* — the two need different words on the page, and an empty list alone
cannot tell them apart.

### 8.2 `GET /api/analyses/{analysis_id}/credentials/summary`

Counts only — **no values at all, not even previews** — plus the same `scan` block:

```json
{
  "total": 3,
  "occurrences": 9,
  "by_kind": { "username": 1, "password": 2 },
  "by_protocol": { "http": 1, "smtp": 2 },
  "by_confidence": { "high": 3, "medium": 0, "low": 0 },
  "high_confidence": 3,
  "streams": [
    { "stream_id": 16, "protocol": "smtp", "findings": 2 }
  ],
  "stream_count": 1,
  "limits": ["…"],
  "scan": { "…": "as above" }
}
```

Every count is of **distinct values**, matching §8.1's default view, and `occurrences` carries
the stored rows behind them, so the tiles and the listing can never disagree about how many
credentials a capture holds. `stream_count` counts distinct **(protocol, stream_id) pairs**: one
stream carrying two protocols counts twice, because the two are different sessions that happen
to share a number — `streams[].findings` stays a count of stored occurrences in that stream, so
the per-stream evidence is still visible. `limits` carries the caps that applied to this scan in
words, so the page can state them without inventing them.

### 8.3 `POST /api/analyses/{analysis_id}/credentials/scan`

Re-runs the stage in the background and answers `202` with `{job_id, kind, status}` like every
other rescan in this application. `409` when the analysis is not ready, `503`-style
`409 credential_scan_disabled` when the setting is off (the operator must enable it first,
and the message says so).

---

## 9. Caps

| Constant | Value | What it limits |
|---|---|---|
| `MAX_FINDINGS` | `200` | rows stored per analysis, highest confidence first |
| `MAX_VALUE_CHARS` | `512` | a stored value's length (truncated, `value_truncated` set) |
| `MAX_BODY_CHARS` | `262144` | characters of any one body examined (the body preview cap) |
| `MAX_FIELDS_PER_LOCATION` | `200` | candidate fields taken from one form/JSON/query |
| `MIN_VALUE_CHARS` | `3` | shorter values are ignored |
| `PREVIEW_HEAD` / `PREVIEW_TAIL` | `3` / `2` | §5 |
| `JSON_DEPTH` | `6` | how deep the JSON walker looks |
| `MAX_CONTROL_STREAMS` | `25` | control streams reassembled per protocol (§2b), lowest stream id first, so a capture with thousands of mail streams stays cheap and the cap is reported |
| `MAX_STREAM_CHARS` | `262144` | characters examined from one reassembled control stream |
| `STREAM_TIMEOUT_S` | `20` | wall clock for one reassembly, after which that stream is skipped and named in the stage warning |

---

## 10. Limits, stated on the page

* **A finding is a lead.** A value in a field called `password` is a credential the capture
  carried; it is not proof that it worked, that it is current, or that it is not a test value.
* **Encrypted traffic is not examined at all.** Nothing here implies a TLS or SSH session
  holds no credentials.
* **Only what the other analysers kept, plus the control channels of §2b.** HTTP bodies are
  read from the stored previews (`MAX_BODY_CHARS`), so a credential the earlier stage did not
  record cannot be found here; the command protocols are read from their reassembled control
  streams, capped at `MAX_CONTROL_STREAMS` per protocol, so a capture with more mail streams
  than that has the rest unscanned — and the stage says so rather than implying it looked.
* **The value is stored in exactly one place.** `credentials` is the only table that holds a
  credential value; `protocol_sessions.detail` continues to record `password_present: true`
  and nothing more, so no protocol page serves a value the operator did not ask to see.
* **Base64 is encoding, not encryption** — and this is why Basic and `AUTH LOGIN` are readable.
* **Shapes are not validity checks.** An `AKIA…`-shaped string is reported as an AWS access key
  *identifier*; the matching secret is not in it.
* **Patterns only fire on selected values,** so a secret pasted into an unlabelled free-text
  body is reported at `low` confidence — or not at all if it matches no shape.
* **The scan is off-switchable** (§7), and when it is off the page says so rather than showing
  an empty list as if the capture were clean.
