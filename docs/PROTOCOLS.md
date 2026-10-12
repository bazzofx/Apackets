# Protocol sessions contract

**Status:** normative for the five protocol sections that are not HTTP, DNS or TLS —
**Email** (`/email`), **SSH** (`/ssh`), **FTP** (`/ftp`), **VoIP** (`/voip`) and **SMB**
(`/smb`). `docs/CONTRACT.md` governs everything older; where the two touch, that document
wins. This one defines the session table, the two endpoints, the per-protocol detail keys,
the lead flags, the caps and the honest limits.

---

## 1. What a session is

These five families are not one request and one response. They are **conversations with a
lifecycle**: a client opens a connection, both sides exchange a handshake, commands and
replies follow, and the connection ends. HTTP is modelled in this application as
transactions, DNS as queries, TLS as sessions. These five are modelled as **sessions**:

> one row per stream in which the protocol appeared, with the endpoints, the times, the
> volume in each direction, and a JSON `detail` object holding whatever the dissector
> actually produced for that protocol.

Everything that is not per-protocol lives in shared columns, so the five pages are one
query with a different `protocol IN (...)` filter. Everything that *is* per-protocol lives
in `detail`, so adding a protocol never changes the table.

### 1.1 The protocols, and the page each belongs to

| Page | Route | `protocol` values |
|---|---|---|
| Email | `/email` | `smtp`, `pop3`, `imap` |
| SSH | `/ssh` | `ssh` |
| FTP | `/ftp` | `ftp` |
| VoIP | `/voip` | `sip`, `rtp`, `rtcp` |
| SMB | `/smb` | `smb` |

A page requests its family; the API filters on the `protocol` values above.

### 1.2 Session identity and roles

* A session is keyed by `(analysis_id, protocol, stream_id)` where TShark supplied a
  stream. Where it did not (rare: a protocol inside a tunnel), the session is keyed by the
  endpoint pair — `(analysis_id, protocol, client_ip, client_port, server_ip, server_port)` —
  because splitting a stream-less protocol into sessions would need an idle threshold that
  nothing in this contract defines, and inventing one would invent sessions. No frame in the
  captures this installation holds has needed the fallback.
* **Client and server are assigned by role, never by port size.** The rule, in order:
  1. the endpoint using one of the protocol's registered or well-known ports is the server.
     The list is deliberately wider than the single registered port, because the well-known
     alternates carry the same protocol and a tool that calls standard submission traffic
     unusual is a tool that cries wolf:

     | Protocol | Ports that make its endpoint the server |
     |---|---|
     | `smtp` | `25`, `587` (submission), `465` (implicit TLS) |
     | `pop3` | `110`, `995` (implicit TLS) |
     | `imap` | `143`, `993` (implicit TLS) |
     | `ssh` | `22` |
     | `ftp` | `21`, `20` (the data channel) |
     | `sip` | `5060`, `5061` (TLS) |
     | `smb` | `445`, `139` (NetBIOS session service) |
     | `rtp`, `rtcp` | none: they take the role of the SIP session that produced them, if one exists |
  2. otherwise the endpoint that sent the first *server-role* message is the server — the
     `220` greeting for SMTP/FTP, the `+OK` for POP3, the `* OK` for IMAP, a status line for
     SIP. **SSH is deliberately not in this list**, and an earlier draft of this contract was
     wrong to put it there: both ends send an `SSH-2.0-...` identification string and the
     *client* sends its banner first, so a banner can never say which side serves. An SSH
     session on a port outside §1.2's list therefore falls to rule 3, and both banners are
     still recorded, attributed to the direction that carried them;
  3. otherwise the endpoint that sent the first frame of the session is the client.
* The rule that applied is recorded in the row's `note`, so a reader is never asked to
  guess how the roles were decided.
* Rows are never merged across streams. Two concurrent SMTP sessions to the same server
  are two rows, because they are two connections with their own banners and their own
  command sequences.

### 1.3 Rows this contract refuses to produce

* **No invented commands.** A command appears only if the dissector produced it. A session
  with no parsed commands is a session with an empty `commands` list, not a guess from the
  port number.
* **No payload content.** Email bodies, FTP file contents and SMB file bytes are not copied
  into `detail`. Where the application can carve content it is the
  [Files and Objects](../Documentation/Files-and-Objects.md) page that owns it. `detail`
  holds protocol *metadata*: verbs, arguments, codes, names, banners, algorithms.
* **No credentials, only their presence.** A password is recorded as
  `password_present: true`, never as a value. A username *is* recorded, because it is an
  identity and the app's other pages already surface identities.
* **Nothing is sampled.** Every stream the dissector reported becomes a row.

---

## 2. Storage

```sql
CREATE TABLE IF NOT EXISTS protocol_sessions (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id    TEXT    NOT NULL,
  protocol       TEXT    NOT NULL,   -- smtp | pop3 | imap | ssh | ftp | sip | rtp | rtcp | smb
  stream_id      INTEGER,            -- tcp.stream or udp.stream, when TShark gave one
  transport      TEXT,               -- 'tcp' | 'udp'
  client_ip      TEXT,
  client_port    INTEGER,
  server_ip      TEXT,
  server_port    INTEGER,
  first_frame    INTEGER,            -- frame.number of the session's first frame
  last_frame     INTEGER,
  start_time     REAL,               -- epoch seconds, first frame
  end_time       REAL,               -- epoch seconds, last frame
  duration       REAL,               -- end_time - start_time
  packets        INTEGER NOT NULL DEFAULT 0,
  bytes          INTEGER NOT NULL DEFAULT 0,
  client_packets INTEGER NOT NULL DEFAULT 0,
  client_bytes   INTEGER NOT NULL DEFAULT 0,
  server_packets INTEGER NOT NULL DEFAULT 0,
  server_bytes   INTEGER NOT NULL DEFAULT 0,
  detail         TEXT NOT NULL DEFAULT '{}',   -- JSON object, §3
  flags          TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings, §4
  note           TEXT,               -- how the roles were assigned, or a limit of this row
  created_at     REAL
);
CREATE INDEX IF NOT EXISTS idx_proto_analysis ON protocol_sessions(analysis_id, protocol, start_time);
CREATE INDEX IF NOT EXISTS idx_proto_stream   ON protocol_sessions(analysis_id, protocol, stream_id);
CREATE INDEX IF NOT EXISTS idx_proto_server   ON protocol_sessions(analysis_id, server_ip, server_port);
CREATE INDEX IF NOT EXISTS idx_proto_client   ON protocol_sessions(analysis_id, client_ip);
```

The table is created by `backend/app/db/schema.sql` and applies to every database on the
next start, so an existing installation gains it without a migration step.

**Existing analyses have no rows.** The extractor runs as a pipeline stage, so a capture
indexed before this feature existed reports zero sessions until it is re-extracted. That is
stated on the page, and `POST /protocols/rescan` (§5.4) is how it is fixed — the page
offers it rather than implying the capture held nothing.

---

## 3. `detail`, per protocol

Values are the dissector's own. `-T fields` escapes backslashes (an SMB share arrives as
`\\\\server\\share` where `-T json` shows `\\server\share`), so each value is un-escaped exactly
once on the way into the table; SMB command, dialect and NT-status names come from this build's
own `-G values` tables, and anything outside them is kept as the hex the dissector printed.

Keys are **present only when the capture yielded them**. An extractor must not emit a key it
could not fill, and must not emit a plausible-looking value. Every list is capped (§6) and,
where a cap bit, the key's sibling `*_truncated` boolean is `true`.

### 3.1 `smtp`

| Key | Type | Meaning |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | Client verbs (`EHLO`, `MAIL`, `RCPT`, `AUTH`, `DATA`, `QUIT`), with their argument where there was one, deduplicated with a count |
| `response_codes` | `{code: count}` | Server reply codes (`220`, `250`, `354`, `535`, …) |
| `helo` | string | The name the client announced, from `EHLO`/`HELO` |
| `mail_from` | string[] | Envelope senders |
| `rcpt_to` | string[] | Envelope recipients |
| `auth_username` | string | `AUTH` / `SMTP AUTH` user name |
| `password_present` | bool | A password crossed the wire (never its value) |
| `auth_mechanisms` | string[] | Mechanisms offered or used (`PLAIN`, `LOGIN`, `CRAM-MD5`) |
| `data_blocks` | int | Number of `DATA` transfers completed |

### 3.2 `pop3`

| Key | Type | Meaning |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | `USER`, `PASS`, `STAT`, `LIST`, `RETR`, `DELE`, `QUIT`, … |
| `response_indicators` | `{indicator: count}` | `+OK` / `-ERR` counts |
| `username` | string | From `USER` |
| `password_present` | bool | A `PASS` was seen |
| `retrieved` | int | `RETR` count |
| `deleted` | int | `DELE` count |
| `message_count` | int | The count reported by `STAT`/`LIST`, when it parsed |

### 3.3 `imap`

| Key | Type | Meaning |
|---|---|---|
| `commands` | `[{verb, count}]` | `CAPABILITY`, `LOGIN`, `SELECT`, `FETCH`, `UID`, `LOGOUT`, … |
| `statuses` | `{status: count}` | `OK` / `NO` / `BAD` counts |
| `username` | string | From `LOGIN` |
| `password_present` | bool | A `LOGIN` carried a password |
| `folders` | string[] | Mailboxes selected or listed |
| `fetches` | int | `FETCH` / `UID FETCH` count |

### 3.4 `ssh`

| Key | Type | Meaning |
|---|---|---|
| `client_banner` | string | The client's identification string |
| `server_banner` | string | The server's identification string |
| `kex_algorithms` | string[] | Key-exchange algorithms offered |
| `server_host_key_algorithms` | string[] | Host-key algorithms offered |
| `encryption_client_to_server` | string[] | Ciphers offered in that direction |
| `encryption_server_to_client` | string[] | Ciphers offered in that direction |
| `mac_client_to_server` | string[] | MACs offered |
| `messages` | `{message_code: count}` | Message-type histogram (`20` KEXINIT, `30` KEXDH_INIT, …) |

### 3.5 `ftp`

| Key | Type | Meaning |
|---|---|---|
| `commands` | `[{verb, arg, count}]` | Control-channel verbs (`USER`, `PASS`, `CWD`, `TYPE`, `PASV`, `RETR`, `STOR`, `LIST`, `QUIT`) |
| `response_codes` | `{code: count}` | `220`, `230`, `331`, `150`, `226`, … |
| `username` | string | From `USER` |
| `password_present` | bool | A `PASS` was seen |
| `paths` | string[] | Directories entered (`CWD`, `PWD`) |
| `files_requested` | string[] | Arguments of `RETR` / `STOR` / `APPE` / `DELE` (names, not contents) |
| `data_streams` | int | Data connections the session opened |

### 3.6 `sip`

| Key | Type | Meaning |
|---|---|---|
| `methods` | `{method: count}` | `INVITE`, `ACK`, `BYE`, `REGISTER`, `OPTIONS`, `CANCEL` |
| `status_codes` | `{code: count}` | `100`, `180`, `200`, `401`, `404`, `486`, … |
| `call_ids` | string[] | `Call-ID` values seen in this stream |
| `from_users` | string[] | `From` user parts |
| `to_users` | string[] | `To` user parts |
| `request_uris` | string[] | Request-URI host and user parts |
| `user_agents` | string[] | `User-Agent` values |

### 3.7 `rtp` / `rtcp`

| Key | Type | Meaning |
|---|---|---|
| `ssrc` | string | The synchronisation source, as the dissector printed it |
| `payload_types` | `{pt: count}` | RTP payload type numbers with the packet count of each |
| `packets_lost` | int | Sequence-number gaps the extractor can see (never a claim about jitter). **RTP only**: RTCP carries no sequence numbers, and `rtcp.ssrc.cum_nr` is the peer's own claim rather than a gap this extractor can see |
| `rtcp_packet_types` | `{pt: count}` | RTCP only: `200` SR, `201` RR, `202` SDES, … |

An RTP row is **media seen**, not a call. A payload type number is not translated into a
codec by this build, and the RTP dissector in the TShark this installation ships exposes no
codec field at all — so in practice the payload types stay numbers, and no codec name is
invented to fill the gap.

### 3.8 `smb`

| Key | Type | Meaning |
|---|---|---|
| `commands` | `{cmd: count}` | `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT`, `CREATE`, `READ`, `WRITE`, `CLOSE`, … as the dissector names them |
| `dialects` | string[] | Dialects negotiated (`SMB 2.002`, `SMB 3.0.2`, …); an SMB1 session records `SMB 1` |
| `trees` | string[] | Share paths connected |
| `filenames` | string[] | File names requested (names, never contents) |
| `statuses` | `{nt_status: count}` | NT status codes, including the failures |
| `signing_required` | bool | Negotiation required signing |
| `encryption_capable` | bool | Negotiation advertised encryption |
| `server` | string | Server name from a session setup, when the dissector republished one. No capture in this installation has yet: the real SMB sessions authenticate with Kerberos, and TShark 4.6.8 does not put that identity into `smb2.host`. The key is kept in the contract because it is a real field of the protocol, and it is omitted rather than guessed |

---

## 4. Lead flags

Flags use the application's existing convention, the same one HTTP, DNS and TLS use: the
column holds a **JSON array of strings**, each either a bare `code` or `"code: detail"`
where the detail is the measurement the flag rests on (for example
`"cleartext_credentials: USER ftp seen in the clear"`). The code-to-label-and-meaning
mapping lives in the frontend catalogue (`FRONTEND_FLAG_CATALOG`), next to the other three,
so one legend component explains all five sections. The badge splits on the first `:`.

A flag is a lead, not a verdict: every catalogue entry states why the pattern is worth
reviewing *and* what legitimate traffic looks like the same way.

| `code` | Fires when | Applies to |
|---|---|---|
| `cleartext_credentials` | A password was seen in the clear (`AUTH`, `USER`/`PASS`, `LOGIN`) | smtp, pop3, imap, ftp |
| `cleartext_username` | A user name was seen without a password | smtp, pop3, imap, ftp |
| `no_encryption_upgrade` | The session ran on a port that carries the protocol **in the clear and expects an optional upgrade** — `25`, `587` (SMTP), `110` (POP3), `143` (IMAP), `21` (FTP) — and no `STARTTLS` / `STLS` / `AUTH TLS` exchange was seen. The detail names the port the session actually used, never a port it did not. It never fires on the implicit-TLS ports (`465`, `995`, `993`), because a session there is TLS from its first byte and is not dissected as this protocol at all | smtp, pop3, imap, ftp |
| `anonymous_login` | `anonymous` / `ftp` / guest-style identity attempted or accepted | ftp, smb |
| `legacy_dialect` | An SMB1 session was negotiated | smb |
| `signing_not_required` | Negotiation did not require signing | smb |
| `unusual_port` | The server port is in none of the ports of §1.2 that carry this protocol | all |
| `large_transfer` | Bytes above `LARGE_TRANSFER_BYTES` (§6) | all |
| `many_commands` | Commands above `MANY_COMMANDS` (§6) | smtp, pop3, imap, ftp |
| `long_session` | Duration above `LONG_SESSION_SECONDS` (§6) | all |
| `media_without_signalling` | RTP/RTCP with no SIP session naming its addresses | rtp, rtcp |
| `auth_failures` | Repeated rejected authentications (SMTP `535`, POP3 `-ERR`, IMAP `NO`, FTP `530`) | smtp, pop3, imap, ftp |

At most `FLAG_CAP` flags are kept per session, most serious first, and the `detail` half of
each string quotes the count or value that produced it. In practice the cap is defensive: the
per-protocol gating means the most any one session can carry is **seven**, and the two port
flags are mutually exclusive — a session is either on a port the protocol is expected on (so
no `unusual_port`) or it is not (so no `no_encryption_upgrade`) — so the cap is defensive and
it is the severity ordering a reader will actually see exercised. The seven an FTP session on
port 21 can reach are `cleartext_credentials`, `auth_failures`, `anonymous_login`,
`no_encryption_upgrade`, `large_transfer`, `many_commands` and `long_session`. A flag never replaces a
measurement: the counts it reasons about are in `detail` on the same row, and the row's
`packets` / `bytes` are the session's own.

## 5. Endpoints

### 5.1 `GET /api/analyses/{analysis_id}/protocols`

| Parameter | Default | Range | Meaning |
|---|---|---|---|
| `protocol` | — | one of §1.1 | Filter to one protocol; repeatable or comma-separated |
| `family` | — | `email`, `ssh`, `ftp`, `voip`, `smb` | Shorthand for that family's protocols |
| `q` | — | 1–200 chars | Case-insensitive substring over endpoint, server name, file name, path, username and command arguments |
| `flagged` | `false` | bool | Only sessions carrying at least one flag |
| `sort` | `start_time` | `start_time`, `bytes`, `packets`, `duration` | Sort key |
| `order` | `desc` | `asc`, `desc` | Sort direction. `desc` is the useful default for a time column: the newest session first. A page must send it, because its sort control offers both directions and a control that does nothing is worse than no control. |
| `page` | `1` | ≥1 | Page number |
| `page_size` | `100` | 1–1000 | Rows per page |

Envelope:

```json
{
  "analysis_id": "…",
  "generated_at": 1700000000.0,
  "family": "email",
  "protocols": ["smtp", "pop3", "imap"],
  "total": 3,
  "page": 1,
  "page_size": 100,
  "counts": {
    "by_protocol": {"smtp": 3},
    "sessions": 3,
    "flagged": 1,
    "bytes": 123456,
    "packets": 900,
    "first_seen": 1700000000.0,
    "last_seen": 1700000600.0
  },
  "note": "what this page is, and what it is not",
  "extracted": true,
  "capped": false,
  "session_cap": 2000,
  "stored_rows": 3,
  "rows": [ { "…": "§2 columns, detail and flags decoded" } ]
}
```

`capped` is true when `SESSION_CAP` cut the rows this response could carry, `session_cap` is
the cap that applied, and `stored_rows` is what the analysis actually holds — so a capped
response can state its own limit instead of presenting a short list as the whole table. The
page says so and points the reader at the filters.

`extracted` is `false` when the analysis holds no `protocol_sessions` rows at all **and** the
capture is old enough that the stage may never have run: the page then offers the rescan
instead of reporting an empty capture as a clean one. `note` always states the section's
limits in one sentence.

### 5.2 `GET /api/analyses/{analysis_id}/protocols/summary`

Per-family totals for the five pages' headers, so a nav entry can show whether its protocol
is in the capture at all: `{analysis_id, generated_at, extracted, families: {email: {protocols, sessions, flagged, bytes, packets, first_seen, last_seen}, …}, note}`.

### 5.3 `GET /api/analyses/{analysis_id}/protocols/{session_id}`

One session: every §2 column, `detail` decoded, `flags` as the §4 strings, plus
`frame_numbers` (the session's first and last frame) and `links` (into `/packets` and the
pages that hold the rows). Unknown id: `404 session_not_found`.

### 5.4 `POST /api/analyses/{analysis_id}/protocols/rescan`

Re-runs the extraction for a capture that is already indexed, returning `202` with
`{analysis_id, job_id, kind: "protocol_rescan", status}`. It is a job rather than an inline
call like `/findings/rescan` and `/objects/extract`, because the extraction is five TShark
passes; the job system necessarily writes the `jobs` row and the analysis's own status, so a
rescan in flight reports the analysis as busy (`409 analysis_not_ready` for other readers)
exactly as a full analysis does. What the *extractor* writes is only `protocol_sessions`, and
that isolation is asserted in the suite by snapshotting every other table.

### 5.5 Errors

| Failure | Status | Code |
|---|---|---|
| Unknown analysis | `404` | `analysis_not_found` |
| Not finished | `409` | `analysis_not_ready` |
| Unknown protocol or family | `422` | `validation_error` |
| Bad page/page_size | `422` | `validation_error` |
| Unknown session id | `404` | `session_not_found` |

---

## 6. Caps

| Constant | Value | What it limits |
|---|---|---|
| `SESSION_CAP` | `2000` | Session rows read for one request |
| `LIST_CAP` | `50` | Entries in any `detail` list (`mail_from`, `filenames`, `trees`, …) |
| `COMMAND_CAP` | `25` | Distinct commands kept per session |
| `FLAG_CAP` | `10` | Flags kept per session |
| `COUNT_CAP` | `200` | Distinct codes/statuses kept in a count map |
| `LARGE_TRANSFER_BYTES` | `10485760` | The `large_transfer` flag's threshold |
| `MANY_COMMANDS` | `40` | The `many_commands` flag's threshold |
| `LONG_SESSION_SECONDS` | `3600` | The `long_session` flag's threshold |

A capped list sets its `*_truncated` sibling. A session cut by `SESSION_CAP` is reported in
the envelope, never silently dropped.

---

## 7. Honest limits

* **Encrypted payloads are not decrypted, and never will be.** SSH records the banner and the
  algorithms that crossed the wire in the clear; SMB3 encryption and `POP3S`/`IMAPS`/
  `SMTPS` sessions record endpoints, times and volume, and nothing else. A page therefore
  answers "who spoke this protocol, when, with what handshake" for every family, and only
  "what was said" where the protocol is genuinely readable.
* **A session is not a user.** One address running many sessions is a busy host, not a person.
* **A flag is a lead.** Every flag carries the sentence saying what it does not prove.
* **RTP is media seen, not a call.** Without SIP signalling this build will not turn a
  payload type into a codec, and it will not claim a call existed.
* **`protocol_sessions` is per capture.** Nothing is correlated across captures, and no
  session is attributed to an identity outside the ones the wire carried.
* **The extractor reports what TShark dissected.** A capture taken mid-session, a protocol on
  a non-standard port that the dissector did not recognise, or traffic inside a tunnel the
  dissector did not decode appears as no session at all — which is why `extracted: false`
  and the rescan control exist rather than a silent empty page.
