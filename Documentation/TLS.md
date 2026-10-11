# TLS

Handshake metadata for every TLS session in the selected capture — versions, SNI, ALPN, cipher
suite, JA3/JA3S/JA4 fingerprints, certificate fields, handshake status — plus a second view that
groups the same sessions by fingerprint value.

The page is `frontend/src/pages/TlsPage.tsx` and its route is `/tls`. It sits with the other two
protocol pages, [HTTP](HTTP.md) and [DNS](DNS.md), under **Protocols** in the left-hand navigation.
The normative interface shape is [`docs/CONTRACT.md`](../docs/CONTRACT.md) §5.

---

## 1. What it is for

**How did this encrypted connection introduce itself, and does anything about that introduction
stand out?** TLS payloads are not decrypted anywhere in this app, so the only evidence available
about an encrypted connection is what its handshake carries in the clear: the versions offered and
negotiated, the server name, the application protocols, the cipher suite, the certificate fields
the handshake exposed, and the fingerprints of the Hello messages themselves. This page puts those
in one table, grouped a second way by JA3/JA3S/JA4 so that sessions built by the same software can
be found together. It describes the handshake and nothing inside it.

## 2. What is on the screen

### Lead flag legend

The first thing on the page, and **collapsed by default**: a **How to read TLS lead flags** panel
enumerating every TLS flag, with the note that these describe the handshake and the capture and
that none of them comes from decrypted application data, because there is none. *Show* opens it.
It is not gated on the view, so it is there for the session and fingerprint views alike.

There is no scope panel on this page. What it used to state still holds and is worth knowing:
payloads inside TLS are **not** decrypted and nothing on the page is derived from them, and an
empty SNI, cipher or certificate cell means the value was not in the file, not that the connection
used none.

### The view switch

A **View** toggle, exactly two options:

| `view` | What it shows |
|---|---|
| `sessions` (default) | One row per TLS session, from handshake metadata only. Any value other than `fingerprints` selects this view. |
| `fingerprints` | JA3, JA3S and JA4 values grouped with their session counts. |

### The filters

Every filter lives in the query string. The complete list of parameters this page owns, transcribed
from `URL_KEYS` in `TlsPage.tsx`, in order:

```ts
const URL_KEYS = [
  'view',
  'sni',
  'version',
  'ip',
  'port',
  'alpn',
  'ja3',
  'has_cert',
  'sort',
  'order',
  'page',
  'page_size',
  'sel',
  'ftype',
  'fsearch',
]
```

| Parameter | What it filters |
|---|---|
| `view` | `sessions` (or absent) or `fingerprints`. |
| `sni` | **Substring** match on the SNI. A session with no SNI stores NULL and can never match this filter, whatever the value — the tooltip says so. |
| `version` | **Exact** match on the negotiated `version` column. The dropdown lists only the versions stored in this analysis. |
| `ip` | **Exact** match on the client address **or** the server address, so it finds a host in either role. |
| `port` | **Exact** match on the client port or the server port. A value that is not a number makes the query match nothing at all (`0 = 1`), silently. |
| `alpn` | **Substring** match on the stored ALPN string — the offered list joined with commas, or the ServerHello's own list when no ClientHello was captured. |
| `ja3` | **Exact** match against `ja3`, `ja3s` **or** `ja4`, so one value finds a client fingerprint or a server fingerprint. This is what the "Sessions" buttons in the fingerprints view set. |
| `has_cert` | `true` — any of `cert_serial`, `cert_subject`, `cert_issuer`, `cert_not_before`, `cert_not_after` is non-null. `false` — none of them is. Both are real filters; an absent `has_cert` is the only "no filter" state, and the select's empty option is labelled "any". |
| `sort` | Sort column. The UI offers `time_epoch`, `sni`, `version`, `server_port` and `cipher_suite`; the endpoint also allows `stream_id`. |
| `order` | `asc` (the page's default) or `desc`. |
| `page` | 1-based page number. |
| `page_size` | Rows per page; default `100`, capped by the API at `MAX_PAGE_SIZE = 1000`. |
| `sel` | The id of the session whose detail panel is open. Selection state, not a filter. |
| `ftype` | **Client-side** filter on the fingerprints view: `ja3`, `ja3s`, `ja4`, or empty for all types. The select only offers the types present in the returned rows. |
| `fsearch` | **Client-side** substring search over a group's fingerprint, its SNIs and its clients. |

`view`, `sel`, `ftype`, `fsearch`, `sort`, `order`, `page` and `page_size` are in `NON_FILTER_KEYS`
(`frontend/src/components/protocols/ProtocolFilters.tsx`): they do not count towards "filters
active", they survive **Reset filters**, and changing one does not reset the page. **Reset filters**
clears the server-side filters and then explicitly drops `ftype` and `fsearch`, which are
browser-side state rather than filters.

### The sessions view

**Lead flag legend** — the collapsed panel at the top of the page, enumerating every TLS flag,
with the note that these
describe the handshake and the capture and that none of them comes from decrypted application data,
"because there is none".

**TLS sessions** panel. Columns, with the tooltip each header carries:

| Column | Meaning |
|---|---|
| Time | The ClientHello's frame time, or the first TLS frame in the stream when no ClientHello was captured. |
| Client | `client_ip:client_port`, and both stay empty when no ClientHello was seen. |
| Server | `server_ip` taken from the ClientHello's destination. |
| Port | `server_port` — the server's port, not the client's. |
| Version | The negotiated version (`server_version` if a ServerHello was seen, otherwise the client's). |
| SNI | The server name from the ClientHello; empty when the client sent none, when it was concealed, or when the ClientHello is not in the capture. |
| ALPN | The application protocols offered; the server's selection is shown in the detail panel. |
| Cipher | The negotiated cipher suite, as the hex code carried in the ServerHello. |
| JA3 | ClientHello fingerprint. |
| JA3S | ServerHello fingerprint; empty means no ServerHello was seen in this capture. |
| JA4 | The same idea as JA3 in JA4's readable format. |
| Certificate | A chip in one of three states — see below. |
| Handshake | `complete`, `client_hello_only`, `server_hello_only`, `alert` or `unknown`, colour-coded (complete green, alert amber, otherwise muted) with a one-line explanation on hover. |
| Lead flags | One badge per recorded flag, full reasoning on hover; `—` when there are none. |

The certificate chip distinguishes three genuinely different situations:

| Chip | Condition | Meaning |
|---|---|---|
| `not available` | None of the five certificate columns is set | No certificate was decoded for this session. |
| `present` | A certificate column is set and the subject or issuer is readable | Certificate metadata decoded. |
| `serial only` | A certificate column is set but neither subject nor issuer is | The serial and/or the validity window were decoded while subject and issuer were not usable; the backend stores NULL rather than a wrong value. |

That third state is the normal one in real captures, which is the reason the chip exists. In
`sf19us-MTA-lab-01.pcap`, all 41 sessions have a certificate serial and a validity window, none has
a usable subject or issuer, and 4 have no certificate at all: the split is 37 `serial only`, 4
`not available` and no `present` at all. In `tls.pcap` the same is true of the one completed
handshake.

Below the table a footer states how many sessions **on this page** carry certificate metadata and
how many have no SNI recorded, and repeats that TLS 1.3 encrypts the certificate, that a ClientHello
may carry no server name, and that the paths, headers and bodies of these connections are not
available anywhere in this app.

**Session detail.** Selecting a row sets `sel` and opens a panel headed by chips for the SNI (with a
copy button), the version, the handshake status and — when present — the alert rendered as
`alert <n> — <name>` from the page's own RFC 8446 / RFC 5246 table of 29 descriptions (an unknown
code shows the number only). Then:

* a detail grid — Time, Client, Client port, Server, Server port, Stream, Client packet, Server
  packet, Records (`record_count`), Version (negotiated), Client version, Server version, SNI, ALPN
  offered, ALPN selected, Cipher suite, Cipher (registry) — a name looked up from the small
  16-entry IANA table built into the view, with an explicit note that an unlisted code shows no name
  — Handshake status, Alert, JA3, JA3 (full string), JA3S, JA4;
* a one-line explanation of the handshake status, or a statement that the value was not one this
  view documents and is shown verbatim;
* one chip per available fingerprint with its own copy button and a **Sessions** button that jumps
  to the sessions view filtered to that value;
* the **Certificate** panel — Subject, Issuer, Serial, Validity from, Validity to and a Validity
  check that compares the window against **the session's own time**, not today's clock: "Expired at
  this session's time (…)", "Not yet valid …", or "Within the validity window …". When the dates
  cannot be parsed the panel says no comparison is made. When no certificate was decoded it states
  that this is a statement about the capture, not evidence that the peer presented none;
* the full reasoning for each recorded flag.

### The fingerprints view

**TLS fingerprints** panel, fed by its own endpoint. Subtitle: how many of the returned groups are
shown, and "(filtered in the browser)" when the client-side filter is active. Two controls, both
client-side:

* **Type** — `ja3`, `ja3s`, `ja4`, or "all types". Only the types actually present in the returned
  rows are offered, and the tooltip says JA3 and JA4 describe the client's ClientHello while JA3S
  describes the server's ServerHello;
* **Search** — a substring over the fingerprint, its SNIs and its clients.

Columns: Fingerprint, Type, Sessions (the number of stored sessions with this value), SNIs seen with
it (`none recorded` when no session in the group carried one, with the explanation that the
ClientHello may have carried none or it was concealed), Clients (the distinct client addresses),
and a **Sessions** button that switches to the sessions view with `ja3=<value>`. Rows are ordered by
session count, then fingerprint.

Two standing notes sit under the table: that JA3/JA3S are hashes of the handshake parameters
(versions, cipher suites, extensions, curves, formats) and JA4 is the same idea in a readable
format, that a shared fingerprint means the peers built their Hello the same way — a strong hint
about the TLS library or tool, not a statement about what the software was asked to do — and that
collisions and small variations between builds do occur; and that certificate subject and issuer can
legitimately be absent even when a certificate is present, which is why the session table reports
`serial only` instead of pretending the certificate is missing.

### What the page shows when there is nothing

* **No capture selected** — the shared `AnalysisGuard` points at [PCAP-Files.md](PCAP-Files.md); a
  running analysis shows progress, a failed or cancelled one shows the reason.
* **No sessions, no filters** — *"TShark dissected no TLS handshake in this capture. TLS carried
  over a port other than the usual one, or a capture that ended before the handshake, both produce
  this."*
* **No sessions matching filters** — a separate empty state that names the certificate filter as the
  usual culprit, since most sessions in a modern capture carry no readable certificate.
* **Fingerprints view** — "No fingerprints in this analysis" when no session carried a JA3, JA3S or
  JA4 value, with the explanation that an incomplete ClientHello accounts for it; or "No fingerprint
  matches that filter" when groups exist but the type or search text excludes them all. The first of
  those is a real state: `nmap_sn_livehosts.pcapng` stores 4 TLS sessions and **zero** fingerprint
  groups, because none of them carried a fingerprintable ClientHello.

## 3. Where the data comes from

| Layer | Name |
|---|---|
| Page component | `frontend/src/pages/TlsPage.tsx` — `TlsPage` (wrapped in `AnalysisGuard`), `TlsContent`, `SessionDetail`, `SessionDetailBody`, `FingerprintsPanel`, `ViewToggle` |
| Shared filter state | `useUrlFilters` in `frontend/src/components/protocols/ProtocolFilters.tsx` |
| Flags and legends | `TLS_FLAG_CATALOG`, `TLS_FLAG_KEYS` in `frontend/src/components/protocols/ProtocolFlags.tsx` |
| Certificate rendering | `frontend/src/components/protocols/CertificatePanel.tsx` (`hasCertificate`, `certificateSummary`) |
| Frontend client | `tlsApi.list` / `tlsApi.get` / `tlsApi.fingerprints` in `frontend/src/services/api.ts` |
| Endpoints | `GET /api/analyses/{analysis_id}/tls` (list, plus `snis` and `versions`), `GET /api/analyses/{analysis_id}/tls/{session_id}` (detail), `GET /api/analyses/{analysis_id}/tls/fingerprints` (groups) |
| Route module | `backend/app/api/routes_tls.py` (router prefix `/api/analyses/{analysis_id}`) |
| Table | `tls_sessions` in `backend/app/db/schema.sql` |
| Analysis that fills it | `backend/app/services/tls_analyzer.py`, run as the `tls` stage of `backend/app/services/pipeline.py` |

The list serves `tls_sessions` only; `snis` and `versions` are distinct values from that table for
the whole analysis, so the dropdowns can only offer values the capture actually contains.

The fingerprints endpoint aggregates the same rows with `GROUP BY ja3`/`ja3s`/`ja4`, using
`GROUP_CONCAT(DISTINCT sni)` and `GROUP_CONCAT(DISTINCT client_ip)`. It accepts an optional `type`
parameter with the alias `type` (values `ja3`, `ja3s`, `ja4`), **but this page never sends it** —
`tlsApi.fingerprints` calls the endpoint with no parameters and the Type select filters what came
back in the browser. An empty group's SNI or client list is empty, never padded.

Sessions are grouped by `tcp.stream`, and the client is defined as the peer that sent the
ClientHello. When no ClientHello is in the capture, the client columns, the SNI, JA3, JA4 and the
client version all stay NULL rather than being guessed from packet direction — the module comment
records that choice. The negotiated `version` is the server's version when a ServerHello was seen
and the client's otherwise; a client's version is the highest **known** value in its
`supported_versions` extension, falling back to the handshake version, so GREASE and unknown values
are ignored rather than reported as a version. Handshake status is decided in this order: a
ClientHello and a ServerHello together are `complete`; otherwise an alert makes it `alert`; then
`client_hello_only`, then `server_hello_only`, then `unknown`.

JA3, JA3 (full string), JA3S and JA4 are **computed by TShark 4.6.8 itself** (`tls.handshake.ja3`,
`tls.handshake.ja3_full`, `tls.handshake.ja3s`, `tls.handshake.ja4`) and stored verbatim; this app
does not compute a fingerprint of its own.

## 4. What the flags mean

All six are computed by `compute_flags(session, client_frame, cert_frames)` in
`backend/app/services/tls_analyzer.py` and stored in `tls_sessions.flags` at analysis time. The
route does not recompute them, and the sessions view has no "flagged only" filter at all — the flags
are read as badges, in the legend and in the detail panel.

| Flag | Exact condition (as written in the code) | What it does not establish |
|---|---|---|
| `sni_absent:<explanation>` | `client_frame is not None and not session.sni`. The flag carries its own explanation text: "no SNI in the ClientHello (an encrypted ClientHello or a non-SNI client may explain this)". | That the peer hid its identity. A client given a bare address, an old or minimal client, and ECH all produce it. Note the ClientHello condition: a session with no ClientHello at all does **not** raise it, even though its SNI is also empty. |
| `no_certificate` | `client_frame is not None and not cert_frames` | That the peer presented no certificate, or that a client rejected one. TLS 1.3 encrypts the Certificate message, a capture can end before the certificate flight, and a failed handshake never reaches it. |
| `tls10_or_older` | `session.version in LEGACY_VERSIONS`, where `LEGACY_VERSIONS = {"SSL 3.0", "TLS 1.0"}` | Weakest-common-denominator negotiation by two modern peers. It is a narrower set than the Threat Map detection's `_LEGACY_TLS`: **TLS 1.1 is not flagged here** (see [ThreatHunter/SuspiciousTls.md](ThreatHunter/SuspiciousTls.md)). Legacy appliances, embedded devices and old libraries do negotiate these in otherwise normal networks. |
| `self_signed_suspected` | `session.cert_subject and session.cert_issuer and session.cert_subject == session.cert_issuer` | That the certificate was self-signed, or that it was not. It is an exact string comparison of TShark's rendered subject and issuer: internal test CAs, lab equipment and interception proxies produce it, and the opposite finding proves nothing either. |
| `alert` | `session.alert is not None` — any alert description seen in the session | Malice. Fatal alerts are normal when a client rejects an expired or mismatched certificate and when a proxy refuses a connection. The analyser records the numeric description; it does not read the alert **level**, so a benign `close_notify` (code 0) raises the same flag as `handshake_failure` (40). |
| `incomplete_handshake` | `session.handshake_status != STATUS_COMPLETE` | Anything about the peers: it says the capture lacks a complete ClientHello/ServerHello pair. It fires for `client_hello_only`, `server_hello_only`, `alert` and `unknown`. |

Measured examples. In `tls.pcap`, three sessions produce exactly this: one clean `complete` session
with no flags; one `client_hello_only` session carrying `sni_absent`, `no_certificate` and
`incomplete_handshake`; and one session ending in alert 40 (`handshake_failure`) carrying
`no_certificate`, `alert` and `incomplete_handshake`. In `SpaceX_111025.pcapng`, 17 of 20 sessions
carry `no_certificate` and 2 carry `incomplete_handshake`, while 19 sessions have no certificate
metadata at all — the two sessions with no ClientHello raise no flag, because the flag requires a
client frame. That gap between "19 without a certificate" and "17 flagged" is the flag's own
precondition at work, not a counting error.

## 5. Links into the rest of the app

The page navigates within itself: the **Sessions** button on a fingerprint row — and on the
fingerprint chips in the detail panel — sets `ja3=<value>` and switches the view to `sessions`. It
has no link out to the packet view or the hosts table. The parameters are the hand-off, and they are
the ones the Threat Map detections already use:

| To get there | Use | What to look for |
|---|---|---|
| Sessions to one name | `/tls?sni=<server name>` | Versions, cipher suites and fingerprints per name; substring, so a base domain brings its subdomains. |
| Sessions with no name | `/tls?ip=<server address>` | What else went to that address, which is how an SNI-less session gets identified. |
| One fingerprint's sessions | `/tls?ja3=<ja3, ja3s or ja4>` | Every session built the same way, across names and clients. |
| The fingerprint families | `/tls?view=fingerprints` | Which values recur, and which names and clients they recur with. |
| Old versions | `/tls?version=TLS%201.0` | Whether obsolete TLS is one legacy device or a pattern. |
| Sessions that did present a certificate | `/tls?has_cert=true` | The complement of the `no_certificate` flag, and a reminder of how few sessions carry one. |
| By port | `/tls?port=8443` | TLS on a port the network does not expect. |

The packet and stream numbers in the detail panel are the hand-off to the raw traffic: open a frame
in [Packets.md](Packets.md) with `/packets?mode=basic&sel=<frame number>` and add
`&stream_id=<id>&transport=tcp` to read the whole handshake. The client or server address is best
followed up in [Hosts.md](Hosts.md) with `/hosts?ip=<address>`, and the cleartext side of the same
network in [HTTP.md](HTTP.md) and [DNS.md](DNS.md).

The detections built on these columns are
[ThreatHunter/SuspiciousTls.md](ThreatHunter/SuspiciousTls.md),
[ThreatHunter/PossibleMalwareDownload.md](ThreatHunter/PossibleMalwareDownload.md),
[ThreatHunter/C2Beaconing.md](ThreatHunter/C2Beaconing.md) and
[ThreatHunter/DataExfiltration.md](ThreatHunter/DataExfiltration.md).

## 6. Limits and honest caveats

* **Nothing inside TLS is readable, ever.** No HTTP path, header, body, form field or credential
  inside an encrypted session appears anywhere in this app, and no field on this page is derived
  from application data. What you get is the handshake; what happened afterwards is inferred from
  packet sizes and timing at best, never read.
* **Certificate coverage is thin, and TLS 1.3 is the reason.** The Certificate message in TLS 1.3 is
  encrypted, so those sessions never carry certificate fields. The analyser also reads a fixed set
  of `x509*` fields, and TShark's `x509af.subject`/`issuer` are not usable for every certificate —
  in this build the analyser drops numeric CHOICE indices so the column is NULL instead of holding
  `0`. `serial only` is therefore a normal, expected state, as the measured counts above show.
* **The leaf certificate is the one whose serial is shown**, taken from the first certificate frame
  that carried a serial; `cert_not_before` is the earliest and `cert_not_after` the latest validity
  time across those frames, compared as strings because TShark renders them as sortable
  `YYYY-MM-DD HH:MM:SS (UTC)` text. A certificate chain's other members are not broken out, and a
  value TShark renders as "Not representable" is dropped rather than stored.
* **The analyser reads a SAN field the page cannot show.** `x509ce.dNSName` is collected into the
  frame's `dns_names`, and `tls_sessions` has no column for it, so subject alternative names are
  not displayed anywhere. Nothing in the app exposes them.
* **No SNI means no name — and the filter cannot find it.** `sni` is a substring match, so sessions
  with NULL SNI never match any `sni` value. The lead flag legend says this outright; use the
  `sni_absent` flag, scan the SNI column, or filter by `has_cert=false` instead.
* **`has_cert` is about decoded fields, not trust.** A session counts as having a certificate when
  *any* of the five certificate columns was decoded, including a bare serial and validity window,
  and `has_cert=false` does not mean the session presented none — it was encrypted or not captured.
* **An ALPN match is a substring match on a joined list.** The stored `alpn` is a comma-joined
  string, so `alpn=h2` also matches an offer list containing `h2c` or `h2something`; and when no
  ClientHello was captured the value comes from the ServerHello, so the column then shows what the
  server offered rather than what the client sent.
* **A missing fingerprint is not a missing session.** JA3/JA3S/JA4 come from TShark and need a
  ClientHello (or ServerHello) it can fingerprint. A session whose handshake is incomplete can
  legitimately have none, which is why `nmap_sn_livehosts.pcapng` stores 4 sessions and no
  fingerprint groups at all — the fingerprints view says so in its own words rather than showing an
  empty table without explanation.
* **A shared fingerprint is a hint about software.** It groups peers that built their Hello the same
  way. Different builds of the same library, and libraries with a randomised extension order, break
  the grouping; unrelated tools can also collide. The page's note calls it a lead, not a statement
  about behaviour.
* **Alert codes are labelled from a fixed table.** The page maps 29 known descriptions to names; any
  other code is displayed as its number. Also, the `alert` column can hold several comma-joined
  codes when a session carried more than one, and in that case the label is the raw list with no
  name lookup.
* **A default page size and a cap.** `page_size` defaults to 100 and the API caps it at
  `MAX_PAGE_SIZE = 1000`. The certificate and no-SNI counts in the panel footer describe the current
  page, not the whole analysis.
* **An empty table is a capture statement.** No TLS rows can mean TLS on an unexpected port, a
  capture that ended before the handshake, or a capture with no TLS at all — the page's empty state
  says the first two. It never means the traffic was safe.

---

**Related:** [HTTP](HTTP.md) · [DNS](DNS.md) · [Hosts](Hosts.md) · [Packets](Packets.md) · [Threat-Hunt.md](Threat-Hunt.md) · [SuspiciousTls](ThreatHunter/SuspiciousTls.md) · [C2Beaconing](ThreatHunter/C2Beaconing.md) · [README.md](README.md)
