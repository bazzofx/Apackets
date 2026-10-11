# Suspicious TLS Connections (`suspicious_tls`)

Part of the **Threat Map** section (`/threat-hunt`). Read
[ThreatHunter.md](ThreatHunter.md) first for the endpoint, the envelope and the
`availability` rules. This document follows the structure defined in
[EachFeature.md](EachFeature.md). The normative contract is
[`docs/THREAT_HUNT.md`](../../docs/THREAT_HUNT.md).

---

## 1. What it answers

**Do TLS sessions lack identity, use obsolete versions, or fail mid-handshake?**

## 2. How to read the card

The headline counts *TLS sessions carrying an observation*: sessions with at least
one lead flag from the TLS analyser, an obsolete protocol version, or no server name.
It is a count of sessions.

Two visuals are drawn:

* **bars** of sessions by observation — one bar per distinct reason, showing how many
  sessions carry it. A session with three reasons contributes to three bars, so the
  bars sum to more than the headline. The labels are the analyser's own wording
  (`no certificate observed`, `TLS 1.0 or older`, `self-signed certificate
  suspected`, `TLS alert`, `incomplete handshake`, `no server name in the
  ClientHello`);
* a **table** of the sessions themselves, capped at `TABLE_CAP = 50` rows, ordered by
  how many observations each session carries and then newest first: the server name
  (linked to the TLS page, or `(no server name)` when there is none), the server
  address, the version, the list of observations, and the client frame number linked
  to `/packets?sel=`.

A **high** reading is a large count spread across several reasons, or a big
`no server name` bar — sessions with no SNI at all are the least explicable of the
set. A **low** reading is a handful of sessions, usually old versions on a legacy
server. A zero headline with `availability: "empty"` means no session carried a flag,
no version matched an obsolete prefix, and every session had a server name.

Be aware that the bars can look alarming on a perfectly normal capture: sessions that
start before the capture begins have no ClientHello, hence no SNI, hence
`no server name in the ClientHello`; sessions captured only after the handshake have
no certificate. Both are artefacts of where the capture started.

The headline is `0` only when `availability` is not `"ok"`.

## 3. Detection logic

Implemented by `_suspicious_tls(index)` with the helper `_tls_reasons(row)` in
`backend/app/services/threat_hunt.py`.

1. If the TLS index holds no rows, return `not_applicable` with
   `the capture recorded no TLS sessions`.
2. Read up to `PACKET_SCAN_CAP` sessions in time order, taking the id, stream, time,
   addresses, ports, SNI, version, selected ALPN, cipher suite, JA3, handshake status,
   alert, client frame and `flags` JSON.
3. For each session, collect the reasons:
   * every token in `flags`, split at its first `:` (so
     `sni_absent:no SNI in the ClientHello …` becomes `sni_absent`);
   * `tls10_or_older`, added when the session's `version` starts with `SSL`,
     `TLS 1.0` or `TLS 1.1` and the flag did not already say so;
   * `sni_absent`, added when `sni` is NULL or empty and the flag did not already
     say so.
4. Keep only sessions with at least one reason; count how many sessions carry each
   reason.
5. Order the flagged sessions by reason count (most first), then by timestamp
   (newest first). The headline is how many sessions were kept.
6. Draw bars for the reasons, most frequent first, and the table for the first
   `TABLE_CAP = 50` sessions.
7. Collect up to five links, one per distinct server name (or server address where
   there is no name).

Nothing is tested about the certificate beyond the analyser's
`self_signed_suspected` flag, and no session is judged on its cipher suite, JA3 or
JA4 — those columns are read by the query and never used.

## 4. Thresholds

There is no numeric threshold: the gates are version-prefix matching, the absence of
an SNI, and the flags written by `backend/app/services/tls_analyzer.py`.

| Constant | Value | What it does |
|---|---|---|
| `_LEGACY_TLS` | `("SSL", "TLS 1.0", "TLS 1.1")` | Prefixes tested against `tls_sessions.version`; a match adds the `tls10_or_older` reason. |
| `_TLS_LABELS` | 6 entries: `no_certificate` → "no certificate observed", `tls10_or_older` → "TLS 1.0 or older", `self_signed_suspected` → "self-signed certificate suspected", `alert` → "TLS alert", `incomplete_handshake` → "incomplete handshake", `sni_absent` → "no server name in the ClientHello" | The wording used for the bars and the table. Any other token is shown with underscores replaced by spaces. |
| `PACKET_SCAN_CAP` | `20000` | Maximum sessions read. |
| `TABLE_CAP` | `50` | Maximum rows in the session table. |
| `top` | `12` (1–50) | Bars in the observation chart. |
| `ROW_SCAN_CAP` | `500` | Not used by this detection. |
| `TIMELINE_CAP`, `SCATTER_CAP` | `240`, `200` | Not used by this detection. |

The flags themselves come from `backend/app/services/tls_analyzer.py`:

| Constant (in `tls_analyzer.py`) | Value | Flag it raises |
|---|---|---|
| `LEGACY_VERSIONS` | `{"SSL 3.0", "TLS 1.0"}` | `tls10_or_older` — note this is a narrower set than the Threat Map detection's `_LEGACY_TLS`, which also catches `TLS 1.1` from the `version` column |
| — | client frame present and no SNI | `sni_absent` |
| — | client frame present and no certificate frames | `no_certificate` |
| — | `cert_subject` equal to `cert_issuer` (both non-empty) | `self_signed_suspected` |
| — | `alert` is not NULL | `alert` |
| — | `handshake_status` is not `complete` | `incomplete_handshake` |

Because the two version tests differ, a `TLS 1.1` session raises no analyser flag but
is still counted here, with the reason supplied by `_LEGACY_TLS`.

## 5. Indexed fields used

| Column | Supplies |
|---|---|
| `tls_sessions.flags` | The analyser's JSON lead-flag array, the main source of reasons. |
| `tls_sessions.version` | The obsolete-version test, and the version column of the table. |
| `tls_sessions.sni` | The `sni_absent` test, the table's server name, and the `/tls?sni=` link. |
| `tls_sessions.server_ip` | The table's server column and the `/tls?ip=` link when there is no name. |
| `tls_sessions.client_packet` | The `/packets?sel=` frame link. |
| `tls_sessions.time_epoch` | The sort order of the flagged sessions. |
| `tls_sessions.id` | Tie-break ordering of the query. |
| `tls_sessions.stream_id`, `client_ip`, `server_port`, `selected_alpn`, `cipher_suite`, `ja3`, `handshake_status`, `alert` | Selected by the query but **not rendered** on the card. The cipher suite, JA3/JA4 and ALPN evidence behind a session is therefore not shown here, even though it is read from the database. |

## 6. Fields the analyst brief asks for but the index does not hold

* **Certificate trust.** There is no validation result in the index: no chain
  status, no revocation state, no trusted-CA flag. `cert_subject`, `cert_issuer`,
  `cert_not_before`, `cert_not_after` and `cert_serial` are indexed and the Threat
  Hunt engine does not read them at all — `self_signed_suspected` is the analyser's
  heuristic (subject equals issuer) and is the only certificate signal on the card.
  A certificate issued by a corporate CA that the analyst does not trust looks
  identical to one they do.
* **A decrypted view of the session.** Nothing is decrypted. The card cannot say
  what was sent, and a session to a hard-coded controller looks exactly like a
  session to a legitimate service of the same shape.
* **JA3/JA4 correlation.** `ja3`, `ja3_full`, `ja3s` and `ja4` are indexed, and the
  engine reads `ja3` into the row without using it. Fingerprint-based detection is
  possible from the index (the `/tls` page reads `ja3`), but it is not part of this
  indicator, and there is no fingerprint reputation data offline.
* **`tls.handshake.extensions_server_name` absence versus encrypted ClientHello.**
  The index records that the SNI is absent; it cannot distinguish "no extension",
  "encrypted ClientHello (ECH)" or "capture started mid-session". The analyser's own
  flag text acknowledges this, and the effect on the card is that all three look
  like `no server name in the ClientHello`.
* **Application identity.** No ALPN-derived application label appears on the card
  and there is no SNI-to-category mapping, so `no server name` cannot be
  automatically reduced to "a known application".
* **`tls.record.content_type` and handshake message types.** Not indexed; the only
  handshake-level field is the analyser's `handshake_status`.

## 7. How to investigate further

| Step | Link | What to look for |
|---|---|---|
| The named server | `/tls?sni=<server name>` | Every session to that name, with versions and fingerprints. |
| An unnamed server | `/tls?ip=<server address>` | What else went to that address, which is how an SNI-less session gets identified. |
| Sessions with old versions | `/tls?version=TLS%201.0` | Whether obsolete TLS is one legacy server or a pattern across the capture. |
| Sessions with certificates | `/tls?has_cert=true` | The sessions that did present a certificate, as the complement of the flag. |
| The fingerprint view | `/tls?view=fingerprints` | The JA3/JA4 families present, which groups these sessions with others from the same client software. |
| The frame | `/packets?sel=<client frame>` | The ClientHello itself, which shows the offered versions and extensions. |
| The conversation | `/conversations?stream=tcp:<stream_id>` | Session length and byte balance; a long session to an unnamed server is a different case from a short one. |
| The client | `/hosts?ip=<client>` | Whether one host is responsible for all the unnamed sessions. |

## 8. What it does not prove

A missing server name, an old version, a self-signed certificate or a failed
handshake do not establish malicious traffic. Each of them has a mundane
explanation, and the card's own caveat names them:

> None of these establish malicious traffic. Captures that start mid-session,
> encrypted ClientHello, appliances with private certificate authorities and
> intentionally blocked destinations all produce these flags.

Nothing here says what was carried inside the session, who operated the server, or
whether the client intended anything.

## 9. Known limits and false positives

* **Captures that start mid-session.** A session whose ClientHello is not in the
  capture has no SNI and no certificate, so it raises `sni_absent` and often
  `no_certificate` — two observations from one capture artefact.
* **Encrypted ClientHello.** A client using ECH sends no plaintext SNI; it is
  indistinguishable here from a client that sends none.
* **Private certificate authorities.** Appliances, internal services and development
  servers commonly present self-signed certificates, and
  `self_signed_suspected` fires whenever the subject and issuer strings match.
* **Intentionally blocked destinations.** A firewall or proxy that rejects a TLS
  connection produces an `alert` or an `incomplete_handshake` — the capture is
  recording a defence working.
* **Legacy versions on purpose.** Old printers, medical devices, industrial
  equipment and embedded management interfaces genuinely speak TLS 1.0, and will
  raise `tls10_or_older` forever.
* **The bars over-count by design.** A session with three observations appears in
  three bars, so the chart's totals do not match the headline count.
* **Blind spots.** Only sessions the TLS analyser produced exist in this table, so
  TLS over non-standard ports that the analyser did not dissect, and TLS wrapped in
  another protocol, are absent; and nothing about the certificate or the cipher
  suite reaches the card even though the index holds it.
* **An empty card is not a clean capture.** It means no session carried a lead flag,
  no session's version began with `SSL`, `TLS 1.0` or `TLS 1.1`, and every session
  had a server name.

---

**Related:** [Threat Map](../Threat-Hunt.md) · [TLS](../TLS.md) · [Hosts](../Hosts.md) · [PossibleMalwareDownload](PossibleMalwareDownload.md) · [C2Beaconing](C2Beaconing.md)
