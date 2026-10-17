# Suricata rule audit

A review of the Suricata rule set the .pcap analysis software ships and runs,
the defects that were found, the corrections that were applied, and the evidence
behind each one.

- **Date:** 2026-10-11
- **Rules reviewed:** 284 vendored files / 1,615 rules (daffainfo 1,167, oisf 448)
- **Rules corrected:** 17, all in the locally maintained layer `local/`
  (SIDs 50200001-50200016, 50500002)
- **Vendored upstream files:** not modified - see section 1.3

---

## 1. Scope and method

### 1.1 What was audited

The software has no Suricata binary. Rules are read from `backend/rules/**` into
the `suricata_rules` table by `POST /api/suricata/rules/seed` (or automatically
on first use) and then evaluated by `app/services/suricata_engine.py` against the
fields TShark already indexed. "The existing Suricata rules" therefore means:

* the 284 vendored `.rules` files under `backend/rules/`, recorded with their
  upstream commits in `PROVENANCE.md`, and
* whatever those files put into the rule store - which, before this audit, was
  1,615 rules, 1,114 of them evaluable.

### 1.2 How each rule was validated

Suricata itself is not installed in this environment and the host has no network
access, so "Suricata loads the rules" could not be demonstrated directly. Every
claim below rests on one of four independent sources instead:

| Evidence | What it establishes |
| --- | --- |
| The application's own parser (`suricata_rules.parse_rule`) | Header, action, protocol, addresses, ports, direction, option handling, buffer binding, which options the matcher will honour |
| Independent compilation of every `pcre` with Python's `re` | Whether a pattern can match at all - a pattern that fails to compile inside the matcher is swallowed silently and produces no error and no match |
| TShark 4.6.8 against the captures themselves | Ground truth: what the packets actually contain, independent of the rule engine |
| End-to-end offline runs of the real pipeline (TShark -> index -> HTTP -> matcher) on 39 purpose-built captures plus the 11 real captures already in the database | Whether a rule fires, on what, with which bytes, before and after each change |

The 39 purpose-built captures (known-positive / known-negative pairs, one HTTP
transaction each) were generated with Scapy and analysed through the same code
path the application uses; they are described in section 5.2.

### 1.3 Where the corrections were written

The vendored files are third-party data and the repository's own instruction
(`backend/rules/README.md`) is not to edit them in place, because a re-import
would overwrite the edit and falsify the provenance record. Corrections therefore
live in `backend/rules/local/` and carry **the same SID as the rule they
correct**. The importer upserts by SID, so a local rule supersedes the vendored
text at every future seed; the vendored file stays byte-identical to the upstream
commit and `PROVENANCE.md` stays true. A corrected rule's `source` becomes
`bundled:local`, which is how the rules list distinguishes it.

The SID inventory is unchanged: 1,615 SIDs before, 1,615 after.

### 1.4 What was not done

The rule set was not redesigned, no capture was re-authored, no detection feature
was added, and no rule that already behaved correctly was rewritten. Rules whose
detection is limited by the *platform* rather than by their own logic were
reported, not "fixed" - see section 4 and section 7.

---

## 2. Inventory of the rule set as found

| Measure | Value |
| --- | ---: |
| Vendored `.rules` files | 284 |
| Rules parsed | 1,615 |
| Parse failures (rejected by the parser) | **0** |
| Duplicate SIDs | **0** |
| Rules the matcher can evaluate (`supported = 1`) | 1,114 |
| Rules the matcher skips (`supported = 0`) | 501 |
| `content` options | 4,779 |
| `pcre` options | 72 |
| `flow` options | 191 |
| Rules using no buffer selector at all (default buffer) | 72 |
| Rules with a needle of two bytes or fewer | 21 |
| `pcre` patterns that do not compile | **1** (SID 50500002 - section 3.2) |

Protocol distribution: `http` 1,223, `pkthdr` 107, `tcp` 63, `tls` 30,
`http2` 21, `smb` 19, `smtp` 15, everything else 14 or fewer.

Why rules are skipped (501 rules):

| Reason | Rules |
| --- | ---: |
| Engine event rules (`app-layer-event` / `decode-event` / `stream-event`) - every rule in `oisf/` | 448 |
| Unimplemented PCRE modes: `U` (URL-decode) 36, `P` (body) 15, `H` 1, `I` 1 | 53 |

All 448 `oisf/` rules are event rules and can never fire here; all 53
unimplemented-PCRE-mode rules are in `daffainfo/`, and 1,114 of that set's 1,167
rules are evaluable. The corrections in section 3 move one more rule (50500002)
out of the skipped set, so 1,115 `daffainfo` rules are evaluated after this audit.

---

## 3. Defects corrected

### 3.1 Defect D1 - SIDs 50200001-50200016: a directory name matched the first letters of an unrelated path element

**File:** `backend/rules/daffainfo/http/web-attacks/linux-structures.rules`
**Correction:** `backend/rules/local/linux-structures.rules` (same 16 SIDs, `rev` 1 -> 2)

**Original rule shape** (SID 50200005; the others are identical modulo the
directory name):

```
alert http any any -> any any (msg:"Attempt to access /proc*"; content:"proc"; nocase; pcre:"/(\/|%2F)proc/i"; classtype:attempted-recon; sid:50200005; rev:1;)
```

**Defect.** The `pcre` requires only a leading separator and the directory
name. Nothing terminates the name, so a complete, benign path element that merely
*starts* with those letters satisfies both conditions. The rule then reports
"Attempt to access /proc" with classtype `attempted-recon` for traffic that
never referenced `/proc`.

The defect is structural - it is the same template in all 16 rules - and it is
not an artefact of the matcher: a bare `content`/`pcre` pair is evaluated
against the payload, whose bytes
(`GET /assets/Owner/arm/ProcessMAU.txt HTTP/1.1 ...`) contain `/Proc` exactly as
the pattern describes, so a stock Suricata would alert on the same packets.

**Packet-level evidence, real capture.** Analysis `08dfb402`
(`2026-10-01-traffic-analysis-exercise.pcap`, 42,497 packets) produced two
SID 50200005 findings for one ordinary software-update fetch:

```
packet 40888  10.10.1.128:63740 -> 23.213.232.136:80   GET /assets/Owner/arm/ProcessMAU.txt
  matched  'Proc'   hex 50726f63
  excerpt  'GET /assets/Owner/arm/ProcessMAU.txt HTTP/1.1 GET /assets/Owner/arm/ProcessMAU.txt'
```

There is no `/proc` in that request; the match is the `Proc` of "ProcessMAU".

**Evidence, controlled.** 15 of the 16 rules reproduced the same false positive
on known-benign captures, each against a path element that merely begins with the
directory name:

| Rule | Benign request that alerted before the correction |
| --- | --- |
| 50200001 | `/binary/blob.bin`, `/bins/list.json` |
| 50200002 | `/sbinner/tool` |
| 50200003 | `/etcetera/notes.txt` |
| 50200004 | `/development/index.html`, `/devices/list.json` |
| 50200005 | `/assets/Owner/arm/ProcessMAU.txt` |
| 50200006 | `/assets/variables.js` |
| 50200007 | `/tmpfoo.txt` |
| 50200008 | `/usrsupport/app.js` |
| 50200009 | `/homepage.html`, `/homeowners/list` |
| 50200010 | `/bootstrap.min.css` |
| 50200011 | `/library/app.js`, `/libstdc/readme` |
| 50200012 | `/options.json`, `/optin/confirm` |
| 50200013 | `/mntpoint/data.txt` |
| 50200014 | `/mediawiki/index.php`, `/mediator/page` |
| 50200015 | `/srvless/app.js`, `/srvx/app.js` |

**Second defect in the same family - SID 50200016.** Unlike its 15 siblings its
pattern is anchored: `pcre:"/^(\/|%2F)root/i"`. The inspected buffer never starts
with the directory name (it starts with the method, or with the response status
line), so the rule could not fire at all: `GET /root/.ssh/id_rsa` produced no
alert. This is why 50200016 shows no false positive in the table above - the
anchor hid it.

**Correction.** Require the directory name to be a complete path element:

```
content:"proc"; nocase; pcre:"/(?:\/|%2f)proc(?![\w.~-])/i";
```

The negative lookahead rejects a following name character, so `/proc/self/environ`
and `/proc` still match, `%2F`-encoded forms still match, and
`/ProcessMAU.txt`, `/etcetera` and `/development` no longer do. SID, `msg`,
`classtype`, protocol, addresses and the `content` fast-pattern are unchanged;
only `rev` was raised to 2, which is the convention for a changed rule. SID
50200016's anchor was dropped so that it behaves like its siblings.

**Interpretation recorded explicitly.** `msg:"Attempt to access /proc*"` could be
read as a shell glob (`/proc*` = anything beginning with `/proc`). That reading
was rejected: the rule's purpose is to flag access to the system directory, the
glob reading is precisely what produces the false positives demonstrated above,
and the alert text ("Attempt to access /proc") is a claim the glob reading cannot
support for `/ProcessMAU.txt`. If the glob semantics are wanted after all, this
is the decision to revisit.

### 3.2 Defect D2 - SID 50500002: a rule that could never alert on its own target

**File:** `backend/rules/daffainfo/http/web-attacks/path-traversal.rules`
**Correction:** `backend/rules/local/path-traversal.rules` (same SID, `rev` 1 -> 2)

**Original rule:**

```
alert http any any -> any any (msg:"Possible Path Traversal attack, repeated dot-dot-backslash sequence"; content:"..|5C|"; http_uri; pcre:"/(?:\.\\){2,}/U"; classtype:web-application-attack; sid:50500002; rev:1;)
```

**Observed.** `GET /..\..\..\windows\win.ini` - the exact traffic the rule
describes - produced no SID 50500002 finding, before or after any other change.

**Three independent causes, all measured:**

1. **The `U` mode is not implemented.** The matcher records `pcre-flag:U` as
   unsupported and stores the rule with `supported = 0`; a rule that is not fully
   evaluable is skipped rather than half-matched. It was therefore never
   evaluated. (53 rules in the set share this fate - section 4.3.)

2. **The pattern never compiled.** Extracting the pattern from its quoted option
   collapses the two-character sequence backslash-backslash into one backslash,
   which removes the escape before the group's closing bracket. Reproduced against
   the parser:

   ```
   option value : '"/(?:\\.\\.\\\\){2,}/U"'
   after unquote: '/(?:\\.\\.\\){2,}/U'
   pattern      : '(?:\\.\\.\\){2,}'   hex 28 3f 3a 5c 2e 5c 2e 5c 29 7b 32 2c 7d
   re.compile   : error: missing ), unterminated subpattern at position 0
   ```

   The matcher swallows a non-compiling `pcre` and returns no match and no error,
   so this was a silent false negative on top of the first cause.

3. **The indexed buffer carries TShark's escaped field text.** TShark writes one
   backslash on the wire as two in `-T fields` output
   (`backend/app/services/tshark.py` passes `-E separator` and `-E occurrence` but
   not `-E escape`), so for a request line containing single backslashes the
   indexed request target holds doubled ones. The capture bytes are
   `47 45 54 20 2f 2e 2e 5c 2e 2e 5c 2e 2e 5c 77 69 6e ...` while the matcher's
   `http.uri` for the same request is `2f 2e 2e 5c 5c 2e 2e 5c 5c 2e 2e 5c 5c ...`.
   A pattern requiring exactly one backslash between the `..` pairs can therefore
   never match an indexed URI.

**Correction:**

```
content:"..|5C|"; http_uri; pcre:"/(?:\.\.\x5c{1,2}){2,}/";
```

* The backslash is written as the hex escape `\x5c`, which means the same thing in
  PCRE and in Python's engine and survives the unquoting step intact (cause 2).
* The separator accepts **one or two** backslashes. One backslash is the wire form
  - what Suricata itself inspects - so nothing is lost there; two backslashes is
  how this matcher's indexed buffer spells the same bytes, so the rule finally
  detects its own target here (cause 3). A doubled separator in a request target
  is at least as suspicious as a single one, so the widening is not a
  false-positive risk.
* The unimplementable `U` mode is dropped (cause 1). The rule's own
  `content:"..|5C|"; http_uri` already required a literal backslash in the request
  target, so `U` could only have helped a mixed literal / percent-encoded form -
  and that form is covered by the sibling rules 50500004 (`..%2f`) and 50500005
  (`..%5c`), which match it directly.

Detection objective, SID and classtype are unchanged; `rev` 1 -> 2.

**Caveat, stated plainly.** Cause 3 is a defect of the *pipeline*, not of the
rule, and it is **not fixed** by this audit (section 4.6). Accepting one or two
backslashes is the narrowest way to make the rule work within the platform
without making it wrong for Suricata; the more invasive alternative - making the
indexed buffer carry the wire bytes - was judged out of scope for a rules review.

---

## 4. Detected but deliberately not corrected

Each of these was reproduced or measured; none was changed, and the reason is
given. The distinction matters: a rule that is wrong and a rule that cannot be
fully exercised by this platform are different problems.

### 4.1 SIDs 50300004 and 50300001 - single-quote needles, an explicit false-positive source (not corrected)

`content:"'"; nocase; http_client_body;` (50300004) and
`content:"'"; nocase; http_uri;` (50300001) match any single apostrophe byte.
On the real capture `51171325` (`2026-09-11-traffic-analysis-exercise.pcap`)
50300004 produced **29 matches, filling the 25-per-rule finding cap**. The bodies
are not SQL:

```
frame 73447   POST second.bert-hits.com  /68ca/jcwnotqm0a&99099.../789o4vgzlrx
              Content-Type: application/octet-stream   Content-Length: 26655
              body[0:16] = 1f 8b 08 00 00 00 00 00 00 0a ac bc 55 50 9d 5d   (gzip magic)
33 of the 43 POST bodies in the capture contain a 0x27 byte.
```

The rule fires on a compressed C2 payload because a gzip stream contains 0x27 by
chance. It is nevertheless **left unchanged**: its `msg` says "Contains
singlequote POST DATA", and it detects exactly that. The defect is that a
one-byte condition cannot support a `web-application-attack` / high
classification - a judgement about the rule's design, not a mismatch between its
logic and its stated objective. Rewriting it (for example to require surrounding
SQL syntax) would replace its documented objective rather than correct it, which
the audit brief rules out. Recommended instead: disable it in the rules list for
captures of this kind, or take the change upstream.

The same reasoning leaves the rest of the 50300001-50300023 family alone; the
other members pair their needle with a discriminating `pcre`.

### 4.2 SIDs 12021007 and 22014001 - duplicate detection logic

`CNVD-2021-26422` (SID 12021007) and `CVE-2014-1203` (SID 22014001) are the
same vulnerability: identical protocol, method, URI and body conditions, in
different files with different `reference` metadata. Both were kept. They are
distinct catalogue entries upstream, and on this matcher they produce two
findings for one event, which is visible to the analyst rather than misleading.
Flagged here so the duplication is not later mistaken for a defect this audit
introduced.

### 4.3 53 rules carrying PCRE modes the matcher does not implement

`U` (36), `P` (15), `H` (1), `I` (1), spread across
`command-injection.rules`, `path-traversal.rules`, `sql-injection.rules`,
`server-side-template-injection.rules`, `nosql-injection.rules`,
`jndi-injection.rules`, `xml-external-entity.rules`,
`deserialization.rules`, `cross-site-scripting.rules` and others. Because the
matcher refuses to half-match, all 53 are stored `supported = 0` and are skipped:
they detect nothing at all today. This is a **capability gap in the matcher**, not
a rule defect - the rules are valid Suricata. Fixing it means implementing the
modes, which is outside a rules review. Only 50500002 was re-authored, because in
its case a further, rule-level defect (a pattern that cannot compile) made the
rule inert for reasons beyond the missing mode. The remaining 52 are listed here
so the coverage gap is on the record rather than inferred from silence.

### 4.4 448 event rules in oisf/

All of `oisf/` is `app-layer-event` / `decode-event` / `stream-event`
rules. They describe events the Suricata engine itself would raise, and there is
no engine here, so they are skipped by design. No change proposed.

### 4.5 72 rules with no buffer selector

These rely on the default buffer. Suricata's default is the raw packet payload;
this matcher's is a synthetic join of the fields it indexed (method, URI, host,
user agent, bodies - see `packet_buffers` / `http_buffers`). Matching therefore
happens against a *reconstruction*, which can both miss a payload-only pattern and
match across a field boundary that does not exist on the wire. The engine's own
module docstring says such rules are marked `approximate`, but nothing sets it:
every rule in the store has `approximate = 0`, so a finding never tells the
analyst that its basis is weaker. No rule was changed - the correction belongs in
the engine - but the audit records the unfulfilled docstring, and the
reconstructed-buffer behaviour is exactly why D1 was demonstrable in the first
place. The affected families are 50100001-50100003, 50200001-50200016,
50400001-50400013, 50600001-50600006, 50700001-50700003, 50900008, 51000005,
51000009, 51100001-51100005, 51300002 (72 rules in total).

### 4.6 TShark field escaping is not undone in the indexed buffers

As shown in section 3.2 cause 3, a backslash on the wire appears doubled in the
buffers rules inspect. It affects any rule matching a literal backslash
(`content:"..|5C|"`, and 50500002's pattern). Recommended fix, not applied:
pass `-E escape=none` (or unescape the field text) in `tshark.run_fields`. This
is a pipeline change, not a rules change.

### 4.7 One transaction can produce two findings

Every rule with a `->` in its header is evaluated against the request packet row
*and* the response packet row, because the response row also carries
`http_uri`/`http_method`. `GET /etc/passwd` therefore produced two SID
50200003 findings and two SID 50500009 findings for a single exchange, and
`GET /search?q=1'` produced two SID 50300001 findings even though that rule
carries `flow:established,to_server` - `_flow_satisfied` deliberately ignores the
direction qualifiers. This is pre-existing behaviour of the packet-scope pass;
nothing in this audit introduced or worsened it, and the correction to D1 reduces
alert volume without touching it. Recorded so the doubling is not mistaken for a
duplicate introduced by the change. The 50200003/50500009 alerts on `0697f87e`
are genuine (frame 12 really is `GET /../../etc/passwd`); only their doubling is
an artefact.

### 4.8 http_header maps to request *and* response headers

SID 51000006 (`content:"jndi|3A|"; http_header;`) and 51000009 use the legacy
`http_header` modifier. Suricata documents that spelling as an alias for the
*request* header buffer; the matcher binds it to `http.header`, which it builds
from the request headers **and** the response headers. A response header containing
`jndi:` would therefore satisfy a rule that means to inspect the request. No
such false positive was observed in the 11 real captures (both rules matched
nothing after the re-run below), so no change was made; flagged as a latent
over-match, and as a mapping question for the engine rather than for the rule.

### 4.9 Stale findings from an earlier engine build (not a rule defect)

The findings stored before this audit included 30 "Possible JNDI Injection
attack (Log4Shell)" alerts (16 on `08dfb402`, 11 on `7c3997ca`, 2 on `9e2ef6a9`,
1 on `bbbad262`) on requests such
as `GET /connecttest.txt` and `GET /pr` whose headers contain no `jndi:` -
they were produced by an older matcher that decoded `content:"jndi|3A|"` down to
the needle `":"`, and the analyses were never re-run. Re-running the Suricata
stage with the current engine produces none of them. This is recorded because it
is the kind of alert that looks like a rule defect and is not one.

---

## 5. Verification

### 5.1 Syntax and loadability

* All 1,615 rules parse; 0 parse failures, 0 duplicate SIDs (unchanged before and
  after).
* The 17 corrected rules parse, bind every option, and are marked
  `supported = 1` with an empty `unsupported` list.
* Every one of the 17 corrected `pcre` patterns compiles under Python's `re`,
  and each uses only constructs common to PCRE (character classes, alternation,
  non-capturing groups, negative lookahead, bounded quantifiers, `\x5c` escapes),
  none of which Suricata rejects. This is the strongest statement available
  without a Suricata binary; the limitation is stated in section 7.
* Seeding the whole directory reports `files: 286, imported: 1,615, updated: 17,
  errors: 0` - i.e. 17 rules superseded in place and no rule added or lost.

### 5.2 Known-positive / known-negative matrix

39 captures, one HTTP transaction each, all pushed through the real offline
pipeline (TShark -> packet index -> HTTP -> Suricata matcher) in an isolated data
directory, once against the vendored rules and once with `local/` applied.
`neg_*` captures must stay silent; `pos_*` must alert. SIDs are listed once
each even when a rule produced two findings (section 4.7).

| Case | Expectation | Before | After |
| --- | --- | --- | --- |
| `neg_binary_dir` | must be silent | [50200001] | silent |
| `neg_binary_post_body` | must be silent | [50300004] | [50300004] |
| `neg_bins_dir` | must be silent | [50200001] | silent |
| `neg_bootstrap_css` | must be silent | [50200010] | silent |
| `neg_development_dir` | must be silent | [50200004] | silent |
| `neg_device_file` | must be silent | [50200004] | silent |
| `neg_etcetera_dir` | must be silent | [50200003] | silent |
| `neg_homeowners` | must be silent | [50200009] | silent |
| `neg_homepage` | must be silent | [50200009] | silent |
| `neg_library` | must be silent | [50200011] | silent |
| `neg_libstdc` | must be silent | [50200011] | silent |
| `neg_mediator` | must be silent | [50200014] | silent |
| `neg_mediawiki` | must be silent | [50200014] | silent |
| `neg_mntpoint_dir` | must be silent | [50200013] | silent |
| `neg_optin` | must be silent | [50200012] | silent |
| `neg_options_json` | must be silent | [50200012] | silent |
| `neg_process_file` | must be silent | [50200005] | silent |
| `neg_rooted_dir` | must be silent | silent | silent |
| `neg_sbinner_dir` | must be silent | [50200002] | silent |
| `neg_single_backslash_traversal` | must be silent | silent | silent |
| `neg_single_dotdot_slash` | must be silent | silent | silent |
| `neg_srvless` | must be silent | [50200015] | silent |
| `neg_srvx` | must be silent | [50200015] | silent |
| `neg_tmpfoo` | must be silent | [50200007] | silent |
| `neg_userprofile` | must be silent | silent | silent |
| `neg_usrsupport_js` | must be silent | [50200008] | silent |
| `neg_variables_js` | must be silent | [50200006] | silent |
| `pos_backslash_traversal` | must alert | [50500012] | [50500002, 50500012] |
| `pos_dev_null` | must alert | [50200004] | [50200004] |
| `pos_dotdot_slash_traversal` | must alert | [22025044, 50200003, 50500009] | [22025044, 50200003, 50500009] |
| `pos_double_backslash_traversal` | must alert | [50500012] | [50500002, 50500012] |
| `pos_etc_passwd` | must alert | [50200003, 50500009] | [50200003, 50500009] |
| `pos_etc_percent_encoded` | must alert | [50200003] | [50200003] |
| `pos_proc_exact` | must alert | [50200005] | [50200005] |
| `pos_proc_self_environ` | must alert | [50200005, 50500011] | [50200005, 50500011] |
| `pos_root_ssh` | must alert | silent | [50200016] |
| `pos_sql_quote_uri` | must alert | [50300001] | [50300001] |
| `pos_var_exact` | must alert | [50200006] | [50200006] |
| `pos_xss_uri` | must alert | [50100003] | [50100003] |

Reading of the matrix:

* **15 false positives removed**: every `neg_*` case that alerted before is
  silent after. Between them they cover all 15 rules that could false-positive.
* **2 false negatives removed**: `pos_root_ssh` now yields SID 50200016, and
  `pos_backslash_traversal` and `pos_double_backslash_traversal` now yield
  SID 50500002. Neither alerted before.
* **No true positive lost**: every `pos_*` case that alerted before still alerts
  after, with the same SIDs.
* **Correct negative controls stayed negative**: `neg_single_dotdot_slash`
  (`/a/../b.txt`) and `neg_single_backslash_traversal` (`/a..\b/c.txt`) are
  not repeated traversal sequences and stay silent.
* `neg_binary_post_body` still alerts SID 50300004 - the deliberately unchanged
  behaviour of section 4.1, kept in the matrix so the decision is visible rather
  than implied.

### 5.3 Real captures

The 11 captures already analysed in the application database were re-evaluated
with each rule layer (identical packet and HTTP index; only the rules changed):

| SID | Before | After | Reading |
| --- | ---: | ---: | --- |
| 50200005 | 2 | 0 | Both were the `/ProcessMAU.txt` false positive of section 3.1 |
| 50200003 | 2 | 2 | True positive, `GET /../../etc/passwd` (frame 12 of http.pcap) |
| 50500009 | 2 | 2 | True positive, same request |
| 22025044 | 1 | 1 | True positive, every CVE-2025-2294 condition present |
| 50100003 | 2 | 2 | True positive, `/search?q=javascript:alert(1)` (frame 4 of xss-evidence.pcap) |
| 50100017 | 1 | 1 | True positive, POST body `comment=<a href="javascript:alert(1)">go</a>&x=1` (frame 6) |
| 50300004 | 29 | 29 | Unchanged by decision - section 4.1 |

Every surviving alert was checked against the packet rather than accepted from
the rule output: the URIs above come from TShark reading the captures directly
(these captures are the application's own uploads from earlier analyses: two
malware traffic-analysis exercises, three SpaceX workstation captures, two
sf19us-MTA lab captures, one Nmap host-discovery scan and two synthetic test
captures). No alert was created and no legitimate alert was suppressed on real
traffic.

### 5.4 Regression suite

* `pytest backend/tests/test_suricata_rules.py` - 24 passed.
* `pytest backend/tests/test_api_and_pipeline.py backend/tests/test_storage_and_validation.py` -
  121 passed, 1 skipped.

No test references the corrected rules, so these runs confirm that the extra
local rule file, the new `source`/`category` values and the re-seed path break
nothing.

### 5.5 Rule interactions

* No corrected rule shares a SID with another rule: the inventory is 1,615 SIDs
  before and after, and the seed reports `imported: 1,615, updated: 17` with no
  duplicates.
* No corrected rule became a neighbour's precondition: none of the 17 uses
  `flowbits`, the set contains no `pass` rules, and all 17 remain plain
  `alert` actions.
* No unrelated rule changed behaviour. In the case matrix the only differences
  between before and after are the intended ones, and on the real captures the
  only delta is 50200005 going from 2 to 0.
* The 17 rules keep their original `classtype`, severity (`attempted-recon` ->
  medium, `web-application-attack` -> high), protocol and address scope.
* The duplicate findings of section 4.7 are counted and explained; the change did
  not increase them.

### 5.6 Applied to, and read back from, the running application

The live rule store was re-seeded and every analysis that held a Suricata finding
was re-evaluated, then read back through the running backend's own API at
`http://127.0.0.1:8000` (this is the same `POST /api/suricata/rules/seed` and
`POST /api/analyses/{id}/suricata/run` the interface calls):

* `GET /api/suricata/rules/50200005` and `/50500002` return `rev: 2`,
  `source: "bundled:local"`, `supported: true` and the corrected rule text.
* `GET /api/suricata/rules/stats` returns `total: 1615, enabled: 1615,
  supported: 1115, unsupported: 500`, with sources `bundled:daffainfo 1150`,
  `bundled:oisf 448`, `bundled:local 17` - no rule added, none lost, and one
  rule (50500002) moved from skipped to evaluated.

Findings before (backup of the stored state) and after the re-run, per analysis:

| Analysis | Capture | Findings before | Findings after |
| --- | --- | ---: | ---: |
| 08dfb402 | 2026-10-01 traffic-analysis exercise | 18 (16 stale Log4Shell, 2 false-positive `/proc`) | 0 |
| 7c3997ca | sf19us-MTA-lab-07 | 11 (all stale Log4Shell) | 0 |
| 9e2ef6a9 | sf19us-MTA-lab-09 | 2 (stale Log4Shell) | 0 |
| bbbad262 | SpaceX curl download | 1 (stale Log4Shell) | 0 |
| 0697f87e | http.pcap | 5 (verified true positives) | 5 |
| 8fa9b573 | xss-evidence.pcap | 3 (verified true positives) | 3 |
| 51171325 | 2026-09-11 traffic-analysis exercise | 25 (SID 50300004, unchanged by decision) | 25 |

The 30 stale Log4Shell findings are the pre-existing engine artefact of section
4.9, not a rule change; the 2 removed `/proc` findings are the false positive
this audit corrects. Nothing else moved: no analysis gained an alert, and every
surviving alert is one of the true positives verified against packet contents in
section 5.3.

---

## 6. Change record

Every corrected rule keeps its SID. `rev` is raised to 2 because the detection
logic changed; `source` becomes `bundled:local`.

| SID | msg | Original defect | Correction |
| --- | --- | --- | --- |
| 50200001 | Attempt to access /bin* | no right-hand boundary; matched `/binary`, `/bins` | pcre `"/(?:\/\|%2f)bin(?![\w.~-])/i"` |
| 50200002 | Attempt to access /sbin* | matched `/sbinner` | as above, `sbin` |
| 50200003 | Attempt to access /etc* | matched `/etcetera` | as above, `etc` |
| 50200004 | Attempt to access /dev* | matched `/development`, `/devices` | as above, `dev` |
| 50200005 | Attempt to access /proc* | matched `/ProcessMAU.txt` on real traffic | as above, `proc` |
| 50200006 | Attempt to access /var* | matched `/variables.js` | as above, `var` |
| 50200007 | Attempt to access /tmp* | matched `/tmpfoo.txt` | as above, `tmp` |
| 50200008 | Attempt to access /usr* | matched `/usrsupport` | as above, `usr` |
| 50200009 | Attempt to access /home* | matched `/homepage.html`, `/homeowners` | as above, `home` |
| 50200010 | Attempt to access /boot* | matched `/bootstrap.min.css` | as above, `boot` |
| 50200011 | Attempt to access /lib* | matched `/library`, `/libstdc` | as above, `lib` |
| 50200012 | Attempt to access /opt* | matched `/options.json`, `/optin` | as above, `opt` |
| 50200013 | Attempt to access /mnt* | matched `/mntpoint` | as above, `mnt` |
| 50200014 | Attempt to access /media* | matched `/mediawiki`, `/mediator` | as above, `media` |
| 50200015 | Attempt to access /srv* | matched `/srvless`, `/srvx` | as above, `srv` |
| 50200016 | Attempt to access /root* | pattern anchored with `^`; could never fire | dropped the anchor, added the boundary lookahead, `root` |
| 50500002 | Possible Path Traversal attack, repeated dot-dot-backslash sequence | skipped for the unimplemented `U` mode; pattern did not compile; buffer holds doubled backslashes | dropped `U`, wrote the backslash as `\x5c`, separator accepts one or two backslashes |

Files added: `backend/rules/local/linux-structures.rules`,
`backend/rules/local/path-traversal.rules`.

Files changed: `backend/rules/README.md` (documents the `local/` layer),
`backend/rules/PROVENANCE.md` (records the layer and the unchanged SID count),
`backend/rules/RULE-AUDIT.md` (this report).

Files not changed: every file under `backend/rules/daffainfo/` and
`backend/rules/oisf/`.

The rule store in `data/apackets.db` was re-seeded so the corrected text is what
the application actually runs; the upsert deliberately leaves each rule's
enabled/disabled state alone.

---

## 7. Remaining limitations and uncertainty

1. **No Suricata binary was available**, so "Suricata loads these rules
   successfully" is asserted from the rules' conformity to documented Suricata
   and PCRE syntax, not from an actual `suricata -T` run. If a Suricata build
   becomes available, `suricata -T -S backend/rules/local/linux-structures.rules`
   (and the path-traversal file) is the remaining step. Nothing in the corrected
   rules uses a construct the parser cannot explain and each pattern was compiled
   independently, but that is not the same as a load test.
2. **The `{1,2}` separator in SID 50500002 is a platform accommodation**
   (section 3.2 cause 3). It is defensible - a doubled separator is still a
   traversal, and the single-backslash wire form still matches - but it exists
   because the pipeline stores TShark-escaped text. If that is fixed, the pattern
   should be revisited and the `{1,2}` narrowed to a single separator.
3. **Encrypted and truncated traffic bounds every claim.** Where the request or
   response body is absent from the index (encrypted C2, truncated captures,
   HTTP/2 that was not dissected), body-scoped rules (50100017, 50300004,
   50500008, 50500015, 50500016, 50400014-50400018, 50900007, 51000008, 51300007,
   51400010-51400012) cannot match. Their silence on such a capture is not
   evidence that the traffic is clean.
4. **The 53 PCRE-mode rules and 448 event rules detect nothing here**
   (sections 4.3, 4.4). The corrected set is a small improvement in that
   direction, not a solution.
5. **The default-buffer approximation is invisible** (section 4.5): findings do
   not say that their basis is a reconstructed field join.
6. **Detection is not attribution.** An alert means the named bytes were present
   in the named buffer. It does not mean an attack succeeded, or that an attack
   occurred; conversely the absence of an alert means only that no rule's
   conditions were met. These captures are general traffic plus one exercise
   capture, not a labelled corpus, so precision and recall were measured against
   constructed cases and a small number of individually verified real alerts -
   not against ground truth.
7. **The 25-per-rule findings cap** (`max_findings_per_rule`) means a rule that
   over-fires hides its own volume: SID 50300004's 29 matches are stored as 25
   findings. The counts in section 5.3 come from the matcher, not the findings
   table.
8. **The interpretation in section 3.1** (complete path element vs shell glob) is
   a judgement. It is stated in the rule file and here so it can be reviewed on
   its merits.

---

## 8. Reproducing this audit

```
# 1. Static inventory: parse every rule, list errors, duplicate SIDs,
#    unsupported options and non-compiling pcre.
python .tmp/rule-audit/audit.py

# 2. Static defect scan (default buffers, short needles, unsupported pcre modes,
#    duplicate logic).
python .tmp/rule-audit/static_defects.py

# 3. Build the 39 known-positive / known-negative captures.
python .tmp/rule-audit/make_cases.py

# 4. Run them through the real offline pipeline, with and without local/.
python .tmp/rule-audit/run_cases.py before
python .tmp/rule-audit/run_cases.py after

# 5. Re-evaluate the real captures in the database, with and without local/.
python .tmp/rule-audit/census2.py before
python .tmp/rule-audit/census2.py after

# 6. Regression suite.
python -m pytest backend/tests/test_suricata_rules.py -q
```

The scripts under `.tmp/rule-audit/` are scratch tooling, not part of the
product. They read a throwaway copy of the analysis database under `.tmp/` and
write nothing outside it.
