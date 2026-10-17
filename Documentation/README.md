# APackets — documentation

APackets is a **locally hosted** PCAP/PCAPNG forensics workbench. It dissects a capture
with TShark on this machine, indexes the result into SQLite, and serves a dark-themed
analyst UI. No capture data leaves the host.

This folder documents **every section of the running application**, one document per
section, plus the machinery they all depend on.

---

## Start here

| Document | What it covers |
|---|---|
| [Getting-Started.md](Getting-Started.md) | Install, run, upload a first capture, and what to expect while it processes |
| [Architecture.md](Architecture.md) | How a capture becomes a page: stages, storage, the local-only guarantee |
| [Performance.md](Performance.md) | What loading and navigating actually cost, measured, and what was changed |
| [Reference/API.md](Reference/API.md) | The REST surface, and how it relates to the frozen contract |

## The application, section by section

The order below is the order of the left-hand navigation.

The headings below are the five headings the sidebar draws, in its order.

### Dashboard

| Section | Document | Route |
|---|---|---|
| Dashboard | [Dashboard.md](Dashboard.md) | `/` |
| Info | [Info.md](Info.md) | `/info` |
| Hosts | [Hosts.md](Hosts.md) | `/hosts` |

### Connections

| Section | Document | Route |
|---|---|---|
| Conversations | [Conversations.md](Conversations.md) | `/conversations` |
| Packets | [Packets.md](Packets.md) | `/packets` |
| Findings | [Findings.md](Findings.md) | `/findings` |

### Investigate

| Section | Document | Route |
|---|---|---|
| Threat Map | [Threat-Hunt.md](Threat-Hunt.md) | `/threat-hunt` |
| Baseline Check | [Baseline-Check.md](Baseline-Check.md) | `/baseline-check` |
| Hunt | [Investigate.md](Investigate.md) | `/investigate` |
| Files and Objects | [Files-and-Objects.md](Files-and-Objects.md) | `/objects` |
| Users & Passwords | [Credentials.md](Credentials.md) | `/credentials` |

### Protocols

| Section | Document | Route |
|---|---|---|
| HTTP | [HTTP.md](HTTP.md) | `/http` |
| DNS | [DNS.md](DNS.md) | `/dns` |
| TLS | [TLS.md](TLS.md) | `/tls` |
| Email | [Email.md](Email.md) | `/email` |
| SSH | [SSH.md](SSH.md) | `/ssh` |
| FTP | [FTP.md](FTP.md) | `/ftp` |
| VoIP | [VoIP.md](VoIP.md) | `/voip` |
| SMB | [SMB.md](SMB.md) | `/smb` |

### Settings

| Section | Document | Route |
|---|---|---|
| PCAP Files | [PCAP-Files.md](PCAP-Files.md) | `/files` |
| Settings | [Settings.md](Settings.md) | `/settings` |
| Alert Settings | [Alert-Settings.md](Alert-Settings.md) | `/alert-settings` |

**Threat Map** is the one section with a document per detection. Its section document
is [Threat-Hunt.md](Threat-Hunt.md); the seventeen detections each have their own page
under [ThreatHunter/](ThreatHunter/ThreatHunter.md), starting with the overview.

**Baseline** is one global reference network: chosen from the Baseline column on
[PCAP Files](PCAP-Files.md) (`/files`), shown in the top bar of every page, read as a
difference on [Baseline Check](Baseline-Check.md) (`/baseline-check`), and recorded on
[Findings](Findings.md) by seven `baseline_*` rules. The configuration, comparison and
rules are documented in [Baseline.md](Baseline.md); its API and rule text are
[`docs/CONTRACT.md`](../docs/CONTRACT.md) §8.

**Hunt** ([Investigate.md](Investigate.md)) is the one section that reads one entity
rather than the whole capture: it is documented against its own normative
contract, [`docs/ENTITY_PROFILE.md`](../docs/ENTITY_PROFILE.md).

---

## How these documents link

This set is written to be **published as a site**, so the links are the interface.
The rules, which every document here follows:

1. **Cross-references are relative links to the target document**, never to a heading
   alone: `[Packets](Packets.md)`, not "see the Packets page". A generator turns each
   file into a route, so a link that names the file is a link that keeps working.
2. **Paths are relative to the linking file.** A document in a subfolder reaches a
   top-level one as `../Name.md`; the Threat Hunter pages do exactly that.
3. **Every document opens with a one-line summary** and a **Related** line naming its
   neighbours, so no page is a dead end and every page is reachable from every page.
4. **Application routes are code, not links.** `` `/packets` `` is a path in the
   running app, not a document. Writing it as a link would produce a link that 404s
   once published, so routes are always inline code. When a document wants you to look
   at a screen it names the section (linking to its document) *and* gives the route in
   backticks.
5. **The frozen contract stays where it is.** [`docs/CONTRACT.md`](../docs/CONTRACT.md)
   is the normative API and schema specification, and
   [`docs/THREAT_HUNT.md`](../docs/THREAT_HUNT.md) is the normative Threat Map
   contract. These documents explain the application; those two define it. Where a
   section depends on a rule, it links to the contract rather than restating it.
   Five features carry their own normative contract alongside them:
   [`docs/PROTOCOLS.md`](../docs/PROTOCOLS.md) for the five protocol-session sections,
   [`docs/GEOGRAPHY.md`](../docs/GEOGRAPHY.md) for the Dashboard map,
   [`docs/IP_LOOKUP.md`](../docs/IP_LOOKUP.md) for the registration rail in the host
   detail, [`docs/ENTITY_PROFILE.md`](../docs/ENTITY_PROFILE.md) for Hunt, and
   [`docs/CREDENTIALS.md`](../docs/CREDENTIALS.md) for credential discovery — the
   **Users & Passwords** page.
## What these documents are not

* **Not a restatement of the contract.** Interface shapes live in
  [`docs/CONTRACT.md`](../docs/CONTRACT.md); this set explains behaviour and reasoning.
* **Not aspirational.** Every claim here describes the build as it is, including the
  limits. Where a detection or a page cannot see something, the document says so.
* **Not a place for invented numbers.** Figures quoted in these documents were measured
  on the captures in `data/`, and each is attributed to the capture it came from.
