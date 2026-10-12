# IP lookup contract

**Status:** normative for the registration panel on the Hosts page — the right-hand side of a
host's detail view. `docs/CONTRACT.md` governs everything older; where the two touch, that
document wins.

---

## 1. What it is for

The host detail already answers *what this address did in this capture*. It cannot answer *whose
address is this* — and that is the first question an analyst asks about an unfamiliar peer.

This feature adds a second column to that panel:

| Left | Right |
|---|---|
| Everything the capture recorded: packets and bytes in each direction, ports, protocols, peers, names, conversations, DNS, HTTP, TLS. | **Registration data** for the address: the network it belongs to, the registry that holds it, its country, its origin AS, the contacts the registry publishes, and the names *this capture* saw pointing at it. |

"Whois" is used loosely in the request and precisely here: the lookup is **RDAP** — the
Registration Data Access Protocol, the JSON successor to port-43 whois, run by the same five
regional internet registries — plus **Team Cymru's** AS data over DNS, which is what
`whois -h whois.cymru.com` reads. Both are public, unauthenticated and key-free. The legacy
whois server each registry still runs is reported from RDAP's own `port43` field, so a reader
who prefers the old tool has the hostname.

## 2. What it looks up, and what it deliberately does not

| Source | Gives | Notes |
|---|---|---|
| IANA RDAP bootstrap (`data.iana.org/rdap/ipv4.json`, `ipv6.json`) | the RDAP base URL for the address's registry | Cached in memory for the process; the longest matching prefix wins (measured: `150.171.109.217` matches a `/8` entry and is served by APNIC's RDAP, `51.132.193.108` by RIPE's) |
| The registry's RDAP record | `name`, `handle`, start/end address, allocation `type`, `status`, `country` where the registry publishes one, `port43`, `remarks`, and the `entities` with their roles | ARIN does not publish a country on network objects; RIPE does. A field a registry does not publish is **null**, never guessed |
| Team Cymru over DNS (`origin.asn.cymru.com` TXT, via DNS-over-HTTPS) | origin **AS**, prefix, country, registry, allocation date | Measured: `8.8.8.8` → `15169 \| 8.8.8.0/24 \| US \| arin \| 2023-12-28` |

**Domains are not looked up.** The names shown are the ones **this capture** observed pointing at
the address — `dns_queries.answer_ips` containing it, and its TLS SNI values — because those are
evidence, while a reverse-DNS name is a claim by whoever controls the PTR record. A name that no
capture row supports is not shown, and the panel says which table each name came from.

**Nothing is inferred.** No hosting provider, no cloud region, no "organisation" reconstructed
from a network name, no city, no coordinates, and no reputation. If a registry publishes
`MSFT` and Cymru says AS8075, that is what the panel says.

## 3. The egress policy: explicit, per address, cached

The application promises that no capture data leaves the host. **An IP address taken from a
capture is capture data**, so a lookup is a deliberate act and never automatic:

1. **Opening a host panel performs no network request.** The right-hand column shows what is
   local — the country from the installed DB-IP dataset (§`docs/GEOGRAPHY.md`), the capture's
   names, the address's own class — and a **Look up registration data** button.
2. **The lookup runs only when that button is pressed**, for that one address, and sends the
   address to at most two public services: the registry's RDAP endpoint and a DNS-over-HTTPS
   resolver for the AS query. Nothing else — no capture, no filename, no analysis id, no
   timestamp of the capture.
3. **The answer is cached** in `ip_lookups` (§4), keyed by address alone, so a second reader and
   a second capture cost nothing. The panel shows when the record was fetched and offers a
   refresh when it is older than `LOOKUP_MAX_AGE_DAYS`.
4. **Private and reserved addresses are never sent anywhere.** They are answered from the address
   itself (`ipaddress`), with the reason: no registry holds them. `192.168.0.0/16` does appear in
   ARIN's registry as an IANA reservation whose own remark says the space is used by millions of
   independent networks — the panel states that rather than pretending the lookup failed.
5. The panel names the two services and links the RDAP record, so the reader can see exactly
   where the answer came from.

## 4. Storage

```sql
CREATE TABLE IF NOT EXISTS ip_lookups (
  ip         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,   -- 'public' | 'private' | 'reserved' | 'loopback' | 'multicast' | 'unknown'
  source     TEXT,            -- the registry's RDAP base URL, or NULL when nothing was queried
  asn        TEXT,            -- the origin AS number as a string, or NULL
  country    TEXT,            -- ISO 3166-1 alpha-2 from RDAP or Cymru, or NULL
  fetched_at REAL NOT NULL,
  payload    TEXT NOT NULL DEFAULT '{}'   -- the normalised record, §5.3
);
```

Keyed by address and not by analysis: registration data belongs to the address, so two captures
that contain the same peer share one record. A failed lookup writes nothing.

## 5. Endpoints

### 5.1 `GET /api/analyses/{analysis_id}/hosts/{ip}/lookup`

The panel's first paint: **never fetches anything**. Returns the cached record if there is one,
the capture-local block, and the address's own class.

```json
{
  "ip": "150.171.109.217",
  "kind": "public",
  "lookup_possible": true,
  "reason": null,
  "cache": {
    "fetched_at": 1791832173.1,
    "age_days": 2.4,
    "stale": false,
    "source": "https://rdap.apnic.net/"
  },
  "record": {
    "registry": "APNIC",
    "network_name": "MSFT",
    "handle": "NET-150-171-0-0-1",
    "range": { "start": "150.171.0.0", "end": "150.171.255.255" },
    "allocation_type": "DIRECT ALLOCATION",
    "status": ["active"],
    "country": "US",
    "port43": "whois.apnic.net",
    "rdap_url": "https://rdap.apnic.net/ip/150.171.109.217",
    "asn": { "number": "8075", "prefix": "150.171.0.0/16", "country": "US", "registry": "arin", "allocated": "2015-11-24" },
    "contacts": [
      { "role": "registrant", "handle": "MSFT", "name": "Microsoft Corporation", "emails": [] },
      { "role": "abuse", "handle": "MAC274-RIPE", "name": "Microsoft Abuse Contact", "emails": ["abuse@microsoft.com"] }
    ],
    "remarks": ["…"]
  },
  "local": {
    "country": "ZA",
    "country_source": "DB-IP Lite 2026-10",
    "names": [
      { "name": "download.sysinternals.com", "from": "dns_answer", "rows": 3 },
      { "name": "ctldl.windowsupdate.com", "from": "tls_sni", "rows": 1 }
    ],
    "names_truncated": false
  },
  "note": "…"
}
```

* `record` is `null` when nothing has been looked up yet, or when `kind` is not public.
* `lookup_possible` is `false` for `private`, `loopback`, `multicast`, `link_local` and
  `reserved`, with `reason` naming why — the panel shows that instead of a button that would
  fail.
* `local.names` comes only from the capture (§2) and is capped by `LOCAL_NAME_CAP` (25), with
  `names_truncated`.

### 5.2 `POST /api/analyses/{analysis_id}/hosts/{ip}/lookup`

Performs the lookup now and caches it. Returns the same envelope as §5.1 with `cache` populated.

* The whole lookup is bounded by `LOOKUP_TIMEOUT_S` (20 s) shared across its steps.
* A step that fails does not discard the others: RDAP may fail while Cymru answers, and the
  record then carries what came back plus a `failures[]` list naming what did not, so a partial
  answer is never presented as a whole one.
* Nothing at all came back → `502 lookup_failed` with the reasons; **nothing is cached**.
* A non-public address → `200` with `lookup_possible: false` and no request made. This is not an
  error: there is simply no registry to ask.
* Malformed address → `422 validation_error`. Unknown analysis → `404`, unfinished `409`, exactly
  as every other analysis-scoped route.

## 6. Caps

| Constant | Value | What it limits |
|---|---|---|
| `LOOKUP_TIMEOUT_S` | `20` | The whole lookup, all steps together |
| `LOCAL_NAME_CAP` | `25` | Names taken from the capture, by rows seen |
| `CONTACT_CAP` | `10` | Contacts kept, registrant and abuse roles first |
| `REMARK_CAP` | `5` | Registry remarks kept, each truncated to 400 characters |
| `LOOKUP_MAX_AGE_DAYS` | `30` | When a cached record is reported `stale` (still shown, never hidden) |

## 7. Honest limits, stated on the panel

* **Registration is not location.** A country here is where the block or the AS is registered;
  this is a different claim from `docs/GEOGRAPHY.md`'s, made from different data, and the two can
  disagree. When they do, both are shown with their sources rather than reconciled.
* **Contacts are the registry's published ones**, often an abuse desk rather than an operator,
  and frequently redacted — RIPE publishes an abuse mailbox, ARIN often publishes a name and no
  address at all. An empty list means the registry published nothing, not that nobody owns it.
* **A name is what the capture saw**, not a reverse lookup and not a claim by the holder.
* **The lookup is a snapshot.** Allocations change; the panel shows the fetch time and says when
  the record is stale rather than silently serving an old answer as current.
* **Nothing is scored.** A network name is a registry label, not a reputation, and this panel
  raises no finding from it.
* **The address goes to a third party when you press the button** — that is the whole reason the
  button exists, and the panel says so next to it.

## 8. Where the code lives

| Part | File |
|---|---|
| Lookup service (RDAP + Cymru, normalisation, cache) | `backend/app/services/ip_lookup.py` |
| Endpoints | `backend/app/api/routes_hosts.py` (`/hosts/{ip}/lookup`) |
| Cache table | `backend/app/db/schema.sql` (`ip_lookups`) |
| Panel | `frontend/src/components/hosts/HostLookupPanel.tsx` |
| Panel layout | `frontend/src/components/hosts/HostDetailPanel.tsx` |
