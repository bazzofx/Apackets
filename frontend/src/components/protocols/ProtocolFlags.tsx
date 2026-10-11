import { useState, type ReactNode } from 'react'
import clsx from 'clsx'
import { ChevronDown, Info, Lightbulb, ShieldQuestion } from 'lucide-react'

/**
 * Lead-flag rendering (HTTP / DNS / TLS).
 *
 * A "lead" is something the analyser noticed in the observed fields. It is never
 * a verdict: every catalogue entry below explains why the pattern is worth
 * reviewing *and* what legitimate traffic looks like the same way. Wording must
 * stay investigative ("worth reviewing"), never "malware" / "attack confirmed".
 */

export interface FlagHelp {
  /** Short human label rendered in the badge. */
  label: string
  /** Why it is worth reviewing, and what else produces the same pattern. */
  meaning: string
}

export type FlagCatalog = Record<string, FlagHelp>

/** `"cleartext_credentials:password"` -> `{ key, detail: "password" }`. */
export function splitFlag(raw: string): { key: string; detail: string | null } {
  const index = raw.indexOf(':')
  if (index <= 0) return { key: raw.trim(), detail: null }
  return { key: raw.slice(0, index).trim(), detail: raw.slice(index + 1).trim() || null }
}

/** Fallback label for a key the catalogue does not describe. */
function prettifyKey(key: string): string {
  return key.replace(/_/g, ' ')
}

/** Detail suffixes short enough to show inside the badge itself. */
const INLINE_DETAIL_MAX = 28

export interface LeadFlagBadgeProps {
  raw: string
  catalog: FlagCatalog
  className?: string
}

/** One lead flag as a small badge; the tooltip carries the full explanation. */
export function LeadFlagBadge({ raw, catalog, className }: LeadFlagBadgeProps) {
  const { key, detail } = splitFlag(raw)
  const help = catalog[key]
  const label = help?.label ?? prettifyKey(key)
  const inline = detail !== null && detail.length <= INLINE_DETAIL_MAX ? detail : null
  const title = [
    `${key}${detail !== null ? `: ${detail}` : ''}`,
    help?.meaning ?? 'Recorded by the analyser; no explanation is available for this lead in this build.',
  ].join('\n\n')

  return (
    <span
      className={clsx('chip border-warn/40 bg-warn/10 text-warn', className)}
      title={title}
    >
      <ShieldQuestion size={10} className="shrink-0 opacity-80" aria-hidden />
      <span className="truncate">
        {label}
        {inline !== null ? `: ${inline}` : ''}
      </span>
    </span>
  )
}

export interface LeadFlagListProps {
  /** Raw flag strings as returned by the API (JSON arrays of strings). */
  flags: readonly string[] | null | undefined
  catalog: FlagCatalog
  className?: string
  /** Rendered when the list is empty. */
  emptyText?: string
}

/** Compact flag list for table cells. */
export function LeadFlagList({ flags, catalog, className, emptyText = '—' }: LeadFlagListProps) {
  const list = flags ?? []
  if (list.length === 0) {
    return <span className="text-faint">{emptyText}</span>
  }
  return (
    <span className={clsx('flex flex-wrap items-center gap-1', className)}>
      {list.map((flag, index) => (
        <LeadFlagBadge key={`${flag}-${index}`} raw={flag} catalog={catalog} />
      ))}
    </span>
  )
}

export interface FlagExplanationsProps {
  flags: readonly string[] | null | undefined
  catalog: FlagCatalog
  /** Intro sentence shown above the list. */
  intro?: ReactNode
}

/**
 * Full reasoning for each recorded lead — the inline explanation used by the
 * detail panes, so an analyst can see why a row was flagged.
 */
export function FlagExplanations({ flags, catalog, intro }: FlagExplanationsProps) {
  const list = flags ?? []
  if (list.length === 0) {
    return (
      <p className="text-xs leading-relaxed text-muted">
        No lead flags were recorded for this row. That means the analyser saw nothing worth
        flagging in the fields it reads — not that the traffic is benign.
      </p>
    )
  }
  return (
    <div className="flex flex-col gap-2">
      {intro ? <p className="text-2xs leading-relaxed text-faint">{intro}</p> : null}
      <ul className="flex flex-col gap-2">
        {list.map((flag, index) => {
          const { key, detail } = splitFlag(flag)
          const help = catalog[key]
          return (
            <li
              key={`${flag}-${index}`}
              className="flex flex-col gap-1 rounded border border-border bg-surface2/40 px-2 py-1.5"
            >
              <span className="flex flex-wrap items-center gap-1.5">
                <LeadFlagBadge raw={flag} catalog={catalog} />
                {detail !== null && detail.length > INLINE_DETAIL_MAX ? (
                  <span className="mono text-2xs text-faint">{detail}</span>
                ) : null}
              </span>
              <span className="text-xs leading-relaxed text-muted">
                {help?.meaning ??
                  'This lead was recorded by the analyser. This build has no written explanation for it — treat it as something to look at, not as a finding.'}
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export interface FlagLegendProps {
  catalog: FlagCatalog
  /** Restrict the legend to these keys (defaults to the whole catalogue). */
  keys?: string[]
  /** Heading, e.g. "How to read HTTP lead flags". */
  title?: string
  subtitle?: string
  /** Standing caveat rendered under the legend. */
  note?: ReactNode
  defaultOpen?: boolean
}

/**
 * Short legend listing every lead this page can produce, with the caveat that a
 * lead is not a verdict.
 */
export function FlagLegend({
  catalog,
  keys,
  title = 'How to read these lead flags',
  subtitle = 'every flag this page can show, and what else produces the same pattern',
  note,
  defaultOpen = true,
}: FlagLegendProps) {
  const [open, setOpen] = useState(defaultOpen)
  const entries = (keys ?? Object.keys(catalog))
    .filter((key) => catalog[key] !== undefined)
    .map((key) => ({ key, help: catalog[key] }))

  return (
    <section className="panel help-panel">
      <header className="panel-header p-0">
        <button
          type="button"
          className="panel-disclosure"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          title={open ? 'Collapse this legend' : 'Show every flag this page can produce'}
        >
          <div className="min-w-0 flex-1">
            <div className="panel-title flex items-center gap-1.5">
              <Lightbulb size={13} className="help-mark" aria-hidden />
              <span>{title}</span>
            </div>
            <div className="panel-subtitle">{subtitle}</div>
          </div>
          <ChevronDown
            size={14}
            className={clsx('shrink-0 text-muted transition-transform', !open && '-rotate-90')}
            aria-hidden
          />
        </button>
      </header>
      {open ? (
        <div className="flex flex-col gap-2 p-3">
          <div className="flex items-start gap-2 rounded border border-border bg-surface2/40 px-2 py-1.5">
            <Info size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            <p className="text-xs leading-relaxed text-muted">
              A flag means the analyser matched a pattern in fields it reads. It is a lead to look
              into against the rest of the capture, never a conclusion about a host, a user or a
              domain.
            </p>
          </div>
          {entries.length === 0 ? (
            <p className="text-xs text-faint">No flag explanations are registered in this build.</p>
          ) : (
            <dl className="grid grid-cols-1 gap-x-4 gap-y-2 md:grid-cols-2">
              {entries.map(({ key, help }) => (
                <div key={key} className="flex flex-col gap-0.5">
                  <dt className="mono text-2xs text-warn">{key}</dt>
                  <dd className="text-xs leading-relaxed text-muted">
                    <span className="text-text">{help.label}</span> — {help.meaning}
                  </dd>
                </div>
              ))}
            </dl>
          )}
          {note ? <div className="text-2xs leading-relaxed text-faint">{note}</div> : null}
        </div>
      ) : null}
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Catalogue: HTTP                                                     */
/* ------------------------------------------------------------------ */

export const HTTP_FLAG_CATALOG: FlagCatalog = {
  client_error: {
    label: '4xx response',
    meaning:
      'The server answered with a 4xx status. Worth reviewing when several share one client (enumeration and fuzzing look like this), but single 404s and 403s are ordinary browsing and application errors.',
  },
  server_error: {
    label: '5xx response',
    meaning:
      'The server answered with a 5xx status. It can show a failing or probed endpoint, and is just as often a healthy service returning an error for one bad request.',
  },
  unusual_method: {
    label: 'Unusual method',
    meaning:
      'The request method is outside the common set (GET, POST, HEAD, PUT, DELETE, OPTIONS). WebDAV, REST APIs and troubleshooting tools legitimately use methods such as PROPFIND, PATCH, TRACE and CONNECT.',
  },
  suspicious_path: {
    label: 'Suspicious path',
    meaning:
      'The request line or a request header contains a pattern often used in traversal, file-inclusion or injection attempts (for example "../"). Legitimate URLs contain the same substrings, so read the response status and the rest of the session before drawing conclusions.',
  },
  ip_host: {
    label: 'Host is a literal IP',
    meaning:
      'The Host header is an IP address rather than a hostname. Connections addressed by literal IP are common in scanners and in automated tooling, and equally common in direct-IP testing, internal services and misconfigured clients — read it as a reason to check where the address belongs.',
  },
  cleartext_credentials: {
    label: 'Cleartext credential field',
    meaning:
      'A field name associated with secrets appears in the request URI, headers or body, and this is HTTP — so the value travelled unencrypted and is readable by anyone on the path. Check whether the value is real and whether it is still valid; the field name alone is a lead, not proof that a secret was used.',
  },
  unusual_user_agent: {
    label: 'Unusual User-Agent',
    meaning:
      'The User-Agent is missing, unusually long, or matches a known command-line/automation tool. Administrators and monitoring systems use those tools as well as anyone else, so treat it as context rather than intent.',
  },
}

/* ------------------------------------------------------------------ */
/* Catalogue: DNS                                                      */
/* ------------------------------------------------------------------ */

export const DNS_SHAPE_THRESHOLDS = {
  longLabel: 40,
  longName: 100,
  highEntropy: 3.8,
  manyIps: 4,
} as const

export const DNS_FLAG_CATALOG: FlagCatalog = {
  nxdomain: {
    label: 'NXDOMAIN',
    meaning:
      'The resolver answered NXDOMAIN (rcode 3): the name does not exist. This is one of the most common DNS answers on any network — mistyped hosts, blocked names, expired ad/tracker domains and DGA-style rotation all produce it. Volume and timing matter far more than a single answer.',
  },
  unanswered: {
    label: 'No response seen',
    meaning:
      'No matching response appears in the capture. The resolver may have been unreachable or the query dropped, the response may have been lost, or the capture may simply have ended or missed it. Confirm against the other traffic before treating it as a failure.',
  },
  servfail: {
    label: 'SERVFAIL',
    meaning:
      'The resolver answered SERVFAIL. Usually a resolver or upstream failure and very common during outages; deliberately unresponsive or poisoned zones produce it too.',
  },
  long_label: {
    label: `Label ≥ ${DNS_SHAPE_THRESHOLDS.longLabel} chars`,
    meaning: `A single label is at least ${DNS_SHAPE_THRESHOLDS.longLabel} characters. Long labels can carry data, which is how DNS tunnelling encodes payloads — but DKIM selectors, ACME/DCV certificate-validation names, CDN edge names and telemetry identifiers are routinely this long.`,
  },
  long_name: {
    label: `Name ≥ ${DNS_SHAPE_THRESHOLDS.longName} chars`,
    meaning: `The full query name is at least ${DNS_SHAPE_THRESHOLDS.longName} characters. Same reasoning as long labels: it makes tunnelling easier, and it is also normal for cloud, CDN and anti-abuse names that embed long identifiers.`,
  },
  high_entropy: {
    label: 'High character entropy',
    meaning: `The characters of the name look close to random (default threshold: entropy > ${DNS_SHAPE_THRESHOLDS.highEntropy} with at least 3 labels). DGAs and DNS tunnels produce random-looking names, and so do CDNs, cloud load balancers and telemetry endpoints that embed random or hashed IDs. Useful as a ranking signal, not as a verdict.`,
  },
  many_ips: {
    label: `≥ ${DNS_SHAPE_THRESHOLDS.manyIps} answer IPs`,
    meaning: `The answer set contains at least ${DNS_SHAPE_THRESHOLDS.manyIps} distinct addresses. Large answer sets are the normal shape of CDNs, load balancers and round-robin pools; fast-flux abuse looks identical inside a single capture.`,
  },
  txt_record: {
    label: 'TXT query',
    meaning:
      'The query type is TXT. TXT records carry arbitrary text, which makes them a common DNS tunnelling channel — and the standard carrier for SPF, DKIM and DMARC policy, so most TXT traffic on a real network is routine mail authentication.',
  },
}

/* ------------------------------------------------------------------ */
/* Catalogue: TLS                                                      */
/* ------------------------------------------------------------------ */

export const TLS_FLAG_CATALOG: FlagCatalog = {
  sni_absent: {
    label: 'No SNI in ClientHello',
    meaning:
      'The ClientHello carried no server name. Common and benign causes: the client was given an IP address, the client is old or minimal, or the name was concealed with Encrypted ClientHello (ECH) or a similar mechanism. It says nothing on its own about who the peer is.',
  },
  no_certificate: {
    label: 'No certificate seen',
    meaning:
      'No certificate was decoded for this session. TLS 1.3 encrypts the certificate, a capture may be incomplete, or the handshake may have stopped before the certificate flight. Absence of a certificate here is a capture limitation, not a client that rejected one.',
  },
  tls10_or_older: {
    label: 'TLS 1.0 or older',
    meaning:
      'The negotiated version is TLS 1.0 or older, which is deprecated and no longer considered secure. Legacy appliances, embedded devices, mainframes and old libraries still negotiate it in otherwise normal networks.',
  },
  self_signed_suspected: {
    label: 'Self-signed (heuristic)',
    meaning:
      'The certificate subject and issuer are identical, which is what a self-signed certificate looks like. This is a name comparison only: internal test CAs, lab equipment and interception proxies produce it, and the opposite conclusion (a valid public certificate) proves nothing either.',
  },
  alert: {
    label: 'TLS alert',
    meaning:
      'A TLS alert record was seen. Fatal alerts are normal when a client rejects an expired or mismatched certificate, and when a proxy or middlebox actively refuses a connection. The alert code in this session tells you which.',
  },
  incomplete_handshake: {
    label: 'Incomplete handshake',
    meaning:
      'The session has no complete ClientHello/ServerHello pair in this capture. The capture likely ended early, dropped packets, or the connection was cut short — this is a statement about the capture, not about the peers.',
  },
}

/** Keys rendered by the legend on each page, in reading order. */
export const HTTP_FLAG_KEYS = [
  'client_error',
  'server_error',
  'unusual_method',
  'suspicious_path',
  'ip_host',
  'cleartext_credentials',
  'unusual_user_agent',
]

export const DNS_FLAG_KEYS = [
  'nxdomain',
  'unanswered',
  'servfail',
  'long_label',
  'long_name',
  'high_entropy',
  'many_ips',
  'txt_record',
]

export const TLS_FLAG_KEYS = [
  'sni_absent',
  'no_certificate',
  'tls10_or_older',
  'self_signed_suspected',
  'alert',
  'incomplete_handshake',
]
