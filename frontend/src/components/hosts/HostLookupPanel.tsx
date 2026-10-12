/**
 * Registration data for the selected host — the right half of the host detail
 * (docs/IP_LOOKUP.md).
 *
 * The panel keeps two kinds of statement visibly apart, because they answer
 * different questions and come from different places:
 *
 *  * **From this capture** — the country the local DB-IP copy gives this
 *    address and the domain names the capture itself observed in DNS answers
 *    and TLS SNI. All of it is already on disk, so it is shown on first paint
 *    with no network call at all.
 *  * **From the registry** — network, ASN, status and contacts, which no
 *    capture can know. This needs an explicit button: pressing it sends *this
 *    one address*, and nothing else from the capture, to the RIR's RDAP service
 *    and to Team Cymru's DNS service. The result is cached server-side, so the
 *    same address is never asked for twice within the cache lifetime.
 *
 * An address with no registry (private, loopback, multicast, link-local,
 * reserved) is not an error and gets no button: there is simply nobody to ask,
 * and `reason` says so.
 */

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  Building2,
  ChevronDown,
  Globe2,
  Info,
  Lightbulb,
  RefreshCw,
  Search,
  ShieldAlert,
} from 'lucide-react'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import { hostsApi } from '@/services/api'
import { countryName } from '@/theme/worldMap'
import type { IpLookupContact, IpLookupRecord, IpLookupResponse } from '@/types'
import { EMPTY, formatNumber, formatTimestamp } from '@/utils/format'

/* ------------------------------------------------------------------ */
/* labels                                                              */
/* ------------------------------------------------------------------ */

/** Plain-english reading of the address class the API reported. */
const KIND_LABEL: Record<string, string> = {
  public: 'Public address',
  private: 'Private address',
  reserved: 'Reserved address',
  loopback: 'Loopback address',
  multicast: 'Multicast address',
  link_local: 'Link-local address',
  unknown: 'Address class unknown',
}

/**
 * Where a capture-observed name came from. The API emits exactly these two
 * (docs/IP_LOOKUP.md §5.1); anything else is shown as the API sent it rather
 * than guessed at.
 */
const NAME_SOURCE: Record<string, string> = {
  dns_answer: 'DNS answer',
  tls_sni: 'TLS SNI',
}

const ROLE_LABEL: Record<string, string> = {
  registrant: 'Registrant',
  administrative: 'Administrative',
  technical: 'Technical',
  abuse: 'Abuse contact',
  routing: 'Routing',
  'zone-contact': 'Zone contact',
  noc: 'NOC',
}

function nameSource(from: string): string {
  return NAME_SOURCE[from] ?? from
}

function roleLabel(role: string | null): string {
  if (!role) return 'Contact'
  return ROLE_LABEL[role] ?? role.replace(/[_-]/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
}

/* ------------------------------------------------------------------ */
/* small pieces                                                        */
/* ------------------------------------------------------------------ */

/** One labelled fact. `hint` carries the provenance of the value. */
function Fact({
  label,
  value,
  hint,
  mono = false,
  tone,
}: {
  label: string
  value: React.ReactNode
  hint?: React.ReactNode
  mono?: boolean
  tone?: 'warn' | 'ok'
}) {
  const empty = value === null || value === undefined || value === ''
  return (
    <div className="lookup-fact">
      <div className="lookup-fact-label">{label}</div>
      <div
        className={[
          'lookup-fact-value',
          mono && !empty ? 'mono' : '',
          empty ? 'text-faint' : tone === 'warn' ? 'text-warn' : '',
        ]
          .filter(Boolean)
          .join(' ')}
      >
        {empty ? EMPTY : value}
      </div>
      {hint && !empty ? <div className="lookup-fact-hint">{hint}</div> : null}
    </div>
  )
}

function countryLabel(code: string | null): React.ReactNode {
  if (!code) return null
  return (
    <>
      {countryName(code)} <span className="text-faint">({code})</span>
    </>
  )
}

function ContactLine({ contact }: { contact: IpLookupContact }) {
  const isAbuse = contact.role === 'abuse'
  /* Registries frequently publish the same string as the handle and the name
     (RIPE's `servers-tech-mnt`, ARIN's `GOGL`), so the name is only printed when
     it adds something the handle did not already say. */
  const name =
    contact.name && contact.name.toLowerCase() !== (contact.handle ?? '').toLowerCase()
      ? contact.name
      : null
  return (
    <li className="lookup-contact" data-role={contact.role ?? 'contact'}>
      <div className="flex items-start gap-1.5">
        {isAbuse ? (
          <ShieldAlert size={12} className="mt-0.5 shrink-0 text-warn" aria-hidden />
        ) : (
          <Building2 size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
        )}
        <div className="min-w-0">
          <div className="text-2xs uppercase tracking-wider text-faint">
            {roleLabel(contact.role)}
            {contact.handle ? <span className="ml-1 text-muted">· {contact.handle}</span> : null}
          </div>
          {name ? <div className="break-words text-xs text-text">{name}</div> : null}
          {!name && !contact.handle ? (
            <div className="text-2xs text-faint">The registry published no name for this role.</div>
          ) : null}
          {contact.emails.length > 0 ? (
            <div className="mt-0.5 flex flex-col">
              {contact.emails.map((email) => (
                <a key={email} className="lookup-mail" href={`mailto:${email}`}>
                  {email}
                </a>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </li>
  )
}

/** Everything the registry returned, once there is something to show. */
function RecordBlock({ record, local }: { record: IpLookupRecord; local: IpLookupResponse['local'] }) {
  const asn = record.asn
  const range = record.range ? `${record.range.start} – ${record.range.end}` : null
  const disagrees = Boolean(record.country && local.country && record.country !== local.country)

  return (
    <>
      <Fact label="Registrar / registry" value={record.registry ?? null} hint={record.port43 ? `legacy whois ${record.port43}` : undefined} />
      <Fact label="Network name" value={record.network_name ?? null} />
      <Fact label="Handle" value={record.handle ?? null} mono />
      <Fact label="Address range" value={range} mono />
      <Fact label="Allocation" value={record.allocation_type ?? null} />
      <Fact label="Status" value={record.status.length > 0 ? record.status.join(', ') : null} />
      <Fact
        label="Registered country"
        value={countryLabel(record.country)}
        tone={disagrees ? 'warn' : undefined}
        hint={
          disagrees ? (
            <span className="text-warn">
              Disagrees with this capture&rsquo;s geolocation ({local.country}). Registration says who
              holds the block, not where a packet went; both are shown as reported.
            </span>
          ) : (
            'As registered by the RIR'
          )
        }
      />
      <Fact
        label="ASN"
        value={asn && asn.number ? `AS${asn.number}` : null}
        hint={
          asn
            ? [
                asn.prefix ? `prefix ${asn.prefix}` : null,
                asn.registry ? `registry ${asn.registry}` : null,
                asn.country ? `country ${asn.country}` : null,
                asn.allocated ? `allocated ${asn.allocated}` : null,
              ]
                .filter(Boolean)
                .join(' · ')
            : undefined
        }
      />

      {record.contacts.length > 0 ? (
        <div className="lookup-block">
          <div className="lookup-section">Contacts</div>
          <ul className="flex flex-col gap-2">
            {record.contacts.map((contact, index) => (
              <ContactLine key={`${contact.role ?? 'c'}:${contact.handle ?? index}`} contact={contact} />
            ))}
          </ul>
        </div>
      ) : null}

      {record.remarks.length > 0 ? (
        <div className="lookup-block">
          <div className="lookup-section">Registry remarks</div>
          <ul className="flex flex-col gap-1">
            {record.remarks.map((remark, index) => (
              <li key={index} className="lookup-remark">
                {remark}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {record.failures && record.failures.length > 0 ? (
        <div className="lookup-warn">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>
            Part of this lookup did not answer: {record.failures.join(', ')}. What is shown above is
            what did come back.
          </span>
        </div>
      ) : null}

      {record.rdap_url ? (
        <a className="lookup-link" href={record.rdap_url} target="_blank" rel="noreferrer noopener">
          <Globe2 size={12} aria-hidden />
          Open the registry&rsquo;s own RDAP record
        </a>
      ) : null}
    </>
  )
}

/* ------------------------------------------------------------------ */
/* panel                                                               */
/* ------------------------------------------------------------------ */

/**
 * The API's own statement of what a lookup is and is not.
 *
 * It is a paragraph of provenance, not a fact about the address, so it starts
 * collapsed: the rail stays a column of facts, and the whole header is the
 * control, as everywhere else in the app.
 */
function NoteDisclosure({ note }: { note: string }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="lookup-disclosure">
      <button
        type="button"
        className="lookup-disclosure-head"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        title={open ? 'Hide what this lookup covers' : 'Show what this lookup covers'}
      >
        <Lightbulb size={12} className="help-mark" aria-hidden />
        <span className="lookup-disclosure-title">What this lookup is, and is not</span>
        <ChevronDown
          size={13}
          className={open ? 'shrink-0 text-muted' : 'shrink-0 -rotate-90 text-muted'}
          aria-hidden
        />
      </button>
      {open ? <p className="lookup-disclosure-body">{note}</p> : null}
    </section>
  )
}

export interface HostLookupPanelProps {
  analysisId: string
  ip: string
}

/**
 * Right-hand column of the host detail: whois/RDAP registration data for the
 * selected address, next to what the capture already knows about it.
 */
export function HostLookupPanel({ analysisId, ip }: HostLookupPanelProps) {
  const queryClient = useQueryClient()
  const key = ['ip-lookup', analysisId, ip] as const

  const lookup = useQuery({
    queryKey: key,
    queryFn: () => hostsApi.lookup(analysisId, ip),
    enabled: Boolean(analysisId && ip),
    retry: false,
    // Registration data does not change while an operator watches it; it is
    // refreshed only when the button is pressed.
    staleTime: Infinity,
  })

  const run = useMutation({
    mutationFn: () => hostsApi.fetchLookup(analysisId, ip),
    onSuccess: (data) => {
      queryClient.setQueryData(key, data)
    },
  })

  if (lookup.isLoading) {
    return (
      <aside className="lookup-panel">
        <LoadingState label="Reading the local lookup cache…" rows={4} />
      </aside>
    )
  }

  if (lookup.error) {
    return (
      <aside className="lookup-panel">
        <header className="lookup-head">
          <div className="lookup-title">
            <Globe2 size={13} aria-hidden />
            Registration lookup
          </div>
          <div className="lookup-sub">{ip}</div>
        </header>
        <div className="lookup-body">
          <ErrorState
            error={lookup.error}
            title="Could not read the lookup cache"
            onRetry={() => void lookup.refetch()}
          />
        </div>
      </aside>
    )
  }

  const data = lookup.data
  if (!data) {
    return (
      <aside className="lookup-panel">
        <div className="lookup-body text-xs text-muted">
          The backend returned no lookup state for {ip}.
        </div>
      </aside>
    )
  }

  const { local, record, cache } = data
  const pending = run.isPending
  const names = local.names ?? []

  return (
    <aside className="lookup-panel" data-lookup-panel data-lookup-kind={data.kind}>
      <header className="lookup-head">
        <div className="lookup-title">
          <Globe2 size={13} aria-hidden />
          Registration lookup
        </div>
        <div className="lookup-sub">
          <span className="mono">{data.ip}</span> — whois / RDAP
        </div>
      </header>

      <div className="lookup-body">
        <div className="lookup-class">
          <span className="lookup-chip">{KIND_LABEL[data.kind] ?? data.kind}</span>
          {data.reason ? <span className="lookup-class-reason">{data.reason}</span> : null}
        </div>

        {/* Local first: it needs no egress, so it is always available. */}
        <section className="lookup-block">
          <div className="lookup-section">
            From this capture
            <span className="lookup-section-note">no request made</span>
          </div>
          <Fact
            label="Country (geolocation)"
            value={countryLabel(local.country)}
            hint={local.country_source ? `source: ${local.country_source}` : 'no geolocation data installed'}
          />
          {names.length > 0 ? (
            <>
              <Fact
                label="Domains seen"
                value={formatNumber(names.length)}
                hint="names the capture itself observed for this address"
              />
              <ul className="lookup-names">
                {names.map((entry) => (
                  <li key={`${entry.from}:${entry.name}`} className="lookup-name">
                    <span className="lookup-name-value">{entry.name}</span>
                    <span className="lookup-name-from">
                      {nameSource(entry.from)} · {formatNumber(entry.rows)}{' '}
                      {entry.rows === 1 ? 'row' : 'rows'}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <div className="text-2xs leading-relaxed text-faint">
              No DNS answer or TLS SNI in this capture names this address. A name only appears here
              if the capture itself carried it — nothing is resolved on demand.
            </div>
          )}
          {local.names_truncated ? (
            <div className="text-2xs text-faint">
              The list is capped; the busiest names are shown.
            </div>
          ) : null}
        </section>

        {/* Registry half. */}
        <section className="lookup-block">
          <div className="lookup-section">
            From the registry
            {record ? (
              <span className="lookup-section-note">
                {cache?.age_days !== null && cache?.age_days !== undefined
                  ? `cached ${cache.age_days < 1 ? 'today' : `${cache.age_days.toFixed(1)} days ago`}`
                  : 'cached'}
                {cache?.stale ? ' · stale' : ''}
              </span>
            ) : null}
          </div>

          {record ? (
            <>
              <RecordBlock record={record} local={local} />
              <div className="lookup-provenance">
                <div>
                  Fetched {cache?.fetched_at ? formatTimestamp(cache.fetched_at) : EMPTY}
                  {cache?.source ? (
                    <>
                      {' '}
                      from <span className="mono">{cache.source}</span>
                    </>
                  ) : null}
                </div>
                <button
                  type="button"
                  className="btn"
                  onClick={() => run.mutate()}
                  disabled={pending}
                  title="Ask the registry again and replace the cached record"
                >
                  <RefreshCw size={12} aria-hidden className={pending ? 'animate-spin' : undefined} />
                  {pending ? 'Looking up…' : 'Look up again'}
                </button>
              </div>
            </>
          ) : data.lookup_possible ? (
            <>
              <div className="text-2xs leading-relaxed text-muted">
                Nothing has been looked up for this address yet.
              </div>
              <button
                type="button"
                className="btn btn-primary lookup-action"
                onClick={() => run.mutate()}
                disabled={pending}
              >
                <Search size={13} aria-hidden className={pending ? 'animate-pulse' : undefined} />
                {pending ? 'Looking up…' : 'Look up registration data'}
              </button>
            </>
          ) : (
            <div className="lookup-note">
              <Info size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
              <span>
                No registry holds this address, so there is nothing to look up. Addresses like this
                belong to the local network or a reserved range, and their meaning comes from the
                capture itself.
              </span>
            </div>
          )}

          {run.error ? (
            <div className="lookup-warn">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden />
              <span>
                The lookup did not complete and nothing was cached. The registry or the DNS service
                may be unreachable from this host.
              </span>
            </div>
          ) : null}
        </section>

        <div className="lookup-egress">
          <Info size={11} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <span>
            Only the button sends anything off this machine, and it sends this address alone to the
            responsible RIR&rsquo;s RDAP service and to Team Cymru&rsquo;s DNS service. No capture
            data, payload or name leaves the host, and the answer is stored in the local database so
            the same address is not asked for twice.
          </span>
        </div>

        {data.note ? <NoteDisclosure note={data.note} /> : null}
      </div>
    </aside>
  )
}

export default HostLookupPanel
