import { useMemo, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Fingerprint,
  Globe,
  Server,
  ShieldAlert,
  Waypoints,
  Workflow,
} from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import KpiTile from '@/components/dashboard/KpiTile'
import { ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import { useAnalysis } from '@/hooks/useAnalysis'
import { baselineApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatNumber } from '@/utils/format'
import type { BaselineSummary } from '@/types'

/**
 * Baseline Check — what this capture holds that the reference capture never did.
 *
 * One query (`GET /api/analyses/{id}/baseline`) answers the whole page: the same
 * comparison the seven `baseline_*` rules run, returned as counts and capped samples
 * instead of findings. Nothing is re-dissected and nothing is stored, so the page is
 * the report behind the findings rather than a second detector.
 *
 * The page is deliberately *quiet* about things it cannot claim: with no baseline, with
 * the mode off, or with a capture that shares no local address with the reference, it
 * says so and draws no novelty list at all. Reporting a foreign network as "new" is the
 * failure mode this section exists to avoid, not a longer list it could provide.
 */

/** The six novelty kinds the endpoint can return, in report order. */
const NOVELTY_KINDS = ['hosts', 'peers', 'services', 'dns_names', 'sni', 'ja3'] as const
type NoveltyKind = (typeof NOVELTY_KINDS)[number]

/** The label each kind carries on a tile and a panel header. */
const KIND_LABEL: Record<NoveltyKind, string> = {
  hosts: 'New addresses',
  peers: 'New pairs',
  services: 'New services',
  dns_names: 'New DNS names',
  sni: 'New TLS server names',
  ja3: 'New TLS client fingerprints',
}

const KIND_HINT: Record<NoveltyKind, string> = {
  hosts: 'Addresses this capture holds that the reference never did, as a source or a destination',
  peers: 'Ordered source → destination pairs the reference never recorded',
  services: 'Address and port pairs the reference never answered on, read from SYN and low-port traffic',
  dns_names: 'Names this capture resolved that the reference never queried',
  sni: 'Server names offered in a TLS handshake that the reference never saw',
  ja3: 'TLS client fingerprints absent from the reference',
}

interface PairGroup {
  source: string
  targets: string[]
}

interface ServiceGroup {
  host: string
  services: Array<{ port: string; transport: string }>
}

/** Split `a|b` rows into one group per source, biggest group first. */
function groupPairs(values: readonly string[]): PairGroup[] {
  const groups = new Map<string, string[]>()
  for (const value of values) {
    const split = value.indexOf('|')
    if (split <= 0) continue
    const source = value.slice(0, split)
    const target = value.slice(split + 1)
    if (source === '' || target === '') continue
    const existing = groups.get(source)
    if (existing === undefined) groups.set(source, [target])
    else if (!existing.includes(target)) existing.push(target)
  }
  return [...groups.entries()]
    .map(([source, targets]) => ({ source, targets: [...targets].sort() }))
    .sort((left, right) => right.targets.length - left.targets.length || left.source.localeCompare(right.source))
}

/** Split `ip|port|transport` rows into one group per host. */
function groupServices(values: readonly string[]): ServiceGroup[] {
  const groups = new Map<string, Array<{ port: string; transport: string }>>()
  for (const value of values) {
    const parts = value.split('|')
    if (parts.length !== 3) continue
    const [host, port, transport] = parts
    if (host === '' || port === '') continue
    const entry = { port, transport: transport === '' ? 'ip' : transport }
    const existing = groups.get(host)
    if (existing === undefined) groups.set(host, [entry])
    else if (!existing.some((each) => each.port === entry.port && each.transport === entry.transport))
      existing.push(entry)
  }
  return [...groups.entries()]
    .map(([host, services]) => ({
      host,
      services: [...services].sort((left, right) => Number(left.port) - Number(right.port)),
    }))
    .sort((left, right) => right.services.length - left.services.length || left.host.localeCompare(right.host))
}

/** A monospaced address, linked into the page that holds every row about it. */
function EntityLink({ value, to, className }: { value: string; to: string; className?: string }) {
  return (
    <Link
      to={to}
      className={clsx('mono text-accent2 underline-offset-2 hover:underline', className)}
      title={'Open everything this capture recorded about ' + value}
      data-ip={/^[0-9.]+$/.test(value) ? value : undefined}
    >
      {value}
    </Link>
  )
}

/** Up to `limit` chips, with the remainder counted rather than hidden. */
function ChipList({
  values,
  linkFor,
  label,
  limit = 8,
}: {
  values: readonly string[]
  linkFor?: (value: string) => string
  label: (value: string) => string
  limit?: number
}) {
  const shown = values.slice(0, limit)
  const hidden = values.length - shown.length
  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map((value) => {
        const text = label(value)
        return linkFor === undefined ? (
          <span key={value} className="chip">
            {text}
          </span>
        ) : (
          <Link key={value} to={linkFor(value)} className="chip hover:border-accent/60" title={value}>
            {text}
          </Link>
        )
      })}
      {hidden > 0 ? (
        <span className="text-2xs text-faint" title={values.slice(limit).join(', ')}>
          {'+' + formatNumber(hidden) + ' more'}
        </span>
      ) : null}
    </div>
  )
}

function openEntity(kind: 'ip' | 'domain', value: string): string {
  return '/investigate?kind=' + kind + '&entity=' + encodeURIComponent(value)
}

/**
 * How a novel address took part, as far as the sampled pairs show.
 *
 * The pairs list is capped by the endpoint, so this is stated as what the sample shows
 * rather than as a property of the capture.
 */
function roleOf(address: string, sources: Set<string>, destinations: Set<string>): string {
  const asSource = sources.has(address)
  const asDestination = destinations.has(address)
  if (asSource && asDestination) return 'source and destination'
  if (asSource) return 'source'
  if (asDestination) return 'destination'
  return 'in the sampled pairs: neither'
}

/** One novelty section: header with the kind's count, then the rows. */
function NoveltyPanel({
  kind,
  count,
  shown,
  children,
}: {
  kind: NoveltyKind
  count: number
  /** How many rows the payload actually carried; the endpoint caps each list. */
  shown: number
  children: ReactNode
}) {
  const truncated = count > shown
  return (
    <Panel
      title={KIND_LABEL[kind]}
      subtitle={KIND_HINT[kind]}
      actions={<span className="chip border-accent/40 bg-accent/10 text-accent2">{formatNumber(count)}</span>}
      flush
    >
      {truncated ? (
        <div className="border-b border-border px-3 py-1 text-2xs text-faint">
          {'Showing the first ' +
            formatNumber(shown) +
            ' of ' +
            formatNumber(count) +
            ': the comparison returns a capped sample per list, and the counts above are the full totals.'}
        </div>
      ) : null}
      {children}
    </Panel>
  )
}

/** The comparison itself, as the seven rules see it. */
function BaselineReport({ summary }: { summary: BaselineSummary }) {
  const baseline = summary.baseline
  const capture = summary.capture
  const overlap = summary.overlap
  const novel = summary.novel ?? {}
  const counts = summary.novel_counts ?? {}

  const pairGroups = useMemo(() => groupPairs(novel.peers ?? []), [novel.peers])
  const serviceGroups = useMemo(() => groupServices(novel.services ?? []), [novel.services])
  const sources = useMemo(() => new Set(pairGroups.map((group) => group.source)), [pairGroups])
  const destinations = useMemo(
    () => new Set(pairGroups.flatMap((group) => group.targets)),
    [pairGroups],
  )
  const totals = NOVELTY_KINDS.reduce(
    (sum, kind) => sum + (counts[kind] ?? 0),
    0,
  )
  const emptyKinds = NOVELTY_KINDS.filter((kind) => (counts[kind] ?? 0) === 0)

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Measured against the baseline network"
        subtitle={
          baseline === undefined
            ? undefined
            : (baseline.label ?? baseline.filename ?? baseline.analysis_id) +
              ' · ' +
              formatNumber(baseline.packets) +
              ' frames · ' +
              formatNumber(baseline.counts.hosts ?? 0) +
              ' addresses'
        }
      >
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          <KpiTile
            label="New addresses"
            value={counts.hosts ?? 0}
            icon={Server}
            detail="the new_host rule's input"
          />
          <KpiTile
            label="New pairs"
            value={counts.peers ?? 0}
            icon={Workflow}
            detail="source → destination"
          />
          <KpiTile
            label="New services"
            value={counts.services ?? 0}
            icon={Waypoints}
            detail="address + port"
          />
          <KpiTile
            label="New names"
            value={(counts.dns_names ?? 0) + (counts.sni ?? 0)}
            icon={Globe}
            detail={formatNumber(counts.dns_names ?? 0) + ' DNS · ' + formatNumber(counts.sni ?? 0) + ' TLS'}
          />
        </div>

        <dl className="mt-3 grid grid-cols-1 gap-x-5 gap-y-1 text-2xs md:grid-cols-2">
          <div className="flex items-baseline justify-between gap-2 border-b border-border/40 py-0.5">
            <dt className="text-faint uppercase tracking-wide">This capture</dt>
            <dd className="mono truncate text-text" title={capture?.filename ?? undefined}>
              {capture?.filename ?? '—'}
            </dd>
          </div>
          <div className="flex items-baseline justify-between gap-2 border-b border-border/40 py-0.5">
            <dt className="text-faint uppercase tracking-wide">Frames compared</dt>
            <dd className="mono text-text">
              {formatNumber(capture?.packets ?? 0)} + {formatNumber(baseline?.packets ?? 0)}
            </dd>
          </div>
          <div className="flex items-baseline justify-between gap-2 border-b border-border/40 py-0.5">
            <dt className="text-faint uppercase tracking-wide">Shared addresses</dt>
            <dd className="mono text-text">
              {formatNumber(overlap?.shared_hosts ?? 0)} of {formatNumber(overlap?.capture_hosts ?? 0)}
              {' · '}
              {formatNumber(overlap?.shared_private_hosts ?? 0)} local
            </dd>
          </div>
          <div className="flex items-baseline justify-between gap-2 border-b border-border/40 py-0.5">
            <dt className="text-faint uppercase tracking-wide">Shared pairs / DNS names</dt>
            <dd className="mono text-text">
              {formatNumber(overlap?.shared_peers ?? 0)} / {formatNumber(overlap?.shared_dns_names ?? 0)}
            </dd>
          </div>
        </dl>

        <SectionNote className="mt-3" tone={totals === 0 ? 'info' : 'warn'}>
          {totals === 0
            ? 'Nothing novel: every address, pair, service, name and fingerprint this capture holds is also in the reference. That is a statement about these two captures, not a clean bill of health.'
            : formatNumber(totals) +
              ' differences across ' +
              formatNumber(NOVELTY_KINDS.length - emptyKinds.length) +
              ' of the ' +
              formatNumber(NOVELTY_KINDS.length) +
              ' novelty kinds' +
              (emptyKinds.length > 0 ? ' (' + emptyKinds.map((kind) => KIND_LABEL[kind]).join(', ') + ' are empty)' : '') +
              '. Novelty is a fact about the two captures, not intent: a new address is as often a DHCP lease as it is a device worth chasing.'}
        </SectionNote>
      </Panel>

      {(counts.hosts ?? 0) > 0 ? (
        <NoveltyPanel kind="hosts" count={counts.hosts ?? 0} shown={(novel.hosts ?? []).length}>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Seen as</th>
                  <th className="text-right">Novel pairs</th>
                  <th className="text-right">Open</th>
                </tr>
              </thead>
              <tbody>
                {(novel.hosts ?? []).map((address) => (
                  <tr key={address}>
                    <td>
                      <EntityLink value={address} to={openEntity('ip', address)} />
                    </td>
                    <td className="text-2xs text-muted">
                      {roleOf(address, sources, destinations)}
                    </td>
                    <td className="text-right mono text-2xs text-muted">
                      {formatNumber(pairGroups.filter((group) => group.source === address).reduce((sum, group) => sum + group.targets.length, 0))}
                    </td>
                    <td className="text-right">
                      <Link to={'/packets?ip=' + encodeURIComponent(address)} className="btn-tab" title={'Frames involving ' + address}>
                        Packets
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <SectionNote className="m-3 mt-0">
            The <span className="mono">new_host</span> rule reports only the private addresses in this
            list; a public address here is usually a CDN edge or a resolver the reference never
            contacted, which the rule leaves to the destination list below.
          </SectionNote>
        </NoveltyPanel>
      ) : null}

      {(counts.peers ?? 0) > 0 ? (
        <NoveltyPanel kind="peers" count={counts.peers ?? 0} shown={(novel.peers ?? []).length}>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destinations the reference never recorded</th>
                </tr>
              </thead>
              <tbody>
                {pairGroups.map((group) => (
                  <tr key={group.source}>
                    <td className="align-top">
                      <EntityLink value={group.source} to={openEntity('ip', group.source)} />
                    </td>
                    <td>
                      <ChipList
                        values={group.targets}
                        linkFor={(value) => openEntity('ip', value)}
                        label={(value) => value}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <SectionNote className="m-3 mt-0">
            One row per source address. Multicast, broadcast and documentation addresses are
            excluded from the <span className="mono">new_destination</span> rule, because they are
            not destinations anyone chose to contact.
          </SectionNote>
        </NoveltyPanel>
      ) : null}

      {(counts.services ?? 0) > 0 ? (
        <NoveltyPanel kind="services" count={counts.services ?? 0} shown={(novel.services ?? []).length}>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Ports the reference never answered on</th>
                </tr>
              </thead>
              <tbody>
                {serviceGroups.map((group) => (
                  <tr key={group.host}>
                    <td className="align-top">
                      <EntityLink value={group.host} to={openEntity('ip', group.host)} />
                    </td>
                    <td>
                      <ChipList
                        values={group.services.map((service) => service.port + '/' + service.transport)}
                        linkFor={(value) => {
                          const [port] = value.split('/')
                          return '/packets?ip=' + encodeURIComponent(group.host) + '&port=' + encodeURIComponent(port ?? '')
                        }}
                        label={(value) => value}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <SectionNote className="m-3 mt-0">
            A service is read from a SYN to a port below 49152, so a capture that starts mid-flow
            shows fewer services than the network really offered — the gap is the capture's, not
            the network's.
          </SectionNote>
        </NoveltyPanel>
      ) : null}

      {(counts.dns_names ?? 0) > 0 ? (
        <NoveltyPanel kind="dns_names" count={counts.dns_names ?? 0} shown={(novel.dns_names ?? []).length}>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Name this capture resolved</th>
                  <th className="text-right">Open</th>
                </tr>
              </thead>
              <tbody>
                {(novel.dns_names ?? []).map((name) => (
                  <tr key={name}>
                    <td>
                      <EntityLink value={name} to={openEntity('domain', name)} />
                    </td>
                    <td className="text-right">
                      <Link to={openEntity('domain', name)} className="btn-tab" title={'Everything this capture knows about ' + name}>
                        Hunt
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </NoveltyPanel>
      ) : null}

      {(counts.sni ?? 0) > 0 ? (
        <NoveltyPanel kind="sni" count={counts.sni ?? 0} shown={(novel.sni ?? []).length}>
          <div className="flex flex-wrap gap-1 p-3">
            {(novel.sni ?? []).map((name) => (
              <Link key={name} to={openEntity('domain', name)} className="chip mono hover:border-accent/60" title={name}>
                {name}
              </Link>
            ))}
          </div>
        </NoveltyPanel>
      ) : null}

      {(counts.ja3 ?? 0) > 0 ? (
        <NoveltyPanel kind="ja3" count={counts.ja3 ?? 0} shown={(novel.ja3 ?? []).length}>
          <div className="flex flex-col gap-1 p-3">
            {(novel.ja3 ?? []).map((fingerprint) => (
              <div key={fingerprint} className="flex items-center gap-2">
                <Fingerprint size={12} className="shrink-0 text-muted" aria-hidden />
                <span className="mono min-w-0 flex-1 truncate text-2xs text-text" title={fingerprint}>
                  {fingerprint}
                </span>
                <CopyButton value={fingerprint} label="Copy this JA3 fingerprint" />
              </div>
            ))}
          </div>
          <SectionNote className="m-3 mt-0">
            A fingerprint identifies the client software's TLS settings, so a new one is a
            program that was not talking when the baseline was taken — as often a new browser
            build as anything else.
          </SectionNote>
        </NoveltyPanel>
      ) : null}

      <SectionNote>
        These differences are also written to <Link to="/findings" className="underline underline-offset-2">Findings</Link>
        {' '}by the seven <span className="mono">baseline_*</span> rules. Changing the baseline does not
        rewrite stored findings: re-run the rules on this analysis to recompute them.
      </SectionNote>
    </div>
  )
}

function BaselineCheckBody() {
  const { analysisId } = useAnalysis()
  const summaryQuery = useQuery({
    queryKey: ['baseline-compare', analysisId],
    queryFn: () => baselineApi.compare(analysisId as string),
    enabled: Boolean(analysisId),
  })

  const summary = summaryQuery.data

  if (summaryQuery.isLoading) {
    return <LoadingState label="Comparing this capture against the baseline network…" rows={5} />
  }
  if (summaryQuery.error) {
    return (
      <ErrorState
        error={summaryQuery.error}
        title="Could not compare this capture"
        onRetry={() => void summaryQuery.refetch()}
      />
    )
  }
  if (summary === undefined) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="The backend returned no comparison"
        description="The request succeeded but carried no payload, so nothing is drawn rather than an empty difference list."
      />
    )
  }

  if (!summary.active && (summary.reason ?? '').includes('is the baseline itself')) {
    return (
      <div className="flex flex-col gap-3">
        <Panel
          title="This capture is the baseline network"
          subtitle="A reference cannot be compared with itself — there is nothing to diff"
        >
          <SectionNote>
            Baseline mode is on and this capture is the reference every other analysis is
            measured against, so its own novelty list would be empty by construction. Open a
            different capture in the top bar to see how it differs, or choose another
            reference on <Link to="/files" className="underline underline-offset-2">PCAP Files</Link>.
          </SectionNote>
        </Panel>
      </div>
    )
  }

  if (!summary.active) {
    return (
      <div className="flex flex-col gap-3">
        <Panel title="Baseline mode is not in force" subtitle="Nothing is compared until a reference capture is chosen and the mode is on">
          <SectionNote tone="warn">{summary.reason ?? 'No comparison was made.'}</SectionNote>
          <p className="mt-2 text-2xs leading-relaxed text-muted">
            The reference is chosen in the <span className="mono">Baseline</span> column of
            {' '}<Link to="/files" className="underline underline-offset-2">PCAP Files</Link>, which also
            carries the baseline mode switch. One capture is the reference for the whole
            application, so every analysis is compared against the same one.
          </p>
        </Panel>
      </div>
    )
  }

  if (summary.comparable === false) {
    return (
      <div className="flex flex-col gap-3">
        <Panel
          title="This capture and the baseline are different networks"
          subtitle={
            summary.baseline === undefined
              ? undefined
              : 'no local address shared with ' +
                (summary.baseline.label ?? summary.baseline.filename ?? summary.baseline.analysis_id)
          }
        >
          <SectionNote tone="warn">
            {'None of this capture\'s ' +
              formatNumber(summary.overlap?.capture_hosts ?? 0) +
              ' addresses appear among the ' +
              formatNumber(summary.overlap?.baseline_hosts ?? 0) +
              " the baseline holds, so novelty is not reported: comparing against a different network would label everything new and mean nothing. "}
            {'This capture shares ' +
              formatNumber(summary.overlap?.shared_hosts ?? 0) +
              ' public address(es) with the reference, which is not the same network.'}
          </SectionNote>
          <p className="mt-2 text-2xs leading-relaxed text-muted">
            The <span className="mono">baseline_no_overlap</span> rule records exactly this, and the six
            novelty rules stay silent. Choose a capture from this network as the reference, or switch
            baseline mode off while you work on this one.
          </p>
        </Panel>
      </div>
    )
  }

  return <BaselineReport summary={summary} />
}

/** The section shell: headline outside the guard, body behind it. */
export function BaselineCheckPage() {
  const { analysisId } = useAnalysis()
  const statusQuery = useQuery({ queryKey: ['baseline'], queryFn: () => baselineApi.status() })
  const active = statusQuery.data?.active === true
  const reference = statusQuery.data?.baseline?.original_filename

  return (
    <Page
      section={SECTIONS.baselineCheck}
      meta={
        <div className="flex flex-wrap items-center gap-1.5">
          <span
            className={clsx(
              'chip',
              active
                ? 'border-warn/60 bg-warn/15 text-warn'
                : 'border-border2 bg-surface2 text-faint',
            )}
            title={
              active
                ? 'Every analysis is compared against ' + (reference ?? 'the baseline capture')
                : 'Baseline mode is off, so nothing is compared'
            }
          >
            {active ? 'Baseline mode : enabled' : 'Baseline mode : off'}
          </span>
          {reference !== undefined ? (
            <Link to="/files" className="chip mono" title="Choose the reference capture on PCAP Files">
              {reference}
            </Link>
          ) : (
            <Link to="/files" className="chip" title="Choose a reference capture on PCAP Files">
              no baseline network set
            </Link>
          )}
          {analysisId === null ? null : (
            <Link to="/findings" className="chip" title="The seven baseline rules write these differences as findings">
              findings
            </Link>
          )}
        </div>
      }
    >
      <ScopeNote
        title="How to read this section"
        collapsible
        defaultOpen={false}
        items={[
          {
            can: true,
            text: 'What this capture contains that one reference capture does not — addresses, source/destination pairs, services, DNS names and TLS names and fingerprints — read from this analysis index.',
          },
          {
            can: true,
            text: 'The overlap the comparison was measured on: how many addresses the two captures share, and how many of those are local, which is what makes the captures comparable at all.',
          },
          {
            can: false,
            text: 'A verdict. A new address, service or name is novelty; whether it is a problem needs the owner of the network, not this page.',
          },
          {
            can: false,
            text: 'Novelty between different networks. When the two captures share no local address the page reports that instead of listing a whole foreign network as new.',
          },
          {
            can: false,
            text: 'Time. The profile is a set, so “new” means absent from the reference — never first seen at a particular moment.',
          },
        ]}
        caveat="Every value here is read from this analysis' index and the reference's index. Nothing is estimated, and a comparison that cannot be made says why instead of showing an empty list."
      />
      <AnalysisGuard>
        <BaselineCheckBody />
      </AnalysisGuard>
    </Page>
  )
}

export default BaselineCheckPage
