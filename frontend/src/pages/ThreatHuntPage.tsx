import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { CircleSlash, Gauge, Radar, ShieldAlert, ShieldCheck, Wrench, X } from 'lucide-react'
import pageBackground from '@/assets/threatMap_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import { ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import IndicatorCard from '@/components/threat/IndicatorCard'
import DetectionGrid, { type DetectionGroup } from '@/components/threat/DetectionGrid'
import DetectionSignal from '@/components/threat/DetectionSignal'
import StatusDonut from '@/components/threat/StatusDonut'
import { IpCountryProvider } from '@/components/threat/IpFlag'
import {
  KpiCard,
  STATUS_META,
  reportedSignal,
  statusCounts,
  useStatusColours,
} from '@/components/threat/cockpitKit'
import { useAnalysis } from '@/hooks/useAnalysis'
import { threatHuntApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntAvailability, ThreatHuntIndicator } from '@/types'

/**
 * Threat Map - the cockpit.
 *
 * The page used to be one card per detection behind six tabs. It is a cockpit now: a
 * command strip of KPIs, two summary plots, a grid of every detection grouped by the
 * question it asks, and the full card of whichever detection is selected - all of it
 * read from the single response the backend already produced.
 *
 * Nothing here re-computes a detection and nothing is invented. The KPIs sum headlines
 * and count statuses that arrived in the payload; the plots draw those numbers; the
 * cards carry each detection's own measure. The one arithmetic the page performs is
 * stated wherever it is shown, because a total of unlike units is a sense of volume,
 * never a count of incidents.
 *
 * Two parameters ride in the URL: `detection` (what the investigation panel shows) and
 * `status` (which of the three states the grid is narrowed to), so a view worth sharing
 * is a link and survives a reload.
 */

/** The 17 detections of the contract, in the order the endpoint returns them. */
const CONTRACT_INDICATOR_IDS: readonly string[] = [
  'c2_beaconing',
  'network_scanning',
  'dns_anomalies',
  'data_exfiltration',
  'lateral_movement',
  'suspicious_http',
  'suspicious_tls',
  'unusual_ports',
  'high_fan_out',
  'rare_pairs',
  'malware_download',
  'dns_tunnelling',
  'ids_matches',
  'traffic_bursts',
  'unusual_egress',
  'data_staging',
  'failed_connections',
]

/**
 * The seven analytical groups, in the order an analyst works them.
 *
 * Presentation only: the ids stay the contract's, every one of them is drawn, and an id
 * no group claims falls into "Other" rather than being hidden by a layout decision.
 */
const DETECTION_GROUPS: readonly { id: string; label: string; hint: string; ids: readonly string[] }[] = [
  {
    id: 'behaviour',
    label: 'Network behaviour',
    hint: 'Who is talking to whom, how widely, and on what ports',
    ids: ['network_scanning', 'high_fan_out', 'unusual_ports', 'traffic_bursts'],
  },
  {
    id: 'anomalies',
    label: 'Connection anomalies',
    hint: 'Rare pairs, unanswered attempts and internal movement',
    ids: ['rare_pairs', 'failed_connections', 'lateral_movement'],
  },
  {
    id: 'dns-c2',
    label: 'DNS and command-and-control',
    hint: 'Beaconing, name-resolution anomalies and tunnelling',
    ids: ['c2_beaconing', 'dns_anomalies', 'dns_tunnelling'],
  },
  {
    id: 'tls',
    label: 'TLS and encrypted traffic',
    hint: 'Sessions whose metadata carried an observation',
    ids: ['suspicious_tls'],
  },
  {
    id: 'data',
    label: 'Data movement and exfiltration',
    hint: 'Outbound volume, unexpected egress, staging and downloads',
    ids: ['data_exfiltration', 'unusual_egress', 'data_staging', 'malware_download'],
  },
  {
    id: 'http',
    label: 'HTTP and payload analysis',
    hint: 'Requests the capture could read and what they carried',
    ids: ['suspicious_http'],
  },
  {
    id: 'ids',
    label: 'IDS and signature detection',
    hint: 'Matches from the imported Suricata rules',
    ids: ['ids_matches'],
  },
]

/** Read `?status=` back into one of the three states, or null. */
function parseStatus(value: string | null): ThreatHuntAvailability | null {
  return value === 'ok' || value === 'empty' || value === 'not_applicable' ? value : null
}

function ThreatHuntContent() {
  const { analysisId } = useAnalysis()
  /* Fixed: this page reads an indexed capture, not a live feed, so the bucket width is
     not a user setting. */
  const window = 60
  /* Fixed, like the bucket width: this page is a reading of an indexed capture, not a
     control panel. The endpoint still accepts `top` from 1 to 50. */
  const top = 12
  const [searchParams, setSearchParams] = useSearchParams()

  const params = useMemo(() => ({ window, top }), [window, top])

  const query = useQuery({
    queryKey: ['threat-hunt', analysisId, params],
    queryFn: () => threatHuntApi.get(analysisId as string, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const tokens = useThemeTokens()
  const colours = useStatusColours()
  const data = query.data
  const indicators = useMemo<ThreatHuntIndicator[]>(() => data?.indicators ?? [], [data])
  const ids = indicators.map((indicator) => indicator.id)
  const missing = CONTRACT_INDICATOR_IDS.filter((id) => !ids.includes(id))

  const byId = useMemo(() => {
    const map = new Map<string, ThreatHuntIndicator>()
    for (const indicator of indicators) map.set(indicator.id, indicator)
    return map
  }, [indicators])

  /* Ids the contract lists but no group claims, plus ids the backend invented: both are
     shown rather than dropped, so a layout decision can never hide a detection. */
  const claimed = new Set(DETECTION_GROUPS.flatMap((group) => group.ids))
  const unclaimed = ids.filter((id) => !claimed.has(id))

  const groups = useMemo<DetectionGroup[]>(() => {
    const list: DetectionGroup[] = DETECTION_GROUPS.map((group) => ({
      id: group.id,
      label: group.label,
      hint: group.hint,
      members: group.ids
        .map((id) => byId.get(id))
        .filter((indicator): indicator is ThreatHuntIndicator => indicator !== undefined),
    }))
    if (unclaimed.length > 0) {
      list.push({
        id: 'other',
        label: 'Other',
        hint: 'Detections this response returned that the page has no group for',
        members: unclaimed
          .map((id) => byId.get(id))
          .filter((indicator): indicator is ThreatHuntIndicator => indicator !== undefined),
      })
    }
    return list
  }, [byId, unclaimed])

  const counts = statusCounts(indicators)
  const signal = reportedSignal(indicators)
  const total = indicators.length
  const coverage = total === 0 ? 0 : counts.ok / total
  const maxHeadline = Math.max(
    1,
    ...indicators.map((indicator) => Math.max(0, indicator.headline.value)),
  )

  const requestedDetection = searchParams.get('detection')
  const selected = requestedDetection === null ? null : byId.get(requestedDetection) ?? null
  const statusFilter = parseStatus(searchParams.get('status'))

  const update = (key: string, value: string | null) => {
    const next = new URLSearchParams(searchParams)
    if (value === null) next.delete(key)
    else next.set(key, value)
    setSearchParams(next, { replace: true })
  }

  const selectDetection = (id: string) =>
    update('detection', requestedDetection === id ? null : id)
  const setStatusFilter = (status: ThreatHuntAvailability | null) =>
    update('status', status)

  /* The strongest computed detection, offered when nothing is selected: the reader is
     never left in front of an empty panel wondering what to open. */
  const strongest = useMemo(() => {
    const computed = indicators.filter((indicator) => indicator.availability === 'ok')
    if (computed.length === 0) return null
    return computed.reduce((best, indicator) =>
      indicator.headline.value > best.headline.value ? indicator : best,
    )
  }, [indicators])

  return (
    <div className="flex flex-col gap-3">
      <ScopeNote
        title="How to read this section"
        collapsible
        defaultOpen={false}
        items={[
          {
            can: true,
            text: 'One detection per card, computed from the indexed tables of this analysis - packets, conversations, DNS, HTTP, TLS, hosts and findings.',
          },
          {
            can: true,
            text: 'A headline count, the chart it came from, and links that open the underlying rows on the page that holds them.',
          },
          {
            can: false,
            text: 'A verdict. A match is a lead to check, not a conclusion - the section says what each pattern does not prove.',
          },
          {
            can: false,
            text: 'Values this capture cannot answer. A detection that could not run says so, and a detection that ran and matched nothing is reported as a measured zero - the two are never shown as the same thing.',
          },
          {
            can: false,
            text: 'The contents of encrypted traffic: TLS/HTTPS payloads are not decrypted, so a detection reads only the metadata TShark indexed.',
          },
          {
            can: false,
            text: 'Anything TShark did not dissect. A detection is silent about traffic the capture never contained.',
          },
        ]}
        caveat={
          data?.note ??
          'Every number on this page is read from this analysis’ index. No value is estimated, sampled or filled in, and a detection that cannot be computed says so instead of showing a zero.'
        }
      />

      {query.isLoading ? (
        <LoadingState label="Running the detections over the indexed tables…" rows={6} />
      ) : query.error ? (
        <ErrorState
          error={query.error}
          title="Could not load the threat map"
          onRetry={() => void query.refetch()}
        />
      ) : !data ? (
        <EmptyState
          icon={ShieldAlert}
          title="The backend returned no threat-hunt payload"
          description="The request succeeded but carried no envelope, so there is nothing to show. Nothing is drawn rather than an empty list of detections."
        />
      ) : indicators.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No indicators were returned"
          description="The threat-hunt endpoint answered with an empty indicator list for this capture. The cockpit is not padded with placeholders: an absent detection is absent, not clean."
        />
      ) : (
        <IpCountryProvider analysisId={analysisId}>
          {missing.length > 0 ? (
            <SectionNote tone="warn">
              {`The contract lists ${String(CONTRACT_INDICATOR_IDS.length)} indicators and this response has no card for ${missing.join(', ')}. A missing detection is reported here rather than silently omitted.`}
            </SectionNote>
          ) : null}

          {/* Layer A: what the strip was computed from, then the strip. */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-1 text-2xs text-faint">
            <span className="uppercase tracking-wider">detection run</span>
            <span className="mono text-muted">{formatNumber(data.packets_scanned)} packets indexed</span>
            <span className="text-border2">|</span>
            <span className="mono text-muted">{String(data.window)} s buckets</span>
            <span className="text-border2">|</span>
            <span className="mono text-muted">top {String(data.top)}</span>
            <span className="ml-auto">read from the analysis&rsquo; index, nothing re-dissected</span>
          </div>

          <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6" data-threat-kpis>
            <KpiCard
              icon={<Radar size={13} />}
              label="Detections"
              value={formatNumber(total)}
              detail={`of ${String(CONTRACT_INDICATOR_IDS.length)} in the contract`}
              colour={tokens.accent2}
              testId="total"
              title="Every detection the contract defines, whether or not this capture could answer it"
            />
            <KpiCard
              icon={<ShieldCheck size={13} />}
              label="With matches"
              value={formatNumber(counts.ok)}
              detail="computed a result"
              colour={colours.ok}
              testId="ok"
              title="Detections that ran and returned a result - a result can be zero"
            />
            <KpiCard
              icon={<CircleSlash size={13} />}
              label="Nothing matched"
              value={formatNumber(counts.empty)}
              detail="ran, under threshold"
              colour={colours.empty}
              testId="empty"
              title="Detections that ran and found nothing above their threshold. A measured answer, not a missing one"
            />
            <KpiCard
              icon={<Wrench size={13} />}
              label="Not computable"
              value={formatNumber(counts.not_applicable)}
              detail="capture lacks the data"
              colour={colours.not_applicable}
              testId="not-applicable"
              title="Detections this capture cannot answer at all - never the same reading as a zero"
            />
            <KpiCard
              icon={<Gauge size={13} />}
              label="Reported signal"
              value={formatNumber(signal)}
              detail="sum of computed headlines"
              colour={tokens.warn}
              testId="signal"
              title="The sum of each computed detection's own headline measure. The units differ between detections, so this is a sense of volume, not a count of incidents"
            />
            <KpiCard
              icon={<ShieldCheck size={13} />}
              label="Coverage"
              value={`${String(Math.round(coverage * 100))}%`}
              detail={`${String(counts.ok)} of ${String(total)} answerable`}
              colour={tokens.accent2}
              progress={coverage}
              testId="coverage"
              title="How much of the brief this capture could actually be asked"
            />
          </div>

          {/* Layers B and C in one two-column shell: the plots and the grid on the left,
              the investigation panel pinned on the right where it can be read while
              clicking through the cards. */}
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_25rem]">
            <div className="flex min-w-0 flex-col gap-3">
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                <Panel
                  className="lg:col-span-2"
                  title="Detection signal"
                  subtitle="ranked by each detection's own headline measure - a triage order, not a common scale"
                  flush
                >
                  <div className="p-2">
                    <DetectionSignal
                      indicators={indicators}
                      selectedId={selected?.id ?? null}
                      onSelect={selectDetection}
                    />
                  </div>
                </Panel>
                <Panel
                  title="Detection status"
                  subtitle="computed, measured nothing, or never ran"
                >
                  <StatusDonut counts={counts} filter={statusFilter} onFilter={setStatusFilter} />
                </Panel>
              </div>

              <Panel
                title="Detection analysis"
                subtitle={
                  statusFilter === null
                    ? `every detection, grouped by the question it asks - ${String(total)} in ${String(groups.length)} groups`
                    : `filtered to ${STATUS_META[statusFilter].label.toLowerCase()} - ${String(counts[statusFilter])} of ${String(total)} detections`
                }
                actions={
                  statusFilter === null ? null : (
                    <button
                      type="button"
                      className="btn px-1.5 py-0.5 text-2xs"
                      onClick={() => setStatusFilter(null)}
                      title="Show every status again"
                    >
                      <X size={11} aria-hidden />
                      clear filter
                    </button>
                  )
                }
              >
                <DetectionGrid
                  groups={groups}
                  max={maxHeadline}
                  selectedId={selected?.id ?? null}
                  filter={statusFilter}
                  onSelect={selectDetection}
                />
              </Panel>
            </div>

            <aside className="min-w-0 xl:sticky xl:top-3 xl:self-start">
              {selected === null ? (
                <Panel title="Investigation" subtitle="nothing selected">
                  <div className="flex flex-col gap-2">
                    <p className="text-2xs leading-relaxed text-muted">
                      Pick a detection from the signal chart or the grid and its full card opens
                      here: what the pattern may indicate, the evidence behind it, and the links
                      into the rows it came from.
                    </p>
                    {strongest !== null ? (
                      <button
                        type="button"
                        className="cockpit-card is-active text-left"
                        onClick={() => selectDetection(strongest.id)}
                        title="Open the detection with the largest computed signal"
                      >
                        <span className="text-2xs text-faint">largest computed signal</span>
                        <span className="text-xs text-text">{strongest.title}</span>
                        <span className="mono text-lg leading-none text-text">
                          {formatNumber(strongest.headline.value)}
                        </span>
                        <span className="text-2xs text-muted">{strongest.headline.label}</span>
                      </button>
                    ) : (
                      <p className="text-2xs leading-relaxed text-faint">
                        No detection in this capture produced a result to open. The grid still
                        says, for each one, whether it ran.
                      </p>
                    )}
                  </div>
                </Panel>
              ) : (
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 truncate text-2xs uppercase tracking-wider text-faint">
                      Investigation
                    </span>
                    <span
                      className="chip shrink-0"
                      style={{
                        borderColor: colours[selected.availability] + '66',
                        color: colours[selected.availability],
                      }}
                      title={STATUS_META[selected.availability].description}
                    >
                      {STATUS_META[selected.availability].short}
                    </span>
                    <button
                      type="button"
                      className="btn px-1 py-0.5"
                      onClick={() => selectDetection(selected.id)}
                      title="Close this detection"
                      aria-label="Close this detection"
                    >
                      <X size={11} aria-hidden />
                    </button>
                  </div>
                  <IndicatorCard indicator={selected} />
                </div>
              )}
            </aside>
          </div>
        </IpCountryProvider>
      )}

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <ShieldAlert size={12} aria-hidden />
        <span>
          Each card quotes the threshold that produced it where the backend reported one. Read a
          card as a direction to look in, then check the rows behind it through the links it
          carries.
        </span>
      </div>
    </div>
  )
}

/** Threat Map - the cockpit over the 17 detections of the contract. */
export function ThreatHuntPage() {
  return (
    <Page section={SECTIONS.threatHunt} headerImage={pageBackground}>
      <AnalysisGuard emptyDescription="Upload a PCAP/PCAPNG capture or select an existing analysis in the top bar to hunt across its indexed tables. Threat Map reads only tables that already exist, so it needs a finished analysis.">
        <ThreatHuntContent />
      </AnalysisGuard>
    </Page>
  )
}

export default ThreatHuntPage