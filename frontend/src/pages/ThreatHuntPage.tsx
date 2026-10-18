import { useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import { ShieldAlert } from 'lucide-react'
import pageBackground from '@/assets/threatMap_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import { ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import IndicatorCard from '@/components/threat/IndicatorCard'
import { AVAILABILITY_TONE, availabilityChipLabel } from '@/components/threat/visualKit'
import { useAnalysis } from '@/hooks/useAnalysis'
import { threatHuntApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntIndicator } from '@/types'

/**
 * Threat Map — every detection of docs/THREAT_HUNT.md §1 for one analysis.
 *
 * The page owns the section's single query and hands each indicator to a purely
 * presentational card, which is what makes the cards checkable from a fixture.
 * Nothing here re-dissects a capture: the endpoint reads the indexed tables only,
 * so the section stays fast and survives an upload being purged.
 *
 * The detections are grouped into tabs rather than stacked on one page, because
 * seventeen cards is a scroll, not a glance, and the groups follow the phases an
 * analyst actually works in. The active tab lives in the URL, so a group is
 * shareable and survives a reload.
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

interface ThreatGroup {
  id: string
  label: string
  hint: string
  ids: readonly string[]
}

/**
 * The tabs, in the order they are shown.
 *
 * The grouping is presentation only: every id stays in the payload exactly as the
 * contract returns it, and an id no group claims is shown under "Other" rather than
 * being dropped — a detection must never be hidden by a layout decision.
 */
const THREAT_GROUPS: readonly ThreatGroup[] = [
  {
    id: 'overview',
    label: 'Overview',
    hint: 'Every detection at a glance: its headline number and whether this capture could answer it',
    ids: [],
  },
  {
    id: 'recon',
    label: 'Recon and movement',
    hint: 'Scanning, fan-out, rare pairs, unexpected ports, failed connections and lateral movement',
    ids: [
      'network_scanning',
      'high_fan_out',
      'rare_pairs',
      'unusual_ports',
      'failed_connections',
      'lateral_movement',
    ],
  },
  {
    id: 'c2',
    label: 'C2 and name resolution',
    hint: 'Beaconing, DNS anomalies and tunnelling, and suspicious TLS',
    ids: ['c2_beaconing', 'dns_anomalies', 'dns_tunnelling', 'suspicious_tls'],
  },
  {
    id: 'exfil',
    label: 'Exfiltration and staging',
    hint: 'Outbound volume, unexpected egress, staged data and downloads',
    ids: ['data_exfiltration', 'unusual_egress', 'data_staging', 'malware_download'],
  },
  {
    id: 'web',
    label: 'Web and alerts',
    hint: 'HTTP behaviour, traffic bursts and the IDS alerts themselves',
    ids: ['suspicious_http', 'traffic_bursts', 'ids_matches'],
  },
]

/** One compact line per detection, so the whole hunt fits on a screen. */
function OverviewRow({
  indicator,
  onOpen,
}: {
  indicator: ThreatHuntIndicator
  onOpen: () => void
}) {
  const tone = AVAILABILITY_TONE[indicator.availability] ?? AVAILABILITY_TONE.empty
  return (
    <button
      type="button"
      onClick={onOpen}
      data-threat-overview-row={indicator.id}
      title={`${indicator.question} — open this detection`}
      className="flex w-full items-center gap-2 border-b border-border/50 px-3 py-1.5 text-left last:border-0 hover:bg-surface2/60"
    >
      <span className={clsx('chip shrink-0', tone)} data-threat-overview-availability={indicator.availability}>
        {availabilityChipLabel(indicator.availability)}
      </span>
      <span className="min-w-0 flex-1 truncate text-xs text-text">{indicator.title}</span>
      <span className="shrink-0 text-2xs text-muted">{indicator.headline.label}</span>
      <span
        className={clsx(
          'mono w-14 shrink-0 text-right text-xs font-semibold',
          indicator.availability === 'ok' ? 'text-text' : 'text-faint',
        )}
      >
        {formatNumber(indicator.headline.value)}
      </span>
    </button>
  )
}

function ThreatHuntContent() {
  const { analysisId } = useAnalysis()
  /* Fixed: this page reads an indexed capture, not a live feed, so the bucket
     width is not a user setting. */
  const window = 60
  /* Fixed, like the bucket width: this page is a reading of an indexed capture,
     not a control panel. The endpoint still accepts `top` from 1 to 50. */
  const top = 12
  const [searchParams, setSearchParams] = useSearchParams()

  const params = useMemo(() => ({ window, top }), [window, top])

  const query = useQuery({
    queryKey: ['threat-hunt', analysisId, params],
    queryFn: () => threatHuntApi.get(analysisId as string, params),
    enabled: Boolean(analysisId),
    // Changing the bucket size must not blank the page: the previous response
    // stays on screen until the new one arrives.
    placeholderData: keepPreviousData,
  })

  const data = query.data
  const indicators = data?.indicators ?? []
  const ids = indicators.map((indicator) => indicator.id)
  const missing = CONTRACT_INDICATOR_IDS.filter((id) => !ids.includes(id))

  const byId = useMemo(() => {
    const map = new Map<string, ThreatHuntIndicator>()
    for (const indicator of indicators) map.set(indicator.id, indicator)
    return map
  }, [indicators])

  /* Ids the contract lists but no group claims, plus ids the backend invented: both
     are shown rather than dropped, so a layout decision can never hide a detection. */
  const claimed = new Set(THREAT_GROUPS.flatMap((group) => group.ids))
  const unclaimed = ids.filter((id) => !claimed.has(id))

  const tabs = useMemo(() => {
    const build = (group: ThreatGroup) => {
      const members = group.ids.map((id) => byId.get(id)).filter((i): i is ThreatHuntIndicator => i !== undefined)
      return {
        group,
        members,
        computed: members.filter((i) => i.availability === 'ok').length,
      }
    }
    const list = THREAT_GROUPS.map(build)
    if (unclaimed.length > 0) {
      const extra = unclaimed.map((id) => byId.get(id)).filter((i): i is ThreatHuntIndicator => i !== undefined)
      list.push({
        group: {
          id: 'other',
          label: 'Other',
          hint: 'Detections this response returned that the page has no group for',
          ids: unclaimed,
        },
        members: extra,
        computed: extra.filter((i) => i.availability === 'ok').length,
      })
    }
    return list
  }, [byId, unclaimed])

  const requested = searchParams.get('tab') ?? 'overview'
  const active = tabs.some((tab) => tab.group.id === requested) ? requested : 'overview'
  const activeTab = tabs.find((tab) => tab.group.id === active) ?? tabs[0]

  const setTab = (id: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('tab', id)
    setSearchParams(next, { replace: true })
  }


  return (
    <div className="flex flex-col gap-3">
      <ScopeNote
        title="How to read this section"
        collapsible
        defaultOpen={false}
        items={[
          {
            can: true,
            text: 'One card per detection in the analyst brief, computed from the indexed tables of this analysis — packets, conversations, DNS, HTTP, TLS, hosts and findings.',
          },
          {
            can: true,
            text: 'A headline count, the chart it comes from, and links that open the underlying rows on the page that holds them.',
          },
          {
            can: false,
            text: 'A verdict. Every card carries the caveat naming what its pattern does not prove, because a match is a lead to check, not a conclusion.',
          },
          {
            can: false,
            text: 'Values this capture cannot answer: those cards state why. A detection below its threshold still shows the numbers that stayed under it.',
          },
          {
            can: false,
            text: 'The contents of encrypted traffic: TLS/HTTPS payloads are not decrypted, so a detection reads only the metadata TShark indexed.',
          },
          {
            can: false,
            text: 'Anything TShark did not dissect. A detection is silent about traffic the capture never contained, which a filtered or truncated capture will show as “nothing matched”.',
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
          description="The threat-hunt endpoint answered with an empty indicator list for this capture. The cards are not padded with placeholders: an absent detection is absent, not clean."
        />
      ) : (
        <>
          {missing.length > 0 ? (
            <SectionNote tone="warn">
              {`The contract lists ${CONTRACT_INDICATOR_IDS.length} indicators and this response has no card for ${missing.join(', ')}. A missing detection is reported here rather than silently omitted.`}
            </SectionNote>
          ) : null}

          <div className="flex flex-wrap items-center gap-1 border-b border-border px-2 pt-1">
            {tabs.map((tab) => {
              const isActive = tab.group.id === active
              return (
                <button
                  key={tab.group.id}
                  type="button"
                  className={clsx(
                    '-mb-px border-b-2 px-2.5 py-1.5 text-xs font-medium transition-colors',
                    isActive ? 'border-accent text-text' : 'border-transparent text-muted hover:text-text',
                  )}
                  aria-current={isActive ? 'page' : undefined}
                  title={tab.group.hint}
                  data-threat-tab={tab.group.id}
                  onClick={() => setTab(tab.group.id)}
                >
                  {tab.group.label}
                  {tab.group.id === 'overview' ? null : (
                    <span
                      className={clsx('ml-1.5 mono text-2xs', tab.computed > 0 ? 'text-accent2' : 'text-faint')}
                      title={`${tab.computed} of ${tab.members.length} detection(s) in this tab computed something for this capture`}
                    >
                      {tab.computed}/{tab.members.length}
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {activeTab.group.id === 'overview' ? (
            <div className="panel flex flex-col" data-threat-overview>
              <div className="panel-header">
                <div className="min-w-0">
                  <div className="panel-title">All {formatNumber(indicators.length)} detections</div>
                  <div className="mt-0.5 text-2xs text-faint">
                    the headline number of each, and whether this capture could answer it — open a row for the
                    chart, the reasoning and the links
                  </div>
                </div>
              </div>
              <div className="flex flex-col">
                {tabs
                  .filter((tab) => tab.group.id !== 'overview')
                  .flatMap((tab) => tab.members)
                  .map((indicator) => (
                    <OverviewRow
                      key={indicator.id}
                      indicator={indicator}
                      onOpen={() => {
                        const owner = tabs.find((tab) => tab.group.ids.includes(indicator.id))
                        setTab(owner === undefined ? 'overview' : owner.group.id)
                      }}
                    />
                  ))}
                {activeTab.members.length === 0 && unclaimed.length === 0 ? (
                  <div className="px-3 py-4 text-center text-2xs text-faint">
                    No detection matched the contract’s id list, so there is nothing to summarise.
                  </div>
                ) : null}
              </div>
            </div>
          ) : (
            <>
              {activeTab.members.map((indicator) => (
                <IndicatorCard key={indicator.id} indicator={indicator} />
              ))}
            </>
          )}
        </>
      )}

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <ShieldAlert size={12} aria-hidden />
        <span>
          Each card quotes the threshold that produced it where the backend reported one. Read a card as a
          direction to look in, then check the rows behind it through the links it carries.
        </span>
      </div>
    </div>
  )
}

/** Threat Map — the 17 detections of the contract, grouped into tabs. */
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
