import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeftRight,
  Clock,
  Crosshair,
  FileText,
  Globe,
  HardDrive,
  List,
  Radar,
  Search,
  Server,
  ShieldAlert,
  Waypoints,
} from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import ChartPanel from '@/components/ChartPanel'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import CountryList from '@/components/dashboard/CountryList'
import DomainBars from '@/components/dashboard/DomainBars'
import KpiTile from '@/components/dashboard/KpiTile'
import NetworkMap from '@/components/dashboard/NetworkMap'
import WorldMap, { BuildDatasetButton } from '@/components/dashboard/WorldMap'
import ProtocolMix from '@/components/dashboard/ProtocolMix'
import TrafficExtremeCard from '@/components/dashboard/TrafficExtremeCard'
import TrafficSparkline from '@/components/dashboard/TrafficSparkline'
import { useAnalysis, useAnalysisSummary } from '@/hooks/useAnalysis'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { SECTIONS } from '@/theme/sections'
import { geoApi, hostsApi } from '@/services/api'
import { formatDuration, formatNumber } from '@/utils/format'

/** An analysis stays "fresh" for this long: findings can still arrive from a
 *  Suricata rule run or a pipeline that has only just reported completion. */
const FRESH_WINDOW_S = 300
const FRESH_POLL_MS = 5000

/**
 * The two views of the map panel (docs/GEOGRAPHY.md).
 *
 * `geo` is the default because "where is this capture talking to" is the question the panel
 * is opened with; `graph` is the conversation graph the panel has always drawn, kept because
 * topology and geography are different questions and neither replaces the other.
 */
type MapView = 'geo' | 'graph'

function MapViewToggle({ view, onChange }: { view: MapView; onChange: (next: MapView) => void }) {
  return (
    <span className="flex items-center gap-1 rounded border border-border bg-surface2 p-0.5" role="tablist">
      {(['geo', 'graph'] as const).map((each) => (
        <button
          key={each}
          type="button"
          role="tab"
          aria-selected={view === each}
          data-map-view={each}
          className={
            view === each
              ? 'rounded bg-accent/15 px-2 py-0.5 text-2xs text-text'
              : 'rounded px-2 py-0.5 text-2xs text-muted hover:text-text'
          }
          title={
            each === 'geo'
              ? 'Where this capture\u2019s public addresses are, one dot per country'
              : 'Who talked to whom, sized by bytes'
          }
          onClick={() => onChange(each)}
        >
          {each === 'geo' ? 'Geography' : 'Conversations'}
        </button>
      ))}
    </span>
  )
}

function DashboardOverview() {
  const { analysisId, selected } = useAnalysis()
  const tokens = useThemeTokens()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()

  /* The map's view lives in the URL, like every other view toggle in the app, so a
     geography link is shareable and Back returns to the graph. */
  const mapView: MapView = searchParams.get('map') === 'graph' ? 'graph' : 'geo'
  const setMapView = (next: MapView) => {
    const params = new URLSearchParams(searchParams)
    if (next === 'graph') params.set('map', 'graph')
    else params.delete('map')
    setSearchParams(params, { replace: true })
  }
  const [focusedCountry, setFocusedCountry] = useState<string | null>(null)
  /* True between asking for the dataset and the first response that has it: the download is
     a job, so the map has to look for it rather than assume it arrived with the POST. */
  const [waitingForDataset, setWaitingForDataset] = useState(false)

  const geography = useQuery({
    queryKey: ['geography', analysisId],
    queryFn: () => geoApi.geography(analysisId as string),
    enabled: Boolean(analysisId),
    /* Countries do not change while the page is open; a re-read would only repeat the SQL. */
    staleTime: 60_000,
    /* While a download is in flight, ask again every few seconds — and stop the moment the
       dataset is there, so a finished download fills the map without a reload. */
    refetchInterval: waitingForDataset ? 3000 : false,
  })

  useEffect(() => {
    if (waitingForDataset && geography.data?.dataset.available === true) {
      setWaitingForDataset(false)
    }
  }, [waitingForDataset, geography.data])

  const buildDataset = useMutation({
    mutationFn: () => geoApi.refresh(),
    onSuccess: () => {
      setWaitingForDataset(true)
      void queryClient.invalidateQueries({ queryKey: ['geography', analysisId] })
    },
  })

  const openIp = useCallback(
    (ip: string) => navigate(`/hosts?ip=${encodeURIComponent(ip)}`),
    [navigate],
  )

  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now() / 1000), 30_000)
    return () => window.clearInterval(timer)
  }, [])
  const isFresh = useMemo(() => {
    const stamp = selected?.finished_at ?? selected?.updated_at ?? null
    if (stamp === null) return false
    return now - stamp < FRESH_WINDOW_S
  }, [selected?.finished_at, selected?.updated_at, now])

  const summary = useAnalysisSummary(analysisId, {
    refetchInterval: isFresh ? FRESH_POLL_MS : false,
  })

  const graph = useQuery({
    queryKey: ['host-graph', analysisId],
    queryFn: () => hostsApi.graph(analysisId as string),
    enabled: Boolean(analysisId),
    staleTime: 30_000,
  })

  if (summary.isLoading) return <LoadingState label="Loading the analysis overview…" rows={6} />

  if (summary.error) {
    return (
      <ErrorState
        error={summary.error}
        title="Could not load the analysis summary"
        onRetry={() => void summary.refetch()}
      />
    )
  }

  const data = summary.data
  if (!data) {
    return (
      <EmptyState
        title="No summary available"
        description="The backend returned no summary for this analysis."
      />
    )
  }

  const totals = data.totals
  const extremes = data.traffic_extremes
  const domains = data.top_domains ?? []
  const severity = data.severity_counts
  const findingsTotal =
    totals.findings ?? severity.high + severity.medium + severity.low + severity.informational
  const interval = data.series_interval

  return (
    <div className="flex flex-col gap-3">
      <div>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7">
          <KpiTile
            label="DNS requests"
            value={totals.dns_queries}
            icon={Search}
            hue="red"
            detail="queries seen in this capture"
            to="/dns"
            title="Open the DNS queries behind this number"
          />
          <KpiTile
            label="Conversations"
            value={totals.conversations}
            icon={ArrowLeftRight}
            hue="cyan"
            detail="reassembled streams"
            to="/conversations"
            title="Open the conversations behind this number"
          />
          <KpiTile
            label="Hosts"
            value={totals.hosts}
            icon={Server}
            hue="blue"
            detail="distinct addresses"
            to="/hosts"
            title="Open the host inventory behind this number"
          />
          <KpiTile
            label="Findings"
            value={findingsTotal}
            icon={ShieldAlert}
            hue={severity.high > 0 ? 'red' : 'gold'}
            tone={severity.high > 0 ? 'danger' : 'default'}
            detail={`high ${severity.high} · medium ${severity.medium} · low ${severity.low} · info ${severity.informational}`}
            to="/findings"
            title="Open the findings workbench behind this number"
          />
          <KpiTile
            label="Packets"
            value={totals.packets}
            icon={List}
            hue="cyan"
            detail="indexed frames"
            to="/packets"
            title="Open the packet browser behind this number"
          />
          <KpiTile
            label="Bytes"
            value={totals.bytes}
            format="bytes"
            icon={HardDrive}
            hue="gold"
            detail="on the wire"
            to="/packets"
            title="Open the packet browser, where each frame's length is listed"
          />
        <KpiTile
          label="Duration"
          value={totals.duration}
          format="duration"
          icon={Clock}
          hue="violet"
          detail={`${formatNumber(totals.tcp_packets)} TCP · ${formatNumber(totals.udp_packets)} UDP`}
          to="/info"
          title="Open the capture reference view behind this number"
          />
        </div>
      </div>

      {/* Full width, above the map: the shape of the capture over time is the
          first thing to read, and a time series wants the width far more than a
          half column can give it. */}
      <ChartPanel
        title={
          <span className="flex items-center gap-1.5">
            <Crosshair size={13} className="text-accent" aria-hidden />
            Traffic over time
          </span>
        }
        subtitle={
          interval && interval > 0
            ? `${(data.traffic_series ?? []).length} buckets · ${formatDuration(interval)} per bucket`
            : `${(data.traffic_series ?? []).length} buckets`
        }
        height={210}
        isEmpty={(data.traffic_series ?? []).length === 0}
        emptyTitle="No traffic series"
        emptyDescription="The capture has no packets to bucket over time."
      >
        <TrafficSparkline series={data.traffic_series ?? []} />
      </ChartPanel>

      <Panel
        title={
          <span className="flex items-center gap-1.5">
            <Radar size={13} className="text-accent2" aria-hidden />
            Network map
          </span>
        }
        subtitle={
          mapView === 'geo'
            ? 'where the addresses in this capture are, one dot per country'
            : 'who talked to whom in this capture, sized by bytes'
        }
        flush
        actions={
          <>
            <MapViewToggle view={mapView} onChange={setMapView} />
            <Link to="/hosts" className="btn">
              <Server size={13} aria-hidden />
              Host inventory
            </Link>
          </>
        }
      >
        {mapView === 'graph' ? (
          <div className="p-2">
            <NetworkMap
              nodes={graph.data?.nodes ?? []}
              edges={graph.data?.edges ?? []}
              isLoading={graph.isLoading}
              error={graph.error}
              onRetry={() => void graph.refetch()}
              onSelect={openIp}
            />
          </div>
        ) : geography.isLoading && geography.data === undefined ? (
          <div className="p-3">
            <LoadingState label="Placing this capture's addresses…" rows={4} />
          </div>
        ) : geography.error ? (
          <div className="p-3">
            <ErrorState
              error={geography.error}
              title="Could not load the geographic view"
              onRetry={() => void geography.refetch()}
            />
          </div>
        ) : geography.data !== undefined ? (
          <div className="p-2">
            <WorldMap
              data={geography.data}
              analysisId={analysisId as string}
              focused={focusedCountry}
              onFocus={setFocusedCountry}
              onSelectIp={openIp}
              datasetAction={
                <BuildDatasetButton
                  onBuild={() => buildDataset.mutate()}
                  building={buildDataset.isPending}
                  error={buildDataset.error}
                  jobId={buildDataset.data?.job_id}
                  waiting={waitingForDataset}
                />
              }
            />
            <div className="mt-2 border-t border-border">
              <CountryList
                data={geography.data}
                focused={focusedCountry}
                onFocus={setFocusedCountry}
                onSelectIp={openIp}
              />
            </div>
          </div>
        ) : null}
      </Panel>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TrafficExtremeCard
          title="Most data sent"
          direction="sent"
          host={extremes?.max_sender ?? null}
          onSelect={(ip) => navigate(`/hosts?ip=${encodeURIComponent(ip)}`)}
        />
        <TrafficExtremeCard
          title="Most data received"
          direction="received"
          host={extremes?.max_receiver ?? null}
          onSelect={(ip) => navigate(`/hosts?ip=${encodeURIComponent(ip)}`)}
        />
      </div>

      <Panel
        title="Top domains"
        subtitle="bytes exchanged with names this capture resolved"
        flush
        actions={
          <div className="flex items-center gap-2 text-2xs">
            <span className="flex items-center gap-1 text-muted">
              <span className="inline-block h-2 w-3 rounded-sm" style={{ background: tokens.accent }} />
              sent
            </span>
            <span className="flex items-center gap-1 text-muted">
              <span className="inline-block h-2 w-3 rounded-sm" style={{ background: tokens.accent2 }} />
              received
            </span>
          </div>
        }
      >
        <DomainBars
          domains={domains}
          onSelect={(ip) => navigate(`/hosts?ip=${encodeURIComponent(ip)}`)}
        />
        <div className="border-t border-border px-3 py-2 text-2xs leading-relaxed text-faint">
          {data.top_domains_note ??
            'Domain totals are attributed from the IP addresses this capture observed in DNS answers, then summed from the conversations with those addresses.'}
        </div>
      </Panel>

      {/* Protocol mix is full width now that the time series has moved above the
          map: one chart alone in a two-column grid would have sat in half the
          width with nothing beside it. */}
      <ChartPanel
        title="Protocol mix"
        subtitle={`top ${Math.min(7, (data.protocol_distribution ?? []).length)} protocols`}
        height={210}
        isEmpty={(data.protocol_distribution ?? []).length === 0}
        emptyTitle="No protocol distribution"
        emptyDescription="No packets were indexed for this capture."
      >
        <ProtocolMix distribution={data.protocol_distribution ?? []} />
      </ChartPanel>

      <div className="flex flex-wrap items-center gap-2 px-1 pb-1 text-2xs text-muted">
        <FileText size={13} className="text-faint" aria-hidden />
        <span>
          Full detail for this capture — top talkers, top ports, conversations, protocol hierarchy,
          findings and the analysis limitations — lives on the Info page.
        </span>
        <Link to="/info" className="btn ml-auto">
          <FileText size={13} aria-hidden />
          Open Info
        </Link>
      </div>

      <div className="flex flex-wrap items-center gap-2 px-1 text-2xs text-faint">
        <Globe size={12} aria-hidden />
        <span>
          Every figure is derived from this capture&apos;s own packets; nothing is estimated. Values
          that could not be derived are shown as “—”, and empty panels stay empty rather than being
          filled with placeholders.
        </span>
        {severity.high > 0 ? <SeverityBadge severity="high" count={severity.high} /> : null}
        <Waypoints size={12} className="ml-auto" aria-hidden />
      </div>
    </div>
  )
}

/** Visual overview of one analysis: KPIs, the conversation map, domains and shape. */
export function DashboardPage() {
  return (
    <Page section={SECTIONS.dashboard}>
      <AnalysisGuard>
        <DashboardOverview />
      </AnalysisGuard>
    </Page>
  )
}

export default DashboardPage