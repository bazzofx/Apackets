import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeftRight,
  Clock,
  FileText,
  Globe,
  HardDrive,
  List,
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
import DomainBars from '@/components/dashboard/DomainBars'
import KpiTile from '@/components/dashboard/KpiTile'
import NetworkMap from '@/components/dashboard/NetworkMap'
import ProtocolMix from '@/components/dashboard/ProtocolMix'
import TrafficExtremeCard from '@/components/dashboard/TrafficExtremeCard'
import TrafficSparkline from '@/components/dashboard/TrafficSparkline'
import { useAnalysis, useAnalysisSummary } from '@/hooks/useAnalysis'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { SECTIONS } from '@/theme/sections'
import { hostsApi } from '@/services/api'
import { formatDuration, formatNumber } from '@/utils/format'

/** An analysis stays "fresh" for this long: findings can still arrive from a
 *  Suricata rule run or a pipeline that has only just reported completion. */
const FRESH_WINDOW_S = 300
const FRESH_POLL_MS = 5000

function DashboardOverview() {
  const { analysisId, selected } = useAnalysis()
  const tokens = useThemeTokens()
  const navigate = useNavigate()

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
      <div className="accent-bloom">
        <div className="relative z-10 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7">
          <KpiTile
            label="DNS requests"
            value={totals.dns_queries}
            icon={Search}
            detail="queries seen in this capture"
            to="/dns"
            title="Open the DNS queries behind this number"
          />
          <KpiTile
            label="Conversations"
            value={totals.conversations}
            icon={ArrowLeftRight}
            detail="reassembled streams"
            to="/conversations"
            title="Open the conversations behind this number"
          />
          <KpiTile
            label="Hosts"
            value={totals.hosts}
            icon={Server}
            detail="distinct addresses"
            to="/hosts"
            title="Open the host inventory behind this number"
          />
          <KpiTile
            label="Findings"
            value={findingsTotal}
            icon={ShieldAlert}
            tone={severity.high > 0 ? 'danger' : 'accent'}
            detail={`high ${severity.high} · medium ${severity.medium} · low ${severity.low} · info ${severity.informational}`}
            to="/findings"
            title="Open the findings workbench behind this number"
          />
          <KpiTile
            label="Packets"
            value={totals.packets}
            icon={List}
            detail="indexed frames"
            to="/packets"
            title="Open the packet browser behind this number"
          />
          <KpiTile
            label="Bytes"
            value={totals.bytes}
            format="bytes"
            icon={HardDrive}
            detail="on the wire"
            to="/packets"
            title="Open the packet browser, where each frame's length is listed"
          />
        <KpiTile
          label="Duration"
          value={totals.duration}
          format="duration"
          icon={Clock}
          detail={`${formatNumber(totals.tcp_packets)} TCP · ${formatNumber(totals.udp_packets)} UDP`}
          to="/info"
          title="Open the capture reference view behind this number"
          />
        </div>
      </div>

      <Panel
        className="shadow-bloom"
        subtitle="who talked to whom in this capture, sized by bytes"
        flush
        actions={
          <Link to="/hosts" className="btn">
            <Server size={13} aria-hidden />
            Host inventory
          </Link>
        }
      >
        <div className="p-2">
          <NetworkMap
            nodes={graph.data?.nodes ?? []}
            edges={graph.data?.edges ?? []}
            isLoading={graph.isLoading}
            error={graph.error}
            onRetry={() => void graph.refetch()}
            onSelect={(ip) => navigate(`/hosts?ip=${encodeURIComponent(ip)}`)}
          />
        </div>
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

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
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

        <ChartPanel
          title="Traffic over time"
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
      </div>

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