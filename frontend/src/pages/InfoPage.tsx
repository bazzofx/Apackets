import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { CSSProperties } from 'react'
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Clock,
  Globe,
  HardDrive,
  Info,
  Layers,
  List,
  Lock,
  LayoutDashboard,
  RefreshCw,
  Search,
  ShieldAlert,
  Waypoints,
} from 'lucide-react'
import clsx from 'clsx'
import AnalysisGuard from '@/components/AnalysisGuard'
import ChartPanel from '@/components/ChartPanel'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import StatCard from '@/components/StatCard'
import { useAnalysis, useAnalysisSummary } from '@/hooks/useAnalysis'
import type { AnalysisSummary, Severity } from '@/types'
import {
  formatBytes,
  formatClockTime,
  formatDuration,
  formatNumber,
  formatTimestamp,
} from '@/utils/format'

const AXIS_TICK = { fill: '#8296b4', fontSize: 11 }
const GRID_STROKE = '#22304d'
const TOOLTIP_STYLE: CSSProperties = {
  background: '#16203a',
  border: '1px solid #2c3c5e',
  borderRadius: 4,
  fontSize: 11,
  color: '#e2e8f0',
}
const TOOLTIP_LABEL_STYLE: CSSProperties = { color: '#8296b4', fontSize: 11 }

const PROTOCOL_COLORS = [
  '#3b82f6',
  '#60a5fa',
  '#38bdf8',
  '#0ea5e9',
  '#6366f1',
  '#8b5cf6',
  '#a855f7',
  '#ec4899',
  '#f59e0b',
  '#eab308',
  '#22c55e',
  '#14b8a6',
  '#94a3b8',
  '#64748b',
  '#475569',
]

function InlineEmpty({ message }: { message: string }) {
  return <div className="px-3 py-6 text-center text-2xs text-faint">{message}</div>
}

const SEVERITY_ORDER: Severity[] = ['high', 'medium', 'low', 'informational']

function severityCount(counts: AnalysisSummary['severity_counts'], severity: Severity): number {
  return counts?.[severity] ?? 0
}

/** An analysis stays "fresh" for this long: findings can still be produced by a
 *  Suricata rule run or by a pipeline that has only just reported completion. */
const FRESH_WINDOW_S = 300
const FRESH_POLL_MS = 5000

function InfoContent() {
  const { analysisId, selected } = useAnalysis()

  // Poll the summary while the analysis is recent, so the findings panel updates
  // on its own when an analysis finishes or rules are re-run. Older analyses are
  // fetched on demand only (window focus or the refresh button).
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
  const [protocolMetric, setProtocolMetric] = useState<'packets' | 'bytes'>('packets')
  const [trafficMetric, setTrafficMetric] = useState<'both' | 'packets' | 'bytes'>('both')

  if (summary.isLoading) return <LoadingState label="Loading analysis summary…" rows={6} />

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
  const protocolRows = [...(data.protocol_distribution ?? [])].sort(
    (a, b) => (b[protocolMetric] ?? 0) - (a[protocolMetric] ?? 0),
  )
  const series = data.traffic_series ?? []
  const talkers = data.top_talkers ?? []
  const ports = data.top_ports ?? []
  const conversations = data.top_conversations ?? []
  const findings = data.findings_summary ?? []
  const hierarchy = data.protocol_hierarchy ?? []
  const notes = data.notes ?? []
  const severityTotals = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: severityCount(data.severity_counts, severity),
  }))

  const interval = data.series_interval
  const trafficSubtitle =
    interval && interval > 0
      ? `${series.length} buckets · ${formatDuration(interval)} per bucket`
      : `${series.length} buckets`

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-2xs text-muted">
        <Info size={13} className="text-faint" aria-hidden />
        <span>
          Reference view: every number the backend derived for this capture, including the caveats.
        </span>
        <Link to="/" className="btn ml-auto">
          <LayoutDashboard size={13} aria-hidden />
          Visual overview
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
        <StatCard label="Packets" value={totals.packets} icon={List} />
        <StatCard label="Bytes" value={totals.bytes} format="bytes" icon={HardDrive} />
        <StatCard label="Duration" value={totals.duration} format="duration" icon={Clock} />
        <StatCard label="Unique src IPs" value={totals.unique_src_ips} icon={ArrowUpRight} />
        <StatCard label="Unique dst IPs" value={totals.unique_dst_ips} icon={ArrowDownRight} />
        <StatCard label="TCP packets" value={totals.tcp_packets} icon={Waypoints} />
        <StatCard label="UDP packets" value={totals.udp_packets} icon={Waypoints} />
        <StatCard label="DNS queries" value={totals.dns_queries} icon={Search} />
        <StatCard label="HTTP requests" value={totals.http_requests} icon={Globe} />
        <StatCard label="TLS connections" value={totals.tls_connections} icon={Lock} />
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
        <Panel title="Capture window" className="xl:col-span-1" flush>
          <dl className="grid grid-cols-[7.5rem_1fr] gap-x-3 gap-y-1 px-3 py-2.5 text-2xs">
            <dt className="text-faint">First packet</dt>
            <dd className="mono text-text">{formatTimestamp(totals.start_time)}</dd>
            <dt className="text-faint">Last packet</dt>
            <dd className="mono text-text">{formatTimestamp(totals.end_time)}</dd>
            <dt className="text-faint">Conversations</dt>
            <dd className="mono text-text">{formatNumber(totals.conversations)}</dd>
            <dt className="text-faint">Hosts</dt>
            <dd className="mono text-text">{formatNumber(totals.hosts)}</dd>
            <dt className="text-faint">Findings</dt>
            <dd className="mono text-text">{formatNumber(totals.findings)}</dd>
          </dl>
        </Panel>

        <ChartPanel
          title="Protocol distribution"
          subtitle={`top ${protocolRows.length} protocols by ${protocolMetric}`}
          height={230}
          isEmpty={protocolRows.length === 0}
          emptyTitle="No protocol data"
          emptyDescription="No packets were indexed for this capture."
          actions={
            <div className="flex items-center gap-1">
              {(['packets', 'bytes'] as const).map((metric) => (
                <button
                  key={metric}
                  type="button"
                  className={clsx('btn px-1.5 py-0.5', protocolMetric === metric && 'btn-primary')}
                  onClick={() => setProtocolMetric(metric)}
                >
                  {metric}
                </button>
              ))}
            </div>
          }
          className="xl:col-span-1"
        >
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={protocolRows}
              layout="vertical"
              margin={{ top: 4, right: 12, bottom: 4, left: 4 }}
            >
              <CartesianGrid horizontal={false} stroke={GRID_STROKE} />
              <XAxis type="number" tick={AXIS_TICK} stroke={GRID_STROKE} />
              <YAxis
                type="category"
                dataKey="protocol"
                width={84}
                tick={AXIS_TICK}
                stroke={GRID_STROKE}
              />
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                labelStyle={TOOLTIP_LABEL_STYLE}
                formatter={(value) => formatNumber(Number(value))}
                cursor={{ fill: '#1b2745' }}
              />
              <Bar dataKey={protocolMetric} name={protocolMetric} barSize={9} radius={[0, 2, 2, 0]}>
                {protocolRows.map((entry, index) => (
                  <Cell
                    key={`${entry.protocol}-${index}`}
                    fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel
          title="Traffic over time"
          subtitle={trafficSubtitle}
          height={230}
          isEmpty={series.length === 0}
          emptyTitle="No traffic series"
          emptyDescription="The capture has no packets to bucket over time."
          actions={
            <div className="flex items-center gap-1">
              {(['both', 'packets', 'bytes'] as const).map((metric) => (
                <button
                  key={metric}
                  type="button"
                  className={clsx('btn px-1.5 py-0.5', trafficMetric === metric && 'btn-primary')}
                  onClick={() => setTrafficMetric(metric)}
                >
                  {metric}
                </button>
              ))}
            </div>
          }
          className="xl:col-span-1"
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
              <CartesianGrid stroke={GRID_STROKE} vertical={false} />
              <XAxis
                dataKey="t"
                tick={AXIS_TICK}
                stroke={GRID_STROKE}
                minTickGap={28}
                tickFormatter={(value: number) => formatClockTime(value)}
              />
              {(trafficMetric === 'both' || trafficMetric === 'packets') && (
                <YAxis
                  yAxisId="packets"
                  tick={AXIS_TICK}
                  stroke={GRID_STROKE}
                  width={48}
                  tickFormatter={(value: number) => formatNumber(value)}
                />
              )}
              {(trafficMetric === 'both' || trafficMetric === 'bytes') && (
                <YAxis
                  yAxisId="bytes"
                  orientation="right"
                  tick={AXIS_TICK}
                  stroke={GRID_STROKE}
                  width={56}
                  tickFormatter={(value: number) => formatBytes(value, 0)}
                />
              )}
              <Tooltip
                contentStyle={TOOLTIP_STYLE}
                labelStyle={TOOLTIP_LABEL_STYLE}
                labelFormatter={(label) => `t = ${formatTimestamp(Number(label))}`}
                formatter={(value, name) => {
                  const n = Number(value)
                  return [name === 'bytes' ? formatBytes(n) : formatNumber(n), String(name)]
                }}
              />
              {trafficMetric !== 'bytes' ? (
                <Area
                  yAxisId="packets"
                  type="monotone"
                  dataKey="packets"
                  name="packets"
                  stroke="#3b82f6"
                  strokeWidth={1.5}
                  fill="#3b82f6"
                  fillOpacity={0.18}
                  dot={false}
                  isAnimationActive={false}
                />
              ) : null}
              {trafficMetric !== 'packets' ? (
                <Area
                  yAxisId="bytes"
                  type="monotone"
                  dataKey="bytes"
                  name="bytes"
                  stroke="#60a5fa"
                  strokeWidth={1.5}
                  strokeDasharray="3 2"
                  fill="#60a5fa"
                  fillOpacity={0.12}
                  dot={false}
                  isAnimationActive={false}
                />
              ) : null}
            </AreaChart>
          </ResponsiveContainer>
        </ChartPanel>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Panel title="Top talkers" subtitle="by packets observed" flush>
          {talkers.length === 0 ? (
            <InlineEmpty message="No IP traffic was observed in this capture." />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="dt">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Direction</th>
                    <th className="text-right">Packets</th>
                    <th className="text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {talkers.map((talker, index) => (
                    <tr key={`${talker.ip}-${talker.direction}-${index}`}>
                      <td>
                        <MonoCell>{talker.ip}</MonoCell>
                      </td>
                      <td className="text-muted">{talker.direction}</td>
                      <td className="text-right">{formatNumber(talker.packets)}</td>
                      <td className="text-right">{formatBytes(talker.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Top ports" subtitle="by packets observed" flush>
          {ports.length === 0 ? (
            <InlineEmpty message="No TCP/UDP ports were observed in this capture." />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="dt">
                <thead>
                  <tr>
                    <th className="text-right">Port</th>
                    <th>Protocol</th>
                    <th className="text-right">Packets</th>
                    <th>Service</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((port, index) => (
                    <tr key={`${port.protocol}-${port.port}-${index}`}>
                      <td className="text-right">{formatNumber(port.port)}</td>
                      <td className="text-muted">{port.protocol}</td>
                      <td className="text-right">{formatNumber(port.packets)}</td>
                      <td>
                        <MonoCell>{port.service}</MonoCell>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Panel title="Top conversations" subtitle="by total bytes" flush>
          {conversations.length === 0 ? (
            <InlineEmpty message="No conversations were reassembled from this capture." />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="dt">
                <thead>
                  <tr>
                    <th>A</th>
                    <th>B</th>
                    <th>Transport</th>
                    <th className="text-right">Packets</th>
                    <th className="text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {conversations.map((conversation, index) => (
                    <tr key={`${conversation.conv_id}-${index}`}>
                      <td>
                        <MonoCell maxWidth={220}>{conversation.endpoint_a}</MonoCell>
                      </td>
                      <td>
                        <MonoCell maxWidth={220}>{conversation.endpoint_b}</MonoCell>
                      </td>
                      <td className="text-muted">{conversation.transport}</td>
                      <td className="text-right">{formatNumber(conversation.packets_total)}</td>
                      <td className="text-right">{formatBytes(conversation.bytes_total)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Protocol hierarchy" subtitle="tshark -z io,phs" flush>
          {hierarchy.length === 0 ? (
            <InlineEmpty message="No protocol hierarchy was recorded for this capture." />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="dt">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th className="text-right">Frames</th>
                    <th className="text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {hierarchy.map((entry, index) => (
                    <tr key={`${entry.protocol}-${entry.depth}-${index}`}>
                      <td>
                        <span
                          className="flex items-center gap-1"
                          style={{ paddingLeft: Math.max(0, entry.depth) * 12 }}
                        >
                          {entry.depth === 0 ? (
                            <Layers size={11} className="text-faint" aria-hidden />
                          ) : null}
                          <MonoCell>{entry.protocol}</MonoCell>
                        </span>
                      </td>
                      <td className="text-right">{formatNumber(entry.frames)}</td>
                      <td className="text-right">{formatBytes(entry.bytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <Panel
        title="Findings"
        subtitle={
          severityTotals.some((entry) => entry.count > 0)
            ? severityTotals.map((entry) => `${entry.severity}: ${entry.count}`).join(' · ')
            : 'no detection rules matched'
        }
        flush
        actions={
          <>
            {summary.isFetching ? (
              <span className="text-2xs text-faint" aria-live="polite">
                updating…
              </span>
            ) : null}
            <button
              type="button"
              className="btn"
              onClick={() => void summary.refetch()}
              title="Re-read the findings for this analysis"
            >
              <RefreshCw size={13} aria-hidden />
              Refresh
            </button>
            <Link to="/findings" className="btn">
              <ShieldAlert size={13} aria-hidden />
              Open findings
            </Link>
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-1.5 px-3 py-2">
          {severityTotals.map((entry) => (
            <SeverityBadge key={entry.severity} severity={entry.severity} count={entry.count} />
          ))}
        </div>
        {findings.length === 0 ? (
          <InlineEmpty message="No findings were produced for this capture — that means no rule matched, not that the traffic is clean." />
        ) : (
          <ul className="divide-y divide-border/60">
            {findings.map((finding) => (
              <li key={finding.id}>
                <Link
                  to="/findings"
                  className="flex items-center gap-2 px-3 py-2 hover:bg-surface2/70"
                >
                  <SeverityBadge severity={finding.severity} showLabel />
                  <span className="min-w-0 flex-1 truncate text-xs text-text" title={finding.title}>
                    {finding.title}
                  </span>
                  <span className="chip border-border2 bg-surface2 text-faint" title={finding.rule_id}>
                    {finding.rule_id}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        title="Analysis limitations"
        subtitle="real caveats recorded by the backend for this capture"
        flush
      >
        {notes.length === 0 ? (
          <InlineEmpty message="No limitations were recorded. Absence of a note is not proof that the capture is complete." />
        ) : (
          <ul className="flex flex-col gap-1.5 px-3 py-2.5">
            {notes.map((note, index) => (
              <li key={index} className="flex items-start gap-2 text-xs leading-relaxed text-muted">
                <Info size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
                <span>{note}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <Activity size={12} aria-hidden />
        <span>
          analysis {data.analysis.id.slice(0, 12)}… · {data.analysis.original_filename}
          {data.analysis.capture_start !== null
            ? ` · started ${formatTimestamp(data.analysis.capture_start)}`
            : ''}
          {data.analysis.file_sha256 ? ` · sha256 ${data.analysis.file_sha256.slice(0, 12)}…` : ''}
        </span>
        <span className="ml-auto">values shown as — are unknown, never guessed</span>
      </div>
    </div>
  )
}

/** Info — the full reference view for one analysis, built from `GET /api/analyses/{id}/summary`. */
export function InfoPage() {
  return (
    <AnalysisGuard>
      <InfoContent />
    </AnalysisGuard>
  )
}

export default InfoPage
