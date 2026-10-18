import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeftRight,
  Clock,
  Files,
  Globe,
  Info,
  Link2,
  ListTree,
  RefreshCw,
  ShieldAlert,
  Table2,
} from 'lucide-react'
import pageBackground from '@/assets/findings_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import Toolbar from '@/components/Toolbar'
import FindingAppLayer from '@/components/findings/FindingAppLayer'
import FindingConversation from '@/components/findings/FindingConversation'
import FindingObjects from '@/components/findings/FindingObjects'
import FindingOverview from '@/components/findings/FindingOverview'
import FindingPackets from '@/components/findings/FindingPackets'
import FindingRelated from '@/components/findings/FindingRelated'
import FindingTimeline from '@/components/findings/FindingTimeline'
import FindingsList from '@/components/findings/FindingsList'
import { useAnalysis } from '@/hooks/useAnalysis'
import { findingsApi, suricataApi, toApiError } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatNumber } from '@/utils/format'
import type { Finding } from '@/types'

type Tab = 'overview' | 'timeline' | 'packets' | 'conversation' | 'application' | 'files' | 'related'

const TABS: { id: Tab; label: string; icon: typeof Table2 }[] = [
  { id: 'overview', label: 'Overview', icon: Info },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'packets', label: 'Packets', icon: Table2 },
  { id: 'conversation', label: 'Conversation', icon: ArrowLeftRight },
  { id: 'application', label: 'Application', icon: Globe },
  { id: 'files', label: 'Files', icon: Files },
  { id: 'related', label: 'Related', icon: Link2 },
]

const SEVERITY_FILTERS = ['', 'high', 'medium', 'low', 'informational'] as const

function FindingsWorkbench() {
  const { analysisId } = useAnalysis()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { findingId } = useParams<{ findingId?: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = (searchParams.get('tab') as Tab) ?? 'overview'

  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [suricataOnly, setSuricataOnly] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const list = useQuery({
    queryKey: ['findings', analysisId, severity, search, ruleId],
    queryFn: () =>
      findingsApi.list(analysisId as string, {
        page: 1,
        page_size: 500,
        severity: severity || undefined,
        search: search.trim() || undefined,
        rule_id: ruleId || undefined,
      }),
    enabled: Boolean(analysisId),
  })

  const rules = useQuery({
    queryKey: ['finding-rules', analysisId],
    queryFn: () => findingsApi.rules(analysisId as string),
    enabled: Boolean(analysisId),
    staleTime: 60_000,
  })

  const items = useMemo<Finding[]>(() => {
    const all = list.data?.items ?? []
    return suricataOnly ? all.filter((item) => item.rule_id.startsWith('suricata:')) : all
  }, [list.data, suricataOnly])

  const context = useQuery({
    queryKey: ['finding-context', analysisId, findingId],
    queryFn: () => findingsApi.context(analysisId as string, findingId as string),
    enabled: Boolean(analysisId && findingId),
    placeholderData: (previous) => previous,
  })

  const setTab = useCallback(
    (next: Tab) => {
      const params = new URLSearchParams(searchParams)
      params.set('tab', next)
      setSearchParams(params, { replace: true })
    },
    [searchParams, setSearchParams],
  )

  const select = useCallback(
    (finding: Finding) => {
      navigate(`/findings/${encodeURIComponent(finding.id)}?tab=${tab}`)
    },
    [navigate, tab],
  )

  // Deep link without an id: open the first finding of the current filter.
  useEffect(() => {
    if (findingId || items.length === 0) return
    navigate(`/findings/${encodeURIComponent(items[0].id)}?tab=${tab}`, { replace: true })
  }, [findingId, items, navigate, tab])

  // j/k and the arrow keys walk the list.
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement
      ) {
        return
      }
      const key = event.key
      if (!['j', 'k', 'ArrowDown', 'ArrowUp'].includes(key)) return
      const index = items.findIndex((item) => item.id === findingId)
      const delta = key === 'j' || key === 'ArrowDown' ? 1 : -1
      const next = items[index + delta]
      if (!next) return
      event.preventDefault()
      select(next)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [items, findingId, select])

  /**
   * Rescan runs the built-in detection engine and then the Suricata matcher.
   * The detection engine rewrites every finding row for the analysis, so
   * Suricata matches have to be re-created afterwards.
   */
  const rescan = useMutation({
    mutationFn: async () => {
      const built = await findingsApi.rescan(analysisId as string)
      const suricata = await suricataApi.run(analysisId as string)
      return { built, suricata }
    },
    onSuccess: ({ built, suricata }) => {
      setNotice(
        `Re-ran ${formatNumber(built.rules_run)} built-in rule(s) → ${formatNumber(
          built.findings,
        )} finding(s); Suricata matched ${formatNumber(suricata.rules_matched)} rule(s) → ${formatNumber(
          suricata.findings,
        )} finding(s).`,
      )
      void queryClient.invalidateQueries({ queryKey: ['findings', analysisId] })
      void queryClient.invalidateQueries({ queryKey: ['finding-rules', analysisId] })
      void queryClient.invalidateQueries({ queryKey: ['finding-context'] })
      void queryClient.invalidateQueries({ queryKey: ['findings-counts', analysisId] })
      void queryClient.invalidateQueries({ queryKey: ['summary', analysisId] })
    },
  })

  const counts = list.data?.counts
  const total = list.data?.total ?? 0

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <Panel flush>
        <Toolbar>
          <div className="flex items-center gap-1">
            {SEVERITY_FILTERS.map((value) => {
              const count = value ? counts?.[value] : counts ? counts.high + counts.medium + counts.low + counts.informational : 0
              return (
                <button
                  key={value || 'all'}
                  type="button"
                  className={clsx('btn px-1.5 py-1', severity === value && 'btn-primary')}
                  onClick={() => setSeverity(value)}
                  title={value ? `Only ${value} findings` : 'All severities'}
                >
                  {value === '' ? 'all' : value}
                  <span className="mono text-2xs text-faint">{formatNumber(count ?? 0)}</span>
                </button>
              )
            })}
          </div>
          <input
            className="input w-56"
            placeholder="search title, reason, rule id…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <select
            className="select max-w-56"
            value={ruleId}
            onChange={(event) => setRuleId(event.target.value)}
            title="Filter by rule"
          >
            <option value="">all rules</option>
            {(rules.data?.items ?? []).map((rule) => (
              <option key={rule.rule_id} value={rule.rule_id}>
                {rule.rule_id} ({rule.hits ?? rule.count ?? 0})
              </option>
            ))}
          </select>
          <label className="flex items-center gap-1 text-2xs text-muted">
            <input
              type="checkbox"
              checked={suricataOnly}
              onChange={(event) => setSuricataOnly(event.target.checked)}
            />
            Suricata only
          </label>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              type="button"
              className="btn"
              onClick={() => void list.refetch()}
              title="Reload the findings list"
            >
              <RefreshCw size={13} aria-hidden />
              Refresh
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={rescan.isPending}
              onClick={() => rescan.mutate()}
              title="Re-run the built-in detection rules and then the Suricata matcher for this capture"
            >
              <ListTree size={13} aria-hidden />
              {rescan.isPending ? 'Re-running…' : 'Re-run rules'}
            </button>
          </div>
        </Toolbar>

        {notice ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-accent2">
            <Info size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span className="flex-1">{notice}</span>
            <button type="button" className="btn btn-ghost px-1 py-0.5" onClick={() => setNotice(null)}>
              ✕
            </button>
          </div>
        ) : null}
        {rescan.error ? (
          <ErrorState
            error={toApiError(rescan.error)}
            variant="plain"
            title="Could not re-run the rules"
            className="py-3"
          />
        ) : null}
      </Panel>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[22rem_minmax(0,1fr)]">
        {/* One column below `xl` (the two panes stack and the page scrolls), two
            bounded panes from `xl` up: `h-full` fills the grid row and `overflow-hidden` keeps
            the virtualized list inside it. `xl:min-h-0` drops the stacking floor, which
            would otherwise be a floor above the pane and force the page to scroll. */}
        <section className="panel flex min-h-[24rem] flex-col overflow-hidden xl:h-full xl:min-h-0">
          <div className="panel-header">
            <span className="panel-title">Findings</span>
            <span className="text-2xs text-faint">{formatNumber(total)} total</span>
          </div>
          <div className="min-h-0 flex-1">
            <FindingsList
              items={items}
              total={total}
              selectedId={findingId ?? null}
              isLoading={list.isLoading}
              error={list.error}
              onRetry={() => void list.refetch()}
              onSelect={select}
            />
          </div>
        </section>

        <section className="flex min-h-0 flex-col gap-3 xl:overflow-hidden">
          {!findingId ? (
            <EmptyState
              icon={ShieldAlert}
              title="Select a finding"
              description="Pick a finding on the left to see the packets that triggered it, the conversation they belong to and everything else the capture holds about it."
            />
          ) : context.isLoading ? (
            <LoadingState label="Loading the finding context…" rows={6} />
          ) : context.error ? (
            <ErrorState
              error={context.error}
              onRetry={() => void context.refetch()}
              title="Could not load this finding"
            />
          ) : context.data ? (
            <div className="flex min-h-0 flex-1 flex-col gap-3 xl:overflow-hidden">
              <div className="panel flex flex-col">
                <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <SeverityBadge severity={context.data.finding.severity} showLabel />
                  <span className="min-w-0 flex-1 truncate font-display text-[1.3rem] text-text" title={context.data.finding.title}>
                    {context.data.finding.title}
                  </span>
                  <span className="mono text-2xs text-faint">{context.data.finding.rule_id}</span>
                </div>
                <nav className="flex flex-wrap items-center gap-1 border-t border-border px-2 py-1.5">
                  {TABS.map((entry) => {
                    const badge =
                      entry.id === 'packets'
                        ? context.data.counts.alerting_packets
                        : entry.id === 'conversation'
                          ? context.data.counts.conversations
                          : entry.id === 'application'
                            ? context.data.counts.http + context.data.counts.dns + context.data.counts.tls
                            : entry.id === 'files'
                              ? context.data.counts.objects
                              : entry.id === 'related'
                                ? context.data.counts.related
                                : entry.id === 'timeline'
                                  ? context.data.timeline.length
                                  : null
                    return (
                      <button
                        key={entry.id}
                        type="button"
                        className={clsx('btn btn-tab text-[0.7rem]', tab === entry.id && 'btn-primary')}
                        onClick={() => setTab(entry.id)}
                      >
                        <entry.icon size={13} aria-hidden />
                        {entry.label}
                        {badge !== null ? <span className="mono text-faint">{badge}</span> : null}
                      </button>
                    )
                  })}
                </nav>
              </div>

              <div className="min-h-0 flex-1 xl:overflow-auto">
                {tab === 'overview' ? (
                  <FindingOverview context={context.data} />
                ) : null}
                {tab === 'timeline' ? (
                  <FindingTimeline
                    timeline={context.data.timeline}
                    truncated={context.data.truncated.timeline}
                    limit={context.data.limits.timeline}
                    onOpenPacket={(packet) => navigate(`/packets?sel=${packet}`)}
                  />
                ) : null}
                {tab === 'packets' ? (
                  <FindingPackets
                    analysisId={analysisId as string}
                    packets={context.data.packets}
                    truncated={context.data.truncated.packets}
                    limit={context.data.limits.packets}
                    alertingCount={context.data.counts.alerting_packets}
                  />
                ) : null}
                {tab === 'conversation' ? (
                  <FindingConversation
                    analysisId={analysisId as string}
                    context={context.data}
                    conversations={context.data.conversations}
                    streams={context.data.streams}
                    truncated={context.data.truncated.streams}
                    followMode={String(context.data.follow_mode)}
                  />
                ) : null}
                {tab === 'application' ? (
                  <FindingAppLayer
                    http={context.data.http}
                    dns={context.data.dns}
                    tls={context.data.tls}
                  />
                ) : null}
                {tab === 'files' ? (
                  <FindingObjects
                    analysisId={analysisId as string}
                    objects={context.data.objects}
                    truncated={context.data.truncated.objects}
                  />
                ) : null}
                {tab === 'related' ? (
                  <FindingRelated
                    items={context.data.related}
                    truncated={context.data.truncated.related}
                    onSelect={(id) => navigate(`/findings/${encodeURIComponent(id)}?tab=related`)}
                  />
                ) : null}
              </div>
            </div>
          ) : null}
        </section>
      </div>
    </div>
  )
}

/** Findings workbench: triage list on the left, full context on the right. */
export function FindingsPage() {
  return (
    /* `page-fill` gives the workbench a height to resolve its `h-full min-h-0`
       panes against; without it they collapse to their content height. */
    <Page section={SECTIONS.findings} className="page-fill" headerImage={pageBackground}>
      <AnalysisGuard>
        <FindingsWorkbench />
      </AnalysisGuard>
    </Page>
  )
}

export default FindingsPage