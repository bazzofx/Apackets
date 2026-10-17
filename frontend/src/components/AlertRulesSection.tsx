import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Fingerprint, KeyRound, ScanSearch, ShieldAlert, SlidersHorizontal } from 'lucide-react'
import DetectionRulesPanel from '@/components/DetectionRulesPanel'
import IndicatorsPanel from '@/components/IndicatorsPanel'
import SuricataRulesPanel from '@/components/SuricataRulesPanel'
import UsersPasswordsPanel from '@/components/UsersPasswordsPanel'
import { useAnalysis } from '@/hooks/useAnalysis'
import { detectionApi, suricataApi } from '@/services/api'
import { formatNumber } from '@/utils/format'

type AlertTab = 'detection' | 'suricata' | 'credentials' | 'indicators'

interface TabDefinition {
  id: AlertTab
  label: string
  icon: typeof ScanSearch
  blurb: string
  /** Tabs whose rows can be "not at their defaults" carry a count badge. */
  countsDeviations?: boolean
}

const TABS: TabDefinition[] = [
  {
    id: 'detection',
    label: 'Detection rules',
    icon: ScanSearch,
    blurb: 'the built-in heuristics, with their tunable thresholds',
    countsDeviations: true,
  },
  {
    id: 'suricata',
    label: 'Suricata rules',
    icon: ShieldAlert,
    blurb: 'the imported signatures, matched against extracted fields',
    countsDeviations: true,
  },
  {
    id: 'credentials',
    label: 'Users & Passwords',
    icon: KeyRound,
    blurb: 'the cleartext credential stage: whether it runs, and which protocols it reads',
  },
  {
    id: 'indicators',
    label: 'Indicators',
    icon: Fingerprint,
    blurb: 'the analyst-supplied values the indicator_match rule looks for',
  },
]

/**
 * The body of the Alert Settings page: everything that decides what a capture flags,
 * as four tabs.
 *
 * The two rule tables are what fires. The other two tabs are what those tables read:
 * the credential stage is a detection stage with its own switch, and an indicator is
 * the only reason `indicator_match` can ever match - so they are decisions this
 * installation makes about your traffic in exactly the same sense, and they belong
 * beside the rules rather than in the general configuration page.
 *
 * The tab is in the URL (`rules=`) and the two deep links the Findings page uses
 * settle it: `sid=` opens the Suricata table, `rule=` the built-in one.
 */
export function AlertRulesSection() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { analysisId } = useAnalysis()

  /* A finding's own link wins over a remembered tab: an analyst who clicked
     "edit in settings" means that rule, not the tab they used last. */
  const requested = searchParams.get('rules')
  const known = TABS.some((entry) => entry.id === requested)
  const tab: AlertTab = searchParams.get('sid')
    ? 'suricata'
    : searchParams.get('rule')
      ? 'detection'
      : known
        ? (requested as AlertTab)
        : 'detection'

  /* Both counts are read here and by the rule panels below; react-query keys them, so
     this is one request per list, not two. */
  const detection = useQuery({
    queryKey: ['detection-rules', analysisId],
    queryFn: () => detectionApi.rules(analysisId),
  })
  const stats = useQuery({ queryKey: ['suricata-stats'], queryFn: () => suricataApi.stats() })

  const modified: Record<AlertTab, number> = {
    detection: (detection.data?.items ?? []).filter((rule) => rule.modified).length,
    suricata: stats.data?.modified ?? 0,
    credentials: 0,
    indicators: 0,
  }
  const total: Record<AlertTab, number | undefined> = {
    detection: detection.data?.total,
    suricata: stats.data?.total,
    credentials: undefined,
    indicators: undefined,
  }

  const select = (next: AlertTab) => {
    const updated = new URLSearchParams(searchParams)
    updated.set('rules', next)
    /* A deep link describing a rule in another tab would otherwise keep the URL
       pointing at a table that is no longer on screen. */
    if (next === 'suricata') updated.delete('rule')
    else updated.delete('sid')
    setSearchParams(updated, { replace: true })
  }

  return (
    <div className="flex flex-col gap-3">
      <section className="panel">
        <header className="panel-header">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {TABS.map((entry) => {
              const active = tab === entry.id
              const count = modified[entry.id]
              return (
                <button
                  key={entry.id}
                  type="button"
                  className={clsx('btn btn-tab', active && 'btn-primary')}
                  onClick={() => select(entry.id)}
                  aria-pressed={active}
                  title={entry.blurb}
                >
                  <entry.icon size={13} aria-hidden />
                  {entry.label}
                  {typeof total[entry.id] === 'number' ? (
                    <span className="mono text-2xs opacity-70">{formatNumber(total[entry.id])}</span>
                  ) : null}
                  {entry.countsDeviations && count > 0 ? (
                    <span
                      className="chip border-warn/60 bg-warn/15 text-warn"
                      title={formatNumber(count) + ' rule(s) in this family are not at their defaults'}
                    >
                      {formatNumber(count)}
                    </span>
                  ) : null}
                </button>
              )
            })}
          </div>
          <span className="hidden shrink-0 items-center gap-1 text-2xs text-faint md:flex">
            <SlidersHorizontal size={12} aria-hidden />
            tinted rows are not at their defaults
          </span>
        </header>
        <div className="flex items-start gap-2 border-t border-border px-3 py-2 text-2xs text-muted">
          <ShieldAlert size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <span>
            Everything here is a decision this installation makes about your traffic, so everything
            here is editable - and each tab states what it can change and what it cannot. A
            Suricata rule's text is editable and so are the built-in rules' thresholds, but a
            built-in rule's logic is not. <span className="font-semibold">Restore</span> puts a rule
            back to its default: the vendored text for a signature, the documented thresholds for a
            heuristic.
          </span>
        </div>
      </section>

      {tab === 'detection' ? <DetectionRulesPanel /> : null}
      {tab === 'suricata' ? <SuricataRulesPanel /> : null}
      {tab === 'credentials' ? <UsersPasswordsPanel /> : null}
      {tab === 'indicators' ? <IndicatorsPanel /> : null}
    </div>
  )
}

export default AlertRulesSection
