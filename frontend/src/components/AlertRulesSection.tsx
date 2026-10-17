import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ScanSearch, ShieldAlert } from 'lucide-react'
import DetectionRulesPanel from '@/components/DetectionRulesPanel'
import SuricataRulesPanel from '@/components/SuricataRulesPanel'
import { useAnalysis } from '@/hooks/useAnalysis'
import { detectionApi, suricataApi } from '@/services/api'
import { formatNumber } from '@/utils/format'

type RulesTab = 'detection' | 'suricata'

interface TabDefinition {
  id: RulesTab
  label: string
  icon: typeof ScanSearch
  blurb: string
}

const TABS: TabDefinition[] = [
  {
    id: 'detection',
    label: 'Detection rules',
    icon: ScanSearch,
    blurb: 'the built-in heuristics, with their tunable thresholds',
  },
  {
    id: 'suricata',
    label: 'Suricata rules',
    icon: ShieldAlert,
    blurb: 'the imported signatures, matched against extracted fields',
  },
]

/**
 * The Alert rules section: one place for everything that decides what a capture
 * flags, split into the two families of rule the application has.
 *
 * The two panels used to be stacked, which made the page long and made it easy to
 * tune a detection threshold without noticing the Suricata table below it. They
 * are now tabs of one section, and the section header carries the two counts that
 * matter: how many rules in each family are not running their defaults.
 *
 * The tab also settles the two deep links the Findings page uses - sid= for a
 * Suricata rule and rule= for a built-in one - so arriving from a finding always
 * lands on the tab that owns that rule.
 */
export function AlertRulesSection() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { analysisId } = useAnalysis()

  /* A finding's own link wins over a remembered tab: an analyst who clicked
     "edit in settings" means that rule, not the tab they used last. */
  const requested = searchParams.get('rules')
  const tab: RulesTab = searchParams.get('sid')
    ? 'suricata'
    : searchParams.get('rule')
      ? 'detection'
      : requested === 'suricata'
        ? 'suricata'
        : 'detection'

  /* Both counts are read here and by the panels below; react-query keys them, so
     this is one request per list, not two. */
  const detection = useQuery({
    queryKey: ['detection-rules', analysisId],
    queryFn: () => detectionApi.rules(analysisId),
  })
  const stats = useQuery({ queryKey: ['suricata-stats'], queryFn: () => suricataApi.stats() })

  const modified: Record<RulesTab, number> = {
    detection: (detection.data?.items ?? []).filter((rule) => rule.modified).length,
    suricata: stats.data?.modified ?? 0,
  }
  const total: Record<RulesTab, number | undefined> = {
    detection: detection.data?.total,
    suricata: stats.data?.total,
  }

  const select = (next: RulesTab) => {
    const updated = new URLSearchParams(searchParams)
    updated.set('rules', next)
    /* A deep link describing a rule in the other family would otherwise keep the
       URL pointing at a table that is no longer on screen. */
    if (next === 'detection') updated.delete('sid')
    else updated.delete('rule')
    setSearchParams(updated, { replace: true })
  }

  return (
    <div className="flex flex-col gap-3">
      <section className="panel">
        <header className="panel-header">
          <div className="min-w-0">
            <div className="panel-title">Alert rules</div>
            <div className="panel-subtitle">
              everything the analyser flags - rows tinted amber are not running their defaults
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {TABS.map((entry) => {
              const active = tab === entry.id
              const count = modified[entry.id]
              return (
                <button
                  key={entry.id}
                  type="button"
                  className={clsx('btn px-2 py-1', active && 'btn-primary')}
                  onClick={() => select(entry.id)}
                  aria-pressed={active}
                  title={entry.blurb}
                >
                  <entry.icon size={13} aria-hidden />
                  {entry.label}
                  {typeof total[entry.id] === 'number' ? (
                    <span className="mono text-2xs opacity-70">{formatNumber(total[entry.id])}</span>
                  ) : null}
                  {count > 0 ? (
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
        </header>
        <div className="flex items-start gap-2 border-t border-border px-3 py-2 text-2xs text-muted">
          <ShieldAlert size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <span>
            Both families are decisions this installation makes about your traffic, so both are
            editable here. Each panel states what it can change and what it cannot: a Suricata
            rule's text is editable, and so are the built-in rules' thresholds, but a built-in
            rule's logic is not. <span className="font-semibold">Restore</span> puts a rule back to
            its default - the vendored text for a signature, the documented thresholds for a
            heuristic.
          </span>
        </div>
      </section>

      {tab === 'detection' ? <DetectionRulesPanel /> : <SuricataRulesPanel />}
    </div>
  )
}

export default AlertRulesSection
