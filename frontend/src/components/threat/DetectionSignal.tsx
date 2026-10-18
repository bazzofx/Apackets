import clsx from 'clsx'
import { Radar } from 'lucide-react'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntIndicator } from '@/types'
import { STATUS_META, useStatusColours } from './cockpitKit'

export interface DetectionSignalProps {
  indicators: ThreatHuntIndicator[]
  selectedId: string | null
  onSelect: (id: string) => void
}

/**
 * The primary plot: every detection that computed a result, ranked by its own headline.
 *
 * A bar is as long as that detection's headline measure relative to the largest one on
 * the page, and every row prints its own unit beside it. The measures are unlike things -
 * events, hosts, ports, addresses - so the ranking is a triage order, not a comparison of
 * one unit against another; the subtitle and every row's tooltip say so, because a chart
 * that quietly implies comparability would be the one dishonest thing on this page.
 *
 * Each row is a button: the chart is the way into the evidence, not a picture of it. The
 * selected row stays lit so the plot and the investigation panel cannot disagree.
 */
export function DetectionSignal({ indicators, selectedId, onSelect }: DetectionSignalProps) {
  const colours = useStatusColours()
  const rows = indicators
    .filter((indicator) => indicator.availability === 'ok')
    .filter((indicator) => Number.isFinite(indicator.headline.value))
    .slice()
    .sort((left, right) => right.headline.value - left.headline.value)

  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center gap-1 px-3 py-8 text-center">
        <Radar size={20} className="text-faint" aria-hidden />
        <p className="text-xs text-muted">No detection in this capture crossed its threshold</p>
        <p className="max-w-md text-2xs leading-relaxed text-faint">
          Every detection that could run answered with nothing above its threshold, so there
          is nothing to rank here. The grid below still lists each detection, whether it ran,
          and why it stayed quiet.
        </p>
      </div>
    )
  }

  const max = Math.max(1, ...rows.map((row) => Math.max(0, row.headline.value)))

  return (
    <div className="flex flex-col" data-threat-signal>
      {rows.map((indicator) => {
        const value = Math.max(0, indicator.headline.value)
        const active = indicator.id === selectedId
        const colour = colours[indicator.availability]
        return (
          <button
            key={indicator.id}
            type="button"
            onClick={() => onSelect(indicator.id)}
            aria-pressed={active}
            data-threat-signal-row={indicator.id}
            title={
              indicator.title +
              ': ' +
              formatNumber(indicator.headline.value) +
              ' ' +
              indicator.headline.label +
              ' - open its evidence'
            }
            className={clsx('cockpit-signal-row', active && 'is-active')}
          >
            <span className="cockpit-signal-dot" style={{ background: colour }} aria-hidden />
            <span className="cockpit-signal-title truncate">{indicator.title}</span>
            <span className="cockpit-signal-track">
              <span
                className="cockpit-signal-fill"
                style={{ width: `${Math.max(1.5, (value / max) * 100)}%`, background: colour }}
              />
            </span>
            <span className="mono cockpit-signal-value">{formatNumber(indicator.headline.value)}</span>
            <span className="cockpit-signal-label truncate">{indicator.headline.label}</span>
          </button>
        )
      })}
      <p className="px-2 pt-2 text-2xs leading-relaxed text-faint">
        Bar length is each detection&rsquo;s own headline measure against the largest on this
        page, and every row names its own unit &mdash; {STATUS_META.ok.short} detections are
        ranked as a triage order, not compared against a common scale.
      </p>
    </div>
  )
}

export default DetectionSignal