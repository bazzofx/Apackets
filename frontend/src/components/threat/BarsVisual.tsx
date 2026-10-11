import { Link } from 'react-router-dom'
import MonoCell from '@/components/MonoCell'
import type { ThreatHuntBarsVisual } from '@/types'
import { VisualFrame, VisualNoData, formatUnitValue, useSeriesColour } from './visualKit'

export interface BarsVisualProps {
  visual: ThreatHuntBarsVisual
}

/**
 * Ranked horizontal bars (contract §4).
 *
 * `items` arrive already sorted, largest first, and already capped by the
 * backend — this component re-sorts nothing, so what is drawn is what was
 * measured. An item with a `to` is a `Link` into the page that can explain it.
 */
export function BarsVisual({ visual }: BarsVisualProps) {
  const seriesColour = useSeriesColour()
  const items = visual.items ?? []
  const unit = visual.unit ?? null

  if (items.length === 0) {
    return (
      <VisualFrame kind="bars" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="bars"
          why="This ranked-bar visual arrived with no items even though the indicator is marked computed, so nothing is drawn — an empty frame would read as “nothing matched”, which the indicator's own availability states instead."
        />
      </VisualFrame>
    )
  }

  const max = Math.max(1, ...items.map((item) => (Number.isFinite(item.value) ? item.value : 0)))
  const widest = items.reduce((best, item) => (item.value > best.value ? item : best), items[0])

  return (
    <VisualFrame
      kind="bars"
      title={visual.title}
      note={visual.note}
      caption={`${items.length} ranked row${items.length === 1 ? '' : 's'}; bar length is relative to the largest — ${widest.label} at ${formatUnitValue(widest.value, unit)}.`}
    >
      <ol className="flex min-w-0 flex-col gap-1">
        {items.map((item, index) => {
          const value = Number.isFinite(item.value) ? Math.max(0, item.value) : 0
          const percent = (value / max) * 100
          const linked = typeof item.to === 'string' && item.to !== ''
          return (
            <li
              key={`${item.label}-${index}`}
              className="flex min-w-0 items-center gap-2"
              title={`${item.label}: ${formatUnitValue(value, unit)}`}
            >
              <span className="mono w-4 shrink-0 text-right text-2xs text-faint">{index + 1}</span>
              <span className="w-44 min-w-0 shrink-0">
                {linked ? (
                  <Link
                    to={item.to as string}
                    className="block truncate mono text-2xs text-accent2 hover:underline"
                    title={`Open ${item.label}`}
                  >
                    {item.label}
                  </Link>
                ) : (
                  <MonoCell className="text-2xs text-text" maxWidth={176}>
                    {item.label}
                  </MonoCell>
                )}
              </span>
              <span className="h-2.5 min-w-0 flex-1 overflow-hidden rounded-sm bg-surface2">
                <span
                  data-threat-bar
                  data-threat-bar-value={value}
                  className="block h-full rounded-sm"
                  style={{ width: `${percent}%`, background: seriesColour(index) }}
                />
              </span>
              <span className="mono w-20 shrink-0 text-right text-2xs text-text">
                {formatUnitValue(value, unit)}
              </span>
            </li>
          )
        })}
      </ol>
    </VisualFrame>
  )
}

export default BarsVisual
