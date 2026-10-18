import clsx from 'clsx'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { CSSProperties } from 'react'
import { useMotion } from '@/theme/MotionProvider'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntAvailability } from '@/types'
import { STATUS_META, STATUS_ORDER, useStatusColours } from './cockpitKit'

export interface StatusDonutProps {
  counts: Record<ThreatHuntAvailability, number>
  /** The status the grid is filtered to, or null for all of them. */
  filter: ThreatHuntAvailability | null
  onFilter: (status: ThreatHuntAvailability | null) => void
}


/**
 * The status split, as one donut: computed, nothing matched, not computable.
 *
 * The three states are not degrees of one thing. A detection that ran and found nothing
 * is a measured answer; a detection the capture cannot answer is a missing one. Painting
 * them as three sizes of the same ring is honest only because the legend names each and
 * the centre prints the total, so the reader never has to guess what 100% is.
 *
 * A slice is a filter: clicking one narrows the grid to that state, clicking it again
 * clears. That is the only interaction the plot needs, and it writes to the URL so the
 * filtered view is shareable.
 */
export function StatusDonut({ counts, filter, onFilter }: StatusDonutProps) {
  const tokens = useThemeTokens()
  const colours = useStatusColours()
  const { still } = useMotion()
  const total = STATUS_ORDER.reduce((sum, status) => sum + counts[status], 0)

  const data = STATUS_ORDER.filter((status) => counts[status] > 0).map((status) => ({
    status,
    name: STATUS_META[status].label,
    value: counts[status],
  }))

  const tooltipStyle: CSSProperties = {
    background: tokens.surface2,
    border: '1px solid ' + tokens.border2,
    borderRadius: 4,
    fontSize: 11,
    color: tokens.text,
  }

  return (
    <div className="flex flex-col gap-2" data-threat-donut>
      <div className="relative">
        <ResponsiveContainer width="100%" height={168}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={46}
              outerRadius={70}
              paddingAngle={2}
              stroke="none"
              isAnimationActive={!still}
            >
              {data.map((slice) => (
                <Cell
                  key={slice.status}
                  fill={colours[slice.status]}
                  opacity={filter === null || filter === slice.status ? 1 : 0.32}
                  cursor="pointer"
                  onClick={() => onFilter(filter === slice.status ? null : slice.status)}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={tooltipStyle}
              formatter={(value: number) => [formatNumber(value) + ' detection(s)', '']}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="mono text-xl leading-none text-text">{formatNumber(total)}</span>
          <span className="text-2xs text-faint">detections</span>
        </div>
      </div>

      <div className="flex flex-col gap-1">
        {STATUS_ORDER.map((status) => {
          const active = filter === status
          return (
            <button
              key={status}
              type="button"
              onClick={() => onFilter(active ? null : status)}
              aria-pressed={active}
              data-threat-donut-legend={status}
              title={STATUS_META[status].description}
              className={clsx('cockpit-legend-row', active && 'is-active')}
            >
              <span className="cockpit-signal-dot" style={{ background: colours[status] }} aria-hidden />
              <span className="min-w-0 flex-1 truncate text-2xs">{STATUS_META[status].label}</span>
              <span className="mono text-2xs text-text">{formatNumber(counts[status])}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default StatusDonut