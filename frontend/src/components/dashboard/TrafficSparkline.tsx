import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { CSSProperties } from 'react'
import clsx from 'clsx'
import { formatBytes, formatClockTime, formatNumber } from '@/utils/format'
import type { TrafficSeriesPoint } from '@/types'

const AXIS_TICK = { fill: '#8296b4', fontSize: 10 }
const GRID_STROKE = '#22304d'
const TOOLTIP_STYLE: CSSProperties = {
  background: '#16203a',
  border: '1px solid #2c3c5e',
  borderRadius: 4,
  fontSize: 11,
  color: '#e2e8f0',
}

export interface TrafficSparklineProps {
  series: TrafficSeriesPoint[]
  height?: number
}

/** Compact traffic shape: one series at a time, so the scale stays readable. */
export function TrafficSparkline({ series, height = 190 }: TrafficSparklineProps) {
  const [metric, setMetric] = useState<'packets' | 'bytes'>('packets')

  if (series.length === 0) {
    return <div className="px-3 py-8 text-center text-2xs text-faint">No traffic series.</div>
  }

  return (
    <div className="flex h-full flex-col">
      <div className="mb-1 flex items-center gap-1">
        {(['packets', 'bytes'] as const).map((value) => (
          <button
            key={value}
            type="button"
            className={clsx('btn px-1.5 py-0.5', metric === value && 'btn-primary')}
            onClick={() => setMetric(value)}
          >
            {value}
          </button>
        ))}
      </div>
      <div style={{ height: height - 28 }} className="min-h-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={GRID_STROKE} vertical={false} />
            <XAxis
              dataKey="t"
              tick={AXIS_TICK}
              stroke={GRID_STROKE}
              minTickGap={36}
              tickFormatter={(value: number) => formatClockTime(value)}
            />
            <YAxis
              tick={AXIS_TICK}
              stroke={GRID_STROKE}
              width={54}
              tickFormatter={(value: number) =>
                metric === 'bytes' ? formatBytes(value, 0) : formatNumber(value)
              }
            />
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              itemStyle={{ color: '#e2e8f0' }}
              labelFormatter={(label) => formatClockTime(Number(label))}
              formatter={(value) => [
                metric === 'bytes' ? formatBytes(Number(value)) : formatNumber(Number(value)),
                metric,
              ]}
            />
            <Area
              type="monotone"
              dataKey={metric}
              name={metric}
              stroke="#3b82f6"
              strokeWidth={1.5}
              fill="#3b82f6"
              fillOpacity={0.18}
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default TrafficSparkline