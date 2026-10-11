import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { CSSProperties } from 'react'
import clsx from 'clsx'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatBytes, formatClockTime, formatNumber } from '@/utils/format'
import type { TrafficSeriesPoint } from '@/types'


export interface TrafficSparklineProps {
  series: TrafficSeriesPoint[]
  height?: number
}

/** Compact traffic shape: one series at a time, so the scale stays readable. */
export function TrafficSparkline({ series, height = 190 }: TrafficSparklineProps) {
  const tokens = useThemeTokens()
  const axisTick = { fill: tokens.muted, fontSize: 10 }
  const gridStroke = tokens.border
  const tooltipStyle: CSSProperties = {
    background: tokens.surface2,
    border: '1px solid ' + tokens.border2,
    borderRadius: 4,
    fontSize: 11,
    color: tokens.text,
  }
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
            <CartesianGrid stroke={gridStroke} vertical={false} />
            <XAxis
              dataKey="t"
              tick={axisTick}
              stroke={gridStroke}
              minTickGap={36}
              tickFormatter={(value: number) => formatClockTime(value)}
            />
            <YAxis
              tick={axisTick}
              stroke={gridStroke}
              width={54}
              tickFormatter={(value: number) =>
                metric === 'bytes' ? formatBytes(value, 0) : formatNumber(value)
              }
            />
            <Tooltip
              contentStyle={tooltipStyle}
              itemStyle={{ color: tokens.text }}
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
              stroke={tokens.accent}
              strokeWidth={1.5}
              fill={tokens.accent}
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