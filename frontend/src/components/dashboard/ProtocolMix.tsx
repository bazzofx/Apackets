import { useState } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import type { CSSProperties } from 'react'
import clsx from 'clsx'
import { formatBytes, formatNumber } from '@/utils/format'
import type { ProtocolDistributionEntry } from '@/types'

const COLORS = ['#3b82f6', '#60a5fa', '#38bdf8', '#0ea5e9', '#6366f1', '#8b5cf6', '#a855f7']
const TOOLTIP_STYLE: CSSProperties = {
  background: '#16203a',
  border: '1px solid #2c3c5e',
  borderRadius: 4,
  fontSize: 11,
  color: '#e2e8f0',
}

export interface ProtocolMixProps {
  distribution: ProtocolDistributionEntry[]
  height?: number
}

/** Donut plus a small legend: which protocols dominate this capture. */
export function ProtocolMix({ distribution, height = 190 }: ProtocolMixProps) {
  const [metric, setMetric] = useState<'packets' | 'bytes'>('packets')
  const rows = [...distribution].sort((a, b) => (b[metric] ?? 0) - (a[metric] ?? 0)).slice(0, 7)
  const total = rows.reduce((sum, row) => sum + (row[metric] ?? 0), 0)

  if (rows.length === 0) {
    return <div className="px-3 py-8 text-center text-2xs text-faint">No protocol data.</div>
  }

  return (
    <div className="flex h-full items-center gap-3">
      <div style={{ height }} className="min-w-0 flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={rows}
              dataKey={metric}
              nameKey="protocol"
              innerRadius="58%"
              outerRadius="88%"
              paddingAngle={2}
              stroke="#0b1120"
              strokeWidth={1}
              isAnimationActive={false}
            >
              {rows.map((row, index) => (
                <Cell key={`${row.protocol}-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={TOOLTIP_STYLE}
              itemStyle={{ color: '#e2e8f0' }}
              formatter={(value, name) => [
                metric === 'bytes' ? formatBytes(Number(value)) : formatNumber(Number(value)),
                String(name),
              ]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="flex w-40 shrink-0 flex-col gap-1">
        <div className="flex items-center gap-1">
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
        {rows.map((row, index) => {
          const share = total > 0 ? ((row[metric] ?? 0) / total) * 100 : 0
          return (
            <div key={`${row.protocol}-legend-${index}`} className="flex items-center gap-1.5 text-2xs">
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-sm"
                style={{ background: COLORS[index % COLORS.length] }}
              />
              <span className="min-w-0 flex-1 truncate text-text" title={row.protocol}>
                {row.protocol}
              </span>
              <span className="mono shrink-0 text-faint">{share.toFixed(1)}%</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default ProtocolMix