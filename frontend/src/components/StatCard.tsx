import clsx from 'clsx'
import type { LucideIcon } from 'lucide-react'
import { EMPTY, formatBytes, formatDuration, formatNumber } from '@/utils/format'

export type StatFormat = 'number' | 'bytes' | 'duration' | 'raw'

export interface StatCardProps {
  label: string
  value: number | string | null | undefined
  /** Small line under the value (units, numerator, etc.). */
  sublabel?: string | null
  icon?: LucideIcon
  format?: StatFormat
  /** Tooltip text, e.g. the query the number came from. */
  hint?: string
  className?: string
}

function renderValue(value: StatCardProps['value'], format: StatFormat): string {
  if (value === null || value === undefined) return EMPTY
  switch (format) {
    case 'bytes':
      return typeof value === 'number' ? formatBytes(value) : String(value)
    case 'duration':
      return typeof value === 'number' ? formatDuration(value) : String(value)
    case 'number':
      return formatNumber(value)
    case 'raw':
    default:
      return typeof value === 'number' ? formatNumber(value) : value
  }
}

/** Dense KPI tile used across the dashboard. */
export function StatCard({
  label,
  value,
  sublabel,
  icon: Icon,
  format = 'number',
  hint,
  className,
}: StatCardProps) {
  const missing = value === null || value === undefined
  return (
    <div className={clsx('panel px-3 py-2.5', className)} title={hint}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
          {label}
        </span>
        {Icon ? <Icon size={14} className="shrink-0 text-faint" aria-hidden /> : null}
      </div>
      <div
        className={clsx(
          'mt-1 truncate font-mono text-lg leading-tight',
          missing ? 'text-faint' : 'text-text',
        )}
      >
        {renderValue(value, format)}
      </div>
      {sublabel ? (
        <div className="mt-0.5 truncate text-2xs text-faint" title={sublabel}>
          {sublabel}
        </div>
      ) : null}
    </div>
  )
}

export default StatCard
