import clsx from 'clsx'
import { formatNumber } from '@/utils/format'
import type { Severity } from '@/types'

const SEVERITY_STYLES: Record<Severity, string> = {
  informational: 'border-sev-informational/50 bg-sev-informational/15 text-sev-informational',
  low: 'border-sev-low/50 bg-sev-low/15 text-sev-low',
  medium: 'border-sev-medium/50 bg-sev-medium/15 text-sev-medium',
  high: 'border-sev-high/50 bg-sev-high/15 text-sev-high',
}

const SEVERITY_LABELS: Record<Severity, string> = {
  informational: 'info',
  low: 'low',
  medium: 'medium',
  high: 'high',
}

/** Bar/dot colour for a severity, for use outside the badge. */
export const SEVERITY_HEX: Record<Severity, string> = {
  informational: '#64748b',
  low: '#38bdf8',
  medium: '#f59e0b',
  high: '#ef4444',
}

export function isSeverity(value: unknown): value is Severity {
  return (
    value === 'informational' ||
    value === 'low' ||
    value === 'medium' ||
    value === 'high'
  )
}

export interface SeverityBadgeProps {
  severity: Severity | string | null | undefined
  /** Optional count rendered after the label, e.g. `<SeverityBadge severity="high" count={3} />`. */
  count?: number | null
  /** Set false to render only the count. */
  showLabel?: boolean
  className?: string
}

/** Severity chip: informational / low / medium / high, optionally with a count. */
export function SeverityBadge({
  severity,
  count,
  showLabel = true,
  className,
}: SeverityBadgeProps) {
  if (!isSeverity(severity) && (count === null || count === undefined)) return null
  const key: Severity = isSeverity(severity) ? severity : 'informational'
  const label = SEVERITY_LABELS[key]
  return (
    <span
      className={clsx('chip', SEVERITY_STYLES[key], className)}
      title={key}
      data-severity={key}
    >
      {showLabel ? <span className="uppercase tracking-wide">{label}</span> : null}
      {count !== null && count !== undefined ? <span>{formatNumber(count)}</span> : null}
    </span>
  )
}

export default SeverityBadge
