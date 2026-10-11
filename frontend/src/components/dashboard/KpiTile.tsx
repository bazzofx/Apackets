import type { LucideIcon } from 'lucide-react'
import clsx from 'clsx'
import { EMPTY, formatBytes, formatDuration, formatNumber } from '@/utils/format'

export type KpiFormat = 'number' | 'bytes' | 'duration' | 'raw'

export interface KpiTileProps {
  label: string
  value: number | string | null | undefined
  icon: LucideIcon
  format?: KpiFormat
  /** Small line under the number: units, context or a breakdown. */
  detail?: string
  /** Emphasise the tile (used for findings). */
  tone?: 'default' | 'accent' | 'danger'
  className?: string
}

function render(value: KpiTileProps['value'], format: KpiFormat): string {
  if (value === null || value === undefined) return EMPTY
  switch (format) {
    case 'bytes':
      return typeof value === 'number' ? formatBytes(value) : String(value)
    case 'duration':
      return typeof value === 'number' ? formatDuration(value) : String(value)
    case 'number':
      return formatNumber(value)
    default:
      return typeof value === 'number' ? formatNumber(value) : value
  }
}

/** Large at-a-glance tile: big number, quiet label, one icon. */
export function KpiTile({
  label,
  value,
  icon: Icon,
  format = 'number',
  detail,
  tone = 'default',
  className,
}: KpiTileProps) {
  const missing = value === null || value === undefined
  return (
    <div
      className={clsx(
        'panel flex flex-col gap-1 px-3 py-3',
        tone === 'accent' && 'border-accent/40',
        tone === 'danger' && 'border-danger/40',
        className,
      )}
    >
      <div className="flex items-center gap-1.5">
        <Icon
          size={14}
          className={clsx(
            'shrink-0',
            tone === 'danger' ? 'text-danger' : tone === 'accent' ? 'text-accent2' : 'text-faint',
          )}
          aria-hidden
        />
        <span className="truncate text-2xs font-semibold uppercase tracking-wider text-muted">
          {label}
        </span>
      </div>
      <div
        className={clsx(
          'mono text-2xl leading-tight',
          missing ? 'text-faint' : tone === 'danger' ? 'text-red-300' : 'text-text',
        )}
      >
        {render(value, format)}
      </div>
      {detail ? (
        <div className="truncate text-2xs text-faint" title={detail}>
          {detail}
        </div>
      ) : null}
    </div>
  )
}

export default KpiTile