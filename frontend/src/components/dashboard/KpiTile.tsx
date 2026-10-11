import type { LucideIcon } from 'lucide-react'
import { ArrowUpRight } from 'lucide-react'
import { Link } from 'react-router-dom'
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
  /**
   * The page that holds the rows behind this number. When set the tile becomes a
   * link, so a headline can always be opened into the detail it summarises; omit it
   * where no page owns the figure.
   */
  to?: string
  /** Tooltip override; defaults to `Open <label>`. */
  title?: string
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

/**
 * Large at-a-glance tile: big number, quiet label, one icon.
 *
 * With `to` the whole tile is a link into the page that holds the underlying rows,
 * and the corner arrow plus the hover border are the only cues added: the figure,
 * the label and the detail line render identically either way, so a tile that has no
 * page to open does not look disabled.
 */
export function KpiTile({
  label,
  value,
  icon: Icon,
  format = 'number',
  detail,
  tone = 'default',
  className,
  to,
  title,
}: KpiTileProps) {
  const missing = value === null || value === undefined
  const linked = to !== undefined && to !== ''

  const body = (
    <>
      <div className="flex items-center gap-1.5">
        <Icon
          size={14}
          className={clsx(
            'shrink-0',
            tone === 'danger' ? 'text-danger' : tone === 'accent' ? 'text-accent2' : 'text-faint',
          )}
          aria-hidden
        />
        <span className="min-w-0 flex-1 truncate text-2xs font-semibold uppercase tracking-wider text-muted">
          {label}
        </span>
        {linked ? (
          <ArrowUpRight
            size={12}
            className="shrink-0 text-faint transition-colors group-hover:text-accent2"
            aria-hidden
          />
        ) : null}
      </div>
      <div
        className={clsx(
          'mono text-[1.75rem] leading-none tracking-tight',
          missing ? 'text-faint' : tone === 'danger' ? 'text-red-300' : 'text-text',
        )}
      >
        {render(value, format)}
      </div>
      {detail ? (
        <div className="mt-0.5 truncate text-2xs text-faint" title={detail}>
          {detail}
        </div>
      ) : null}
    </>
  )

  const shell = clsx(
    'panel kpi flex flex-col gap-1 px-3 py-3 transition-colors hover:border-border2',
    tone === 'accent' && 'border-accent/40',
    tone === 'danger' && 'border-danger/40',
    linked && 'group h-full cursor-pointer',
    className,
  )

  if (!linked) return <div className={shell}>{body}</div>

  return (
    <Link to={to as string} className={shell} title={title ?? `Open ${label}`} data-kpi-link={to}>
      {body}
    </Link>
  )
}

export default KpiTile