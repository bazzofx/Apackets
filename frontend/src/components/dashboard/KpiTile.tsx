import type { LucideIcon } from 'lucide-react'
import { ArrowUpRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { EMPTY, formatBytes, formatDuration, formatNumber } from '@/utils/format'

export type KpiFormat = 'number' | 'bytes' | 'duration' | 'raw'

/**
 * The hue a metric is read in.
 *
 * Each figure has one colour and keeps it: telemetry cyan for traffic, red for what
 * needs attention, gold for volume, blue for addresses. The colour tints the card's top
 * hairline and the icon - never the number itself, which stays the brightest thing in
 * the card.
 */
export type KpiHue = 'red' | 'cyan' | 'blue' | 'gold' | 'green' | 'violet' | 'muted'

const HUE_VAR: Record<KpiHue, string> = {
  red: '--c-accent',
  cyan: '--c-accent2',
  blue: '--c-sev-low',
  gold: '--c-warn',
  green: '--c-ok',
  violet: '--c-chart-7',
  muted: '--c-faint',
}

export interface KpiTileProps {
  label: string
  value: number | string | null | undefined
  icon: LucideIcon
  format?: KpiFormat
  /** Small line under the number: units, context or a breakdown. */
  detail?: string
  /** Kept for the callers that emphasise a card; the hue now carries the colour. */
  tone?: 'default' | 'accent' | 'danger'
  /** The metric's colour. */
  hue?: KpiHue
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
 * A compact metric card: icon, uppercase label, the figure, one short line of context.
 *
 * With `to` the whole card is a link into the page that holds the underlying rows, and
 * the corner arrow plus the hover border are the only cues added: the figure, the label
 * and the detail line render identically either way, so a card with no page to open
 * does not look disabled.
 */
export function KpiTile({
  label,
  value,
  icon: Icon,
  format = 'number',
  detail,
  tone = 'default',
  hue = 'cyan',
  className,
  to,
  title,
}: KpiTileProps) {
  const missing = value === null || value === undefined
  const linked = to !== undefined && to !== ''
  const resolvedHue: KpiHue = tone === 'danger' ? 'red' : hue
  const hueStyle = { '--metric-hue': `var(${HUE_VAR[resolvedHue]})` } as React.CSSProperties

  const body = (
    <>
      <div className="flex items-center gap-1.5">
        <Icon size={13} className="shrink-0" style={{ color: `var(${HUE_VAR[resolvedHue]})` }} aria-hidden />
        <span className="metric-label min-w-0 flex-1 truncate">{label}</span>
        {linked ? (
          <ArrowUpRight
            size={12}
            className="shrink-0 text-faint transition-colors group-hover:text-accent2"
            aria-hidden
          />
        ) : null}
      </div>
      <div className={clsx('metric-value mono', missing && 'text-faint')}>
        {render(value, format)}
      </div>
      {detail ? (
        <div className="metric-detail truncate" title={detail}>
          {detail}
        </div>
      ) : null}
    </>
  )

  const shell = clsx('metric-card group', linked && 'h-full cursor-pointer', className)

  if (!linked) {
    return (
      <div className={shell} style={hueStyle}>
        {body}
      </div>
    )
  }

  return (
    <Link
      to={to as string}
      className={shell}
      style={hueStyle}
      title={title ?? `Open ${label}`}
      data-kpi-link={to}
    >
      {body}
    </Link>
  )
}

export default KpiTile
