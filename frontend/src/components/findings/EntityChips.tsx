import clsx from 'clsx'

export interface EntityChipsProps {
  label: string
  values: (string | number)[]
  /** Renders each value as a button (e.g. to filter by it). */
  onSelect?: (value: string) => void
  emptyLabel?: string
  className?: string
  max?: number
}

/** Compact, wrapping list of capture-derived entities (IPs, hosts, URIs ...). */
export function EntityChips({
  label,
  values,
  onSelect,
  emptyLabel,
  className,
  max = 24,
}: EntityChipsProps) {
  const items = values.filter((value) => value !== null && value !== undefined && value !== '')
  return (
    <div className={clsx('flex flex-wrap items-center gap-1', className)}>
      <span className="text-2xs uppercase tracking-wider text-faint">{label}</span>
      {items.length === 0 ? (
        <span className="text-2xs text-faint">{emptyLabel ?? 'none'}</span>
      ) : (
        items.slice(0, max).map((value) => {
          const text = String(value)
          return onSelect ? (
            <button
              key={text}
              type="button"
              className="chip border-border2 bg-surface2 text-text hover:border-accent hover:text-accent2"
              onClick={() => onSelect(text)}
              title={`Filter by ${text}`}
            >
              {text}
            </button>
          ) : (
            <span key={text} className="chip border-border2 bg-surface2 text-text" title={text}>
              {text}
            </span>
          )
        })
      )}
      {items.length > max ? (
        <span className="text-2xs text-faint">+{items.length - max} more</span>
      ) : null}
    </div>
  )
}

export default EntityChips