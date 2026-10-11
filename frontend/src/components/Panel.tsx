import type { ReactNode } from 'react'
import clsx from 'clsx'
import { ChevronDown } from 'lucide-react'

export interface PanelProps {
  title?: ReactNode
  subtitle?: ReactNode
  /** Right-aligned header controls. */
  actions?: ReactNode
  children?: ReactNode
  className?: string
  bodyClassName?: string
  /** Render the body without padding (dense tables). */
  flush?: boolean
  /**
   * When set, the whole header becomes the control that toggles the body, so
   * there is no separate Show/Hide button to aim at. `actions` stay outside the
   * control, because a button cannot contain another button.
   */
  onHeaderToggle?: () => void
  /** Expanded state, used for `aria-expanded` and the chevron. */
  headerExpanded?: boolean
}

/** Bordered surface with an optional dense header. */
export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  flush = false,
  onHeaderToggle,
  headerExpanded = true,
}: PanelProps) {
  const hasHeader = title !== undefined || subtitle !== undefined || actions !== undefined
  const heading = (
    <>
      {title !== undefined ? <div className="panel-title">{title}</div> : null}
      {subtitle !== undefined ? (
        <div className="panel-subtitle" title={typeof subtitle === 'string' ? subtitle : undefined}>
          {subtitle}
        </div>
      ) : null}
    </>
  )

  return (
    <section className={clsx('panel flex flex-col', className)}>
      {hasHeader ? (
        onHeaderToggle !== undefined ? (
          <header className="panel-header p-0">
            <button
              type="button"
              className="panel-disclosure"
              onClick={onHeaderToggle}
              aria-expanded={headerExpanded}
              title={headerExpanded ? 'Collapse this panel' : 'Expand this panel'}
            >
              <div className="min-w-0 flex-1">{heading}</div>
              <ChevronDown
                size={14}
                className={clsx(
                  'shrink-0 text-muted transition-transform',
                  !headerExpanded && '-rotate-90',
                )}
                aria-hidden
              />
            </button>
            {actions ? (
              <div className="flex shrink-0 items-center gap-1.5 pr-3">{actions}</div>
            ) : null}
          </header>
        ) : (
          <header className="panel-header">
            <div className="min-w-0">{heading}</div>
            {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
          </header>
        )
      ) : null}
      <div className={clsx(!flush && 'p-3', bodyClassName)}>{children}</div>
    </section>
  )
}

export default Panel
