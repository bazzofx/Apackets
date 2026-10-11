import type { ReactNode } from 'react'
import clsx from 'clsx'

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
}: PanelProps) {
  const hasHeader = title !== undefined || subtitle !== undefined || actions !== undefined
  return (
    <section className={clsx('panel flex flex-col', className)}>
      {hasHeader ? (
        <header className="panel-header">
          <div className="min-w-0">
            {title !== undefined ? <div className="panel-title">{title}</div> : null}
            {subtitle !== undefined ? (
              <div className="mt-0.5 truncate text-2xs text-faint" title={typeof subtitle === 'string' ? subtitle : undefined}>
                {subtitle}
              </div>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={clsx(!flush && 'p-3', bodyClassName)}>{children}</div>
    </section>
  )
}

export default Panel
