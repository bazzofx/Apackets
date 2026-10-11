import type { ReactNode } from 'react'
import clsx from 'clsx'

export interface ToolbarProps {
  children?: ReactNode
  /** Extra controls pinned to the right edge. */
  actions?: ReactNode
  className?: string
}

/** Filter/action strip used above dense tables. */
export function Toolbar({ children, actions, className }: ToolbarProps) {
  return (
    <div
      className={clsx(
        'flex flex-wrap items-center gap-2 border-b border-border px-3 py-2',
        className,
      )}
    >
      {children}
      {actions ? <div className="ml-auto flex items-center gap-1.5">{actions}</div> : null}
    </div>
  )
}

export default Toolbar
