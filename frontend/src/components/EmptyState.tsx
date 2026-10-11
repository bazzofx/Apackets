import type { ReactNode } from 'react'
import clsx from 'clsx'
import { Inbox, type LucideIcon } from 'lucide-react'

export interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: ReactNode
  action?: ReactNode
  className?: string
  /** `panel` draws the bordered surface; `plain` renders inline. */
  variant?: 'panel' | 'plain'
}

/** Honest empty state — never rendered with fake rows behind it. */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
  variant = 'panel',
}: EmptyStateProps) {
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center gap-2 px-6 py-10 text-center',
        variant === 'panel' && 'panel',
        className,
      )}
    >
      <Icon size={22} className="text-faint" aria-hidden />
      <div className="text-sm font-medium text-text">{title}</div>
      {description ? (
        <div className="max-w-md text-xs leading-relaxed text-muted">{description}</div>
      ) : null}
      {action ? <div className="mt-1 flex items-center gap-2">{action}</div> : null}
    </div>
  )
}

export default EmptyState
