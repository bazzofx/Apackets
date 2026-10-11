import clsx from 'clsx'
import { Loader2 } from 'lucide-react'

export interface LoadingStateProps {
  label?: string
  /** Number of skeleton rows to draw (tables/tiles). */
  rows?: number
  className?: string
  inline?: boolean
}

/** Minimal loading indicator: one spinner line, optionally skeleton rows. */
export function LoadingState({
  label = 'Loading…',
  rows = 0,
  className,
  inline = false,
}: LoadingStateProps) {
  return (
    <div
      className={clsx(
        'flex flex-col gap-2 px-3 py-4',
        inline && 'flex-row items-center py-2',
        className,
      )}
      aria-busy="true"
      aria-live="polite"
    >
      <div className="flex items-center gap-2 text-xs text-muted">
        <Loader2 size={13} className="animate-spin text-faint" aria-hidden />
        <span>{label}</span>
      </div>
      {rows > 0 ? (
        <div className="flex flex-col gap-1.5">
          {Array.from({ length: rows }).map((_, index) => (
            <div
              key={index}
              className="h-5 animate-pulse rounded bg-surface2/70"
              style={{ width: `${100 - index * 6}%` }}
            />
          ))}
        </div>
      ) : null}
    </div>
  )
}

export default LoadingState
