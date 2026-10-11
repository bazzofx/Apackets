import type { ReactNode } from 'react'
import clsx from 'clsx'
import { BarChart3 } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'

export interface ChartPanelProps {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  /** Chart height in px (the body is fixed-height and clipped). */
  height?: number
  isEmpty?: boolean
  emptyTitle?: string
  emptyDescription?: ReactNode
  isLoading?: boolean
  error?: unknown
  onRetry?: () => void
  children: ReactNode
  className?: string
}

/** Fixed-height chart container with built-in empty / loading / error states. */
export function ChartPanel({
  title,
  subtitle,
  actions,
  height = 220,
  isEmpty = false,
  emptyTitle = 'No data',
  emptyDescription,
  isLoading = false,
  error,
  onRetry,
  children,
  className,
}: ChartPanelProps) {
  return (
    <section className={clsx('panel flex flex-col', className)}>
      <header className="panel-header">
        <div className="min-w-0">
          <div className="panel-title">{title}</div>
          {subtitle !== undefined ? (
            <div className="panel-subtitle">{subtitle}</div>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
      </header>
      <div className="p-2" style={{ height }}>
        {error ? (
          <ErrorState error={error} onRetry={onRetry} variant="plain" className="h-full py-2" />
        ) : isLoading ? (
          <LoadingState label="Loading chart…" className="h-full justify-center" />
        ) : isEmpty ? (
          <EmptyState
            icon={BarChart3}
            title={emptyTitle}
            description={emptyDescription}
            variant="plain"
            className="h-full py-2"
          />
        ) : (
          <div className="h-full w-full">{children}</div>
        )}
      </div>
    </section>
  )
}

export default ChartPanel
