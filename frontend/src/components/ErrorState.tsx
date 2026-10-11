import clsx from 'clsx'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { toApiError } from '@/services/api'

export interface ErrorStateProps {
  error: unknown
  onRetry?: () => void
  title?: string
  className?: string
  variant?: 'panel' | 'plain'
}

/** Renders an `ApiError` (message, code, retry) or any thrown value. */
export function ErrorState({
  error,
  onRetry,
  title = 'Request failed',
  className,
  variant = 'panel',
}: ErrorStateProps) {
  if (error === null || error === undefined) return null
  const apiError = toApiError(error)
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center gap-2 px-6 py-10 text-center',
        variant === 'panel' && 'panel',
        className,
      )}
      role="alert"
    >
      <AlertTriangle size={22} className="text-danger" aria-hidden />
      <div className="text-sm font-medium text-text">{title}</div>
      <div className="max-w-xl break-words text-xs leading-relaxed text-muted">
        {apiError.message}
      </div>
      <div className="chip border-danger/40 bg-danger/10 text-red-300" title="API error code">
        {apiError.code}
        {apiError.status ? ` · HTTP ${apiError.status}` : ''}
      </div>
      {onRetry ? (
        <button type="button" className="btn btn-primary mt-1" onClick={onRetry}>
          <RefreshCw size={13} aria-hidden />
          Retry
        </button>
      ) : null}
    </div>
  )
}

export default ErrorState
