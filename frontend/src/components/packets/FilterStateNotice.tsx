import { AlertTriangle, Filter, SearchX } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import { toApiError } from '@/services/api'

/**
 * The two packet-filter states that must never be conflated (contract §0):
 *
 * 1. the filter is **invalid** — TShark rejected the expression. `GET /packets`
 *    answers `422 invalid_filter` with `details.reason`, and the list response
 *    echoes `filter_valid: false` / `filter_error`. This is an error state.
 * 2. the filter is **valid but matched nothing** — a real, successful answer of
 *    zero rows. This is an empty state, and it must not be dressed up as an
 *    error.
 */

export interface FilterDiagnostics {
  /** True when the current request failed because the filter is not valid. */
  invalid: boolean
  /** Human-readable summary from the error envelope. */
  message: string | null
  /** TShark's own explanation, when the backend supplied one. */
  reason: string | null
}

/**
 * Classify a list response/error pair.
 *
 * `error` is the thrown `ApiError` (the `422` path); `filterValid`/`filterError`
 * come from a *successful* response body, which the backend also uses to report
 * an invalid display filter.
 */
export function filterDiagnostics(
  error: unknown,
  filterValid: boolean,
  filterError: string | null,
): FilterDiagnostics {
  if (error !== null && error !== undefined) {
    const apiError = toApiError(error)
    const reason = apiError.details?.reason
    return {
      invalid: apiError.code === 'invalid_filter' || apiError.status === 422,
      message: apiError.message,
      reason: typeof reason === 'string' && reason !== '' ? reason : null,
    }
  }
  if (!filterValid) {
    return {
      invalid: true,
      message: 'The backend reported that this display filter is not valid.',
      reason: filterError,
    }
  }
  return { invalid: false, message: null, reason: null }
}

export interface InvalidFilterStateProps {
  diagnostics: FilterDiagnostics
  /** Raw display filter the analyst wrote, echoed back for context. */
  expression?: string
  onClear: () => void
  onEdit?: () => void
}

/** Error state for a display filter TShark refused. */
export function InvalidFilterState({
  diagnostics,
  expression,
  onClear,
  onEdit,
}: InvalidFilterStateProps) {
  return (
    <div className="panel flex flex-col gap-2 p-4" role="alert">
      <div className="flex items-center gap-2">
        <AlertTriangle size={16} className="shrink-0 text-danger" aria-hidden />
        <span className="text-sm font-medium text-text">Invalid display filter</span>
        <span className="chip border-danger/40 bg-danger/10 text-red-300">422 invalid_filter</span>
      </div>
      <p className="text-xs leading-relaxed text-muted">{diagnostics.message}</p>
      {expression ? (
        <p className="mono break-all rounded border border-border bg-surface2/60 px-2 py-1 text-2xs text-text">
          {expression}
        </p>
      ) : null}
      {diagnostics.reason ? (
        <div className="flex flex-col gap-0.5">
          <span className="text-2xs uppercase tracking-wide text-faint">TShark reported</span>
          <p className="mono break-words rounded border border-danger/40 bg-danger/10 px-2 py-1 text-2xs text-red-200">
            {diagnostics.reason}
          </p>
        </div>
      ) : (
        <p className="text-2xs text-faint">
          The backend did not attach TShark&apos;s own reason to this rejection.
        </p>
      )}
      <p className="text-2xs leading-relaxed text-faint">
        An invalid filter is a syntax error and stops the request; it is not the same as a valid
        filter that matches no packets. No packet rows are shown because none were evaluated.
      </p>
      <div className="flex items-center gap-2">
        {onEdit ? (
          <button type="button" className="btn btn-primary" onClick={onEdit}>
            <Filter size={13} aria-hidden />
            Edit the filter
          </button>
        ) : null}
        <button type="button" className="btn" onClick={onClear}>
          Clear the filter
        </button>
      </div>
    </div>
  )
}

export interface ZeroMatchStateProps {
  /** Human-readable summary of what was filtered on. */
  description: string
  onClear: () => void
  /** Set when the whole capture has no packets at all. */
  captureEmpty?: boolean
  packetCount?: number | null
}

/**
 * Empty state for "valid filter, no matching packets" — deliberately not an
 * error, and deliberately worded so it cannot be read as one.
 */
export function ZeroMatchState({
  description,
  onClear,
  captureEmpty = false,
  packetCount = null,
}: ZeroMatchStateProps) {
  if (captureEmpty) {
    return (
      <EmptyState
        icon={SearchX}
        variant="plain"
        title="No packets were indexed for this capture"
        description="The analysis completed but the packet index is empty. Every packet row in this view comes from the index, so there is nothing to show for any filter."
      />
    )
  }
  return (
    <EmptyState
      icon={SearchX}
      variant="plain"
      title="0 packets match this filter"
      description={
        <>
          {description}
          {packetCount !== null && packetCount > 0 ? (
            <>
              {' '}
              The capture has {packetCount.toLocaleString('en-US')} indexed packets, so this is a
              real answer of zero matching frames — not an error.
            </>
          ) : null}
        </>
      }
      action={
        <button type="button" className="btn btn-primary" onClick={onClear}>
          <Filter size={13} aria-hidden />
          Clear the filter
        </button>
      }
    />
  )
}
