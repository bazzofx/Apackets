import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Ban, FileWarning, FolderOpen, Upload } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import StatusChip from '@/components/StatusChip'
import { useAnalysis, useAnalysisDetail } from '@/hooks/useAnalysis'
import { ApiError, toApiError } from '@/services/api'
import { formatNumber } from '@/utils/format'

export interface AnalysisGuardProps {
  children: ReactNode
  /** Replace the default "no capture selected" description. */
  emptyDescription?: ReactNode
}

function progressPercent(progress: number | null | undefined): number {
  if (progress === null || progress === undefined || !Number.isFinite(progress)) return 0
  const pct = progress <= 1 ? progress * 100 : progress
  return Math.max(0, Math.min(100, pct))
}

/**
 * Gate for every data page: requires a selected, `completed` analysis.
 * - no analysis selected -> EmptyState pointing at the upload page
 * - list request failed   -> ErrorState with retry
 * - pending/processing    -> live progress bar (polled every 2 s by the hook)
 * - failed/cancelled      -> honest state with the backend error text
 */
export function AnalysisGuard({ children, emptyDescription }: AnalysisGuardProps) {
  const { analysisId, isLoading, error, refresh } = useAnalysis()
  const detail = useAnalysisDetail(analysisId)

  if (error) {
    return (
      <ErrorState
        error={error}
        onRetry={refresh}
        title="Could not load the analysis list"
      />
    )
  }

  if (isLoading) return <LoadingState label="Loading analyses…" rows={4} />

  if (!analysisId) {
    return (
      <EmptyState
        icon={Upload}
        title="No capture selected"
        description={
          emptyDescription ?? (
            <>
              Upload a PCAP/PCAPNG capture or select an existing analysis in the top bar to
              see this view.
            </>
          )
        }
        action={
          <Link to="/files" className="btn btn-primary">
            <FolderOpen size={13} aria-hidden />
            PCAP Files
          </Link>
        }
      />
    )
  }

  if (detail.isLoading) return <LoadingState label="Loading analysis…" rows={4} />

  if (detail.error) {
    const apiError = toApiError(detail.error)
    return (
      <ErrorState
        error={
          apiError.isNotFound
            ? new ApiError(
                apiError.status,
                apiError.code,
                'This analysis no longer exists on the backend. Pick another capture in the top bar.',
                apiError.details,
              )
            : apiError
        }
        onRetry={() => void detail.refetch()}
        title={apiError.isNotFound ? 'Analysis not found' : 'Could not load the analysis'}
      />
    )
  }

  const analysis = detail.data
  if (!analysis) return <LoadingState label="Loading analysis…" rows={4} />

  if (analysis.status === 'pending' || analysis.status === 'processing') {
    const pct = progressPercent(analysis.progress)
    return (
      <section className="panel mx-auto mt-8 max-w-2xl p-5">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="panel-title">Analysis in progress</div>
            <div className="mt-1 truncate text-sm text-text" title={analysis.original_filename}>
              {analysis.original_filename}
            </div>
          </div>
          <StatusChip status={analysis.status} />
        </div>
        <div className="mt-4 h-1.5 w-full overflow-hidden rounded bg-surface2">
          <div
            className="h-full bg-accent transition-[width] duration-300"
            style={{ width: `${pct}%` }}
            role="progressbar"
            aria-valuenow={Math.round(pct)}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
        <div className="mt-2 flex items-center justify-between text-2xs text-muted">
          <span className="mono">{analysis.stage ?? 'waiting for a worker'}</span>
          <span className="mono">{pct.toFixed(0)}%</span>
        </div>
        <p className="mt-4 text-xs leading-relaxed text-faint">
          Data views unlock when the analysis completes. This page refreshes automatically
          every 2 seconds.
        </p>
      </section>
    )
  }

  if (analysis.status === 'failed') {
    return (
      <ErrorState
        title="Analysis failed"
        error={
          new ApiError(
            500,
            'analysis_failed',
            analysis.error ?? 'The backend did not record a reason for this failure.',
            { analysis_id: analysis.id, stage: analysis.stage },
          )
        }
        onRetry={() => void detail.refetch()}
      />
    )
  }

  if (analysis.status === 'cancelled') {
    return (
      <EmptyState
        icon={Ban}
        title="Analysis was cancelled"
        description={`${analysis.original_filename} was cancelled before it finished${
          analysis.packet_count ? ` (${formatNumber(analysis.packet_count)} packets indexed)` : ''
        }. Re-upload the capture from PCAP Files to analyse it again.`}
        action={
          <Link to="/files" className="btn btn-primary">
            <FolderOpen size={13} aria-hidden />
            PCAP Files
          </Link>
        }
      />
    )
  }

  if (analysis.status !== 'completed') {
    return (
      <EmptyState
        icon={FileWarning}
        title="Analysis is not ready"
        description={`Current status: ${analysis.status}.`}
      />
    )
  }

  return <>{children}</>
}

export default AnalysisGuard
