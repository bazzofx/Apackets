import clsx from 'clsx'
import type { AnalysisStatus, JobStatus } from '@/types'

type AnyStatus = AnalysisStatus | JobStatus | string | null | undefined

const STATUS_STYLES: Record<string, string> = {
  pending: 'border-faint/50 bg-faint/15 text-muted',
  queued: 'border-faint/50 bg-faint/15 text-muted',
  processing: 'border-accent/50 bg-accent/15 text-accent2',
  running: 'border-accent/50 bg-accent/15 text-accent2',
  completed: 'border-ok/50 bg-ok/15 text-ok',
  failed: 'border-danger/50 bg-danger/15 text-red-300',
  cancelled: 'border-border2 bg-surface2 text-faint',
}

const STATUS_LABELS: Record<string, string> = {
  pending: 'pending',
  queued: 'queued',
  processing: 'processing',
  running: 'running',
  completed: 'completed',
  failed: 'failed',
  cancelled: 'cancelled',
}

export interface StatusChipProps {
  status: AnyStatus
  className?: string
}

/** Analysis/job lifecycle chip. Unknown statuses render honestly as-is. */
export function StatusChip({ status, className }: StatusChipProps) {
  if (status === null || status === undefined || status === '') {
    return <span className={clsx('chip border-border2 bg-surface2 text-faint', className)}>unknown</span>
  }
  const key = String(status)
  const style = STATUS_STYLES[key] ?? 'border-border2 bg-surface2 text-muted'
  const label = STATUS_LABELS[key] ?? key
  const animated = key === 'processing' || key === 'running'
  return (
    <span className={clsx('chip', style, className)} data-status={key}>
      {animated ? (
        <span className="inline-block h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-current" />
      ) : null}
      {label}
    </span>
  )
}

export default StatusChip
