import { useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import clsx from 'clsx'
import SeverityBadge from '@/components/SeverityBadge'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import { ShieldAlert } from 'lucide-react'
import { formatNumber } from '@/utils/format'
import type { Finding } from '@/types'

export interface FindingsListProps {
  items: Finding[]
  total: number
  selectedId: string | null
  isLoading: boolean
  error: unknown
  onRetry: () => void
  onSelect: (finding: Finding) => void
}

/** Virtualized findings list: severity, rule id, title and packet count. */
export function FindingsList({
  items,
  total,
  selectedId,
  isLoading,
  error,
  onRetry,
  onSelect,
}: FindingsListProps) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 62,
    overscan: 12,
  })

  if (isLoading) return <LoadingState label="Loading findings…" rows={6} />
  if (error) {
    return <ErrorState error={error} onRetry={onRetry} title="Could not load findings" variant="plain" />
  }
  if (items.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={ShieldAlert}
        title="No findings match"
        description="Adjust the filters, or re-run the rules from the toolbar. An empty list means no rule matched - not that the capture is clean."
        className="py-10"
      />
    )
  }

  return (
    <div ref={parentRef} className="h-full overflow-auto">
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
        {virtualizer.getVirtualItems().map((row) => {
          const finding = items[row.index]
          const active = finding.id === selectedId
          return (
            <button
              key={finding.id}
              type="button"
              onClick={() => onSelect(finding)}
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: row.size,
                transform: `translateY(${row.start}px)`,
              }}
              className={clsx(
                'flex flex-col gap-0.5 border-b border-border/60 px-2 py-1.5 text-left',
                active ? 'bg-accent/15' : 'hover:bg-surface2/70',
              )}
              title={finding.title}
            >
              <div className="flex items-center gap-1.5">
                <SeverityBadge severity={finding.severity} showLabel />
                <span className="truncate text-2xs text-faint" title={finding.rule_id}>
                  {finding.rule_id}
                </span>
                {finding.packet_numbers && finding.packet_numbers.length > 0 ? (
                  <span className="ml-auto shrink-0 text-2xs text-faint">
                    {formatNumber(finding.packet_numbers.length)} pkt
                  </span>
                ) : null}
              </div>
              <div className="line-clamp-2 text-2xs text-text">{finding.title}</div>
            </button>
          )
        })}
      </div>
      <div className="border-t border-border px-2 py-1 text-2xs text-faint">
        {formatNumber(items.length)} of {formatNumber(total)} findings
      </div>
    </div>
  )
}

export default FindingsList