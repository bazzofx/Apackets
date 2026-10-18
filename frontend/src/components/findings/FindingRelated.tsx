import SeverityBadge from '@/components/SeverityBadge'
import EmptyState from '@/components/EmptyState'
import { Link2 } from 'lucide-react'
import type { RelatedFinding } from '@/types'

export interface FindingRelatedProps {
  items: RelatedFinding[]
  truncated: boolean
  onSelect: (id: string) => void
}

/** Other findings that share addresses, names, URIs or packets with this one. */
export function FindingRelated({ items, truncated, onSelect }: FindingRelatedProps) {
  if (items.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={Link2}
        title="Nothing shares artefacts with this finding"
        description="No other finding in this analysis mentions the same addresses, host names, URIs or packets."
        className="py-8"
      />
    )
  }
  return (
    <div className="flex flex-col">
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          onClick={() => onSelect(item.id)}
          className="flex flex-col gap-1 border-b border-border/60 px-3 py-2 text-left last:border-0 hover:bg-surface2/70"
        >
          <div className="flex items-center gap-2">
            <SeverityBadge severity={item.severity} showLabel />
            <span className="text-2xs text-faint" title={item.rule_id}>
              {item.rule_id}
            </span>
            <span className="ml-auto text-2xs text-faint">open</span>
          </div>
          <div className="text-2xs text-text">{item.title}</div>
          <div className="flex flex-wrap gap-1">
            {item.shared.map((value) => (
              <span key={value} className="chip border-border2 bg-surface2 text-faint">
                {value}
              </span>
            ))}
          </div>
        </button>
      ))}
      {truncated ? (
        <div className="px-3 py-2 text-2xs text-faint">
          More findings share artefacts than are listed here.
        </div>
      ) : null}
    </div>
  )
}

export default FindingRelated