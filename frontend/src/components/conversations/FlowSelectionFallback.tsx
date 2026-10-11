import { ArrowLeftRight } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/**
 * Shown when a node is selected but there are no conversations behind it.
 *
 * This state must never be a dead end: the element that caused it is the
 * selection itself, so the way out has to be on screen here. Both controls are
 * offered - clear the selection, or reset the toolbar filters - because the
 * selection can have gone stale precisely *because* a filter changed the rows
 * the diagram was built from.
 */
export interface FlowSelectionFallbackProps {
  /** The selection taken from the URL, shown so it can be recognised. */
  nodeId: string
  onClearSelection: () => void
  onResetFilters: () => void
}

export function FlowSelectionFallback({
  nodeId,
  onClearSelection,
  onResetFilters,
}: FlowSelectionFallbackProps) {
  return (
    <EmptyState
      icon={ArrowLeftRight}
      variant="plain"
      title="This selection no longer matches the diagram"
      description={
        <>
          Nothing in the rows the diagram was drawn from belongs to{' '}
          <span className="mono text-text">{nodeId}</span>. Changing the filters above rebuilds the
          diagram, and a node id can change with it - a group may become a single address, or a port
          may drop out of the capture entirely. Clear the selection to go back to the whole diagram, or
          reset the filters.
        </>
      }
      action={
        <>
          <button
            type="button"
            className="btn btn-primary"
            aria-label="Clear the diagram selection"
            onClick={onClearSelection}
          >
            Clear selection
          </button>
          <button
            type="button"
            className="btn"
            aria-label="Reset the toolbar filters"
            onClick={onResetFilters}
          >
            Reset filters
          </button>
        </>
      }
    />
  )
}

export default FlowSelectionFallback