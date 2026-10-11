import { Globe } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the HTTP analyser view is implemented by another agent. */
export function HttpPage() {
  return (
    <EmptyState
      icon={Globe}
      title="HTTP transactions not implemented yet"
      description="This view is not implemented yet. The HTTP transaction list and request/response detail panes are still being built."
    />
  )
}

export default HttpPage
