import { ShieldAlert } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the findings workbench is implemented by another agent. */
export function FindingsPage() {
  return (
    <EmptyState
      icon={ShieldAlert}
      title="Findings not implemented yet"
      description="This view is not implemented yet. The findings list, rule catalogue and evidence viewer are still being built."
    />
  )
}

export default FindingsPage
