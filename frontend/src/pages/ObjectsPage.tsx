import { Package } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — object extraction views are implemented by another agent. */
export function ObjectsPage() {
  return (
    <EmptyState
      icon={Package}
      title="Files and objects not implemented yet"
      description="This view is not implemented yet. The extracted-object table, hashes and export actions are still being built."
    />
  )
}

export default ObjectsPage
