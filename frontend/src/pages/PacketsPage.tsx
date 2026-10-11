import { List } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the packet browser is implemented by another agent. */
export function PacketsPage() {
  return (
    <EmptyState
      icon={List}
      title="Packet list not implemented yet"
      description="This view is not implemented yet. The packet browser (display filters, hex detail, neighbours, CSV export) is still being built."
    />
  )
}

export default PacketsPage
