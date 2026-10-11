import { Server } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the host inventory view is implemented by another agent. */
export function HostsPage() {
  return (
    <EmptyState
      icon={Server}
      title="Hosts not implemented yet"
      description="This view is not implemented yet. The host inventory, per-host detail and conversation graph are still being built."
    />
  )
}

export default HostsPage
