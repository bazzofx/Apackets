import { Search } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the DNS analyser view is implemented by another agent. */
export function DnsPage() {
  return (
    <EmptyState
      icon={Search}
      title="DNS queries not implemented yet"
      description="This view is not implemented yet. The DNS query table, domain aggregation and suspicious-name highlighting are still being built."
    />
  )
}

export default DnsPage
