import { Lock } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — the TLS analyser view is implemented by another agent. */
export function TlsPage() {
  return (
    <EmptyState
      icon={Lock}
      title="TLS sessions not implemented yet"
      description="This view is not implemented yet. The TLS session table, certificate detail and JA3/JA4 fingerprint views are still being built."
    />
  )
}

export default TlsPage
