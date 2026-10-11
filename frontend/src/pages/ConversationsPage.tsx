import { ArrowLeftRight } from 'lucide-react'
import EmptyState from '@/components/EmptyState'

/** Placeholder — conversation/stream views are implemented by another agent. */
export function ConversationsPage() {
  return (
    <EmptyState
      icon={ArrowLeftRight}
      title="Conversations not implemented yet"
      description="This view is not implemented yet. The conversation table and TShark stream follow view are still being built."
    />
  )
}

export default ConversationsPage
