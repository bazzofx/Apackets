import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeftRight } from 'lucide-react'
import { formatBytes, formatNumber } from '@/utils/format'
import type { Conversation, FindingContext } from '@/types'

/**
 * The conversation a finding's matched evidence belongs to.
 *
 * A matched row is a packet, and every packet records the stream it was reassembled
 * into, so the first match that resolves names the conversation without guessing from
 * addresses. When a finding spans several streams the backend's own correlation is
 * the fallback, which it orders largest first. Null means genuinely nothing to follow
 * - no stream was recorded for these packets - and the button says so rather than
 * jumping somewhere unrelated.
 */
export function resolveFollowConversation(context: FindingContext): Conversation | null {
  const evidence = (context.finding.evidence ?? {}) as Record<string, unknown>
  const matches = Array.isArray(evidence.matches)
    ? (evidence.matches as Record<string, unknown>[])
    : []

  const streamOf = new Map<number, { transport: string; streamId: number }>()
  for (const packet of context.packets) {
    const streamId = packet.transport === 'tcp' ? packet.tcp_stream : packet.udp_stream
    if (packet.transport && typeof streamId === 'number') {
      streamOf.set(packet.number, { transport: packet.transport, streamId })
    }
  }

  for (const match of matches) {
    const number = typeof match.packet === 'number' ? match.packet : null
    if (number === null) continue
    const stream = streamOf.get(number)
    if (stream === undefined) continue
    const hit = context.conversations.find(
      (conversation) =>
        conversation.transport === stream.transport && conversation.stream_id === stream.streamId,
    )
    if (hit !== undefined) return hit
  }

  return context.conversations.length > 0 ? context.conversations[0] : null
}

/** The identity a conversation is addressed by, in the URL and in the alert map. */
export function conversationUrlKey(conversation: { transport: string; stream_id: number }): string {
  return conversation.transport + ':' + String(conversation.stream_id)
}

/**
 * Follow the alert's conversation onto the Conversations page, on its Timeline tab.
 *
 * One implementation shared by the Overview tab and the Conversation tab, so the two
 * buttons cannot drift apart: the same target resolution, the same label, the same
 * destination and the same explanation when there is nothing to follow.
 */
export function FollowConversationButton({
  context,
  className = 'btn px-1.5 py-0.5',
}: {
  context: FindingContext
  className?: string
}) {
  const navigate = useNavigate()
  const follow = useMemo(() => resolveFollowConversation(context), [context])
  const linked = context.conversations.length

  return (
    <button
      type="button"
      className={className}
      disabled={follow === null}
      aria-label="Follow conversation"
      title={
        follow === null
          ? 'None of the matched packets could be tied to a conversation, so there is nothing to follow - open a packet number below instead.'
          : `Open ${follow.transport.toUpperCase()} stream ${String(follow.stream_id)} (${formatBytes(follow.bytes_total)}, ${formatNumber(follow.packets_total)} packets) on the Timeline tab of the Conversations page, with this conversation selected.` +
            (linked > 1
              ? ` ${formatNumber(linked)} conversations are linked to this alert; this is the one the first matched packet belongs to.`
              : '')
      }
      onClick={() => {
        if (follow === null) return
        navigate(`/conversations?stream=${encodeURIComponent(conversationUrlKey(follow))}&tab=timeline`)
      }}
    >
      <ArrowLeftRight size={12} aria-hidden />
      Follow conversation
    </button>
  )
}

export default FollowConversationButton
