import { Layers, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import type { Conversation, StreamMode } from '@/types'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import { ConversationPackets } from './ConversationPackets'
import type { ConversationTarget } from './ConversationPackets'
import { StreamViewer } from './StreamViewer'
import { StateChip, conversationKey } from './ConversationTable'

export type { ConversationTarget }

/**
 * Everything that belongs to one selected conversation: the indexed row, the
 * packets that make it up, and (for TCP) the reassembled stream.
 *
 * The packet list is fetched with the endpoint's `stream_id` parameter plus the
 * conversation's transport, because `stream_id` alone is ambiguous: the packets
 * endpoint matches `tcp_stream` *or* `udp_stream`, while a capture can easily
 * have a TCP stream 0 and a UDP stream 0 at the same time.
 */

export interface ConversationDetailProps {
  analysisId: string
  /** The row, when it is on the page currently loaded. */
  conversation: Conversation | null
  /** Parsed from the URL, so this works even when the row is on another page. */
  target: ConversationTarget
  mode: StreamMode
  onModeChange: (mode: StreamMode) => void
  onOpenPackets: () => void
  /** Open one packet in the packet browser. */
  onOpenPacket?: (packetNumber: number) => void
  onClose: () => void
}

export function ConversationDetail({
  analysisId,
  conversation,
  target,
  mode,
  onModeChange,
  onOpenPackets,
  onOpenPacket,
  onClose,
}: ConversationDetailProps) {
  return (
    <div className="flex flex-col gap-3">
      <Panel
        title={`Conversation ${conversation?.conv_id ?? `${target.transport} stream ${target.streamId}`}`}
        subtitle={
          conversation
            ? `${conversation.endpoint_a} <-> ${conversation.endpoint_b}`
            : 'the selected row is not on this page; details below come from the stream index'
        }
        flush
        actions={
          <>
            <button type="button" className="btn px-1.5 py-1" onClick={onOpenPackets}>
              <Layers size={12} aria-hidden />
              Open in packet browser
            </button>
            <button
              type="button"
              className="btn px-1.5 py-1"
              onClick={onClose}
              title="Collapse this conversation"
            >
              <X size={12} aria-hidden />
              Close
            </button>
          </>
        }
      >
        <div className="flex flex-col gap-3 p-3">
          {conversation ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <span className="mono break-all text-xs text-text" title={conversation.conv_id}>
                  {conversation.conv_id}
                </span>
                <CopyButton value={conversation.conv_id} label="Copy the conversation id" />
                <StateChip state={conversation.state} />
                <span className="chip border-border2 bg-surface2 text-muted">
                  {conversation.transport}
                </span>
              </div>
              <DetailGrid columns={3}>
                <DetailItem
                  label="Endpoint A"
                  value={conversation.endpoint_a}
                  unavailableReason="The conversation row has no endpoint A."
                />
                <DetailItem
                  label="Endpoint B"
                  value={conversation.endpoint_b}
                  unavailableReason="The conversation row has no endpoint B."
                />
                <DetailItem label="Stream id" value={conversation.stream_id} />
                <DetailItem
                  label="Packets A -> B"
                  value={formatNumber(conversation.packets_a_to_b)}
                />
                <DetailItem
                  label="Packets B -> A"
                  value={formatNumber(conversation.packets_b_to_a)}
                />
                <DetailItem label="Packets total" value={formatNumber(conversation.packets_total)} />
                <DetailItem label="Bytes A -> B" value={formatBytes(conversation.bytes_a_to_b)} />
                <DetailItem label="Bytes B -> A" value={formatBytes(conversation.bytes_b_to_a)} />
                <DetailItem label="Bytes total" value={formatBytes(conversation.bytes_total)} />
                <DetailItem label="Started" value={formatTimestamp(conversation.start_time)} />
                <DetailItem label="Ended" value={formatTimestamp(conversation.end_time)} />
                <DetailItem label="Duration" value={formatDuration(conversation.duration)} />
                <DetailItem label="Transport" value={conversation.transport} />
                <DetailItem
                  label="Protocols seen"
                  value={conversation.protocols}
                  unavailableReason="No application protocol was identified inside this stream."
                />
                <DetailItem
                  label="TCP state"
                  value={conversation.state}
                  unavailableReason="The backend recorded no TCP flags for this conversation."
                  title="established / reset / half_open / closed / unknown, derived from the flags that were actually observed"
                />
              </DetailGrid>
              <p className="text-2xs leading-relaxed text-faint">
                Bytes and packet counts are the indexed sums for this conversation only; the columns
                named A and B follow <span className="mono">endpoint_a</span>, the side whose SYN
                (TCP) or first datagram (UDP) was seen first.
              </p>
            </>
          ) : (
            <SectionNote>
              This conversation is not in the page currently loaded, so the indexed row is not shown.
              The packet list and stream below are addressed by{' '}
              <span className="mono">
                {target.transport} stream {target.streamId}
              </span>{' '}
              directly, so they are still accurate for the selected flow.
            </SectionNote>
          )}
        </div>
      </Panel>

      <ConversationPackets
        analysisId={analysisId}
        target={target}
        onOpenPacket={onOpenPacket}
        onOpenPackets={onOpenPackets}
      />

      <StreamViewer
        analysisId={analysisId}
        streamId={target.streamId}
        transport={target.transport}
        convId={conversation?.conv_id ?? null}
        mode={mode}
        onModeChange={onModeChange}
        onOpenPackets={onOpenPackets}
      />

      {conversation ? (
        <p className="px-1 text-2xs text-faint">
          conversation key <span className="mono">{conversationKey(conversation)}</span> · the stream
          viewer reads the flow back from the retained capture, so it can show bytes the index does
          not store.
        </p>
      ) : null}
    </div>
  )
}

export default ConversationDetail