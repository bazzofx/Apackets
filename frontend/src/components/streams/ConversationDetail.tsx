import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Layers, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import type { PacketListParamsWithStream } from '@/components/packets/PacketFilters'
import { packetsApi } from '@/services/api'
import type { Conversation, SortOrder, StreamMode, Transport } from '@/types'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import { StreamViewer } from './StreamViewer'
import { StateChip, conversationKey } from './ConversationTable'

/**
 * Everything that belongs to one selected conversation: the indexed row, the
 * packets that make it up, and (for TCP) the reassembled stream.
 *
 * The packet list is fetched with the endpoint's `stream_id` parameter plus the
 * conversation's transport, because `stream_id` alone is ambiguous: the packets
 * endpoint matches `tcp_stream` *or* `udp_stream`, while a capture can easily
 * have a TCP stream 0 and a UDP stream 0 at the same time.
 */

/** How many stream packets are listed inline before deferring to the browser. */
const PACKET_PREVIEW_LIMIT = 50

export interface ConversationTarget {
  transport: Transport
  streamId: number
}

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
  const params: PacketListParamsWithStream = {
    stream_id: target.streamId,
    transport: target.transport,
    page: 1,
    page_size: PACKET_PREVIEW_LIMIT,
    sort: 'number',
    order: 'asc' as SortOrder,
  }

  const packets = useQuery({
    queryKey: ['conversation-packets', analysisId, target.transport, target.streamId],
    queryFn: () => packetsApi.list(analysisId, params),
    retry: false,
  })

  const items = packets.data?.items ?? []
  const total = packets.data?.total ?? 0

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

      <Panel
        title="Packets in this conversation"
        subtitle={
          total > items.length
            ? `first ${formatNumber(items.length)} of ${formatNumber(total)} frames — open the packet browser for the rest`
            : `${formatNumber(total)} frame(s) indexed for this stream`
        }
        flush
      >
        {packets.isLoading ? (
          <LoadingState label="Loading the stream's packets..." rows={5} />
        ) : packets.error ? (
          <ErrorState
            error={packets.error}
            title="Could not load the packets of this conversation"
            onRetry={() => void packets.refetch()}
          />
        ) : items.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={Layers}
            title="No indexed packets for this stream"
            description={
              <span>
                The conversation has no matching rows in the packet index
                This can happen for a
                stream the conversation analyzer derived from a single frame.
              </span>
            }
            action={
              <button type="button" className="btn" onClick={onOpenPackets}>
                <Layers size={13} aria-hidden />
                Open the packet browser
              </button>
            }
          />
        ) : (
          <div className="max-h-[40vh] overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th className="text-right">#</th>
                  <th>time</th>
                  <th>source</th>
                  <th className="text-right">sport</th>
                  <th>destination</th>
                  <th className="text-right">dport</th>
                  <th>protocol</th>
                  <th className="text-right">len</th>
                  <th className="w-full">info</th>
                </tr>
              </thead>
              <tbody>
                {items.map((packet) => (
                  <tr
                    key={packet.number}
                    className={clsx('', onOpenPacket && 'cursor-pointer')}
                    onClick={onOpenPacket ? () => onOpenPacket(packet.number) : undefined}
                    title={onOpenPacket ? 'Open this packet in the packet browser' : undefined}
                  >
                    <td className="text-right tabular-nums">{formatNumber(packet.number)}</td>
                    <td>{formatTimestamp(packet.time_epoch)}</td>
                    <td>
                      <MonoCell maxWidth={190}>{packet.src_ip}</MonoCell>
                    </td>
                    <td className="text-right tabular-nums">
                      {packet.src_port === null ? <span className="text-faint">—</span> : formatNumber(packet.src_port)}
                    </td>
                    <td>
                      <MonoCell maxWidth={190}>{packet.dst_ip}</MonoCell>
                    </td>
                    <td className="text-right tabular-nums">
                      {packet.dst_port === null ? <span className="text-faint">—</span> : formatNumber(packet.dst_port)}
                    </td>
                    <td>
                      <MonoCell maxWidth={140}>{packet.protocol}</MonoCell>
                    </td>
                    <td className="text-right tabular-nums">
                      {formatNumber(packet.frame_len ?? packet.length ?? null)}
                    </td>
                    <td>
                      <MonoCell maxWidth={900} title={packet.info ?? undefined}>
                        {packet.info}
                      </MonoCell>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

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