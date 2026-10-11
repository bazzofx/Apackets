import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Layers } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import type { PacketListParamsWithStream } from '@/components/packets/PacketFilters'
import { packetsApi } from '@/services/api'
import type { SortOrder, Transport } from '@/types'
import { formatNumber, formatTimestamp } from '@/utils/format'

/** How many stream packets are listed inline before deferring to the browser. */
export const PACKET_PREVIEW_LIMIT = 50

export interface ConversationTarget {
  transport: Transport
  streamId: number
}

export interface ConversationPacketsProps {
  analysisId: string
  target: ConversationTarget
  /** Frames listed inline before the panel defers to the packet browser. */
  limit?: number
  /** Open one packet in the packet browser. */
  onOpenPacket?: (packetNumber: number) => void
  /** Open the packet browser filtered to this stream. */
  onOpenPackets: () => void
}

/**
 * The frames that make up one conversation.
 *
 * Fetched with the endpoint's `stream_id` parameter plus the conversation's
 * transport, because `stream_id` alone is ambiguous: the packets endpoint matches
 * `tcp_stream` *or* `udp_stream`, while a capture can easily hold a TCP stream 0 and
 * a UDP stream 0 at the same time.
 *
 * Shared by the Info tab's detail pane and the Timeline tab, so both list the same
 * frames in the same order instead of drifting apart.
 */
export function ConversationPackets({
  analysisId,
  target,
  limit = PACKET_PREVIEW_LIMIT,
  onOpenPacket,
  onOpenPackets,
}: ConversationPacketsProps) {
  const params: PacketListParamsWithStream = {
    stream_id: target.streamId,
    transport: target.transport,
    page: 1,
    page_size: limit,
    sort: 'number',
    order: 'asc' as SortOrder,
  }

  const packets = useQuery({
    queryKey: ['conversation-packets', analysisId, target.transport, target.streamId, limit],
    queryFn: () => packetsApi.list(analysisId, params),
    retry: false,
  })

  const items = packets.data?.items ?? []
  const total = packets.data?.total ?? 0

  return (
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
  )
}
