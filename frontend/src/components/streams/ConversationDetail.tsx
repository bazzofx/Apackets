import { useMutation, useQuery } from '@tanstack/react-query'
import { CheckCircle2, ExternalLink, Layers, TriangleAlert, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import { flowAddress, flowPort } from '@/components/conversations/flowLayout'
import { toApiError, wiresharkApi } from '@/services/api'
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
  /*
   * The Wireshark pivot. It sends structured facts - an address, the transport and the
   * stream id - and the backend composes the display filter, so nothing here can put
   * filter syntax on a command line. The stream id is the one this application stored,
   * which is TShark's own tcp.stream number, so the window opens on exactly this
   * conversation.
   *
   * Availability is asked for once per analysis (the same query key the IP context menu
   * uses, so the two share one request) and the button is disabled with the reason rather
   * than hidden: an action that silently disappears is harder to explain than one that says
   * why it is unavailable.
   */
  const wiresharkStatus = useQuery({
    queryKey: ['wireshark-status', analysisId],
    queryFn: () => wiresharkApi.status(analysisId),
    retry: false,
    staleTime: 60_000,
  })

  const launch = useMutation({
    mutationFn: (facts: { ip: string; transport: string; stream_id: number; port: number | null }) =>
      wiresharkApi.launch(analysisId, facts),
  })

  /* The A side is the one whose SYN (TCP) or first datagram (UDP) was seen first, and it is
     the side every other panel on this page names first. Either side filters correctly -
     ip.addr matches both directions - so the choice only decides how the filter reads. */
  const address = conversation ? flowAddress(conversation, 'a') : null
  const pivot =
    conversation && address && !address.startsWith('(')
      ? {
          ip: address,
          transport: conversation.transport,
          stream_id: conversation.stream_id,
          port: flowPort(conversation, 'a'),
        }
      : null

  const wiresharkAvailable = wiresharkStatus.data?.available === true
  const pivotTitle = !conversation
    ? 'The conversation row is not on this page, so its address is unknown and Wireshark cannot be filtered to it'
    : pivot === null
      ? 'This conversation row carries no address'
      : wiresharkStatus.isLoading
        ? 'Checking whether the Wireshark GUI is installed on this machine...'
        : wiresharkAvailable
          ? 'Open the capture in Wireshark with this conversation filtered - the same tcp.stream the index recorded'
          : 'Wireshark is unavailable here: ' +
            (wiresharkStatus.data?.reason ??
              (wiresharkStatus.isError
                ? 'the backend could not be asked whether it is installed'
                : 'not installed'))

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
              disabled={pivot === null || !wiresharkAvailable || launch.isPending}
              onClick={() => pivot && launch.mutate(pivot)}
              title={pivotTitle}
            >
              <ExternalLink size={12} aria-hidden />
              {launch.isPending ? 'Opening Wireshark...' : 'Follow in Wireshark'}
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
          {/* What the backend actually did, including the filter it composed - the client never
              sends one, so this line is the only place an analyst can see it. */}
          {launch.isSuccess ? (
            <div className="flex items-start gap-2 rounded border border-ok/40 bg-ok/10 px-2 py-1.5 text-2xs text-ok">
              <CheckCircle2 size={12} className="mt-0.5 shrink-0" aria-hidden />
              <span className="flex-1">
                Wireshark opened on this capture with the filter{' '}
                <span className="mono">{launch.data.filter}</span>.
              </span>
            </div>
          ) : null}
          {launch.isError ? (
            <div className="flex items-start gap-2 rounded border border-danger/40 bg-danger/10 px-2 py-1.5 text-2xs text-danger">
              <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
              <span className="flex-1">{toApiError(launch.error).message}</span>
            </div>
          ) : null}
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