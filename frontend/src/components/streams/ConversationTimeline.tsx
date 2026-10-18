import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Clock } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Panel from '@/components/Panel'
import type { PacketListParamsWithStream } from '@/components/packets/PacketFilters'
import { packetsApi } from '@/services/api'
import type { Conversation, PacketSummary, SortOrder, StreamMode } from '@/types'
import { formatBytes, formatClockTime, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import { ConversationPackets } from './ConversationPackets'
import type { ConversationTarget } from './ConversationPackets'
import { StreamViewer } from './StreamViewer'
import { StateChip } from './ConversationTable'

/** How many event frames are listed before the panel reports the remainder. */
const EVENT_LIMIT = 500

/**
 * The frames that belong on a protocol timeline.
 *
 * Read from the indexed packet rows with the endpoint's display filter, ANDed with
 * the stream id, so a conversation of any size yields a short and complete event
 * list: on lab-09 a 2,947-frame conversation reduces to its SYN and SYN-ACK, the
 * request and the response that carried the alert, and the RST that ended it.
 *
 * The filter is transport-aware because `tcp.flags` cannot match on a UDP flow, and
 * a filter the backend rejects would turn the panel into an error state.
 */
const EVENT_FILTER: Record<string, string> = {
  tcp: 'http or dns or tls or tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1',
  udp: 'dns or tls',
}

export interface TimelineEvent {
  /** Capture time, null when the frame has no timestamp recorded. */
  t: number | null
  /** The protocol this event belongs to, e.g. http, dns, tls, tcp. */
  kind: string
  packet: number
  label: string
}

/**
 * One row of the timeline: which protocol it belongs to and what happened.
 *
 * The label prefers the dissected fields over the raw summary, so an HTTP request
 * reads as `GET /path` with its host, and falls back to TShark's own `info` line for
 * everything else - including the TCP control frames, where `info` already carries
 * the flags that make the event meaningful.
 */
export function timelineEvent(packet: PacketSummary): TimelineEvent {
  const protocol = (packet.protocol ?? '').trim().toLowerCase()
  const kind = protocol === '' ? 'frame' : protocol
  const status = packet.http_status ?? null
  let label: string
  if (packet.http_method && packet.http_uri) {
    label = packet.http_method + ' ' + packet.http_uri
    if (packet.http_host) label += ' \u00b7 ' + packet.http_host
    if (status !== null) label += ' \u2192 ' + String(status)
  } else if (status !== null) {
    label = 'HTTP ' + String(status) + (packet.http_host ? ' \u00b7 ' + packet.http_host : '')
  } else if (packet.dns_query) {
    label = 'DNS ' + packet.dns_query
  } else if (packet.tls_sni) {
    label = 'TLS ' + packet.tls_sni
  } else {
    label = packet.info ?? 'frame ' + String(packet.number)
  }
  return { t: packet.time_epoch ?? null, kind, packet: packet.number, label }
}

export interface ConversationTimelineProps {
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
}

/**
 * The Timeline tab: what was actually transmitted inside one conversation.
 *
 * Three views of the same flow, in order of increasing detail: the event frames that
 * carry protocol meaning, every indexed frame, and the reassembled stream with its
 * chunk timeline. The events come from the packet index rather than the capture, so
 * the panel still works when the upload has been purged.
 */
export function ConversationTimeline({
  analysisId,
  conversation,
  target,
  mode,
  onModeChange,
  onOpenPacket,
  onOpenPackets,
}: ConversationTimelineProps) {
  const params: PacketListParamsWithStream = {
    stream_id: target.streamId,
    transport: target.transport,
    filter: EVENT_FILTER[target.transport] ?? EVENT_FILTER.tcp,
    page: 1,
    page_size: EVENT_LIMIT,
    sort: 'number',
    order: 'asc' as SortOrder,
  }

  const events = useQuery({
    queryKey: ['conversation-timeline', analysisId, target.transport, target.streamId],
    queryFn: () => packetsApi.list(analysisId, params),
    retry: false,
  })

  const rows = useMemo(() => (events.data?.items ?? []).map(timelineEvent), [events.data])
  const total = events.data?.total ?? 0
  /* The protocol mix of the events, so the timeline is readable at a glance before
     any row is. Built from the events themselves, not from a second request. */
  const byKind = useMemo(() => {
    const counts = new Map<string, number>()
    for (const row of rows) counts.set(row.kind, (counts.get(row.kind) ?? 0) + 1)
    return Array.from(counts.entries()).sort((left, right) => right[1] - left[1])
  }, [rows])

  const indexed = conversation?.packets_total ?? null

  return (
    <div className="flex flex-col gap-3">
      <Panel
        flush
        title={
          conversation ? (
            <>
              Timeline of conversation{' '}
              {/* The two endpoints, drawn from their own fields rather than the joined
                  `conv_id`, so the address and the port can be told apart by colour and
                  set in the mono face. The separator is the same string the id uses, with
                  a space on either side of it. */}
              <span className="endpoint-pair">
                {conversation.transport}:
                <span className="endpoint-ip">{conversation.ip_a}</span>
                {conversation.port_a === null ? null : (
                  <span className="endpoint-port">:{String(conversation.port_a)}</span>
                )}
                <span className="endpoint-sep"> - </span>
                <span className="endpoint-ip">{conversation.ip_b}</span>
                {conversation.port_b === null ? null : (
                  <span className="endpoint-port">:{String(conversation.port_b)}</span>
                )}
              </span>
            </>
          ) : (
            `Timeline of ${target.transport} stream ${target.streamId}`
          )
        }
        subtitle={
          conversation
            ? `${conversation.endpoint_a} <-> ${conversation.endpoint_b}`
            : 'the selected row is not on this page; the panels below read the index directly'
        }
        actions={
          <button type="button" className="btn px-1.5 py-1" onClick={onOpenPackets}>
            Open in packet browser
          </button>
        }
      >
        <div className="conversation-facts flex flex-wrap items-center gap-x-3 gap-y-1 p-3 text-2xs text-muted">
          {conversation ? (
            <>
              <StateChip state={conversation.state} />
              <span className="chip border-border2 bg-surface2 text-muted">{conversation.transport}</span>
              <span>
                started <span className="mono text-text">{formatTimestamp(conversation.start_time)}</span>
              </span>
              <span>
                ended <span className="mono text-text">{formatTimestamp(conversation.end_time)}</span>
              </span>
              <span>
                lasted <span className="mono text-text">{formatDuration(conversation.duration)}</span>
              </span>
              <span>
                <span className="mono text-text">{formatNumber(conversation.packets_total)}</span> packets ·{' '}
                <span className="mono text-text">{formatBytes(conversation.bytes_total)}</span>
              </span>
              {conversation.protocols ? (
                <span>
                  protocols <span className="mono text-text">{conversation.protocols}</span>
                </span>
              ) : null}
            </>
          ) : (
            <span>
              {target.transport} stream {target.streamId} is selected, but its row is not on the page
              currently loaded, so the summary above is limited to what the stream index holds.
            </span>
          )}
        </div>
      </Panel>

      <ConversationPackets
        analysisId={analysisId}
        target={target}
        onOpenPacket={onOpenPacket}
        onOpenPackets={onOpenPackets}
      />

      <Panel
        flush
        title="Timeline of events"
        subtitle={
          events.isLoading
            ? 'reading the frames that carry protocol events'
            : total > rows.length
              ? `first ${formatNumber(rows.length)} of ${formatNumber(total)} event frame(s)`
              : `${formatNumber(rows.length)} event frame(s)` +
                (indexed === null ? '' : ` out of ${formatNumber(indexed)} frame(s) in this conversation`)
        }
      >
        {events.isLoading ? (
          <LoadingState label="Reading the protocol events of this conversation..." rows={5} />
        ) : events.error ? (
          <ErrorState
            error={events.error}
            title="Could not read the events of this conversation"
            onRetry={() => void events.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={Clock}
            title="No protocol events in this conversation"
            description={
              <span>
                The filter is valid and the request succeeded - this flow simply carries no HTTP, DNS
                or TLS records, and no TCP control frame the index recorded. The frames themselves are
                listed above.
              </span>
            }
          />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
              <span className="text-2xs text-faint">events by protocol</span>
              {byKind.map(([kind, count]) => (
                <span key={kind} className="chip border-border2 bg-surface2 text-muted">
                  {kind} <span className="mono text-text">{formatNumber(count)}</span>
                </span>
              ))}
            </div>
            <ul className="flex flex-col">
              {rows.map((row) => (
                <li
                  key={row.packet}
                  className="flex items-center gap-2 border-b border-border/50 px-3 py-1.5 text-2xs last:border-0"
                >
                  <Clock size={11} className="shrink-0 text-faint" aria-hidden />
                  <span className="mono w-20 shrink-0 text-muted">{formatClockTime(row.t)}</span>
                  <span className="chip shrink-0 border-border2 bg-surface2 text-faint">{row.kind}</span>
                  {onOpenPacket ? (
                    <button
                      type="button"
                      className="mono shrink-0 text-accent2 hover:underline"
                      onClick={() => onOpenPacket(row.packet)}
                      title="Open this frame in the packet browser"
                    >
                      #{formatNumber(row.packet)}
                    </button>
                  ) : (
                    <span className="mono shrink-0 text-muted">#{formatNumber(row.packet)}</span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-text" title={row.label}>
                    {row.label}
                  </span>
                </li>
              ))}
            </ul>
          </>
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
    </div>
  )
}

export default ConversationTimeline
