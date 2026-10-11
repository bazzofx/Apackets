import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ArrowLeftRight, ArrowRight, Info } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import { conversationsApi } from '@/services/api'
import { formatBytes, formatDuration, formatNumber } from '@/utils/format'
import type { FindingStreamBlock, StreamMode } from '@/types'

const TEXT_PREVIEW = 20_000

export interface FindingConversationProps {
  analysisId: string
  conversations: {
    conv_id: string
    transport: string
    stream_id: number
    endpoint_a: string
    endpoint_b: string
    packets_a_to_b: number
    bytes_a_to_b: number
    packets_b_to_a: number
    bytes_b_to_a: number
    packets_total: number
    bytes_total: number
    duration: number | null
    state: string | null
    protocols: string | null
  }[]
  streams: FindingStreamBlock[]
  truncated: boolean
  followMode: string
}

function StreamContent({ analysisId, streamId, initialMode }: { analysisId: string; streamId: number; initialMode: StreamMode }) {
  const [mode, setMode] = useState<StreamMode>(initialMode)
  const [direction, setDirection] = useState<'c2s' | 's2c'>('c2s')
  const stream = useQuery({
    queryKey: ['stream', analysisId, streamId, mode],
    queryFn: () => conversationsApi.stream(analysisId, streamId, mode),
    staleTime: 60_000,
  })

  if (stream.isLoading) return <div className="px-3 py-3 text-2xs text-muted">Loading stream…</div>
  if (stream.error)
    return <div className="px-3 py-3 text-2xs text-danger">The stream content could not be loaded.</div>
  const follow = stream.data?.follow
  if (!follow) return <div className="px-3 py-3 text-2xs text-faint">No follow content.</div>

  const side = direction === 'c2s' ? follow.client_to_server : follow.server_to_client
  const text = side?.text ?? ''
  const shown = text.length > TEXT_PREVIEW ? text.slice(0, TEXT_PREVIEW) : text

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-1.5 text-2xs">
        <span className="text-faint">
          <span className="mono">{follow.node0 ?? '?'}</span>
          <ArrowLeftRight size={11} className="mx-1 inline" aria-hidden />
          <span className="mono">{follow.node1 ?? '?'}</span>
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            className={clsx('btn px-1.5 py-0.5', direction === 'c2s' && 'btn-primary')}
            onClick={() => setDirection('c2s')}
          >
            client → server ({formatBytes(follow.client_to_server?.bytes ?? null)})
          </button>
          <button
            type="button"
            className={clsx('btn px-1.5 py-0.5', direction === 's2c' && 'btn-primary')}
            onClick={() => setDirection('s2c')}
          >
            server → client ({formatBytes(follow.server_to_client?.bytes ?? null)})
          </button>
        </div>
        <div className="ml-auto flex items-center gap-1">
          {(['ascii', 'hex', 'raw'] as StreamMode[]).map((value) => (
            <button
              key={value}
              type="button"
              className={clsx('btn px-1.5 py-0.5', mode === value && 'btn-primary')}
              onClick={() => setMode(value)}
            >
              {value}
            </button>
          ))}
        </div>
      </div>
      <div className="px-3 py-1 text-2xs text-faint">
        {formatNumber(follow.chunks?.length ?? 0)} chunk(s)
        {follow.chunks_truncated ? ' (chunk list truncated)' : ''} · showing{' '}
        {formatNumber(shown.length)} of {formatNumber(text.length)} characters
      </div>
      <pre className="mono max-h-80 overflow-auto whitespace-pre-wrap break-all px-3 pb-3 text-2xs text-text">
        {shown || '(empty)'}
      </pre>
    </div>
  )
}

/** The conversation(s) the alert belongs to, with TShark's reassembled content. */
export function FindingConversation({
  analysisId,
  conversations,
  streams,
  truncated,
  followMode,
}: FindingConversationProps) {
  if (conversations.length === 0 && streams.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={ArrowLeftRight}
        title="No conversation recorded"
        description="The alerting packets are not part of a reassembled conversation in this capture (a single frame, or traffic the conversation analyzer skipped)."
        className="py-8"
      />
    )
  }

  return (
    <div className="flex flex-col gap-3 p-3">
      {conversations.map((conversation) => (
        <Panel
          key={conversation.conv_id}
          flush
          title={conversation.conv_id}
          subtitle={`${conversation.transport.toUpperCase()} stream ${conversation.stream_id} · ${
            conversation.state ?? 'state unknown'
          }${conversation.protocols ? ` · ${conversation.protocols}` : ''}`}
          actions={
            conversation.duration !== null ? (
              <span className="text-2xs text-faint">{formatDuration(conversation.duration)}</span>
            ) : null
          }
        >
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 px-3 py-2 text-2xs md:grid-cols-[1fr_auto_1fr]">
            <div className="flex flex-col gap-0.5">
              <span className="text-faint">A → B</span>
              <MonoCell>{conversation.endpoint_a}</MonoCell>
              <span className="mono text-muted">
                {formatNumber(conversation.packets_a_to_b)} pkts · {formatBytes(conversation.bytes_a_to_b)}
              </span>
            </div>
            <div className="hidden items-center justify-center text-faint md:flex">
              <ArrowRight size={14} aria-hidden />
            </div>
            <div className="flex flex-col gap-0.5">
              <span className="text-faint">B → A</span>
              <MonoCell>{conversation.endpoint_b}</MonoCell>
              <span className="mono text-muted">
                {formatNumber(conversation.packets_b_to_a)} pkts · {formatBytes(conversation.bytes_b_to_a)}
              </span>
            </div>
          </div>
          <div className="border-t border-border px-3 py-1 text-2xs text-faint">
            total {formatNumber(conversation.packets_total)} packets ·{' '}
            {formatBytes(conversation.bytes_total)}
          </div>
        </Panel>
      ))}

      {streams.map((block, position) => {
        const stream = block.stream
        const streamId = stream?.stream_id ?? null
        return (
          <Panel
            key={`${stream?.transport ?? 'stream'}-${streamId ?? position}`}
            flush
            title={`Reassembled content${streamId !== null ? ` — stream ${streamId}` : ''}`}
            subtitle={
              stream
                ? `${stream.client_ip ?? '?'}:${stream.client_port ?? '?'} → ${stream.server_ip ?? '?'}:${
                    stream.server_port ?? '?'
                  }`
                : 'stream metadata unavailable'
            }
          >
            {block.follow ? (
              streamId !== null ? (
                <StreamContent
                  analysisId={analysisId}
                  streamId={streamId}
                  initialMode={(followMode as StreamMode) ?? 'ascii'}
                />
              ) : null
            ) : (
              <div className="flex items-start gap-2 px-3 py-3 text-2xs text-muted">
                <Info size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
                <span>
                  {block.unavailable?.message ??
                    'The reassembled content is not available for this stream.'}
                </span>
              </div>
            )}
          </Panel>
        )
      })}

      {truncated ? (
        <div className="text-2xs text-faint">
          More streams belong to this alert than are shown; raise the stream cap to see them all.
        </div>
      ) : null}
    </div>
  )
}

export default FindingConversation