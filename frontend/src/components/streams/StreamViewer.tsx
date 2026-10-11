import { useCallback, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ArrowLeftRight, Info, Layers, TriangleAlert } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import { DownloadButton, type DownloadReport } from '@/components/packets/DownloadAction'
import { useAnalysis } from '@/hooks/useAnalysis'
import { conversationsApi } from '@/services/api'
import type { StreamChunk, StreamDetail, StreamFollow, StreamMode, Transport } from '@/types'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import { StreamSearchPanel } from './StreamSearchPanel'
import {
  STREAM_EXPORT_FORMATS,
  clientNodeIndex,
  streamExportUrl,
  type StreamExportFormat,
  type StreamSearchMatch,
} from './streamClient'

/**
 * Follow-stream viewer.
 *
 * The payload always comes from TShark's own `follow,tcp,<mode>,<stream>` output
 * through `GET .../streams/{id}?mode=ascii|hex|raw`; nothing here concatenates
 * packet payloads itself. What the API returns is:
 *
 * * `stream` — the indexed row (client/server endpoints, payload bytes per side,
 *   packet count, start/end time);
 * * `follow.client_to_server` / `follow.server_to_client` — `{direction, bytes,
 *   text, hex, truncated}` for the reassembled bytes of each side;
 * * `follow.chunks[]` — `{index, direction, byte_len, text_preview, hex_preview}`
 *   in capture order, which is what makes the direction changes visible.
 *
 * UDP is deliberately not synthesised by the backend: a UDP "stream" has no
 * ordering, so this viewer says so instead of inventing one.
 */

/** Characters rendered before the payload block has to be expanded. */
const TEXT_RENDER_LIMIT = 200_000
/** Characters of a chunk preview shown before the full preview is revealed. */
const PREVIEW_LIMIT = 400

export interface DirectionInfo {
  label: string
  /** `accent` for client->server, `ok` for server->client, `muted` when unknown. */
  tone: 'accent' | 'ok' | 'muted'
  short: string
}

/**
 * Label a direction from the response itself: prefer the per-side `direction`
 * field the API reports, fall back to `client_node`, and only then describe the
 * two TShark nodes — never guess which side is the client.
 */
export function directionInfo(direction: number, follow: StreamFollow): DirectionInfo {
  const c2s = follow.client_to_server?.direction
  if (c2s !== undefined) {
    return direction === c2s
      ? { label: 'client \u2192 server', tone: 'accent', short: 'c\u2192s' }
      : { label: 'server \u2192 client', tone: 'ok', short: 's\u2192c' }
  }
  const clientNode = clientNodeIndex(follow)
  if (clientNode !== null) {
    const isClient = (direction === 0) === (clientNode === 0)
    return isClient
      ? { label: 'client \u2192 server', tone: 'accent', short: 'c\u2192s' }
      : { label: 'server \u2192 client', tone: 'ok', short: 's\u2192c' }
  }
  const node0 = follow.node0 ?? 'node 0'
  const node1 = follow.node1 ?? 'node 1'
  return direction === 0
    ? { label: `${node0} \u2192 ${node1}`, tone: 'muted', short: 'n0\u2192n1' }
    : { label: `${node1} \u2192 ${node0}`, tone: 'muted', short: 'n1\u2192n0' }
}

/** A long payload block, rendered lazily and never silently truncated. */
function PayloadBlock({ text, tone }: { text: string; tone: 'accent' | 'ok' }) {
  const [expanded, setExpanded] = useState(false)
  if (text === '') {
    return <p className="px-2 py-2 text-2xs text-faint">no bytes in this direction</p>
  }
  const cropped = !expanded && text.length > TEXT_RENDER_LIMIT
  return (
    <div className="flex flex-col">
      <pre
        className={clsx(
          'mono m-0 max-h-[38vh] overflow-auto whitespace-pre-wrap break-all px-2 py-2 text-2xs leading-relaxed',
          tone === 'accent' ? 'bg-accent/5 text-text' : 'bg-ok/5 text-text',
        )}
      >
        {cropped ? text.slice(0, TEXT_RENDER_LIMIT) : text}
      </pre>
      {text.length > TEXT_RENDER_LIMIT ? (
        <div className="flex items-center gap-2 border-t border-border px-2 py-1 text-2xs text-faint">
          <TriangleAlert size={11} className="shrink-0 text-warn" aria-hidden />
          <span className="mono">
            rendering {formatNumber(cropped ? TEXT_RENDER_LIMIT : text.length)} of{' '}
            {formatNumber(text.length)} characters
          </span>
          <button
            type="button"
            className="btn px-1.5 py-0.5"
            onClick={() => setExpanded((value) => !value)}
          >
            {expanded ? 'Render less' : 'Render everything'}
          </button>
        </div>
      ) : null}
    </div>
  )
}

export interface StreamViewerProps {
  analysisId: string
  streamId: number
  transport: Transport
  /** `conv_id` of the conversation this stream belongs to, when known. */
  convId?: string | null
  mode: StreamMode
  onModeChange: (mode: StreamMode) => void
  /** Link to the packet browser filtered to this stream. */
  onOpenPackets: () => void
}

export function StreamViewer({
  analysisId,
  streamId,
  transport,
  convId = null,
  mode,
  onModeChange,
  onOpenPackets,
}: StreamViewerProps) {
  const { selected: analysis } = useAnalysis()
  const chunkRefs = useRef(new Map<number, HTMLTableRowElement | null>())
  const [highlighted, setHighlighted] = useState<number | null>(null)
  const [jumpNotice, setJumpNotice] = useState<string | null>(null)
  const [exportReport, setExportReport] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)

  const isTcp = transport === 'tcp'

  const query = useQuery<StreamDetail>({
    queryKey: ['stream', analysisId, streamId, mode],
    queryFn: () => conversationsApi.stream(analysisId, streamId, mode),
    enabled: isTcp,
    retry: false,
  })

  const follow = query.data?.follow
  const stream = query.data?.stream
  const chunks = follow?.chunks ?? []

  const hasPayload = useMemo(() => {
    if (!follow) return false
    return (
      (follow.client_to_server?.bytes ?? 0) > 0 ||
      (follow.server_to_client?.bytes ?? 0) > 0 ||
      (follow.chunk_count ?? follow.chunks.length) > 0
    )
  }, [follow])

  /** Chunk that carried a given byte offset of a direction, if it is inline. */
  const chunkIndexForOffset = useCallback(
    (direction: number, offset: number): number | null => {
      let cumulative = 0
      for (let index = 0; index < chunks.length; index += 1) {
        const chunk: StreamChunk = chunks[index]
        if (chunk.direction !== direction) continue
        const start = cumulative
        cumulative += chunk.byte_len ?? 0
        if (offset >= start && offset < cumulative) return chunk.index ?? index
      }
      return null
    },
    [chunks],
  )

  const handleJump = useCallback(
    (match: StreamSearchMatch) => {
      const index = chunkIndexForOffset(match.direction, match.offset)
      if (index === null) {
        setHighlighted(null)
        setJumpNotice(
          `Byte ${formatNumber(match.offset)} of this direction falls in a chunk the backend did not return inline (${formatNumber(follow?.chunk_count ?? chunks.length)} chunks in the stream). The hit is listed above but cannot be highlighted.`,
        )
        return
      }
      setJumpNotice(null)
      setHighlighted(index)
      const row = chunkRefs.current.get(index)
      if (row) row.scrollIntoView({ block: 'center' })
    },
    [chunkIndexForOffset, chunks.length, follow?.chunk_count],
  )

  return (
    <div className="flex flex-col gap-2">
      <Panel
        title={`Follow stream ${convId ?? `${transport} ${streamId}`}`}
        subtitle={
          stream
            ? `${stream.client_ip ?? '?'}:${stream.client_port ?? '?'} -> ${stream.server_ip ?? '?'}:${
                stream.server_port ?? '?'
              } \u00b7 ${formatNumber(stream.packets)} packets`
            : 'reassembled by tshark -z follow'
        }
        flush
        actions={
          <>
            <span className="flex items-center gap-1" role="group" aria-label="Stream rendering mode">
              {(['ascii', 'hex', 'raw'] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  className={clsx('btn px-1.5 py-1', mode === value && 'btn-primary')}
                  onClick={() => onModeChange(value)}
                  title={
                    value === 'ascii'
                      ? 'Decoded text (UTF-8 with replacement for invalid bytes)'
                      : value === 'hex'
                        ? 'Lowercase hex of the reassembled bytes'
                        : 'ASCII rendering with every non-printable byte as a dot'
                  }
                  aria-pressed={mode === value}
                >
                  {value}
                </button>
              ))}
            </span>
            {STREAM_EXPORT_FORMATS.map((format: StreamExportFormat) => (
              <DownloadButton
                key={format}
                url={streamExportUrl(analysisId, streamId, mode, format)}
                label={format}
                disabled={!isTcp}
                title={
                  format === 'csv'
                    ? 'Download the chunk list as CSV (index, direction, byte_len, hex)'
                    : format === 'hex'
                      ? 'Download the reassembled bytes as hex text'
                      : format === 'raw'
                        ? 'Download the exact reassembled bytes as a .bin file'
                        : `Download the reassembled payload as text in the current ${mode} mode`
                }
                onReport={(report: DownloadReport) => {
                  setExportError(null)
                  setExportReport(`${report.filename ?? format} \u00b7 ${formatBytes(report.bytes)}`)
                }}
                onError={(message) => {
                  setExportReport(null)
                  setExportError(message)
                }}
              />
            ))}
          </>
        }
      >
        {!isTcp ? (
          <div className="p-3">
            <EmptyState
              variant="plain"
              icon={ArrowLeftRight}
              title="UDP conversations have no reassembled stream"
              description={
                <>
                  TShark&apos;s <span className="mono">follow</span> reassembly is TCP-only, and the
                  backend deliberately does not synthesise an ordering for UDP datagrams — inventing
                  one would be a guess about application semantics. The datagrams of this flow are
                  still in the packet index: use the packet list below, or export the indexed rows as
                  CSV from the packet browser.
                </>
              }
              action={
                <button type="button" className="btn btn-primary" onClick={onOpenPackets}>
                  <Layers size={13} aria-hidden />
                  Open this stream in the packet browser
                </button>
              }
            />
          </div>
        ) : query.isLoading ? (
          <LoadingState label="Reassembling the stream with TShark..." rows={6} />
        ) : query.error ? (
          <ErrorState
            error={query.error}
            title="Could not reassemble this stream"
            onRetry={() => void query.refetch()}
          />
        ) : !stream || !follow ? (
          <div className="p-3">
            <SectionNote>
              The backend returned no stream row for stream {streamId}. That usually means the stream
              id belongs to a different transport namespace in this analysis.
            </SectionNote>
          </div>
        ) : (
          <div className="flex flex-col divide-y divide-border">
            <div className="p-3">
              <DetailGrid columns={3}>
                <DetailItem
                  label="Node 0"
                  value={follow.node0}
                  unavailableReason="TShark reported no node 0 for this stream."
                />
                <DetailItem
                  label="Node 1"
                  value={follow.node1}
                  unavailableReason="TShark reported no node 1 for this stream."
                />
                <DetailItem
                  label="Client side"
                  value={
                    clientNodeIndex(follow) === null
                      ? null
                      : `node${clientNodeIndex(follow)} (${follow.client_endpoint ?? 'endpoint unknown'})`
                  }
                  title={
                    clientNodeIndex(follow) === null
                      ? 'The backend could not match its recorded client endpoint to either TShark node, so the two directions are labelled by node instead.'
                      : undefined
                  }
                  unavailableReason="The recorded client endpoint does not match either node, so directions are named by node."
                />
                <DetailItem label="Client endpoint" value={follow.client_endpoint} />
                <DetailItem label="Server endpoint" value={follow.server_endpoint} />
                <DetailItem label="Stream id" value={streamId} />
                <DetailItem
                  label="Payload client -> server"
                  value={formatBytes(follow.client_to_server?.bytes ?? null)}
                  unavailableReason="No reassembled bytes in this direction."
                />
                <DetailItem
                  label="Payload server -> client"
                  value={formatBytes(follow.server_to_client?.bytes ?? null)}
                  unavailableReason="No reassembled bytes in this direction."
                />
                <DetailItem
                  label="Packets in stream"
                  value={stream.packets === null ? null : formatNumber(stream.packets)}
                  unavailableReason="The indexed stream row has no packet count."
                />
                <DetailItem label="Started" value={formatTimestamp(stream.start_time)} />
                <DetailItem
                  label="Duration"
                  value={
                    stream.start_time !== null && stream.end_time !== null
                      ? formatDuration(Math.max(0, stream.end_time - stream.start_time))
                      : null
                  }
                  unavailableReason="The indexed stream row has no end time."
                />
                <DetailItem
                  label="Chunks"
                  value={`${formatNumber(follow.chunk_count ?? chunks.length)}${
                    follow.chunks_truncated || (follow.chunk_count ?? 0) > chunks.length
                      ? ` (${formatNumber(chunks.length)} inline)`
                      : ''
                  }`}
                />
              </DetailGrid>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <CopyButton
                  value={follow.client_to_server?.text ?? null}
                  label="Copy the client-to-server payload"
                />
                <span className="text-2xs text-faint">
                  copy client to server payload (current mode)
                </span>
                <CopyButton
                  value={follow.server_to_client?.text ?? null}
                  label="Copy the server-to-client payload"
                />
                <span className="text-2xs text-faint">
                  copy server to client payload (current mode)
                </span>
              </div>
            </div>

            {follow.truncated ||
            follow.chunks_truncated ||
            follow.client_to_server?.truncated ||
            follow.server_to_client?.truncated ? (
              <div className="p-3">
                <SectionNote tone="warn">
                  Output was capped by the backend:{' '}
                  {follow.client_to_server?.truncated ? 'client-to-server text/hex ' : ''}
                  {follow.server_to_client?.truncated ? 'server-to-client text/hex ' : ''}
                  {follow.chunks_truncated || (follow.chunk_count ?? 0) > chunks.length
                    ? `only ${formatNumber(chunks.length)} of ${formatNumber(
                        follow.chunk_count ?? chunks.length,
                      )} chunks are listed inline `
                    : ''}
                  — a per-direction rendering is stored up to 2 MiB of source bytes and at most 500
                  chunk previews. The export buttons download the whole reassembled stream, and the
                  byte totals above are always the true ones.
                </SectionNote>
              </div>
            ) : null}

            {!hasPayload ? (
              <div className="p-3">
                <EmptyState
                  variant="plain"
                  icon={ArrowLeftRight}
                  title="This stream carries no payload"
                  description="TShark reassembled the TCP conversation but found no application bytes in either direction — a handshake-only, reset-only or zero-window stream. There is nothing to follow."
                  action={
                    <button type="button" className="btn" onClick={onOpenPackets}>
                      <Layers size={13} aria-hidden />
                      Show the stream&apos;s packets
                    </button>
                  }
                />
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 divide-y divide-border xl:grid-cols-2 xl:divide-x xl:divide-y-0">
                  {(['client_to_server', 'server_to_client'] as const).map((side) => {
                    const block = follow[side]
                    const info = directionInfo(
                      block?.direction ?? (side === 'client_to_server' ? 0 : 1),
                      follow,
                    )
                    return (
                      <section key={side} className="flex min-w-0 flex-col">
                        <header className="flex flex-wrap items-center gap-2 px-2 py-1.5">
                          <span
                            className={clsx(
                              'chip',
                              info.tone === 'accent'
                                ? 'border-accent/50 bg-accent/15 text-accent2'
                                : info.tone === 'ok'
                                  ? 'border-ok/50 bg-ok/15 text-ok'
                                  : 'border-border2 bg-surface2 text-muted',
                            )}
                            title={`direction ${block?.direction ?? 'not reported'}`}
                          >
                            {info.label}
                          </span>
                          <span className="mono text-2xs text-muted">
                            {formatBytes(block?.bytes ?? null)} reassembled
                          </span>
                        </header>
                        <PayloadBlock
                          text={block?.text ?? ''}
                          tone={info.tone === 'ok' ? 'ok' : 'accent'}
                        />
                      </section>
                    )
                  })}
                </div>

                <div className="flex flex-col">
                  <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                    <span className="panel-title">Chunk timeline</span>
                    <span className="text-2xs text-faint">
                      capture order, so direction changes are visible; TShark emits one chunk per
                      reassembled payload segment
                    </span>
                  </div>
                  {jumpNotice ? (
                    <div className="flex items-start gap-2 px-3 pb-2 text-2xs text-warn">
                      <Info size={12} className="mt-0.5 shrink-0" aria-hidden />
                      <span>{jumpNotice}</span>
                    </div>
                  ) : null}
                  <div className="max-h-[46vh] overflow-auto">
                    <table className="dt">
                      <thead>
                        <tr>
                          <th className="text-right">#</th>
                          <th>direction</th>
                          <th className="text-right">bytes</th>
                          <th className="w-full">preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {chunks.map((chunk, index) => {
                          const info = directionInfo(chunk.direction, follow)
                          const preview = chunk.text_preview ?? ''
                          const rowKey = chunk.index ?? index
                          return (
                            <tr
                              key={`${rowKey}-${chunk.direction}`}
                              ref={(element) => {
                                chunkRefs.current.set(rowKey, element)
                              }}
                              className={clsx(highlighted === rowKey && 'selected')}
                              title={
                                chunk.hex_preview
                                  ? `hex: ${chunk.hex_preview.slice(0, 240)}`
                                  : undefined
                              }
                            >
                              <td className="text-right tabular-nums">{formatNumber(rowKey)}</td>
                              <td>
                                <span
                                  className={clsx(
                                    'chip',
                                    info.tone === 'accent'
                                      ? 'border-accent/50 bg-accent/15 text-accent2'
                                      : info.tone === 'ok'
                                        ? 'border-ok/50 bg-ok/15 text-ok'
                                        : 'border-border2 bg-surface2 text-muted',
                                  )}
                                  title={info.label}
                                >
                                  {info.short}
                                </span>
                              </td>
                              <td className="text-right tabular-nums">
                                {formatNumber(chunk.byte_len)}
                              </td>
                              <td>
                                <MonoCell maxWidth={1200} title={preview || undefined}>
                                  {preview === '' ? null : preview.slice(0, PREVIEW_LIMIT)}
                                </MonoCell>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                <StreamSearchPanel
                  analysisId={analysisId}
                  streamId={streamId}
                  mode={mode}
                  follow={follow}
                  onJump={handleJump}
                />
              </>
            )}

            {exportError || exportReport ? (
              <div
                className={clsx('px-3 py-1.5 text-2xs', exportError ? 'text-red-200' : 'text-muted')}
                role={exportError ? 'alert' : undefined}
              >
                <span className="mono">{exportError ?? `downloaded ${exportReport}`}</span>
              </div>
            ) : null}
          </div>
        )}
      </Panel>

      {analysis ? (
        <p className="px-1 text-2xs text-faint">
          Reassembly is TShark&apos;s (<span className="mono">follow,tcp,{mode},{streamId}</span>) over{' '}
          <span className="mono">{analysis.original_filename}</span>; sequence numbers,
          retransmissions and out-of-order segments are handled by TShark, not by this page.
        </p>
      ) : null}
    </div>
  )
}

export default StreamViewer