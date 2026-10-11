import { useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Copy, Layers } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Panel from '@/components/Panel'
import { packetsApi } from '@/services/api'
import { EMPTY, formatClockTime, formatNumber } from '@/utils/format'

type DetailTab = 'layers' | 'hex' | 'raw'

/** Render arbitrary dissector JSON (never as HTML). */
function Node({ label, value, depth = 0 }: { label?: string; value: unknown; depth?: number }): ReactNode {
  if (value === null || value === undefined || value === '') {
    return (
      <>
        {label ? <span className="text-muted">{label}: </span> : null}
        <span className="text-faint">{EMPTY}</span>
      </>
    )
  }
  if (depth > 6) {
    return <span className="text-faint">…</span>
  }
  if (Array.isArray(value)) {
    return (
      <div className="flex flex-col">
        {label ? <div className="text-muted">{label}:</div> : null}
        <div className="pl-3">
          {value.slice(0, 40).map((item, index) => (
            <div key={index} className="flex gap-1">
              <span className="text-faint">[{index}]</span>
              <Node value={item} depth={depth + 1} />
            </div>
          ))}
          {value.length > 40 ? <div className="text-faint">+{value.length - 40} more</div> : null}
        </div>
      </div>
    )
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
    return (
      <div className="flex flex-col gap-0.5">
        {label ? <div className="text-muted">{label}:</div> : null}
        <div className="pl-3">
          {entries.map(([key, item]) => (
            <div key={key} className="flex flex-wrap gap-1">
              <span className="text-faint">{key}</span>
              <Node value={item} depth={depth + 1} />
            </div>
          ))}
        </div>
      </div>
    )
  }
  return (
    <span className="mono break-all">
      {label ? <span className="text-muted">{label}: </span> : null}
      {String(value)}
    </span>
  )
}

export interface PacketDetailViewProps {
  analysisId: string
  number: number
  /** Optional footer (e.g. neighbour navigation buttons). */
  footer?: ReactNode
  className?: string
}

/**
 * Full dissection of one packet: dissector tree, hex dump and the ASCII
 * rendering of the captured bytes. Capture-derived strings are rendered as
 * text only.
 */
export function PacketDetailView({ analysisId, number, footer, className }: PacketDetailViewProps) {
  const [tab, setTab] = useState<DetailTab>('layers')
  const detail = useQuery({
    queryKey: ['packet', analysisId, number],
    queryFn: () => packetsApi.detail(analysisId, number),
    staleTime: 60_000,
  })

  if (detail.isLoading) return <LoadingState label={`Loading packet ${number}…`} rows={4} />
  if (detail.error) {
    return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} title="Could not load the packet" />
  }
  const packet = detail.data
  if (!packet) return null

  const rawText = packet.raw_text ?? ''
  const RAW_PREVIEW = 20_000
  const rawShown = rawText.length > RAW_PREVIEW ? rawText.slice(0, RAW_PREVIEW) : rawText

  return (
    <Panel
      className={className}
      flush
      title={`Packet ${formatNumber(packet.number)}`}
      subtitle={`${packet.protocol ?? 'frame'} · ${formatClockTime(packet.time_epoch)} · ${formatNumber(
        packet.frame_len ?? packet.length ?? null,
      )} bytes${packet.raw_truncated ? ' · raw bytes truncated by the backend' : ''}`}
      actions={
        <div className="flex items-center gap-1">
          {(['layers', 'hex', 'raw'] as DetailTab[]).map((value) => (
            <button
              key={value}
              type="button"
              className={clsx('btn px-1.5 py-0.5', tab === value && 'btn-primary')}
              onClick={() => setTab(value)}
            >
              {value === 'layers' ? 'dissection' : value}
            </button>
          ))}
          <CopyButton value={packet.raw_hex} label="Copy raw hex" />
        </div>
      }
    >
      <div className="max-h-[28rem] overflow-auto p-3 text-2xs">
        {tab === 'layers' ? (
          <div className="flex flex-col gap-2">
            {(packet.layer_order ?? []).length === 0 ? (
              <div className="text-faint">No dissection available for this packet.</div>
            ) : null}
            {(packet.layer_order ?? []).map((layer) => {
              const value = packet.layers?.[layer]
              if (value === undefined) return null
              return (
                <div key={layer} className="border-b border-border/50 pb-2 last:border-0">
                  <div className="mb-1 flex items-center gap-1 text-accent2">
                    <Layers size={11} aria-hidden />
                    <span className="mono uppercase">{layer}</span>
                  </div>
                  <div className="pl-3">
                    <Node value={value} />
                  </div>
                </div>
              )
            })}
          </div>
        ) : null}

        {tab === 'hex' ? (
          <div className="mono">
            {(packet.hex_dump ?? []).length === 0 ? (
              <div className="text-faint">No hex dump available.</div>
            ) : (
              (packet.hex_dump ?? []).map((line) => (
                <div key={line.offset} className="flex gap-3 whitespace-pre">
                  <span className="text-faint">{line.offset.toString(16).padStart(6, '0')}</span>
                  <span className="text-text">{line.hex}</span>
                  <span className="text-muted">{line.ascii}</span>
                </div>
              ))
            )}
          </div>
        ) : null}

        {tab === 'raw' ? (
          <div>
            <div className="mb-1 flex items-center gap-2 text-faint">
              <span>
                {formatNumber(packet.raw_len ?? rawText.length)} bytes, ASCII rendering
                {rawText.length > RAW_PREVIEW ? ` — showing the first ${formatNumber(RAW_PREVIEW)}` : ''}
              </span>
              <CopyButton value={rawShown} label="Copy raw text" />
              <Copy className="hidden" size={1} aria-hidden />
            </div>
            <pre className="mono whitespace-pre-wrap break-all text-2xs text-text">{rawShown}</pre>
          </div>
        ) : null}
      </div>
      {footer ? <div className="border-t border-border px-3 py-2">{footer}</div> : null}
    </Panel>
  )
}

export default PacketDetailView