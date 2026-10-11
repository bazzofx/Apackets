import { useState } from 'react'
import clsx from 'clsx'
import { Binary, FileText, TriangleAlert } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import { SectionNote } from '@/components/protocols/ProtocolDetail'
import type { HexDumpLine, PacketDetail } from '@/types'
import { EMPTY, formatNumber } from '@/utils/format'

/**
 * Hex + ASCII viewer for one packet.
 *
 * The rows come straight from the API's `hex_dump` (`{offset, hex, ascii,
 * bytes}`, 16 bytes per row, contract §7) and are rendered in aligned monospace
 * columns. The ASCII rendering of the captured bytes (`raw_text`, non-printables
 * as `.`) is offered as a second view, with the `raw_truncated` cap stated
 * explicitly instead of being hidden.
 *
 * Selected-byte-range highlighting is deliberately not implemented: the API
 * sends no offset→field mapping, so any highlight would be a guess.
 */

const BYTES_PER_ROW = 16
/** 16 bytes as `xx xx …` = 16 * 2 + 15 spaces. */
const HEX_WIDTH = BYTES_PER_ROW * 2 + (BYTES_PER_ROW - 1)

function offsetLabel(offset: number): string {
  if (!Number.isFinite(offset) || offset < 0) return '????????'
  return offset.toString(16).padStart(8, '0')
}

function paddedHex(line: HexDumpLine): string {
  return (line.hex ?? '').padEnd(HEX_WIDTH, ' ')
}

type View = 'dump' | 'text'

export interface HexDumpViewProps {
  detail: PacketDetail
  className?: string
}

export function HexDumpView({ detail, className }: HexDumpViewProps) {
  const [view, setView] = useState<View>('dump')
  const rows = Array.isArray(detail.hex_dump) ? detail.hex_dump : []
  const rawHex = detail.raw_hex ?? ''
  const rawText = detail.raw_text ?? ''
  const rawLen = Number.isFinite(detail.raw_len) ? detail.raw_len : null
  const hasBytes = rows.length > 0 || rawHex !== ''

  return (
    <div className={clsx('flex flex-col', className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-1" role="group" aria-label="Byte view">
          <button
            type="button"
            className={clsx('btn px-1.5 py-1', view === 'dump' && 'btn-primary')}
            onClick={() => setView('dump')}
            title="Offset, hex bytes and ASCII, 16 bytes per row"
            aria-pressed={view === 'dump'}
          >
            <Binary size={12} aria-hidden />
            Hex + ASCII
          </button>
          <button
            type="button"
            className={clsx('btn px-1.5 py-1', view === 'text' && 'btn-primary')}
            onClick={() => setView('text')}
            title="ASCII rendering of the captured bytes (non-printables as .)"
            aria-pressed={view === 'text'}
          >
            <FileText size={12} aria-hidden />
            Text
          </button>
        </div>
        <span className="mono text-2xs text-faint">
          {rawLen === null ? 'length unknown' : `${formatNumber(rawLen)} bytes captured`}
          {rows.length > 0 ? ` · ${formatNumber(rows.length)} dump rows` : ''}
        </span>
        <span className="ml-auto flex items-center gap-1.5">
          <CopyButton
            value={rawHex}
            label="Copy the raw hex of this packet"
            className="px-1.5 py-1"
            disabled={rawHex === ''}
          />
          <span className="text-2xs text-faint">raw hex</span>
        </span>
      </div>

      {detail.raw_truncated ? (
        <div className="px-3 pt-2">
          <SectionNote tone="warn">
            The text rendering is capped by the backend (8192 characters) and flagged
            <span className="mono"> raw_truncated</span>, so the text below is not the whole
            packet. The hex dump is not affected.
          </SectionNote>
        </div>
      ) : null}

      {view === 'text' ? (
        rawText === '' ? (
          <div className="px-3 py-4 text-2xs leading-relaxed text-muted">
            The backend returned no text rendering for this packet
            {rawLen === 0 ? ' because no bytes were captured.' : '.'}
          </div>
        ) : (
          <pre className="mono m-0 max-h-[52vh] overflow-auto whitespace-pre-wrap break-all px-3 py-2 text-2xs leading-relaxed text-text">
            {rawText}
          </pre>
        )
      ) : !hasBytes ? (
        <div className="flex items-start gap-2 px-3 py-4 text-2xs leading-relaxed text-muted">
          <TriangleAlert size={12} className="mt-0.5 shrink-0 text-warn" aria-hidden />
          <span>
            No bytes came back for this packet. The byte read is a separate TShark invocation from
            the dissection, so this means only that the dump failed or the frame carries no
            captured data — it does not mean the packet is empty.
          </span>
        </div>
      ) : (
        <div className="max-h-[52vh] overflow-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="sticky top-0 z-10 bg-surface2">
                <th className="border-b border-border px-2 py-1 text-left font-semibold text-muted">
                  offset
                </th>
                <th className="border-b border-border px-2 py-1 text-left font-semibold text-muted">
                  bytes
                </th>
                <th className="border-b border-border px-2 py-1 text-left font-semibold text-muted">
                  ascii
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((line, index) => (
                <tr key={`${line.offset}-${index}`} className="hover:bg-surface2/60">
                  <td className="mono whitespace-pre px-2 py-[2px] align-top text-2xs text-faint">
                    {offsetLabel(line.offset)}
                  </td>
                  <td className="mono whitespace-pre px-2 py-[2px] align-top text-2xs text-text">
                    {paddedHex(line)}
                  </td>
                  <td className="mono whitespace-pre px-2 py-[2px] align-top text-2xs text-muted">
                    {line.ascii === '' ? EMPTY : line.ascii}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && rawHex !== '' ? (
            <div className="px-3 py-3 text-2xs leading-relaxed text-muted">
              TShark returned raw hex for this packet but no formatted dump rows, so only the copied
              hex is available.
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}

export default HexDumpView
