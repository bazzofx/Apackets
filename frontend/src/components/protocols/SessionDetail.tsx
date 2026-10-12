import { Link } from 'react-router-dom'
import { ArrowUpRight, TriangleAlert, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem } from '@/components/protocols/ProtocolDetail'
import { FlagExplanations } from '@/components/protocols/ProtocolFlags'
import { DETAIL_LABELS, PROTOCOL_LABELS, SESSION_FLAG_CATALOG } from '@/components/protocols/sessionCatalog'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import type { ProtocolSessionDetail } from '@/types'

/**
 * One protocol session, in full (docs/PROTOCOLS.md §3 and §5.3).
 *
 * The panel draws the row's own facts — endpoints, times, volume by direction — then the
 * `detail` object the extractor produced, then the lead flags with the catalogue's
 * explanation of what each one does and does not prove.
 *
 * `detail` is rendered **generically**: the panel knows how to draw a string, a number, a
 * boolean, a list of strings, a name-to-count map and a list of records, and it walks the
 * object in the order the backend wrote it. It never knows which protocol it is looking at,
 * so a key added for a new protocol appears here without a line of new code, and a key it
 * cannot classify is printed as text rather than dropped.
 */

/** A count map rendered as a sorted, wrapped list of chips. */
function CountMap({ label, value }: { label: string; value: Record<string, number> }) {
  const entries = Object.entries(value).sort((a, b) => b[1] - a[1])
  if (entries.length === 0) return null
  return (
    <DetailItem
      label={label}
      mono={false}
      value={
        <span className="flex flex-wrap items-center gap-1">
          {entries.map(([name, count]) => (
            <span key={name} className="chip border-border2 bg-surface2 text-text">
              {name}
              <span className="text-faint">×{formatNumber(count)}</span>
            </span>
          ))}
        </span>
      }
      title={entries.map(([name, count]) => `${name}: ${formatNumber(count)}`).join('\n')}
    />
  )
}

/** A list of records (the `commands` arrays) as a small table. */
function Records({ label, rows }: { label: string; rows: Record<string, unknown>[] }) {
  const columns = [...new Set(rows.flatMap((row) => Object.keys(row)))]
  if (columns.length === 0) return null
  return (
    <div className="col-span-full">
      <div className="mb-1 text-2xs uppercase tracking-wider text-faint">{label}</div>
      <div className="max-h-64 overflow-auto rounded border border-border">
        <table className="dt">
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column}>{column.replace(/_/g, ' ')}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                {columns.map((column) => (
                  <td key={column}>{row[column] === undefined ? '—' : String(row[column])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** A list of strings as chips, with the truncation flag the contract requires. */
function StringList({
  label,
  values,
  truncated,
}: {
  label: string
  values: string[]
  truncated: boolean
}) {
  if (values.length === 0) return null
  return (
    <DetailItem
      label={truncated ? `${label} (first ${String(values.length)})` : label}
      mono={false}
      value={
        <span className="flex flex-wrap items-center gap-1">
          {values.map((value) => (
            <span key={value} className="chip border-border2 bg-surface2 text-muted">
              {value}
            </span>
          ))}
        </span>
      }
      title={values.join('\n')}
    />
  )
}

/** One `detail` entry, dispatched on the shape of its value. */
function DetailEntry({
  name,
  value,
  detail,
}: {
  name: string
  value: unknown
  detail: Record<string, unknown>
}) {
  const label = DETAIL_LABELS[name] ?? name.replace(/_/g, ' ')
  const truncated = detail[`${name}_truncated`] === true

  if (value === null || value === undefined) return null

  if (typeof value === 'boolean') {
    return (
      <DetailItem
        label={label}
        value={value ? 'yes' : 'no'}
        tone={value ? 'warn' : 'ok'}
        title={`${label}: ${value ? 'yes' : 'no'} — recorded by the extractor, not inferred`}
      />
    )
  }

  if (typeof value === 'number') {
    return <DetailItem label={label} value={formatNumber(value)} />
  }

  if (typeof value === 'string') {
    if (value === '') return null
    return <DetailItem label={label} value={value} />
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return null
    const first = value[0]
    if (first !== null && typeof first === 'object') {
      return <Records label={truncated ? `${label} (first ${String(value.length)})` : label} rows={value as Record<string, unknown>[]} />
    }
    return <StringList label={label} values={value.map((item) => String(item))} truncated={truncated} />
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
    const numeric = entries.every(([, item]) => typeof item === 'number')
    if (numeric && entries.length > 0) {
      return <CountMap label={label} value={value as Record<string, number>} />
    }
    return (
      <DetailItem
        label={label}
        value={entries.map(([key, item]) => `${key}=${String(item)}`).join(', ')}
        title={JSON.stringify(value, null, 2)}
      />
    )
  }

  return <DetailItem label={label} value={String(value)} />
}

/** The `*_truncated` flags are shown beside the list they belong to, not as their own row. */
function isTruncationFlag(name: string): boolean {
  return name.endsWith('_truncated')
}

export interface SessionDetailProps {
  session: ProtocolSessionDetail
  onClose: () => void
}

export function SessionDetail({ session, onClose }: SessionDetailProps) {
  const detail = session.detail ?? {}
  const keys = Object.keys(detail).filter((name) => !isTruncationFlag(name))
  const flags = session.flags ?? []
  const links = session.links ?? []
  const protocol = PROTOCOL_LABELS[session.protocol] ?? session.protocol

  return (
    <Panel
      title={`${protocol} session`}
      subtitle={
        session.stream_id === null
          ? 'stream not reported by the dissector'
          : `${session.transport ?? 'stream'} stream ${String(session.stream_id)}`
      }
      actions={
        <>
          <CopyButton value={String(session.id)} label="Copy the session id" />
          <button type="button" className="btn btn-ghost" onClick={onClose} title="Close this session">
            <X size={13} aria-hidden />
            Close
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <DetailGrid columns={3}>
          <DetailItem
            label="Client"
            value={`${session.client_ip ?? '—'}:${String(session.client_port ?? '—')}`}
          />
          <DetailItem
            label="Server"
            value={`${session.server_ip ?? '—'}:${String(session.server_port ?? '—')}`}
          />
          <DetailItem label="Transport" value={session.transport ?? '—'} />
          <DetailItem label="Started" value={formatTimestamp(session.start_time)} />
          <DetailItem label="Ended" value={formatTimestamp(session.end_time)} />
          <DetailItem label="Duration" value={formatDuration(session.duration)} />
          <DetailItem
            label="Frames"
            value={`${formatNumber(session.packets)} (${formatNumber(session.first_frame)} → ${formatNumber(
              session.last_frame,
            )})`}
            title="Frames attributed to this session, and the first and last frame numbers"
          />
          <DetailItem label="Bytes" value={formatBytes(session.bytes)} />
          <DetailItem
            label="Client → server"
            value={`${formatBytes(session.client_bytes)} in ${formatNumber(session.client_packets)} frame(s)`}
          />
          <DetailItem
            label="Server → client"
            value={`${formatBytes(session.server_bytes)} in ${formatNumber(session.server_packets)} frame(s)`}
          />
        </DetailGrid>

        {session.note !== null && session.note.trim() !== '' ? (
          <div className="flex items-start gap-1.5 rounded border border-border bg-surface2/40 px-2 py-1.5">
            <TriangleAlert size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            <p className="text-2xs leading-relaxed text-muted">{session.note}</p>
          </div>
        ) : null}

        {flags.length > 0 ? (
          <FlagExplanations
            flags={flags}
            catalog={SESSION_FLAG_CATALOG}
            intro="The extraction flagged this session. Each explanation says what the pattern does and does not prove."
          />
        ) : (
          <p className="text-2xs text-faint" data-session-no-flags>
            No lead flag fired for this session. That is an absence of the patterns the extractor looks
            for, not a statement that the session was benign.
          </p>
        )}

        {keys.length > 0 ? (
          <DetailGrid columns={2}>
            {keys.map((name) => (
              <DetailEntry key={name} name={name} value={detail[name]} detail={detail} />
            ))}
          </DetailGrid>
        ) : (
          <p className="text-2xs text-faint" data-session-no-detail>
            The dissector produced no protocol fields for this session, so only its endpoints, times and
            volume are known. Nothing is inferred from the port number.
          </p>
        )}

        {links.length > 0 ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-2xs uppercase tracking-wider text-faint">Check</span>
            {links.map((link, index) => (
              <Link
                key={`${link.to}-${String(index)}`}
                to={link.to}
                className="chip border-border2 bg-surface2 text-muted hover:bg-surface2/60 hover:text-text"
                title={`Open ${link.to}`}
              >
                <ArrowUpRight size={11} aria-hidden />
                {link.label}
              </Link>
            ))}
          </div>
        ) : null}
      </div>
    </Panel>
  )
}

export default SessionDetail
