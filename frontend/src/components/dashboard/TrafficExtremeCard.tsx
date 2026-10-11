import clsx from 'clsx'
import { ArrowDownRight, ArrowUpRight, CircleHelp } from 'lucide-react'
import MonoCell from '@/components/MonoCell'
import { formatBytes, formatNumber } from '@/utils/format'
import type { SummaryTrafficExtreme } from '@/types'

export interface TrafficExtremeCardProps {
  title: string
  direction: 'sent' | 'received'
  host: SummaryTrafficExtreme | null | undefined
  onSelect?: (ip: string) => void
}

/** One side of the "most data sent / received" pair. */
export function TrafficExtremeCard({ title, direction, host, onSelect }: TrafficExtremeCardProps) {
  const Icon = direction === 'sent' ? ArrowUpRight : ArrowDownRight
  const value = host ? (direction === 'sent' ? host.bytes_sent : host.bytes_received) : null

  return (
    <div className="panel flex flex-col gap-2 p-3">
      <div className="flex items-center gap-1.5">
        <Icon size={14} className="text-accent2" aria-hidden />
        <span className="text-2xs font-semibold uppercase tracking-wider text-muted">{title}</span>
        {host ? (
          <span
            className={clsx(
              'chip ml-auto',
              host.is_private === 1
                ? 'border-accent/50 bg-accent/15 text-accent2'
                : host.is_private === 0
                  ? 'border-warn/50 bg-warn/15 text-warn'
                  : 'border-border2 bg-surface2 text-faint',
            )}
            title={
              host.is_private === 1
                ? 'Private address'
                : host.is_private === 0
                  ? 'Public address'
                  : 'Classification not available'
            }
          >
            {host.is_private === 1 ? 'private' : host.is_private === 0 ? 'public' : 'unclassified'}
          </span>
        ) : null}
      </div>

      {!host ? (
        <div className="flex items-center gap-2 py-2 text-2xs text-faint">
          <CircleHelp size={13} aria-hidden />
          <span>
            No host sent (or received) any data in this capture — nothing to rank. Shown honestly
            rather than as a zero row.
          </span>
        </div>
      ) : (
        <>
          <button
            type="button"
            className="text-left"
            onClick={() => onSelect?.(host.ip)}
            title={onSelect ? `Open ${host.ip} on the Hosts page` : undefined}
          >
            <MonoCell className="text-lg text-text">{host.ip}</MonoCell>
          </button>
          <div className="mono text-xl leading-tight text-text">{formatBytes(value)}</div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-muted">
            <span>{formatNumber(host.packets)} packets</span>
            <span>
              sent {formatBytes(host.bytes_sent)} · received {formatBytes(host.bytes_received)}
            </span>
          </div>
          {host.mac ? <MonoCell className="text-2xs text-faint">{host.mac}</MonoCell> : null}
          <div className="flex flex-wrap items-center gap-1">
            {host.hostnames.slice(0, 4).map((name) => (
              <span key={name} className="chip border-border2 bg-surface2 text-text" title={name}>
                {name}
              </span>
            ))}
            {host.hostnames.length > 4 ? (
              <span
                className="chip border-border2 bg-surface2 text-faint"
                title={host.hostnames.slice(4).join(', ')}
              >
                +{host.hostnames.length - 4} more
              </span>
            ) : null}
            {host.hostnames.length === 0 ? (
              <span className="text-2xs text-faint">no names observed for this address</span>
            ) : null}
          </div>
        </>
      )}
    </div>
  )
}

export default TrafficExtremeCard