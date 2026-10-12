import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ArrowLeftRight, Loader2, X } from 'lucide-react'
import ErrorState from '@/components/ErrorState'
import { countryName } from '@/theme/worldMap'
import { geoApi } from '@/services/api'
import { formatBytes, formatNumber } from '@/utils/format'
import type { GeographyCountryDetail } from '@/types'

/**
 * The destination panel: what one dot on the map actually stands for
 * (docs/GEOGRAPHY.md §5.4 and §6).
 *
 * A dot is a country, and a country is a group of addresses — so this panel is where the
 * group is opened up: the packets and bytes in **each direction**, the ports the capture
 * used with the side that owned them, and one row per address with its own counts and a
 * **Follow conversation** button that lands on the earliest conversation involving it, on the
 * Conversations page's timeline.
 *
 * It is fetched when a dot is clicked and not before, so a reader who never opens one never
 * pays for it. Every number comes from the response; an address with no conversation says so
 * instead of offering a link that would open nothing, and the direction mapping is stated in
 * words because "sent" from whose side is exactly the kind of thing a reader should not have
 * to guess.
 */

/** One direction's counts, rendered as a compact pair. */
function Direction({ label, packets, bytes }: { label: string; packets: number; bytes: number }) {
  return (
    <span className="flex items-baseline gap-1.5">
      <span className="text-2xs uppercase tracking-wider text-faint">{label}</span>
      <span className="mono text-xs text-text">{formatBytes(bytes)}</span>
      <span className="text-2xs text-faint">{formatNumber(packets)} pkt</span>
    </span>
  )
}

/** One port chip: the number, the side that owned it, and what it moved. */
function PortChip({
  port,
  side,
  packets,
  bytes,
  addresses,
}: {
  port: number
  side: 'remote' | 'local'
  packets: number
  bytes: number
  addresses: number
}) {
  const remote = side === 'remote'
  return (
    <span
      className={clsx(
        'chip',
        remote ? 'border-accent/50 bg-accent/10 text-accent2' : 'border-border2 bg-surface2 text-muted',
      )}
      title={`Port ${String(port)} belonged to the ${remote ? "destination's address (the service port)" : "capture's own side (usually the ephemeral port)"}: ${formatNumber(packets)} packet(s), ${formatBytes(bytes)}${addresses > 1 ? `, ${formatNumber(addresses)} address(es)` : ''}`}
    >
      {port}
      <span className="text-faint">{remote ? 'remote' : 'local'}</span>
    </span>
  )
}

export interface DestinationPanelProps {
  analysisId: string
  code: string
  onClose: () => void
  onSelectIp: (ip: string) => void
}

/**
 * Where the card sits: vertically centred against the right edge of the map frame, and never
 * anywhere else.
 *
 * It used to be anchored to its dot, which meant it could be pushed into a corner by a dot near
 * an edge and could cover the very country it described. A fixed dock is stable, is always
 * inside the frame whatever the zoom or the country, and leaves the middle of the map — where
 * the dots are — visible. The placement itself is `.world-panel` in index.css.
 */
export function DestinationPanel({
  analysisId,
  code,
  onClose,
  onSelectIp,
}: DestinationPanelProps) {
  const query = useQuery({
    queryKey: ['geography-country', analysisId, code],
    queryFn: () => geoApi.country(analysisId, code),
    staleTime: 60_000,
  })

  const data: GeographyCountryDetail | undefined = query.data

  return (
    <div
      className="world-panel"
      role="dialog"
      aria-label="Destination detail"
      data-destination-panel={code}
      /* The panel lives inside the map's element, so a press here must never reach the map's pan
         handler: stopping it here as well as at the rule is what keeps a link a link. */
      onPointerDown={(event) => event.stopPropagation()}
      onClick={(event) => event.stopPropagation()}
    >
      <header className="sticky top-0 flex items-start justify-between gap-2 border-b border-border bg-surface/95 px-2.5 py-2">
        <div className="min-w-0">
          <div className="flex items-baseline gap-1.5">
            <span className="chip border-border2 bg-surface2 text-text">{code}</span>
            <span className="truncate text-sm font-semibold text-text">
              {code === 'ZZ' ? 'No country in the dataset' : countryName(code)}
            </span>
          </div>
          {data ? (
            <div className="mt-0.5 text-2xs text-faint">
              {formatNumber(data.counts.addresses)} address(es) · {formatNumber(data.counts.packets)}{' '}
              packet(s) · {formatBytes(data.counts.bytes)}
            </div>
          ) : null}
        </div>
        <button
          type="button"
          className="btn btn-ghost px-1.5 py-0.5"
          onClick={onClose}
          aria-label="Close the destination panel"
          title="Close (Esc)"
        >
          <X size={12} aria-hidden />
        </button>
      </header>

      {query.isLoading ? (
        <div className="flex items-center gap-2 px-2.5 py-3 text-2xs text-muted">
          <Loader2 size={12} className="animate-spin" aria-hidden />
          Reading this destination's conversations…
        </div>
      ) : query.error ? (
        <div className="p-2">
          <ErrorState
            error={query.error}
            title="Could not read this destination"
            onRetry={() => void query.refetch()}
          />
        </div>
      ) : data === undefined ? null : (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-2.5 py-2">
            <Direction label="sent" packets={data.counts.sent.packets} bytes={data.counts.sent.bytes} />
            <Direction
              label="received"
              packets={data.counts.received.packets}
              bytes={data.counts.received.bytes}
            />
            <span className="text-2xs text-faint" title="From this capture’s own side: sent is what this side sent, which is what the destination received.">
              from this capture&rsquo;s side
            </span>
          </div>

          {data.ports.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1 px-2.5 pb-2">
              <span className="text-2xs uppercase tracking-wider text-faint">Ports</span>
              {data.ports.map((entry) => (
                <PortChip
                  key={`${String(entry.port)}-${entry.side}`}
                  port={entry.port}
                  side={entry.side}
                  packets={entry.packets}
                  bytes={entry.bytes}
                  addresses={entry.addresses}
                />
              ))}
              {data.ports_truncated ? (
                <span className="text-2xs text-faint" title="Only the busiest ports are listed.">
                  +more
                </span>
              ) : null}
            </div>
          ) : (
            <p className="px-2.5 pb-2 text-2xs text-faint">
              No conversation involving these addresses was recorded, so no port is known.
            </p>
          )}

          <ul className="flex flex-col">
            {data.targets.map((target) => {
              const follow = target.first_conversation
              return (
                <li
                  key={target.ip}
                  className="world-target"
                  data-destination-target={target.ip}
                  /* The row is an address and, when the capture recorded one, a
                     conversation: the context menu uses both, so the Wireshark
                     pivot opens this exchange rather than all of the address's
                     traffic (components/context/IpContextMenu.tsx). */
                  data-ip={target.ip}
                  data-ip-transport={follow?.transport ?? undefined}
                  data-ip-stream={follow?.stream_id ?? undefined}
                  data-ip-port={
                    target.ports.find((entry) => entry.side === 'remote')?.port ?? undefined
                  }
                >
                  <button
                    type="button"
                    className="mono text-xs text-accent2 hover:underline"
                    onClick={() => onSelectIp(target.ip)}
                    title={`Open ${target.ip} on the Hosts page`}
                  >
                    {target.ip}
                  </button>
                  <span className="mono text-2xs text-muted">{formatBytes(target.bytes)}</span>
                  <span className="text-2xs text-faint" title="Bytes this side sent to the address / bytes received from it.">
                    ↑{formatBytes(target.sent.bytes)} ↓{formatBytes(target.received.bytes)}
                  </span>
                  {target.ports.length > 0 ? (
                    <span className="flex flex-wrap items-center gap-1">
                      {target.ports.map((entry) => (
                        <span
                          key={`${String(entry.port)}-${entry.side}`}
                          className={clsx(
                            'chip',
                            entry.side === 'remote'
                              ? 'border-border2 bg-surface2 text-muted'
                              : 'border-border2 bg-surface2 text-faint',
                          )}
                          title={`Port ${String(entry.port)} (${entry.side === 'remote' ? 'destination side' : "capture's own side"}): ${formatNumber(entry.packets)} packet(s)`}
                        >
                          {entry.port}
                        </span>
                      ))}
                      {target.ports_truncated ? (
                        <span
                          className="text-2xs text-faint"
                          title={`This address used more than the ${formatNumber(target.ports.length)} ports shown; the busiest are listed.`}
                        >
                          +more
                        </span>
                      ) : null}
                    </span>
                  ) : null}
                  <span className="ml-auto">
                    {follow === null || follow.stream_id === null ? (
                      <button
                        type="button"
                        className="btn px-1.5 py-0.5"
                        disabled
                        title={
                          follow === null
                            ? `No conversation involving ${target.ip} was recorded in this capture, so there is nothing to follow. A one-way broadcast, or a capture that began mid-session, looks like this.`
                            : `The earliest conversation with ${target.ip} was never reassembled into a stream, so it has no timeline to open. Its packets are still on the host page.`
                        }
                      >
                        <ArrowLeftRight size={11} aria-hidden />
                        {follow === null ? 'No conversation' : 'No stream'}
                      </button>
                    ) : (
                      <FollowButton
                        ip={target.ip}
                        transport={follow.transport}
                        streamId={follow.stream_id}
                        packets={follow.packets}
                        bytes={follow.bytes}
                      />
                    )}
                  </span>
                </li>
              )
            })}
          </ul>

          {data.targets_truncated ? (
            <p className="px-2.5 py-1.5 text-2xs text-faint">
              Only the {formatNumber(data.targets.length)} busiest of {formatNumber(data.counts.addresses)}{' '}
              addresses are listed. The totals above count them all.
            </p>
          ) : null}
        </>
      )}
    </div>
  )
}

/**
 * Follow this address's conversation.
 *
 * The destination is the application's existing conversation deep link
 * (`/conversations?stream=<transport>:<id>&tab=timeline`), the same one the Findings page's
 * Follow conversation button uses, so the two cannot drift apart. The conversation is the
 * earliest involving the address, not the largest, and the tooltip says so.
 */
function FollowButton({
  ip,
  transport,
  streamId,
  packets,
  bytes,
}: {
  ip: string
  transport: string
  streamId: number
  packets: number
  bytes: number
}) {
  return (
    <Link
      className="btn px-1.5 py-0.5"
      to={`/conversations?stream=${encodeURIComponent(`${transport}:${String(streamId)}`)}&tab=timeline`}
      title={`Open the earliest conversation with ${ip} — ${transport.toUpperCase()} stream ${String(streamId)} (${formatBytes(bytes)}, ${formatNumber(packets)} packets) — on the Conversations page's timeline.`}
      data-follow-conversation={ip}
    >
      <ArrowLeftRight size={11} aria-hidden />
      Follow conversation
    </Link>
  )
}

export default DestinationPanel
