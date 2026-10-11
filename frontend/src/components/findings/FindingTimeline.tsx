import clsx from 'clsx'
import Panel from '@/components/Panel'
import { formatClockTime, formatDuration, formatNumber } from '@/utils/format'
import type { FindingTimelineEntry } from '@/types'

export interface FindingTimelineProps {
  timeline: FindingTimelineEntry[]
  truncated: boolean
  /** The backend cap that `truncated` refers to, for the honest note. */
  limit: number
  /** Open one frame in the packet browser. */
  onOpenPacket: (packet: number) => void
}

function hasTimestamp(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

/**
 * The alert's activity on a vertical rail, in the order the backend recorded it.
 *
 * This was a card on the Overview tab; it is a tab of its own because a timeline
 * wants the whole width, and because reading "when did this happen" is a
 * different question from reading "what fired".
 */
export function FindingTimeline({ timeline, truncated, limit, onOpenPacket }: FindingTimelineProps) {
  if (timeline.length === 0) {
    return (
      <Panel flush title="Timeline" subtitle="first and last activity of this alert">
        <div className="px-3 py-6 text-center text-2xs text-faint">No timestamps recorded.</div>
      </Panel>
    )
  }

  const firstT = timeline[0].t
  const lastT = timeline[timeline.length - 1].t
  const span = hasTimestamp(firstT) && hasTimestamp(lastT) ? lastT - firstT : null
  const count = `${formatNumber(timeline.length)} ${timeline.length === 1 ? 'entry' : 'entries'}`

  return (
    <Panel
      flush
      title="Timeline"
      subtitle={
        span !== null ? (
          <span>
            {formatClockTime(firstT)} → {formatClockTime(lastT)}
            {span > 0 ? ` · over ${formatDuration(span)}` : ''} · {count}
          </span>
        ) : (
          `first and last activity of this alert · ${count}`
        )
      }
    >
      <ol className="flex flex-col py-1">
        {timeline.map((entry, index) => {
          const isFirst = index === 0
          const isLast = index === timeline.length - 1
          const packet = entry.packet ?? null
          return (
            <li key={index} className="relative flex items-center gap-2 py-1.5 pl-5 pr-3 text-2xs">
              {!isFirst ? (
                <span className="absolute left-1.5 top-0 h-3.5 w-px bg-border" aria-hidden />
              ) : null}
              {!isLast ? (
                <span className="absolute bottom-0 left-1.5 top-3.5 w-px bg-border" aria-hidden />
              ) : null}
              <span
                className={clsx(
                  'absolute left-[2px] top-[10px] h-2 w-2 rounded-full border',
                  isFirst || isLast ? 'border-accent bg-accent2' : 'border-border2 bg-surface2',
                )}
                aria-hidden
              />
              <span className="mono shrink-0 text-muted">{formatClockTime(entry.t)}</span>
              <span className="chip shrink-0 border-border2 bg-surface2 text-faint">
                {entry.kind}
              </span>
              {isFirst ? (
                <span
                  className="chip shrink-0 border-accent/60 bg-accent/15 text-accent2"
                  title="First activity recorded for this alert"
                >
                  first
                </span>
              ) : null}
              {isLast ? (
                <span
                  className="chip shrink-0 border-accent/60 bg-accent/15 text-accent2"
                  title="Last activity recorded for this alert"
                >
                  last
                </span>
              ) : null}
              {entry.label ? (
                <span className="min-w-0 flex-1 truncate text-text" title={entry.label}>
                  {entry.label}
                </span>
              ) : (
                <span className="min-w-0 flex-1 text-faint">no label recorded</span>
              )}
              {packet !== null ? (
                <button
                  type="button"
                  className="mono shrink-0 text-accent2 hover:underline"
                  onClick={() => onOpenPacket(packet)}
                  title={`Open packet ${packet} in the packet browser`}
                >
                  #{packet}
                </button>
              ) : null}
            </li>
          )
        })}
      </ol>
      {truncated ? (
        <div className="border-t border-border px-3 py-2 text-2xs text-faint">
          Showing the first {formatNumber(limit)} of a longer timeline.
        </div>
      ) : null}
    </Panel>
  )
}

export default FindingTimeline
