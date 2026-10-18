import clsx from 'clsx'
import { CircleSlash, ShieldCheck, Wrench } from 'lucide-react'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntAvailability, ThreatHuntIndicator } from '@/types'
import { STATUS_META, useStatusColours } from './cockpitKit'

export interface DetectionGroup {
  id: string
  label: string
  hint: string
  members: ThreatHuntIndicator[]
}

export interface DetectionGridProps {
  groups: DetectionGroup[]
  /** Largest headline on the page, so every card's bar shares one scale. */
  max: number
  selectedId: string | null
  /** When set, only the detections carrying this status are drawn. */
  filter: ThreatHuntAvailability | null
  onSelect: (id: string) => void
}

/** The icon that says which of the three states a card is in. */
function StatusIcon({ status }: { status: ThreatHuntAvailability }) {
  if (status === 'ok') return <ShieldCheck size={12} aria-hidden />
  if (status === 'empty') return <CircleSlash size={12} aria-hidden />
  return <Wrench size={12} aria-hidden />
}

/**
 * Every detection, as a card in the group that asks the question it answers.
 *
 * Seventeen cards in one column was a scroll; this is a grid a reader can sweep for the
 * shapes that matter - a long bar, a green tick, a wrench - and then open. The groups are
 * presentation only: the ids are the contract's, every one is drawn, and an id no group
 * claims lands in "Other" rather than being lost to a layout decision.
 *
 * Each card is a button. It carries the detection's own headline measure, the status it
 * came in, and a bar on the same scale as every other card, so relative weight is visible
 * without opening anything.
 */
export function DetectionGrid({ groups, max, selectedId, filter, onSelect }: DetectionGridProps) {
  const colours = useStatusColours()

  return (
    <div className="flex flex-col gap-3" data-threat-grid>
      {groups.map((group) => {
        const shown =
          filter === null ? group.members : group.members.filter((member) => member.availability === filter)
        return (
          <section key={group.id} className="flex flex-col gap-1.5" data-threat-group={group.id}>
            <header className="flex items-baseline gap-2">
              <h3 className="cockpit-group-title" title={group.hint}>
                {group.label}
              </h3>
              <span className="mono text-2xs text-faint">
                {filter === null
                  ? formatNumber(group.members.length)
                  : `${String(shown.length)}/${String(group.members.length)}`}
              </span>
              <span className="h-px flex-1 bg-border" aria-hidden />
            </header>
            {shown.length === 0 ? (
              <p className="px-1 text-2xs text-faint">
                No detection in this group carries that status. Clear the filter to see all of
                them.
              </p>
            ) : (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {shown.map((indicator) => {
                  const active = indicator.id === selectedId
                  const value = Math.max(0, indicator.headline.value)
                  const colour = colours[indicator.availability]
                  return (
                    <button
                      key={indicator.id}
                      type="button"
                      onClick={() => onSelect(indicator.id)}
                      aria-pressed={active}
                      data-threat-grid-card={indicator.id}
                      title={
                        indicator.title +
                        ' - ' +
                        STATUS_META[indicator.availability].label +
                        (indicator.availability === 'ok'
                          ? ''
                          : ': ' + (indicator.availability_reason ?? 'no reason given'))
                      }
                      className={clsx('cockpit-card', active && 'is-active')}
                      style={{ ['--card-hue' as string]: colour }}
                    >
                      <span className="flex items-center gap-1.5">
                        <span
                          className="flex h-4 w-4 shrink-0 items-center justify-center rounded-sm"
                          style={{ background: colour + '22', color: colour }}
                          aria-hidden
                        >
                          <StatusIcon status={indicator.availability} />
                        </span>
                        <span className="min-w-0 flex-1 truncate text-2xs text-text">{indicator.title}</span>
                      </span>
                      <span className="flex items-baseline gap-1.5">
                        <span
                          className={clsx(
                            'mono text-lg leading-none',
                            indicator.availability === 'ok' ? 'text-text' : 'text-faint',
                          )}
                        >
                          {formatNumber(indicator.headline.value)}
                        </span>
                        <span className="min-w-0 flex-1 truncate text-2xs text-muted">
                          {indicator.headline.label}
                        </span>
                      </span>
                      <span className="cockpit-card-track" aria-hidden>
                        <span
                          style={{
                            width: `${Math.max(1.5, (value / Math.max(1, max)) * 100)}%`,
                            background: indicator.availability === 'ok' ? colour : 'transparent',
                          }}
                        />
                      </span>
                    </button>
                  )
                })}
              </div>
            )}
          </section>
        )
      })}
    </div>
  )
}

export default DetectionGrid