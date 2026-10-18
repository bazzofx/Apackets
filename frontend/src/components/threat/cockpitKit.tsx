import type { ReactNode } from 'react'
import clsx from 'clsx'
import { useThemeTokens } from '@/theme/ThemeProvider'
import type { ThreatHuntAvailability, ThreatHuntIndicator, ThreatHuntTone } from '@/types'

/**
 * Shared chrome for the Threat Map cockpit (docs/THREAT_HUNT.md).
 *
 * The page was a stack of tab panels showing one card per detection. It is a cockpit
 * now: a KPI strip, two summary plots, a grid of detections, and the full card of
 * whichever detection is selected. This module holds only what all of those share -
 * how a status is coloured and named, how a tone is coloured, and the small KPI card -
 * so there is exactly one definition of each.
 *
 * Nothing here computes a detection. Every number it draws arrives in the payload the
 * backend already produced; the only arithmetic is summing headlines and counting
 * statuses, which is presentation of numbers already on the page.
 */

/** The three availability values, named for a reader rather than for the contract. */
export const STATUS_META: Record<
  ThreatHuntAvailability,
  { label: string; short: string; description: string }
> = {
  ok: {
    label: 'Computed',
    short: 'computed',
    description:
      'The detection ran over this capture\u2019s indexed tables and returned a result. A result can be zero.',
  },
  empty: {
    label: 'Nothing matched',
    short: 'nothing matched',
    description:
      'The detection ran and nothing in this capture crossed its threshold. That is a measured answer, not a missing one.',
  },
  not_applicable: {
    label: 'Not computable',
    short: 'not computable',
    description:
      'This capture does not carry what the detection needs, so it was not evaluated. It is not the same reading as a zero.',
  },
}

/** Order used by the donut, the legend and the KPI strip, so they never disagree. */
export const STATUS_ORDER: readonly ThreatHuntAvailability[] = ['ok', 'empty', 'not_applicable']

/**
 * The theme colour each state is drawn in.
 *
 * Computed is the healthy green, nothing-matched is the quiet muted grey and
 * not-computable is the faint grey: no state takes the red, because none of them is a
 * severity. Red belongs to the severity vocabulary the findings already own, and the
 * cockpit must not borrow it to decorate a status.
 */
export function useStatusColours(): Record<ThreatHuntAvailability, string> {
  const tokens = useThemeTokens()
  return { ok: tokens.ok, empty: tokens.muted, not_applicable: tokens.faint }
}

/** The colour a headline's own tone asks for (presentation only, never a verdict). */
export function useToneColours(): Record<ThreatHuntTone, string> {
  const tokens = useThemeTokens()
  return { info: tokens.accent2, watch: tokens.warn, warn: tokens.sevHigh }
}

/**
 * The sum of the headline measures of the detections that computed a result.
 *
 * Each headline is the detection's own metric - events, ports, hosts, addresses - so
 * the sum is a total of unlike things: it is a sense of how much the capture is
 * reporting, never a count of incidents. Every place that prints it says so.
 */
export function reportedSignal(indicators: ThreatHuntIndicator[]): number {
  return indicators.reduce(
    (total, indicator) =>
      indicator.availability === 'ok' && Number.isFinite(indicator.headline.value)
        ? total + indicator.headline.value
        : total,
    0,
  )
}

/** How many detections carried each status. */
export function statusCounts(
  indicators: ThreatHuntIndicator[],
): Record<ThreatHuntAvailability, number> {
  const counts: Record<ThreatHuntAvailability, number> = { ok: 0, empty: 0, not_applicable: 0 }
  for (const indicator of indicators) counts[indicator.availability] += 1
  return counts
}

/**
 * One KPI in the command strip.
 *
 * The figure is the loudest thing in the card, the label names it and the detail line
 * says what it counts - because a cockpit that prints a number without saying what it
 * is has painted a gauge rather than measured one.
 */
export function KpiCard({
  icon,
  label,
  value,
  detail,
  colour,
  progress,
  title,
  testId,
}: {
  icon: ReactNode
  label: string
  value: string
  detail?: string
  colour: string
  /** 0-1, drawn as a thin bar under the figure. Only where a denominator exists. */
  progress?: number
  title?: string
  testId?: string
}) {
  return (
    <div
      data-threat-kpi={testId}
      className="cockpit-kpi"
      style={{ ['--kpi-hue' as string]: colour }}
      title={title}
    >
      <div className="flex items-center gap-1.5">
        <span className="cockpit-kpi-icon" aria-hidden>
          {icon}
        </span>
        <span className="cockpit-kpi-label truncate">{label}</span>
      </div>
      <div className="cockpit-kpi-value mono">{value}</div>
      {progress !== undefined ? (
        <div className="cockpit-kpi-track" aria-hidden>
          <span style={{ width: `${Math.round(Math.max(0, Math.min(1, progress)) * 100)}%` }} />
        </div>
      ) : null}
      {detail !== undefined ? (
        <div className={clsx('cockpit-kpi-detail', progress === undefined && 'truncate')}>{detail}</div>
      ) : null}
    </div>
  )
}

export default KpiCard