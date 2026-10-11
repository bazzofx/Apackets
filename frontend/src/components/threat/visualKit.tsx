import type { ReactNode } from 'react'
import type { ThreatHuntTone } from '@/types'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { EMPTY, formatBytes, formatNumber } from '@/utils/format'

/**
 * Shared chrome for the Threat Hunt visuals (docs/THREAT_HUNT.md §4).
 *
 * Everything under `components/threat/` is pure presentation: each visual takes
 * one `visual` object from the threat-hunt response and draws it. No component
 * here fetches anything — the page owns the single query — so every card and
 * every visual kind can be rendered directly from a fixture.
 *
 * Colours come from the active theme (`useThemeTokens`) so the section re-themes
 * with the rest of the app; there is no colour literal in this directory.
 */

/** Emphasis colours for the three presentation tones. */
export const TONE_TEXT: Record<ThreatHuntTone, string> = {
  info: 'text-accent2',
  watch: 'text-warn',
  warn: 'text-red-300',
}

/** Chip colours for the same tones. */
export const TONE_CHIP: Record<ThreatHuntTone, string> = {
  info: 'border-border2 bg-surface2 text-accent2',
  watch: 'border-warn/40 bg-warn/10 text-warn',
  warn: 'border-danger/50 bg-danger/15 text-red-300',
}

/** Chip styling for each of the three availability values. */
export const AVAILABILITY_TONE: Record<string, string> = {
  ok: 'border-ok/40 bg-ok/10 text-ok',
  empty: 'border-border2 bg-surface2 text-muted',
  not_applicable: 'border-border2 bg-surface2 text-faint',
}

/** The short label shown beside an indicator's title. */
export function availabilityChipLabel(availability: string): string {
  if (availability === 'ok') return 'computed'
  if (availability === 'empty') return 'nothing matched'
  if (availability === 'not_applicable') return 'not applicable'
  return availability
}

/**
 * Colours for multi-item plots, cycled through the theme's eight chart hues.
 *
 * A ranked bar chart of twelve domains or a scatter of two hundred points is far
 * easier to follow when each item is its own colour, and the themes already define
 * eight hues chosen to stay distinguishable from each other and from the amber/red
 * severity colours. Nothing here is a literal: the palette comes from the theme, so
 * the section re-colours with the rest of the app.
 */
export function useSeriesColour(): (index: number) => string {
  const tokens = useThemeTokens()
  const palette = tokens.chart
  return (index: number) => {
    if (palette.length === 0) return tokens.accent
    return palette[((index % palette.length) + palette.length) % palette.length]
  }
}

/**
 * A measured value with the unit the backend named it in.
 *
 * `bytes` is the one unit that is not a plain count, so it goes through
 * `formatBytes` — and then the unit word is dropped, because the suffix already
 * carries it.
 */
export function formatUnitValue(value: number | null | undefined, unit?: string | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  if (unit === 'bytes') return formatBytes(value)
  const number = formatNumber(value)
  return unit !== null && unit !== undefined && unit.trim() !== '' ? `${number} ${unit}` : number
}

export interface VisualFrameProps {
  /** §4 tag; also the hook the render check asserts on. */
  kind: string
  title?: string | null
  /** Rendered under the chart, as §4 specifies. */
  note?: string | null
  /** A factual line about the drawn data (counts, range, largest value). */
  caption?: ReactNode
  children: ReactNode
}

/**
 * One visual: optional title, the plot itself, an optional caption, the backend's
 * `note` underneath. An empty `note` renders nothing rather than a blank line.
 */
export function VisualFrame({ kind, title, note, caption, children }: VisualFrameProps) {
  const heading = typeof title === 'string' && title.trim() !== '' ? title : null
  const footer = typeof note === 'string' && note.trim() !== '' ? note : null
  return (
    <figure
      data-threat-visual={kind}
      className="flex min-w-0 flex-col gap-1 rounded border border-border/60 bg-surface2/30 p-2"
    >
      {heading !== null ? (
        <figcaption className="text-2xs font-medium uppercase tracking-wide text-muted">
          {heading}
        </figcaption>
      ) : null}
      {caption ? <div className="text-2xs leading-relaxed text-faint">{caption}</div> : null}
      {children}
      {footer !== null ? (
        <p className="text-2xs leading-relaxed text-faint" data-threat-visual-note>
          {footer}
        </p>
      ) : null}
    </figure>
  )
}

/**
 * A visual the backend sent with no rows even though the indicator is marked
 * computed. §4 forbids that shape, so it is reported rather than drawn as an
 * empty frame that would read as "nothing found here".
 */
export function VisualNoData({ kind, why }: { kind: string; why: string }) {
  return (
    <p className="text-2xs leading-relaxed text-warn" data-threat-visual-empty={kind}>
      {why}
    </p>
  )
}
