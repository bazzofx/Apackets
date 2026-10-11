import type { ThreatHuntVisual } from '@/types'
import BarsVisual from '@/components/threat/BarsVisual'
import HeatmapVisual from '@/components/threat/HeatmapVisual'
import HistogramVisual from '@/components/threat/HistogramVisual'
import ScatterVisual from '@/components/threat/ScatterVisual'
import TableVisual from '@/components/threat/TableVisual'
import TimelineVisual from '@/components/threat/TimelineVisual'

/**
 * Drawing one chart of an Investigate widget.
 *
 * The Investigate section reuses the Threat Map's card contract (docs/ENTITY_PROFILE.md
 * §3), so it also reuses the Threat Map's renderers: one implementation per visual
 * kind means the two sections cannot drift apart, and a kind that is fixed in one
 * is fixed in both. This module is the only place that knows which component draws
 * which `kind`.
 */

/**
 * Whether a visual actually carries data.
 *
 * The backend is allowed to send an empty array for a question the capture cannot
 * answer, and it also sends real measurements for a threshold that simply was not
 * crossed. Drawing only what has data keeps both honest: an empty frame that would
 * read as "nothing found here" is never drawn, and no measurement is thrown away.
 */
export function hasVisualData(visual: ThreatHuntVisual): boolean {
  switch (visual.kind) {
    case 'bars':
      return visual.items.length > 0
    case 'timeline':
      return visual.points.length > 0
    case 'histogram':
      return visual.buckets.length > 0
    case 'scatter':
      return visual.points.length > 0
    case 'heatmap':
      return visual.columns.length > 0 && visual.rows.length > 0
    case 'table':
      return visual.rows.length > 0
    default:
      // An unknown kind is reported rather than dropped, so keep it on screen.
      return true
  }
}

/** Dispatches on the contract's `kind` tag. */
export function EntityVisual({ visual }: { visual: ThreatHuntVisual }) {
  switch (visual.kind) {
    case 'bars':
      return <BarsVisual visual={visual} />
    case 'timeline':
      return <TimelineVisual visual={visual} />
    case 'histogram':
      return <HistogramVisual visual={visual} />
    case 'scatter':
      return <ScatterVisual visual={visual} />
    case 'heatmap':
      return <HeatmapVisual visual={visual} />
    case 'table':
      return <TableVisual visual={visual} />
    default: {
      const unknown = visual as { kind?: unknown }
      return (
        <p className="text-2xs leading-relaxed text-warn" data-profile-visual-unknown={String(unknown.kind)}>
          The backend returned a visual of kind “{String(unknown.kind)}”, which this build of APackets does
          not know how to draw.
        </p>
      )
    }
  }
}

export default EntityVisual
