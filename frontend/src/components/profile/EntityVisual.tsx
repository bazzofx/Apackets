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

/**
 * How much of a long visual a tile draws before it says the rest exists.
 *
 * The backend caps a table at fifty rows and a heatmap at fifteen rows by fifteen
 * columns, which is the right size for a card in a column. A tile is one of sixteen in
 * a grid, so a fifty-row table printed whole is the wall of text this page exists to
 * avoid. A tile therefore draws the first few and states, in one chip, how many it did
 * not draw — the rows are not hidden, they are one link away, and the chip says so.
 */
export const TILE_ROWS = 8
export const TILE_MATRIX = 8

/** The chip that keeps a shortened chart honest. */
function NotDrawn({ shown, total, unit }: { shown: number; total: number; unit: string }) {
  const hidden = total - shown
  if (hidden <= 0) return null
  const singular = unit.replace(/s$/, '')
  return (
    <span
      className="chip w-fit border-border2 bg-surface2 text-faint"
      data-profile-visual-cut={unit}
      data-profile-visual-cut-hidden={hidden}
      title={`This chart came back with ${String(total)} ${unit} and the tile draws the first ${String(
        shown,
      )}. The ${unit} that are not drawn are not hidden data: they are on the pages this widget links to.`}
    >
      +{hidden} {hidden === 1 ? singular : unit}
    </span>
  )
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
    case 'heatmap': {
      /* `cells[i]` lines up with `columns[i]` (contract §4.5), so a column is only
         dropped from every row at once. */
      const columns = visual.columns.slice(0, TILE_MATRIX)
      const rows = visual.rows
        .slice(0, TILE_MATRIX)
        .map((row) => ({ ...row, cells: row.cells.slice(0, columns.length) }))
      return (
        <>
          <HeatmapVisual visual={{ ...visual, columns, rows }} />
          <div className="flex flex-wrap gap-1">
            <NotDrawn shown={rows.length} total={visual.rows.length} unit="rows" />
            <NotDrawn shown={columns.length} total={visual.columns.length} unit="columns" />
          </div>
        </>
      )
    }
    case 'table': {
      const rows = visual.rows.slice(0, TILE_ROWS)
      return (
        <>
          <TableVisual visual={{ ...visual, rows }} />
          <NotDrawn shown={rows.length} total={visual.rows.length} unit="rows" />
        </>
      )
    }
    default: {
      const unknown = visual as { kind?: unknown }
      return (
        <p className="text-2xs leading-relaxed text-warn" data-profile-visual-unknown={String(unknown.kind)}>
          The backend returned a visual of kind “{String(unknown.kind)}”, which this build of ShinboShark does
          not know how to draw.
        </p>
      )
    }
  }
}

export default EntityVisual
