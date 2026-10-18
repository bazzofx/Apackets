import clsx from 'clsx'
import MonoCell from '@/components/MonoCell'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntHeatmapVisual } from '@/types'
import { VisualFrame, VisualNoData, formatUnitValue, useSeriesColour } from './visualKit'
import { IpLabel } from './IpFlag'

export interface HeatmapVisualProps {
  visual: ThreatHuntHeatmapVisual
}

/**
 * Matrix of counts — rows against columns (contract §4).
 *
 * `cells[i]` lines up with `columns[i]`, and a column a row does not appear in is
 * a real 0, not a missing reading, so every cell is drawn: a blank cell would be
 * indistinguishable from "not measured". Shade is relative to the busiest cell in
 * this matrix only, which is why the values are printed in every cell.
 */
export function HeatmapVisual({ visual }: HeatmapVisualProps) {
  const seriesColour = useSeriesColour()
  const columns = visual.columns ?? []
  const rows = visual.rows ?? []
  const unit = visual.unit ?? null

  if (columns.length === 0 || rows.length === 0) {
    return (
      <VisualFrame kind="heatmap" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="heatmap"
          why="This matrix visual arrived without both axes (a column set and at least one row) even though the indicator is marked computed, so nothing is drawn."
        />
      </VisualFrame>
    )
  }

  const maxCell = Math.max(
    1,
    ...rows.flatMap((row) =>
      (row.cells ?? []).map((cell) => (Number.isFinite(cell) ? Math.max(0, cell) : 0)),
    ),
  )
  const busiest = rows.reduce(
    (best, row) => {
      const value = Math.max(
        0,
        ...(row.cells ?? []).map((cell) => (Number.isFinite(cell) ? cell : 0)),
      )
      return value > best.value ? { label: row.label, value } : best
    },
    { label: rows[0].label, value: 0 },
  )

  return (
    <VisualFrame
      kind="heatmap"
      title={visual.title}
      note={visual.note}
      caption={
        `${rows.length} row${rows.length === 1 ? '' : 's'} × ${columns.length} column${columns.length === 1 ? '' : 's'}; ` +
        `the busiest cell is ${busiest.label} with ${formatUnitValue(busiest.value, unit)}. ` +
        'A column a row does not appear in is a measured 0, not a missing reading.'
      }
    >
      <div className="overflow-auto">
        <table className="dt" data-threat-heatmap>
          <thead>
            <tr>
              <th className="text-left">{unit !== null && unit.trim() !== '' ? unit : 'value'}</th>
              {columns.map((column, index) => (
                <th key={`${column}-${index}`} className="text-right" title={column}>
                  <IpLabel text={column} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr key={`${row.label}-${rowIndex}`}>
                <td>
                  <MonoCell className="text-2xs text-text" title={row.label} maxWidth={176}>
                    <IpLabel text={row.label} />
                  </MonoCell>
                </td>
                {columns.map((column, columnIndex) => {
                  const raw = (row.cells ?? [])[columnIndex]
                  const value = typeof raw === 'number' && Number.isFinite(raw) ? Math.max(0, raw) : 0
                  const opacity = value > 0 ? 0.18 + 0.72 * (value / maxCell) : 0
                  /* Ramp across the palette as well as the alpha, so a hot cell is a
                     different colour rather than just a stronger wash of the same one. */
                  const ramp = Math.min(3, Math.floor((value / maxCell) * 4))
                  return (
                    <td key={`${column}-${columnIndex}`} className="p-0">
                      <span
                        data-threat-cell
                        data-threat-cell-value={value}
                        className="relative flex h-6 items-center justify-center px-2"
                        title={`${row.label} → ${column}: ${formatUnitValue(value, unit)}`}
                      >
                        {opacity > 0 ? (
                          <span
                            aria-hidden
                            className="absolute inset-x-0 inset-y-0.5 rounded-sm"
                            style={{ background: seriesColour(ramp), opacity }}
                          />
                        ) : null}
                        <span
                          className={clsx('relative mono text-2xs', value > 0 ? 'text-text' : 'text-faint')}
                        >
                          {formatNumber(value)}
                        </span>
                      </span>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </VisualFrame>
  )
}

export default HeatmapVisual
