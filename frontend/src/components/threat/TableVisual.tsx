import { Link } from 'react-router-dom'
import clsx from 'clsx'
import SeverityBadge, { isSeverity } from '@/components/SeverityBadge'
import { IpLabel } from './IpFlag'
import { EMPTY } from '@/utils/format'
import type { ThreatHuntTableVisual } from '@/types'
import { TONE_TEXT, VisualFrame, VisualNoData } from './visualKit'

export interface TableVisualProps {
  visual: ThreatHuntTableVisual
}

/**
 * Tabular rows (contract §4).
 *
 * Each cell is text plus an optional `to` and an optional tone; a cell whose text
 * is a severity word is drawn as the app's `SeverityBadge`, so the section reads
 * the same way as Findings. Rows and columns are drawn exactly as sent — nothing
 * is sorted, filtered or trimmed client-side, and a cap that bit is the backend's
 * `note`, which is rendered underneath.
 */
export function TableVisual({ visual }: TableVisualProps) {
  const columns = visual.columns ?? []
  const rows = visual.rows ?? []

  if (rows.length === 0 || columns.length === 0) {
    return (
      <VisualFrame kind="table" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="table"
          why="This table visual arrived with no rows (or no column headings) even though the indicator is marked computed, so nothing is drawn rather than an empty table body."
        />
      </VisualFrame>
    )
  }

  /* A row carrying more cells than there are headings would otherwise lose data:
     the extra columns are drawn, headingless. */
  const width = Math.max(columns.length, ...rows.map((row) => (row.cells ?? []).length))
  const oversized = width > columns.length

  return (
    <VisualFrame
      kind="table"
      title={visual.title}
      note={visual.note}
      caption={
        `${rows.length} row${rows.length === 1 ? '' : 's'} across ${columns.length} column${columns.length === 1 ? '' : 's'}` +
        (oversized
          ? `; the backend sent rows with ${width} cells, so the extra columns are drawn without a heading rather than dropped.`
          : '.')
      }
    >
      <div className="overflow-auto">
        <table className="dt" data-threat-table>
          <thead>
            <tr>
              {Array.from({ length: width }).map((_, index) => (
                <th key={`column-${index}`} className="text-left" title={columns[index]}>
                  {columns[index] ?? ''}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIndex) => (
              <tr key={`row-${rowIndex}`} data-threat-table-row>
                {Array.from({ length: width }).map((_, cellIndex) => {
                  const cell = (row.cells ?? [])[cellIndex]
                  if (cell === undefined) {
                    return (
                      <td key={`cell-${cellIndex}`} className="text-faint">
                        {EMPTY}
                      </td>
                    )
                  }
                  const tone = cell.tone === null || cell.tone === undefined ? undefined : TONE_TEXT[cell.tone]
                  const text = typeof cell.text === 'string' ? cell.text : String(cell.text)
                  const linked = typeof cell.to === 'string' && cell.to !== ''
                  return (
                    <td key={`cell-${cellIndex}`} className={clsx(tone)} title={text}>
                      {isSeverity(text) ? (
                        <SeverityBadge severity={text} />
                      ) : linked ? (
                        <Link to={cell.to as string} className="text-accent2 hover:underline">
                          <IpLabel text={text} />
                        </Link>
                      ) : (
                        <IpLabel text={text} />
                      )}
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

export default TableVisual
