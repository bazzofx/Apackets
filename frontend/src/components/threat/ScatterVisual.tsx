import { Fragment } from 'react'
import { Link } from 'react-router-dom'
import { useThemeTokens } from '@/theme/ThemeProvider'
import type { ThreatHuntScatterVisual } from '@/types'
import { VisualFrame, VisualNoData, formatUnitValue, useSeriesColour } from './visualKit'
import { IpLabel } from './IpFlag'

const WIDTH = 620
const HEIGHT = 160
const PAD = 10

/** How many linked points are named under the plot before the list is curtailed. */
const LINKED_LABEL_LIMIT = 12

export interface ScatterVisualProps {
  visual: ThreatHuntScatterVisual
}

/**
 * Two measures against each other, one dot per item (contract §4).
 *
 * The plot is drawn at the aspect ratio the panel gives it (circles must stay
 * circles), so it is letterboxed on a very wide card. Points are not aggregated,
 * jittered or de-duplicated: overlapping dots stay overlapping. Every point carrying
 * a `to` is clickable in the plot itself, and the first dozen are also named beneath
 * it: naming them all would be unreadable on a real capture, but leaving the rest
 * unclickable would quietly break a link the response promised.
 */
export function ScatterVisual({ visual }: ScatterVisualProps) {
  const tokens = useThemeTokens()
  const seriesColour = useSeriesColour()
  const points = visual.points ?? []
  const xLabel = visual.x_label ?? null
  const yLabel = visual.y_label ?? null

  if (points.length === 0) {
    return (
      <VisualFrame kind="scatter" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="scatter"
          why="This scatter visual arrived with no points even though the indicator is marked computed, so nothing is drawn rather than showing an empty pair of axes."
        />
      </VisualFrame>
    )
  }

  const xs = points.map((point) => (Number.isFinite(point.x) ? point.x : 0))
  const ys = points.map((point) => (Number.isFinite(point.y) ? point.y : 0))
  const xMin = Math.min(...xs)
  const xMax = Math.max(...xs)
  const yMin = Math.min(...ys)
  const yMax = Math.max(...ys)
  const xSpan = xMax - xMin || 1
  const ySpan = yMax - yMin || 1
  const px = (value: number) => PAD + ((value - xMin) / xSpan) * (WIDTH - PAD * 2)
  const py = (value: number) => HEIGHT - PAD - ((value - yMin) / ySpan) * (HEIGHT - PAD * 2)

  const linked = points.filter((point) => typeof point.to === 'string' && point.to !== '')
  const named = linked.slice(0, LINKED_LABEL_LIMIT)

  return (
    <VisualFrame
      kind="scatter"
      title={visual.title}
      note={visual.note}
      caption={
        `${points.length} point${points.length === 1 ? '' : 's'}; ` +
        `${xLabel ?? 'x'} runs ${formatUnitValue(xMin)} to ${formatUnitValue(xMax)}, ` +
        `${yLabel ?? 'y'} runs ${formatUnitValue(yMin)} to ${formatUnitValue(yMax)}.`
      }
    >
      <svg
        className="h-40 w-full"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Scatter of ${points.length} points, ${xLabel ?? 'x'} against ${yLabel ?? 'y'}`}
      >
        <line
          x1={PAD}
          y1={HEIGHT - PAD}
          x2={WIDTH - PAD}
          y2={HEIGHT - PAD}
          stroke={tokens.border2}
          strokeWidth={1}
        />
        <line x1={PAD} y1={PAD} x2={PAD} y2={HEIGHT - PAD} stroke={tokens.border2} strokeWidth={1} />
        {points.map((point, index) => {
          const linkedPoint = typeof point.to === 'string' && point.to !== ''
          const dot = (
            <circle
              data-threat-point
              data-threat-point-label={point.label}
              cx={px(Number.isFinite(point.x) ? point.x : 0)}
              cy={py(Number.isFinite(point.y) ? point.y : 0)}
              r={4}
              fill={seriesColour(index)}
              fillOpacity={0.75}
              stroke={tokens.accent2}
              strokeWidth={linkedPoint ? 1 : 0}
            >
              <title>{`${point.label} — ${xLabel ?? 'x'}: ${point.x}, ${yLabel ?? 'y'}: ${point.y}`}</title>
            </circle>
          )
          /* SVG honours <a>, so wrapping the dot makes every promised point a real,
             focusable anchor instead of a click handler that no test can see. */
          return (
            <Fragment key={`${point.label}-${index}`}>
              {linkedPoint ? (
                <Link to={String(point.to)} className="cursor-pointer" aria-label={`Open ${point.label}`}>
                  {dot}
                </Link>
              ) : (
                dot
              )}
            </Fragment>
          )
        })}
        <text x={PAD} y={HEIGHT - 1} fill={tokens.faint} fontSize={9}>
          {`${xLabel ?? 'x'}: ${xMin}`}
        </text>
        <text x={WIDTH - PAD} y={HEIGHT - 1} fill={tokens.faint} fontSize={9} textAnchor="end">
          {`${xMax}`}
        </text>
        <text x={2} y={PAD + 4} fill={tokens.faint} fontSize={9}>
          {`${yMax}`}
        </text>
      </svg>

      {linked.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1" data-threat-linked-points>
          <span className="text-2xs text-faint">
            {linked.length === 1 ? 'Point with a link:' : 'Points with a link:'}
          </span>
          {named.map((point, index) => (
            <Link
              key={`${point.label}-${index}`}
              to={point.to as string}
              className="chip border-border2 bg-surface2 text-accent2 hover:border-accent hover:bg-accent/10"
              title={point.to as string}
            >
              <IpLabel text={point.label} />
            </Link>
          ))}
          {linked.length > named.length ? (
            <span className="text-2xs text-faint">
              and {linked.length - named.length} more linked point
              {linked.length - named.length === 1 ? '' : 's'} — every linked point is clickable in the plot
              above; only {named.length} are named here.
            </span>
          ) : null}
        </div>
      ) : null}
    </VisualFrame>
  )
}

export default ScatterVisual
