import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatClockTime } from '@/utils/format'
import type { ThreatHuntTimelineVisual } from '@/types'
import { VisualFrame, VisualNoData, formatUnitValue, useSeriesColour } from './visualKit'

/**
 * Fixed drawing surface. The plot is stretched to the panel width
 * (`preserveAspectRatio="none"`) and the stroke is kept uniform with
 * `vector-effect`, so a wide card does not thicken the line.
 */
const WIDTH = 620
const HEIGHT = 120
const TOP_PAD = 8

export interface TimelineVisualProps {
  visual: ThreatHuntTimelineVisual
}

/**
 * Bucketed time series (contract §4).
 *
 * `t` is the bucket start in epoch seconds and `value` the measure inside it;
 * a bucket with `marker` is a bucket the backend wants read first. Points are
 * sorted by time for drawing only — no value is changed or interpolated, and a
 * missing bucket is simply absent from the line.
 */
export function TimelineVisual({ visual }: TimelineVisualProps) {
  const tokens = useThemeTokens()
  const seriesColour = useSeriesColour()
  const points = [...(visual.points ?? [])].sort((a, b) => a.t - b.t)
  const unit = visual.unit ?? null

  if (points.length === 0) {
    return (
      <VisualFrame kind="timeline" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="timeline"
          why="This time-series visual arrived with no buckets even though the indicator is marked computed, so nothing is drawn — a flat line across an empty axis would look like measured silence."
        />
      </VisualFrame>
    )
  }

  const first = points[0]
  const last = points[points.length - 1]
  const span = last.t - first.t
  const maxValue = Math.max(
    1,
    ...points.map((point) => (Number.isFinite(point.value) ? Math.max(0, point.value) : 0)),
  )
  const x = (t: number) => (span > 0 ? ((t - first.t) / span) * WIDTH : WIDTH / 2)
  const y = (value: number) => HEIGHT - (Math.max(0, value) / maxValue) * (HEIGHT - TOP_PAD)
  const line = points
    .map((point, index) => `${index === 0 ? 'M' : 'L'}${x(point.t).toFixed(2)},${y(point.value).toFixed(2)}`)
    .join(' ')
  const area = `${line} L${x(last.t).toFixed(2)},${HEIGHT} L${x(first.t).toFixed(2)},${HEIGHT} Z`
  const markers = points.filter((point) => point.marker === true)
  const bucketWidth = WIDTH / Math.max(1, points.length)

  return (
    <VisualFrame
      kind="timeline"
      title={visual.title}
      note={visual.note}
      caption={
        `${points.length} bucket${points.length === 1 ? '' : 's'} from ${formatClockTime(first.t)} to ` +
        `${formatClockTime(last.t)}; the tallest holds ${formatUnitValue(maxValue, unit)}` +
        `${markers.length > 0 ? `, and ${markers.length} bucket${markers.length === 1 ? ' is' : 's are'} highlighted` : ''}.`
      }
    >
      <svg
        className="h-28 w-full"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Time series over ${points.length} buckets, tallest ${formatUnitValue(maxValue, unit)}`}
      >
        <path d={area} fill={seriesColour(0)} fillOpacity={0.18} />
        <path
          data-threat-timeline-line
          d={line}
          fill="none"
          stroke={seriesColour(0)}
          strokeWidth={1.5}
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
        {markers.map((point, index) => (
          <rect
            key={`marker-${point.t}-${index}`}
            data-threat-marker
            x={x(point.t) - 1}
            y={0}
            width={2}
            height={HEIGHT}
            fill={tokens.warn}
            fillOpacity={0.5}
          />
        ))}
        {/* One hit area per bucket, so a value can actually be read off the plot. */}
        {points.map((point, index) => (
          <rect
            key={`bucket-${point.t}-${index}`}
            data-threat-timeline-bucket
            x={x(point.t) - bucketWidth / 2}
            y={0}
            width={bucketWidth}
            height={HEIGHT}
            fill="transparent"
          >
            <title>{`${formatClockTime(point.t)} — ${formatUnitValue(point.value, unit)}`}</title>
          </rect>
        ))}
      </svg>
      <div className="flex items-center justify-between gap-2 text-2xs text-faint">
        <span className="mono">{formatClockTime(first.t)}</span>
        <span className="mono">{formatClockTime(last.t)}</span>
      </div>
    </VisualFrame>
  )
}

export default TimelineVisual
