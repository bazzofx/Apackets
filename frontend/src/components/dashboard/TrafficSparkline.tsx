import { useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { CSSProperties } from 'react'
import clsx from 'clsx'
import { useMotion } from '@/theme/MotionProvider'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatBytes, formatClockTime, formatNumber } from '@/utils/format'
import type { TrafficSeriesPoint } from '@/types'


export interface TrafficSparklineProps {
  series: TrafficSeriesPoint[]
  height?: number
  /**
   * Which view the chart opens on. The toggle is a display preference the reader
   * owns, so a page normally leaves this alone — it exists so the three views can
   * be rendered and read one at a time.
   */
  initialMetric?: TrafficMetric
}

export type TrafficMetric = 'both' | 'packets' | 'bytes'

// The props Recharts hands a custom dot. Declared here rather than imported so this
// component does not depend on a private Recharts type that changes between releases.
interface DotRenderProps {
  cx?: number
  cy?: number
  index?: number
  payload?: unknown
}

/**
 * Compact traffic shape.
 *
 * Three views: **both** (the default), `packets` alone, or `bytes` alone. In
 * `both` the two series are drawn over each other — they are not the same
 * quantity, so each gets its own axis: packets on the left, bytes on the right,
 * every tick formatted in its own unit. Overlaying them on one scale would be a
 * lie of arithmetic, not a chart: bytes outnumber packets by two or three orders
 * of magnitude, so the packet line would sit flat on the floor.
 *
 * The two series are told apart twice over, so colour is never the only cue:
 * packets is a solid `accent` line, bytes a dashed `accent2` one, and the swatch
 * legend names both. Same reading as the Info page's own traffic chart, which
 * has had these three views all along.
 */
export function TrafficSparkline({ series, height = 190, initialMetric = 'both' }: TrafficSparklineProps) {
  const tokens = useThemeTokens()
  /* Motion off means no sweep and no pulse - the chart is simply there. */
  const { still } = useMotion()
  const axisTick = { fill: tokens.muted, fontSize: 10 }
  const gridStroke = tokens.border
  const tooltipStyle: CSSProperties = {
    background: tokens.surface2,
    border: '1px solid ' + tokens.border2,
    borderRadius: 4,
    fontSize: 11,
    color: tokens.text,
  }
  const [metric, setMetric] = useState<TrafficMetric>(initialMetric)

  if (series.length === 0) {
    return <div className="px-3 py-8 text-center text-2xs text-faint">No traffic series.</div>
  }

  const showPackets = metric !== 'bytes'
  const showBytes = metric !== 'packets'

  /*
   * The heartbeat dot: one dot at the newest point of the visible trace, with a ring
   * that pulses outward. It marks the leading edge of the chart - the present moment of
   * the capture - the way a monitor marks the last beat it drew. Everything is CSS;
   * this function only decides *where* the dot goes, and returns nothing for the other
   * points so the trace itself stays a clean line.
   */
  const lastIndex = series.length - 1
  const lastPoint = series[lastIndex]
  const pulseDot = (props: DotRenderProps) => {
    const { cx, cy, index, payload } = props
    // Recharts calls this once per point and collects the results into a list, so EVERY
    // element returned needs its own stable key - including the empty ones, or React
    // warns "Each child in a list should have a unique key prop" inside <Area>.
    const key = 'traffic-dot-' + String(index ?? 0)
    // Recharts passes the point index; some versions omit it, so the datum is checked
    // as well. Either way only the newest point draws, and the rest draw nothing.
    const isLast = index === lastIndex || payload === lastPoint
    if (!isLast || cx === undefined || cy === undefined) return <g key={key} />
    return (
      <g className="heart-dot" key={key}>
        <circle
          className="heart-dot-halo"
          cx={cx}
          cy={cy}
          r={4}
          fill="none"
          stroke={tokens.accent}
          strokeWidth={1.2}
        />
        <circle cx={cx} cy={cy} r={2.4} fill={tokens.accent} />
      </g>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="mb-1 flex flex-wrap items-center gap-x-2 gap-y-1">
        <div className="flex items-center gap-1">
          {(['both', 'packets', 'bytes'] as const).map((value) => (
            <button
              key={value}
              type="button"
              className={clsx('btn px-1.5 py-0.5', metric === value && 'btn-primary')}
              onClick={() => setMetric(value)}
              title={
                value === 'both'
                  ? 'Both series overlaid, each on its own axis'
                  : `Only ${value}`
              }
            >
              {value}
            </button>
          ))}
        </div>
        {/* With the series overlapping, the legend is what says which is which;
            the dashed stroke repeats it for anyone who cannot use the colour. */}
        {metric === 'both' ? (
          <div className="flex items-center gap-2 text-2xs text-muted">
            <span className="flex items-center gap-1">
              <span
                className="inline-block h-0.5 w-4 rounded-sm"
                style={{ background: tokens.accent }}
              />
              packets
            </span>
            <span className="flex items-center gap-1">
              <span
                className="inline-block h-0.5 w-4 rounded-sm"
                style={{
                  backgroundImage: `repeating-linear-gradient(90deg, ${tokens.accent2} 0 3px, transparent 3px 5px)`,
                }}
              />
              bytes
            </span>
          </div>
        ) : null}
      </div>
      {/* The sweep: the whole plot is revealed from left to right, once, when the chart
          appears (index.css). With motion off the class is simply absent. */}
      <div
        style={{ height: height - 28 }}
        className={clsx('min-h-0 flex-1', !still && 'chart-sweep')}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={series} margin={{ top: 4, right: showBytes ? 4 : 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke={gridStroke} vertical={false} />
            <XAxis
              dataKey="t"
              tick={axisTick}
              stroke={gridStroke}
              minTickGap={36}
              tickFormatter={(value: number) => formatClockTime(value)}
            />
            {showPackets ? (
              <YAxis
                yAxisId="packets"
                tick={axisTick}
                stroke={gridStroke}
                width={54}
                tickFormatter={(value: number) => formatNumber(value)}
              />
            ) : null}
            {showBytes ? (
              <YAxis
                yAxisId="bytes"
                orientation="right"
                tick={axisTick}
                stroke={gridStroke}
                width={58}
                tickFormatter={(value: number) => formatBytes(value, 0)}
              />
            ) : null}
            <Tooltip
              contentStyle={tooltipStyle}
              itemStyle={{ color: tokens.text }}
              labelFormatter={(label) => formatClockTime(Number(label))}
              formatter={(value, name) => {
                const amount = Number(value)
                return [
                  String(name) === 'bytes' ? formatBytes(amount) : formatNumber(amount),
                  String(name),
                ]
              }}
            />
            {showPackets ? (
              <Area
                yAxisId="packets"
                type="monotone"
                dataKey="packets"
                name="packets"
                stroke={tokens.accent}
                strokeWidth={1.5}
                fill={tokens.accent}
                fillOpacity={0.18}
                dot={showPackets ? pulseDot : false}
                isAnimationActive={false}
              />
            ) : null}
            {showBytes ? (
              <Area
                yAxisId="bytes"
                type="monotone"
                dataKey="bytes"
                name="bytes"
                stroke={tokens.accent2}
                strokeWidth={1.5}
                strokeDasharray="3 2"
                fill={tokens.accent2}
                fillOpacity={0.12}
                dot={showPackets ? false : pulseDot}
                isAnimationActive={false}
              />
            ) : null}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export default TrafficSparkline