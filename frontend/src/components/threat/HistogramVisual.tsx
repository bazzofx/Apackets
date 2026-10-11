import { formatNumber } from '@/utils/format'
import type { ThreatHuntHistogramVisual } from '@/types'
import { VisualFrame, VisualNoData, formatUnitValue, useSeriesColour } from './visualKit'

export interface HistogramVisualProps {
  visual: ThreatHuntHistogramVisual
}

/**
 * Distribution over labelled buckets (contract §4).
 *
 * `label` is the bucket's own description (`30-60 s`), so the axis is the
 * backend's wording and not a range this component guessed. The count above each
 * column is the measured value — nothing is normalised or smoothed.
 */
export function HistogramVisual({ visual }: HistogramVisualProps) {
  const seriesColour = useSeriesColour()
  const buckets = visual.buckets ?? []
  const unit = visual.unit ?? null

  if (buckets.length === 0) {
    return (
      <VisualFrame kind="histogram" title={visual.title} note={visual.note}>
        <VisualNoData
          kind="histogram"
          why="This distribution visual arrived with no buckets even though the indicator is marked computed, so nothing is drawn rather than showing an empty axis."
        />
      </VisualFrame>
    )
  }

  const max = Math.max(
    1,
    ...buckets.map((bucket) => (Number.isFinite(bucket.value) ? Math.max(0, bucket.value) : 0)),
  )
  const tallest = buckets.reduce((best, bucket) => (bucket.value > best.value ? bucket : best), buckets[0])
  const total = buckets.reduce(
    (sum, bucket) => sum + (Number.isFinite(bucket.value) ? Math.max(0, bucket.value) : 0),
    0,
  )

  return (
    <VisualFrame
      kind="histogram"
      title={visual.title}
      note={visual.note}
      caption={
        `${buckets.length} bucket${buckets.length === 1 ? '' : 's'}, ${formatUnitValue(total, unit)} in total; ` +
        `the fullest is ${tallest.label} with ${formatUnitValue(tallest.value, unit)}.`
      }
    >
      <div className="flex items-end gap-1">
        {buckets.map((bucket, index) => {
          const value = Number.isFinite(bucket.value) ? Math.max(0, bucket.value) : 0
          const percent = (value / max) * 100
          return (
            <div
              key={`${bucket.label}-${index}`}
              className="flex min-w-0 flex-1 flex-col items-center gap-0.5"
              title={`${bucket.label}: ${formatUnitValue(value, unit)}`}
            >
              <span className="mono text-2xs text-muted">{formatNumber(value)}</span>
              <div className="flex h-24 w-full items-end rounded-t-sm bg-surface2/60">
                <span
                  data-threat-histogram-column
                  data-threat-bucket-label={bucket.label}
                  data-threat-bucket-value={value}
                  className="block w-full rounded-t-sm"
                  style={{ height: `${percent}%`, background: seriesColour(index) }}
                />
              </div>
              <span
                className="w-full truncate text-center text-2xs text-faint"
                title={bucket.label}
              >
                {bucket.label}
              </span>
            </div>
          )
        })}
      </div>
    </VisualFrame>
  )
}

export default HistogramVisual
