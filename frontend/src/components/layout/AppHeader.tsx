import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { Activity, ChevronDown, Maximize, Minimize, Settings as SettingsIcon } from 'lucide-react'
import StatusChip from '@/components/StatusChip'
import { formatNumber } from '@/utils/format'
import bannerUrl from '@/assets/top_banner.png'
import type { Analysis } from '@/types'

/**
 * The header's rising packets (a purely decorative layer, `aria-hidden` in the markup).
 *
 * Scattered from a seeded hash rather than `Math.random()`, so the field is identical on
 * every render: a capture switch or a status change must not reshuffle the motes under the
 * reader's eye. Each one owns its own column, size, speed and delay, so the band never
 * pulses in unison.
 */
interface HeroMote {
  key: string
  /** Percent from the left edge of the band. */
  left: number
  width: number
  height: number
  /** How far it travels, in pixels — the band is 6.5rem tall and 10.9rem at xl. */
  rise: number
  /** Horizontal sway, so the rise is not a lift shaft. */
  drift: number
  duration: number
  /** Negative, so the field is already flying on the first frame. */
  delay: number
  cool: boolean
}

/** A stable number in [0, 1) for a salt: FNV-1a over a constant string. */
function seededValue(salt: number): number {
  const text = 'shadow-packets:' + String(salt)
  let hash = 2166136261
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return ((hash >>> 0) % 1000) / 1000
}

const HERO_MOTES: HeroMote[] = Array.from({ length: 34 }, (_, index) => {
  const roll = (offset: number) => seededValue(index * 7 + offset)
  return {
    key: 'mote-' + String(index),
    left: 1 + roll(1) * 96,
    width: 1.5 + roll(2) * 1.8,
    height: 5 + roll(3) * 9,
    rise: 70 + roll(4) * 90,
    drift: (roll(5) - 0.5) * 34,
    duration: 6.5 + roll(6) * 6,
    delay: -roll(7) * 12,
    cool: roll(8) > 0.82,
  }
})

export interface AppHeaderProps {
  analyses: Analysis[]
  analysisId: string | null
  selected: Analysis | null
  onSelectAnalysis: (id: string | null) => void
  fullscreen: boolean
  onToggleFullscreen: () => void
}

/**
 * The Shadow Packets header: one cinematic row.
 *
 *   the night-landscape artwork with the rising packet field behind it, the 侍 mark,
 *   the wordmark, the capture selector, the capture status capsule and the two round
 *   utility controls.
 *
 * It used to be two rows. The second - a full-width strip carrying baseline mode,
 * Refresh and Upload at its right edge - was removed when those three controls moved
 * into the navigation, where the reader is already looking; see `Sidebar.tsx`. A row
 * of the shell for three buttons was more height than they were worth.
 *
 * The artwork is the supplied PNG (`assets/top_banner.png`), painted as a CSS
 * background and never re-drawn. Sizes follow the reference image at its full desktop
 * width and compress below `xl`, so the header keeps its proportions on a laptop and
 * stays out of the way on a tablet.
 *
 * Everything here is live: the capture state and packet count come from the selected
 * analysis, the baseline label from `/api/baseline`, and every control calls the same
 * handler or route it always did.
 */
export function AppHeader({
  analyses,
  analysisId,
  selected,
  onSelectAnalysis,
  fullscreen,
  onToggleFullscreen,
}: AppHeaderProps) {
  const status = selected?.status ?? null
  const processing = status === 'pending' || status === 'processing'
  const ready = status === 'completed'

  const statusLabel = selected
    ? processing
      ? 'Capture Active'
      : ready
        ? 'Capture Ready'
        : 'Capture ' + String(status)
    : 'No Capture'

  const dotClass = processing ? 'status-dot status-dot-active' : ready ? 'status-dot' : 'status-dot status-dot-idle'


  return (
    <header className="app-banner shrink-0">
      {/* ---------------------------------------------------------------- */}
      {/* row 1: the painting, the mark, the wordmark, the capture state      */}
      {/* ---------------------------------------------------------------- */}
      {/* The painting is applied here, from the imported asset, so Vite resolves and
          fingerprints the URL itself - a CSS `url()` would depend on how the stylesheet
          is served. Positioning and the dark wash live in index.css. */}
      <div
        className="banner-hero flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2 xl:gap-x-6 xl:px-10 xl:py-0"
        style={{ backgroundImage: 'url(' + bannerUrl + ')' }}
      >
        {/* The packets rising through the painting. Decorative: they encode nothing, they
            are hidden from assistive technology, and the stylesheet removes them outright
            when motion is off. */}
        <div className="brand-motes" aria-hidden>
          {HERO_MOTES.map((mote) => (
            <span
              key={mote.key}
              className={mote.cool ? 'brand-mote brand-mote-cool' : 'brand-mote'}
              style={{
                left: mote.left.toFixed(2) + '%',
                width: mote.width.toFixed(1) + 'px',
                height: mote.height.toFixed(1) + 'px',
                animationDuration: mote.duration.toFixed(2) + 's',
                animationDelay: mote.delay.toFixed(2) + 's',
                '--mote-rise': mote.rise.toFixed(0) + 'px',
                '--mote-drift': mote.drift.toFixed(1) + 'px',
              } as CSSProperties}
            />
          ))}
        </div>

        <Link to="/" className="brand flex min-w-0 items-center gap-3 xl:gap-4" title="Dashboard">
          <span className="brand-jp" aria-hidden>
            侍
          </span>
          <span className="flex min-w-0 flex-col">
            <span className="brand-words">
              <span className="brand-word-shadow">SHADOW</span>{' '}
              <span className="brand-word-packets">PACKETS</span>
            </span>
            <span className="brand-brush" aria-hidden />
          </span>
        </Link>

        {/* The right-hand block: the capture state, the capture list directly beneath it
            (same width, so the two sit flush), and the two round controls. */}
        <div className="ml-auto flex shrink-0 items-center gap-3 xl:gap-4">
          <div className="flex min-w-0 flex-col items-end gap-1.5">
            <div className="flex items-center gap-2">
              <div
                className={clsx('status-pill', !selected && 'status-pill-idle')}
                title={selected ? selected.original_filename : 'Upload a capture to begin'}
              >
                <span className="status-section">
                  <span className={dotClass} aria-hidden />
                  <span className="status-text">{statusLabel}</span>
                </span>
                <span className="status-divider" aria-hidden />
                <span className="status-section">
                  <Activity size={13} className="status-wave" aria-hidden />
                  <span className="status-count mono">
                    {selected && selected.packet_count !== null
                      ? formatNumber(selected.packet_count)
                      : '—'}
                  </span>
                  <span className="status-unit">packets</span>
                  {processing && selected?.progress !== null && selected?.progress !== undefined ? (
                    <span className="status-progress mono">
                      {Math.round(selected.progress <= 1 ? selected.progress * 100 : selected.progress)}%
                    </span>
                  ) : null}
                </span>
              </div>
              {selected ? <StatusChip status={selected.status} /> : null}
            </div>

            {/* The uploaded captures, flush under the state line and exactly its width. */}
            <label className="capture-field w-full">
              <span className="sr-only">Active analysis</span>
              <select
                className="select capture-select w-full"
                value={analysisId ?? ''}
                onChange={(event) => onSelectAnalysis(event.target.value || null)}
                title="Choose the capture the application is showing"
              >
                {analyses.length === 0 ? <option value="">no captures uploaded</option> : null}
                {analysisId === null && analyses.length > 0 ? (
                  <option value="">— select a capture —</option>
                ) : null}
                {analyses.map((analysis) => (
                  <option key={analysis.id} value={analysis.id}>
                    {analysis.original_filename}
                  </option>
                ))}
              </select>
              {/* The native arrow ignores the stylesheet on Windows, and with
                  `appearance: none` the control would have none - so it is drawn here. */}
              <ChevronDown size={12} className="capture-chevron" aria-hidden />
            </label>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              className="banner-circle"
              onClick={onToggleFullscreen}
              aria-pressed={fullscreen}
              title={fullscreen ? 'Leave full screen' : 'Full screen'}
              aria-label={fullscreen ? 'Leave full screen' : 'Full screen'}
            >
              {fullscreen ? <Minimize size={18} aria-hidden /> : <Maximize size={18} aria-hidden />}
            </button>
            <Link to="/settings" className="banner-circle" title="Settings" aria-label="Settings">
              <SettingsIcon size={18} aria-hidden />
            </Link>
          </div>
        </div>
      </div>
    </header>
  )
}

export default AppHeader
