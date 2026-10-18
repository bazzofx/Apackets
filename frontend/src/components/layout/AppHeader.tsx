import { Link } from 'react-router-dom'
import clsx from 'clsx'
import {
  Activity,
  ChevronDown,
  Crosshair,
  Maximize,
  Minimize,
  RefreshCw,
  Settings as SettingsIcon,
  Upload,
} from 'lucide-react'
import StatusChip from '@/components/StatusChip'
import { formatNumber } from '@/utils/format'
import bannerUrl from '@/assets/top_banner.png'
import type { Analysis, BaselineStatus } from '@/types'

export interface AppHeaderProps {
  analyses: Analysis[]
  analysisId: string | null
  selected: Analysis | null
  onSelectAnalysis: (id: string | null) => void
  onRefresh: () => void
  baseline: BaselineStatus | undefined
  fullscreen: boolean
  onToggleFullscreen: () => void
}

/**
 * The Shadow Packets header: a cinematic row and a control row.
 *
 *   row 1  the night-landscape artwork, the 侍 mark, the wordmark, the capture status
 *          capsule, and the two round utility controls;
 *   row 2  the quiet toolbar: the capture selector, the baseline state, Refresh, Upload.
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
  onRefresh,
  baseline,
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

  const baselineOn = baseline?.active === true

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

      {/* ---------------------------------------------------------------- */}
      {/* row 2: the control toolbar                                         */}
      {/* ---------------------------------------------------------------- */}
      <div className="banner-toolbar flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2 xl:gap-x-6 xl:px-10 xl:py-0">
        <div className="ml-auto flex shrink-0 items-center gap-3 xl:gap-6">
          <Link
            to="/baseline-check"
            className={clsx('toolbar-btn toolbar-baseline', baselineOn ? 'is-on' : 'is-off')}
            title={
              baselineOn
                ? 'Baseline mode is on: every analysis is compared against ' +
                  (baseline?.baseline?.original_filename ?? 'the baseline capture')
                : 'No baseline network is set - choose one on PCAP Files'
            }
          >
            <Crosshair size={12} aria-hidden />
            <span className="truncate">
              {'Baseline mode : '}
              {baselineOn ? 'enabled' : 'off'}
            </span>
          </Link>

          <button type="button" className="toolbar-btn toolbar-refresh" onClick={onRefresh} title="Refresh analyses and the current view">
            <RefreshCw size={12} aria-hidden />
            <span>Refresh</span>
          </button>

          <Link to="/files" className="toolbar-btn toolbar-upload" title="Upload a capture">
            <Upload size={12} aria-hidden />
            <span>Upload</span>
          </Link>
        </div>
      </div>
    </header>
  )
}

export default AppHeader
