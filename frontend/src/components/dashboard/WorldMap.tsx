import { useMemo, useState, type CSSProperties } from 'react'
import clsx from 'clsx'
import { Globe2, Loader2, RefreshCw } from 'lucide-react'
import { COUNTRY_NAMES, WORLD_COUNTRIES, WORLD_VIEWBOX, countryName } from '@/theme/worldMap'
import { formatBytes, formatNumber } from '@/utils/format'
import type { GeographyCountry, GeographyOrigin, GeographyResponse, GeographyUnknown } from '@/types'

/**
 * The capture's public destinations on a world map (docs/GEOGRAPHY.md §6).
 *
 * Four things are drawn, and nothing else:
 *
 * 1. **the world**, from the bundled Natural Earth outlines — no tile server, no CDN, no
 *    fetch at render time;
 * 2. **one dot per country**, sized by bytes and tinted by the page's accent hue, with a
 *    label for the largest few. Never one dot per address: a capture with four hundred
 *    destinations still draws at most `COUNTRY_CAP` dots, which is the whole point of
 *    grouping by country;
 * 3. **an arc per country**, flowing slowly outward from the origin hub so the direction of
 *    traffic is legible at a glance. The movement is one travelling dash per arc, and it is
 *    switched off entirely under `prefers-reduced-motion` (see index.css);
 * 4. **the origin hub**, drawn in its own dashed inset in the corner rather than placed on
 *    the map. A private address carries no country and the capture does not contain this
 *    installation's public address, so putting the hub at a location would be an invention;
 *    the inset says what it is.
 *
 * The map is a view of the response, never a source of anything: with no dataset installed
 * it draws the world and says so, and countries the response could not place are counted in
 * the corner chip rather than guessed onto the map.
 */

const ORIGIN = { x: 104, y: WORLD_VIEWBOX.height - 46 }
const HUB = { inset: { x: 16, y: WORLD_VIEWBOX.height - 84, width: 176, height: 68 } }

/** Quadratic arc from the hub to a country's label point, lifted perpendicular to the chord. */
function arcPath(targetX: number, targetY: number, lift: number): string {
  const dx = targetX - ORIGIN.x
  const dy = targetY - ORIGIN.y
  const distance = Math.max(1, Math.hypot(dx, dy))
  const midX = (ORIGIN.x + targetX) / 2
  const midY = (ORIGIN.y + targetY) / 2
  const controlX = midX - (dy / distance) * lift
  const controlY = midY + (dx / distance) * lift
  return `M${ORIGIN.x},${ORIGIN.y} Q${controlX.toFixed(1)},${controlY.toFixed(1)} ${targetX},${targetY}`
}

export interface WorldMapProps {
  data: GeographyResponse
  /** The country the reader is focused on, or `null`. */
  focused: string | null
  onFocus: (code: string | null) => void
  /** Open one address's host page. */
  onSelectIp: (ip: string) => void
  /** Render the "build the dataset" notice inside the map. */
  datasetAction?: React.ReactNode
}

/** A small chip in the corner: what the map is, and what it could not place. */
function CornerChip({
  icon,
  children,
  title,
}: {
  icon?: React.ReactNode
  children: React.ReactNode
  title: string
}) {
  return (
    <span
      className="pointer-events-auto inline-flex items-center gap-1.5 rounded-full border border-border bg-surface/85 px-2.5 py-1 text-2xs text-muted backdrop-blur"
      title={title}
    >
      {icon}
      {children}
    </span>
  )
}

export function WorldMap({ data, focused, onFocus, onSelectIp, datasetAction }: WorldMapProps) {
  const [hovered, setHovered] = useState<string | null>(null)

  const countries = data.countries ?? []
  const origin: GeographyOrigin = data.origin
  const unknown: GeographyUnknown = data.unknown
  const available = data.dataset?.available === true

  const maxBytes = useMemo(
    () => Math.max(1, ...countries.map((country) => country.bytes || 0)),
    [countries],
  )

  /* Dot radius by bytes, square-rooted so one huge CDN does not flatten everything else into
     a speck; a floor of 3 so a country with a handful of packets is still visible. */
  const radiusFor = (country: GeographyCountry): number => {
    const share = Math.sqrt(Math.max(0, country.bytes || 0) / maxBytes)
    return Math.round((3 + share * 9) * 10) / 10
  }

  const labelled = useMemo(
    () =>
      new Set(
        [...countries]
          .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
          .slice(0, 6)
          .map((country) => country.code),
      ),
    [countries],
  )

  const active = hovered ?? focused
  const activeCountry = countries.find((country) => country.code === active) ?? null

  return (
    <div className="relative">
      <div className="map-backdrop overflow-hidden rounded border border-border" data-world-map>
        <svg
          viewBox={`0 0 ${String(WORLD_VIEWBOX.width)} ${String(WORLD_VIEWBOX.height)}`}
          className="h-[26rem] w-full"
          role="img"
          aria-label={`World map of ${formatNumber(countries.length)} destination ${
            countries.length === 1 ? 'country' : 'countries'
          } this capture sent traffic to`}
        >
          <defs>
            <linearGradient id="world-land" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgb(var(--c-surface2))" stopOpacity="0.85" />
              <stop offset="100%" stopColor="rgb(var(--c-surface))" stopOpacity="0.85" />
            </linearGradient>
            <radialGradient id="world-hub">
              <stop offset="0%" stopColor="rgb(var(--c-accent))" stopOpacity="0.55" />
              <stop offset="100%" stopColor="rgb(var(--c-accent))" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* The world, and nothing else: every country is one path, the active one lit. */}
          <g data-world-outline>
            {WORLD_COUNTRIES.map((country) => (
              <path
                key={country.code}
                d={country.path}
                data-world-country={country.code}
                className={clsx('world-country', active === country.code && 'world-country-active')}
              />
            ))}
          </g>

          {/* Arcs: one per country, flowing outward. The dash travel is CSS (§index.css). */}
          <g data-world-arcs>
            {countries.map((country, index) => {
              const point = WORLD_COUNTRIES.find((entry) => entry.code === country.code)
              if (point === undefined) return null
              const distance = Math.hypot(point.x - ORIGIN.x, point.y - ORIGIN.y)
              return (
                <path
                  key={country.code}
                  d={arcPath(point.x, point.y, Math.min(120, distance * 0.28))}
                  data-world-arc={country.code}
                  className={clsx('world-arc', active === country.code && 'world-arc-active')}
                  style={{ animationDelay: `${String(-index * 0.42)}s` } as CSSProperties}
                />
              )
            })}
          </g>

          {/* Destination dots, and the label for the largest few. */}
          <g data-world-dots>
            {countries.map((country) => {
              const point = WORLD_COUNTRIES.find((entry) => entry.code === country.code)
              if (point === undefined) {
                /* A country the outline asset does not draw — N. Cyprus and Somaliland have no
                   ISO code in the source. It is still counted in the list below; the map
                   simply has no shape to put a dot on. */
                return null
              }
              const radius = radiusFor(country)
              const isActive = active === country.code
              return (
                <g
                  key={country.code}
                  data-world-dot={country.code}
                  className="world-dot-group"
                  tabIndex={0}
                  role="button"
                  aria-label={`${countryName(country.code)}: ${formatNumber(country.addresses)} address(es), ${formatBytes(country.bytes)}`}
                  onMouseEnter={() => setHovered(country.code)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(country.code)}
                  onBlur={() => setHovered(null)}
                  onClick={() => onFocus(isActive ? null : country.code)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      onFocus(isActive ? null : country.code)
                    }
                  }}
                >
                  {isActive ? (
                    <circle className="world-dot-pulse" cx={point.x} cy={point.y} r={radius + 6} />
                  ) : null}
                  <circle className="world-dot" cx={point.x} cy={point.y} r={radius} />
                  {labelled.has(country.code) || isActive ? (
                    <text
                      className="world-dot-label"
                      x={point.x}
                      y={point.y - radius - 6}
                      textAnchor="middle"
                    >
                      {country.code} · {formatNumber(country.addresses)}
                    </text>
                  ) : null}
                </g>
              )
            })}
          </g>

          {/* The origin: a labelled inset, deliberately not placed anywhere on the earth. */}
          <g data-world-origin>
            <rect
              className="world-hub-inset"
              x={HUB.inset.x}
              y={HUB.inset.y}
              width={HUB.inset.width}
              height={HUB.inset.height}
              rx={8}
            />
            <circle className="world-hub-glow" cx={ORIGIN.x} cy={ORIGIN.y} r={26} />
            <circle className="world-hub" cx={ORIGIN.x} cy={ORIGIN.y} r={5} />
            <text className="world-hub-label" x={ORIGIN.x} y={ORIGIN.y - 14} textAnchor="middle">
              this capture&rsquo;s own addresses
            </text>
            <text className="world-hub-count" x={ORIGIN.x} y={ORIGIN.y + 20} textAnchor="middle">
              {formatNumber(origin.addresses)} · {formatBytes(origin.bytes)}
            </text>
          </g>
        </svg>

        {/* Corner chips: what is shown, and what could not be placed. They sit over the SVG,
            so a reader sees the caveat without reading a paragraph. */}
        <div className="pointer-events-none absolute inset-x-2 top-2 flex flex-wrap items-start justify-between gap-2">
          <CornerChip
            icon={<Globe2 size={12} aria-hidden />}
            title={data.note}
          >
            {formatNumber(countries.length)} destination{' '}
            {countries.length === 1 ? 'country' : 'countries'} · {formatNumber(data.counts.located)}{' '}
            address(es)
          </CornerChip>
          {unknown.addresses > 0 ? (
            <CornerChip
              title={
                available
                  ? `${formatNumber(unknown.addresses)} address(es) have no country in the dataset and are drawn nowhere. They are listed under the map.`
                  : 'No location dataset is installed yet.'
              }
            >
              {formatNumber(unknown.addresses)} not placed
            </CornerChip>
          ) : null}
        </div>

        {!available ? (
          <div className="pointer-events-none absolute inset-x-3 bottom-3 flex justify-center">
            <div className="pointer-events-auto flex max-w-2xl flex-col gap-2 rounded border border-border bg-surface/95 px-3 py-2.5 text-center shadow-panel backdrop-blur">
              <p className="text-xs leading-relaxed text-muted">
                <span className="text-text">No location dataset yet.</span>{' '}
                {data.dataset?.reason ??
                  'The world outline is part of APackets; the address-to-country table is not.'}{' '}
                It is one public CC BY 4.0 file (DB-IP Lite, country), downloaded only when you ask
                for it — no account, no key, and no capture data is ever sent.
              </p>
              {datasetAction}
            </div>
          </div>
        ) : null}
      </div>

      {/* Hover readout, under the map, so a dot is legible without a floating tooltip. */}
      <div className="mt-1.5 flex min-h-[1.25rem] flex-wrap items-center gap-x-3 gap-y-1 px-1 text-2xs">
        {activeCountry !== null ? (
          <>
            <span className="text-text">
              {countryName(activeCountry.code)}{' '}
              <span className="mono text-faint">{activeCountry.code}</span>
            </span>
            <span className="text-muted">
              {formatNumber(activeCountry.addresses)} address(es) · {formatBytes(activeCountry.bytes)} ·{' '}
              {formatNumber(activeCountry.packets)} packet(s)
            </span>
            {activeCountry.ips.slice(0, 4).map((ip) => (
              <button
                key={ip}
                type="button"
                className="mono text-accent2 hover:underline"
                onClick={() => onSelectIp(ip)}
                title={`Open ${ip}`}
              >
                {ip}
              </button>
            ))}
            {activeCountry.ips.length > 4 ? (
              <span className="text-faint">+{formatNumber(activeCountry.ips.length - 4)} more</span>
            ) : null}
          </>
        ) : (
          <span className="text-faint">
            Hover a country's dot for its addresses, packets and volume. Click one to pin it.
          </span>
        )}
        {available && data.dataset.source !== null ? (
          <span
            className="ml-auto text-faint"
            title={`${data.dataset.source.dataset} · ${data.dataset.source.licence} · ${data.dataset.source.attribution}`}
          >
            {data.dataset.source.dataset} {data.dataset.source.dataset_month} ·{' '}
            {formatNumber(data.dataset.source.ranges)} ranges · IP geolocation by DB-IP
          </span>
        ) : null}
      </div>
    </div>
  )
}

export interface DatasetMissingProps {
  onBuild: () => void
  /** The POST is in flight. */
  building: boolean
  error: unknown
  jobId?: string
  /** The job is running and the page is polling for the dataset it will install. */
  waiting?: boolean
}

/** The control that builds the dataset, shown inside the map when it is absent. */
export function BuildDatasetButton({
  onBuild,
  building,
  error,
  jobId,
  waiting = false,
}: DatasetMissingProps) {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <button
        type="button"
        className="btn btn-primary"
        onClick={onBuild}
        disabled={building}
        title="Download the DB-IP Lite country database (CC BY 4.0) into data/geoip/. POST /geoip/refresh"
      >
        {building ? <Loader2 size={13} className="animate-spin" aria-hidden /> : <RefreshCw size={13} aria-hidden />}
        {building ? 'Downloading…' : 'Build the location dataset'}
      </button>
      {error ? (
        <span className="text-2xs text-warn">
          The download failed: {String((error as { message?: string }).message ?? error)}. Nothing was
          changed; the previous dataset, if any, is still in force.
        </span>
      ) : null}
      {jobId !== undefined ? (
        <span className="flex items-center gap-1.5 text-2xs text-muted">
          {waiting ? <Loader2 size={11} className="animate-spin" aria-hidden /> : null}
          {waiting
            ? `Downloading the dataset (job ${jobId}); this map fills in on its own when it lands.`
            : `Download finished or failed (job ${jobId}). The status line under the map says which.`}
        </span>
      ) : null}
    </div>
  )
}

/** Names for codes, exported so the country list and the page use one source. */
export { COUNTRY_NAMES }

export default WorldMap
