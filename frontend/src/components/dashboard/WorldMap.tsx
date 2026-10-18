import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent } from 'react'
import clsx from 'clsx'
import { Globe2, Loader2, Maximize2, Minus, Plus, RefreshCw } from 'lucide-react'
import DestinationPanel from '@/components/dashboard/DestinationPanel'
import { motionIsStill } from '@/theme/motion'
import { COUNTRY_NAMES, WORLD_COUNTRIES, WORLD_VIEWBOX, countryName } from '@/theme/worldMap'
import { formatBytes, formatNumber } from '@/utils/format'
import type { GeographyCountry, GeographyOrigin, GeographyResponse, GeographyUnknown } from '@/types'

/**
 * The capture's public destinations on a world map (docs/GEOGRAPHY.md §6).
 *
 * Six things are drawn, and nothing else:
 *
 * 1. **the world**, from the bundled Natural Earth outlines — no tile server, no CDN, no
 *    fetch at render time;
 * 2. **one dot per country**, sized by bytes and tinted by the page's accent hue, with a
 *    label for the largest few. Never one dot per address: a capture with four hundred
 *    destinations still draws at most `COUNTRY_CAP` dots, which is the whole point of
 *    grouping by country;
 * 3. **an arc per country**, flowing slowly outward from the origin hub so the direction of
 *    traffic is legible at a glance. The movement is one travelling dash per arc, and the
 *    busiest arcs carry two more layers of it — beads and a flicker — which are decoration
 *    and encode nothing;
 * 4. **a link between two countries**, and only where `links` proves one: a conversation of
 *    this capture with a located endpoint in each. An ordinary capture of one network
 *    talking outward proves none, and then none is drawn;
 * 5. **the origin hub**, drawn in its own dashed inset in the corner rather than placed on
 *    the map. A private address carries no country and the capture does not contain this
 *    installation's public address, so putting the hub at a location would be an invention;
 *    the inset says what it is;
 * 6. **motes** around the busiest dots, thrown outward on a seeded bearing and fading — a
 *    constellation of arrivals, and the only thing here that carries no count at all.
 *
 * Every animated layer is removed rather than frozen when motion is off (`prefers-reduced-
 * motion` or this application's own setting — see index.css), so what a still reader sees is
 * exactly the geometry.
 *
 * The map is a view of the response, never a source of anything: with no dataset installed
 * it draws the world and says so, and countries the response could not place are counted in
 * the corner chip rather than guessed onto the map.
 */

const ORIGIN = { x: 104, y: WORLD_VIEWBOX.height - 46 }
const HUB = { inset: { x: 16, y: WORLD_VIEWBOX.height - 84, width: 176, height: 68 } }

/** How far the map may be zoomed, and how big a step the wheel and the buttons take. */
const MIN_SCALE = 1
const MAX_SCALE = 8
const WHEEL_STEP = 1.25
const BUTTON_STEP = 1.6
/** The scale a dot click zooms to: close enough to read neighbours, far from a single country. */
const FOCUS_SCALE = 4
/**
 * How long to wait before the destination panel appears, in milliseconds.
 *
 * The zoom takes 220 ms, so half a second lets the map come to rest before the card arrives:
 * a panel that appears while the map is still moving reads as if it belongs to wherever the
 * dot *was*. The wait is short enough to feel immediate and long enough to avoid that, and it
 * is skipped entirely under `prefers-reduced-motion`, where there is no movement to wait for.
 */
export const PANEL_DELAY_MS = 500

export interface WorldView {
  scale: number
  tx: number
  ty: number
}

/** Keep the world covering the frame: no zoom level may show empty space beside it. */
export function clampView(view: WorldView): WorldView {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, view.scale))
  const tx = Math.min(0, Math.max(WORLD_VIEWBOX.width - scale * WORLD_VIEWBOX.width, view.tx))
  const ty = Math.min(0, Math.max(WORLD_VIEWBOX.height - scale * WORLD_VIEWBOX.height, view.ty))
  return { scale, tx, ty }
}

/**
 * May a pointer that went down here start a pan?
 *
 * No, for three kinds of target, and the third one was a real bug:
 *
 * 1. **a dot** — pressing on it is a selection, not a drag;
 * 2. **anything interactive** — a link, a button, an input: their own click has to happen;
 * 3. **anything inside the destination panel** — the panel sits inside the map's own element, so
 *    without this every press on it looked like the start of a pan. The map then captured the
 *    pointer, which retargets the following `click` at the map itself, so the panel's links and
 *    buttons — **Follow conversation** above all — silently did nothing.
 *
 * Exported because the rule is invisible in markup and worth a test of its own.
 */
export function startsMapDrag(
  target: { closest?: (selector: string) => unknown } | null,
): boolean {
  if (target === null || typeof target.closest !== 'function') return false
  return (
    target.closest('[data-world-dot]') === null &&
    target.closest('[data-destination-panel]') === null &&
    target.closest('a, button, input, select, textarea, [role="dialog"]') === null
  )
}

/** Zoom about a point in view-box units, so the pixel under the pointer stays put. */
export function zoomAbout(view: WorldView, factor: number, pointX: number, pointY: number): WorldView {
  const scale = Math.min(MAX_SCALE, Math.max(MIN_SCALE, view.scale * factor))
  const ratio = scale / view.scale
  return clampView({ scale, tx: pointX - ratio * (pointX - view.tx), ty: pointY - ratio * (pointY - view.ty) })
}

/** Centre a point at a given scale — what clicking a dot does. */
export function centreOn(pointX: number, pointY: number, scale: number): WorldView {
  const bounded = Math.min(MAX_SCALE, Math.max(MIN_SCALE, scale))
  return clampView({
    scale: bounded,
    tx: WORLD_VIEWBOX.width / 2 - bounded * pointX,
    ty: WORLD_VIEWBOX.height / 2 - bounded * pointY,
  })
}

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

/** Quadratic arc between two countries' label points, bowed perpendicular to the chord. */
function linkPath(fromX: number, fromY: number, toX: number, toY: number, lift: number): string {
  const dx = toX - fromX
  const dy = toY - fromY
  const distance = Math.max(1, Math.hypot(dx, dy))
  const controlX = (fromX + toX) / 2 - (dy / distance) * lift
  const controlY = (fromY + toY) / 2 + (dx / distance) * lift
  return `M${fromX},${fromY} Q${controlX.toFixed(1)},${controlY.toFixed(1)} ${toX},${toY}`
}

/**
 * A stable number in [0, 1) for a country and a salt.
 *
 * The motes are scattered around a dot by a seeded value rather than `Math.random()`,
 * so a re-render — a hover, a theme change, a zoom — scatters them identically instead of
 * reshuffling the constellation under the reader's eye.
 */
function seeded(code: string, salt: number): number {
  const text = code + ':' + String(salt)
  let hash = 2166136261
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return ((hash >>> 0) % 1000) / 1000
}

/**
 * How many arcs carry the particle layers.
 *
 * Each layer is one more animated dash offset on one more path, so the busiest pair of
 * dozen arcs is where they earn their keep; past that the map is already busy and the
 * extra paths cost more than they show.
 */
const SPARK_CAP = 24
/** Motes scattered around each destination dot. */
const MOTES_PER_DOT = 3
/**
 * How many dots carry motes: the busiest, in the same order the API ranks countries.
 *
 * Three motes per country over a sixty-country capture is 180 animated circles, and the
 * countries past the first few dozen are single addresses a pixel wide — the constellation
 * is for the destinations that carry the capture, not for every speck on the map.
 */
const MOTE_CAP = 24
/** How far a mote drifts before it fades, in map units. */
const MOTE_DRIFT = 9

export interface WorldMapProps {
  data: GeographyResponse
  /** The analysis the destination panel reads its conversations from. */
  analysisId: string
  /** The country the reader has opened, or `null`. */
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

export function WorldMap({
  data,
  analysisId,
  focused,
  onFocus,
  onSelectIp,
  datasetAction,
}: WorldMapProps) {
  const [hovered, setHovered] = useState<string | null>(null)
  const [view, setView] = useState<WorldView>({ scale: 1, tx: 0, ty: 0 })
  const [panning, setPanning] = useState(false)
  /* The panel waits for the zoom to finish (see PANEL_DELAY_MS). Closing it is immediate:
     only its appearance is delayed. */
  const [panelReady, setPanelReady] = useState(false)
  const shell = useRef<HTMLDivElement | null>(null)
  const drag = useRef<{ x: number; y: number; origin: WorldView } | null>(null)

  /* Pointer position in view-box units — the space every transform is expressed in. */
  const toViewBox = useCallback((event: { clientX: number; clientY: number }) => {
    const rect = shell.current?.getBoundingClientRect()
    if (rect === undefined || rect === null || rect.width === 0) {
      return { x: WORLD_VIEWBOX.width / 2, y: WORLD_VIEWBOX.height / 2 }
    }
    return {
      x: ((event.clientX - rect.left) / rect.width) * WORLD_VIEWBOX.width,
      y: ((event.clientY - rect.top) / rect.height) * WORLD_VIEWBOX.height,
    }
  }, [])

  const zoomBy = useCallback((factor: number, point?: { x: number; y: number }) => {
    setView((current) => {
      const centre = point ?? { x: WORLD_VIEWBOX.width / 2, y: WORLD_VIEWBOX.height / 2 }
      return zoomAbout(current, factor, centre.x, centre.y)
    })
  }, [])

  /* Wheel zoom. `passive: false` is required to stop the page scrolling underneath: React's
     synthetic handler cannot, so the listener is attached directly. */
  useEffect(() => {
    const element = shell.current
    if (element === null) return
    const onWheel = (event: WheelEvent) => {
      if (!event.ctrlKey && !event.metaKey && Math.abs(event.deltaY) < 1) return
      event.preventDefault()
      const point = toViewBox(event)
      setView((current) => zoomAbout(current, event.deltaY < 0 ? WHEEL_STEP : 1 / WHEEL_STEP, point.x, point.y))
    }
    element.addEventListener('wheel', onWheel, { passive: false })
    return () => element.removeEventListener('wheel', onWheel)
  }, [toViewBox])

  /* Escape closes the panel, which is what a reader expects from a dialog. */
  useEffect(() => {
    if (focused === null) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onFocus(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [focused, onFocus])

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    /* See `startsMapDrag`: the panel, its controls and every dot are excluded, so a press on any
       of them keeps its own click instead of becoming a pan the map captures. */
    if (!startsMapDrag(event.target as { closest?: (selector: string) => unknown })) return
    drag.current = { x: event.clientX, y: event.clientY, origin: view }
    setPanning(true)
    event.currentTarget.setPointerCapture(event.pointerId)
  }

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const started = drag.current
    if (started === null) return
    const rect = shell.current?.getBoundingClientRect()
    if (rect === undefined || rect === null || rect.width === 0) return
    const perPixelX = WORLD_VIEWBOX.width / rect.width
    const perPixelY = WORLD_VIEWBOX.height / rect.height
    setView(
      clampView({
        scale: started.origin.scale,
        tx: started.origin.tx + (event.clientX - started.x) * perPixelX,
        ty: started.origin.ty + (event.clientY - started.y) * perPixelY,
      }),
    )
  }

  const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (drag.current === null) return
    drag.current = null
    setPanning(false)
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId)
    }
  }

  /** Clicking a dot toggles its destination panel; the effect below does the zooming. */
  const openCountry = useCallback(
    (code: string) => {
      onFocus(focused === code ? null : code)
    },
    [focused, onFocus],
  )

  const zoomReset = () => setView({ scale: 1, tx: 0, ty: 0 })

  /* Zoom to whatever is selected, however it was selected — a dot on the map or a row in the
     list under it. One effect, so the two cannot drift apart; the scale is only raised, never
     lowered, so a reader who has zoomed in further stays where they are. */
  useEffect(() => {
    if (focused === null) return
    const point = WORLD_COUNTRIES.find((entry) => entry.code === focused)
    if (point === undefined) return
    setView((current) =>
      centreOn(point.x, point.y, current.scale > FOCUS_SCALE ? current.scale : FOCUS_SCALE),
    )
  }, [focused])

  /* When a new country is opened, hide the card, move the map, and only then show it. A reader
     who opens another country mid-wait, or closes the panel, cancels this cleanly. */
  useEffect(() => {
    if (focused === null) {
      setPanelReady(false)
      return
    }
    setPanelReady(false)
    /* `motionIsStill()` reads both switches: this application's Motion setting and the
       operating system's reduce-motion preference. Asking only the media query would
       animate for a reader who had already turned motion off here. */
    if (motionIsStill()) {
      /* Nothing moves, so nothing to wait for. */
      setPanelReady(true)
      return
    }
    const timer = window.setTimeout(() => setPanelReady(true), PANEL_DELAY_MS)
    return () => window.clearTimeout(timer)
  }, [focused])

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

  /* One arc per country, resolved once: the base path and the two particle layers that
     trace it must be the *same* `d`, and finding a country's label point three times per
     render for sixty countries is 180 searches for one answer. */
  const arcs = useMemo(
    () =>
      countries.flatMap((country, index) => {
        const point = WORLD_COUNTRIES.find((entry) => entry.code === country.code)
        if (point === undefined) return []
        const distance = Math.hypot(point.x - ORIGIN.x, point.y - ORIGIN.y)
        return [
          {
            code: country.code,
            d: arcPath(point.x, point.y, Math.min(120, distance * 0.28)),
            index,
          },
        ]
      }),
    [countries],
  )

  /* §5.3's links: a country pair the capture itself proves. Empty for an ordinary capture
     of one network talking outward, which is the honest answer and not a missing feature. */
  const links = useMemo(
    () =>
      (data.links ?? []).flatMap((link, index) => {
        const from = WORLD_COUNTRIES.find((entry) => entry.code === link.source)
        const to = WORLD_COUNTRIES.find((entry) => entry.code === link.target)
        if (from === undefined || to === undefined) return []
        const distance = Math.hypot(to.x - from.x, to.y - from.y)
        return [
          {
            key: link.source + '-' + link.target,
            d: linkPath(from.x, from.y, to.x, to.y, Math.min(90, distance * 0.22)),
            index,
            source: link.source,
            target: link.target,
            title:
              countryName(link.source) +
              ' ↔ ' +
              countryName(link.target) +
              ': ' +
              formatNumber(link.conversations) +
              ' conversation(s), ' +
              formatBytes(link.bytes),
          },
        ]
      }),
    [data.links],
  )

  /* The constellation around each dot. Seeded, so it never reshuffles between renders. */
  const motes = useMemo(
    () =>
      countries.slice(0, MOTE_CAP).flatMap((country) => {
        const point = WORLD_COUNTRIES.find((entry) => entry.code === country.code)
        if (point === undefined) return []
        const radius = radiusFor(country)
        return Array.from({ length: MOTES_PER_DOT }, (_, index) => {
          const turn = (index / MOTES_PER_DOT) * Math.PI * 2 + seeded(country.code, index) * 1.1
          const reach = 4 + seeded(country.code, index + 9) * MOTE_DRIFT
          const start = radius + 1.5
          return {
            key: country.code + ':' + String(index),
            x: point.x + Math.cos(turn) * start,
            y: point.y + Math.sin(turn) * start,
            dx: Math.cos(turn) * reach,
            dy: Math.sin(turn) * reach,
            size: 0.7 + seeded(country.code, index + 33) * 0.7,
            delay: -(seeded(country.code, index + 21) * 5),
          }
        })
      }),
    [countries, maxBytes],
  )

  const active = hovered ?? focused
  const activeCountry = countries.find((country) => country.code === active) ?? null

  const focusedPoint =
    focused === null ? null : WORLD_COUNTRIES.find((entry) => entry.code === focused) ?? null

  return (
    <div className="relative">
      <div
        ref={shell}
        className="world-map-shell map-backdrop overflow-hidden rounded border border-border"
        data-world-map
        data-panning={panning}
        data-zoom={view.scale.toFixed(2)}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
      >
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

          {/* Everything the map draws sits in one transform group: the zoom is a single
              translate/scale the browser can interpolate (see `.world-zoom` in index.css). */}
          <g
            className="world-zoom"
            data-world-zoom={view.scale.toFixed(2)}
            style={{ transform: `translate(${String(view.tx)}px, ${String(view.ty)}px) scale(${String(view.scale)})` } as CSSProperties}
          >
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

          {/* Country to country: drawn only where one conversation of this capture has an
              endpoint in each country, so the map can never imply a route it did not see. */}
          <g data-world-links>
            {links.map((link) => (
              <g key={link.key}>
                <path
                  d={link.d}
                  data-world-link={link.key}
                  className={clsx(
                    'world-link',
                    (active === link.source || active === link.target) && 'world-link-active',
                  )}
                  style={{ animationDelay: `${String(-link.index * 0.63)}s` } as CSSProperties}
                >
                  <title>{link.title}</title>
                </path>
                <path
                  d={link.d}
                  pathLength={100}
                  aria-hidden
                  className='world-link-spark'
                  style={{ animationDelay: `${String(-link.index * 0.47)}s, ${String(-link.index * 0.29)}s` } as CSSProperties}
                />
              </g>
            ))}
          </g>

          {/* Arcs: one per country, flowing outward from the capture's own side. The base
              line is the geography; the bead and the flicker are the traffic on it, and the
              busiest arcs carry them (see SPARK_CAP in WorldMap.tsx). */}
          <g data-world-arcs>
            {arcs.map((arc) => (
              <g key={arc.code}>
                <path
                  d={arc.d}
                  data-world-arc={arc.code}
                  className={clsx('world-arc', active === arc.code && 'world-arc-active')}
                  style={{ animationDelay: `${String(-arc.index * 0.42)}s` } as CSSProperties}
                />
                {arc.index < SPARK_CAP ? (
                  <>
                    <path
                      d={arc.d}
                      pathLength={100}
                      aria-hidden
                      className='world-spark'
                      style={{ animationDelay: `${String(-arc.index * 0.53)}s, ${String(-arc.index * 0.31)}s` } as CSSProperties}
                    />
                    <path
                      d={arc.d}
                      pathLength={100}
                      aria-hidden
                      className='world-flicker'
                      style={{ animationDelay: `${String(-arc.index * 0.71)}s, ${String(-arc.index * 0.23)}s` } as CSSProperties}
                    />
                  </>
                ) : null}
              </g>
            ))}
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
                  onClick={() => openCountry(country.code)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      openCountry(country.code)
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

          {/* The constellation: motes thrown outward from each dot, fading as they go. They
              carry no data — the dot's size and the arc already say how much traffic there
              is — so they are `aria-hidden` and hidden outright when motion is off. */}
          <g data-world-motes aria-hidden>
            {motes.map((mote) => (
              <circle
                key={mote.key}
                className="world-mote"
                cx={mote.x}
                cy={mote.y}
                r={mote.size}
                style={{
                  '--mote-dx': `${mote.dx.toFixed(1)}px`,
                  '--mote-dy': `${mote.dy.toFixed(1)}px`,
                  animationDelay: `${mote.delay.toFixed(2)}s`,
                } as CSSProperties}
              />
            ))}
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
                  ? `${formatNumber(unknown.addresses)} address(es) have no country in the dataset and are drawn nowhere. They are counted as not placed in the ranking beside the map.`
                  : 'No location dataset is installed yet.'
              }
            >
              {formatNumber(unknown.addresses)} not placed
            </CornerChip>
          ) : null}
        </div>

        {/* The zoom controls: keyboard-reachable buttons, and the current scale in their tooltips
            rather than in a live region that would chatter on every wheel tick. */}
        <div className="world-controls" onPointerDown={(event) => event.stopPropagation()}>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => zoomBy(BUTTON_STEP)}
            aria-label="Zoom in"
            title={`Zoom in (${view.scale.toFixed(1)}× of ${String(MAX_SCALE)}×)`}
            data-world-zoom-in
          >
            <Plus size={12} aria-hidden />
          </button>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => zoomBy(1 / BUTTON_STEP)}
            disabled={view.scale <= MIN_SCALE}
            aria-label="Zoom out"
            title={`Zoom out (${view.scale.toFixed(1)}×)`}
            data-world-zoom-out
          >
            <Minus size={12} aria-hidden />
          </button>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={zoomReset}
            disabled={view.scale === MIN_SCALE && view.tx === 0 && view.ty === 0}
            aria-label="Reset the zoom"
            title="Fit the whole world again (Esc closes the panel first)"
            data-world-zoom-reset
          >
            <Maximize2 size={12} aria-hidden />
          </button>
        </div>

        {focused !== null && focusedPoint !== null && panelReady ? (
          <DestinationPanel
            analysisId={analysisId}
            code={focused}
            onClose={() => onFocus(null)}
            onSelectIp={onSelectIp}
          />
        ) : null}

        {!available ? (
          <div className="pointer-events-none absolute inset-x-3 bottom-3 flex justify-center">
            <div className="pointer-events-auto flex max-w-2xl flex-col gap-2 rounded border border-border bg-surface/95 px-3 py-2.5 text-center shadow-panel backdrop-blur">
              <p className="text-xs leading-relaxed text-muted">
                <span className="text-text">No location dataset yet.</span>{' '}
                {data.dataset?.reason ??
                  'The world outline is part of ShinboShark; the address-to-country table is not.'}{' '}
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
                data-ip={ip}
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
