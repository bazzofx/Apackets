import { useMemo, useState } from 'react'
import clsx from 'clsx'
import { Network } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import { useThemeTokens } from '@/theme/ThemeProvider'
import { formatBytes, formatNumber } from '@/utils/format'
import type { HostGraphEdge, HostGraphNode } from '@/types'

const WIDTH = 1000
const HEIGHT = 620
const PADDING = 56
const ITERATIONS = 140

/** Scope -> colour, resolved from the active theme by the component. */
export interface MapPalette {
  private: string
  public: string
  multicast: string
  local: string
  unclassified: string
}

/**
 * Colour an endpoint by its precise scope.
 *
 * The API reports `scope` (broadcast / multicast / loopback / link_local /
 * private / public / …) and a boolean `is_private`, which on its own classifies
 * `255.255.255.255` and SSDP/LLMNR multicast groups as if they were public
 * internet hosts. `scope` is preferred and `is_private` is the fallback for
 * older responses.
 */
function nodeColour(
  node: { scope?: string | null; is_private?: boolean | null },
  palette: MapPalette,
): string {
  switch (node.scope) {
    case 'private':
      return palette.private
    case 'public':
      return palette.public
    case 'multicast':
    case 'broadcast':
      return palette.multicast
    case 'loopback':
    case 'link_local':
    case 'unspecified':
    case 'reserved':
      return palette.local
    default:
      break
  }
  if (node.is_private === true) return palette.private
  if (node.is_private === false) return palette.public
  return palette.unclassified
}

const SCOPE_LABELS: Record<string, string> = {
  private: 'private address',
  public: 'public address',
  multicast: 'multicast group',
  broadcast: 'broadcast address',
  loopback: 'loopback address',
  link_local: 'link-local address',
  unspecified: 'unspecified address',
  reserved: 'reserved address',
}

/** Human description of an endpoint's scope, for the focus panel. */
function scopeLabel(node: { scope?: string | null; is_private?: boolean | null }): string {
  if (node.scope && SCOPE_LABELS[node.scope]) return SCOPE_LABELS[node.scope]
  if (node.is_private === true) return 'private address'
  if (node.is_private === false) return 'public address'
  return 'classification not available'
}

interface Position {
  x: number
  y: number
}

/** Stable pseudo-random jitter so the layout does not jump between renders. */
function hashUnit(value: string, salt: number): number {
  let hash = 2166136261 ^ salt
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return ((hash >>> 0) % 1000) / 1000
}

/**
 * Static force-directed layout: repulsion between every pair, springs along the
 * observed edges. Deterministic and computed once per graph, so the map never
 * animates or re-shuffles while the analyst is reading it.
 */
function computeLayout(nodes: HostGraphNode[], edges: HostGraphEdge[]): Position[] {
  if (nodes.length === 0) return []
  const index = new Map(nodes.map((node, position) => [node.id, position]))
  const positions = nodes.map((node, position) => {
    const angle = (position / nodes.length) * Math.PI * 2
    const radius = Math.min(WIDTH, HEIGHT) * 0.33 * (0.75 + hashUnit(node.id, 7) * 0.5)
    return {
      x: WIDTH / 2 + Math.cos(angle) * radius,
      y: HEIGHT / 2 + Math.sin(angle) * radius,
    }
  })

  const maxBytes = Math.max(1, ...nodes.map((node) => node.bytes || 0))
  const links = edges
    .map((edge) => ({ a: index.get(edge.source), b: index.get(edge.target), bytes: edge.bytes || 1 }))
    .filter((link): link is { a: number; b: number; bytes: number } => link.a !== undefined && link.b !== undefined)

  for (let step = 0; step < ITERATIONS; step += 1) {
    const cooling = 1 - step / ITERATIONS
    const forces = positions.map(() => ({ x: 0, y: 0 }))

    for (let i = 0; i < positions.length; i += 1) {
      for (let j = i + 1; j < positions.length; j += 1) {
        const dx = positions[j].x - positions[i].x
        const dy = positions[j].y - positions[i].y
        const distanceSq = Math.max(400, dx * dx + dy * dy)
        const push = 26000 / distanceSq
        const distance = Math.sqrt(distanceSq)
        forces[i].x -= (dx / distance) * push
        forces[i].y -= (dy / distance) * push
        forces[j].x += (dx / distance) * push
        forces[j].y += (dy / distance) * push
      }
    }

    for (const link of links) {
      const dx = positions[link.b].x - positions[link.a].x
      const dy = positions[link.b].y - positions[link.a].y
      const distance = Math.max(1, Math.sqrt(dx * dx + dy * dy))
      // Heavier conversations pull their endpoints closer together.
      const target = 90 + 150 * (1 - Math.min(1, link.bytes / maxBytes))
      const pull = ((distance - target) / distance) * 0.06 * cooling
      forces[link.a].x += dx * pull
      forces[link.a].y += dy * pull
      forces[link.b].x -= dx * pull
      forces[link.b].y -= dy * pull
    }

    for (let i = 0; i < positions.length; i += 1) {
      // A gentle pull to the centre keeps disconnected islands on screen.
      forces[i].x += (WIDTH / 2 - positions[i].x) * 0.0025
      forces[i].y += (HEIGHT / 2 - positions[i].y) * 0.0025
      positions[i] = {
        x: Math.min(WIDTH - PADDING, Math.max(PADDING, positions[i].x + forces[i].x * cooling)),
        y: Math.min(HEIGHT - PADDING, Math.max(PADDING, positions[i].y + forces[i].y * cooling)),
      }
    }
  }
  return positions
}

export interface NetworkMapProps {
  nodes: HostGraphNode[]
  edges: HostGraphEdge[]
  isLoading?: boolean
  error?: unknown
  onRetry?: () => void
  /** Called when a node is activated (click, Enter or space). */
  onSelect: (ip: string) => void
  /** How many node labels to draw. */
  labelCount?: number
}

/**
 * Conversation map for one capture: one node per host, one edge per observed
 * conversation. Purely observational - there are no inferred or logical links.
 */
export function NetworkMap({
  nodes,
  edges,
  isLoading = false,
  error,
  onRetry,
  onSelect,
  labelCount = 8,
}: NetworkMapProps) {
  const [focusId, setFocusId] = useState<string | null>(null)
  const tokens = useThemeTokens()
  const palette: MapPalette = {
    private: tokens.mapPrivate,
    public: tokens.mapPublic,
    multicast: tokens.mapMulticast,
    local: tokens.mapLocal,
    unclassified: tokens.mapUnclassified,
  }

  const positions = useMemo(() => computeLayout(nodes, edges), [nodes, edges])

  const stats = useMemo(() => {
    const maxBytes = Math.max(1, ...nodes.map((node) => node.bytes || 0))
    const maxEdgeBytes = Math.max(1, ...edges.map((edge) => edge.bytes || 0))
    return { maxBytes, maxEdgeBytes }
  }, [nodes, edges])

  const labelled = useMemo(
    () =>
      new Set(
        [...nodes]
          .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
          .slice(0, labelCount)
          .map((node) => node.id),
      ),
    [nodes, labelCount],
  )

  const neighbours = useMemo(() => {
    const map = new Map<string, { id: string; bytes: number; packets: number; ports: number[]; protocols: string }[]>()
    for (const edge of edges) {
      for (const [from, to] of [
        [edge.source, edge.target],
        [edge.target, edge.source],
      ]) {
        const list = map.get(from) ?? []
        list.push({
          id: to,
          bytes: edge.bytes,
          packets: edge.packets,
          ports: edge.ports ?? [],
          protocols: edge.protocols ?? '',
        })
        map.set(from, list)
      }
    }
    for (const list of map.values()) list.sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
    return map
  }, [edges])

  if (isLoading) return <LoadingState label="Building the conversation map…" rows={5} />
  if (error) {
    return <ErrorState error={error} onRetry={onRetry} title="Could not load the conversation map" />
  }
  if (nodes.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={Network}
        title="No conversations to map"
        description="The capture recorded no conversations between hosts (a single frame, or traffic the reassembler skipped). Nothing is drawn rather than a placeholder topology."
        className="py-10"
      />
    )
  }

  const positionOf = (id: string) => positions[nodes.findIndex((node) => node.id === id)]
  const focused = nodes.find((node) => node.id === focusId) ?? null
  const focusedNeighbours = focused ? (neighbours.get(focused.id) ?? []).slice(0, 5) : []

  return (
    <div className="map-backdrop relative overflow-hidden rounded-md">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="h-[26rem] w-full"
        role="img"
        aria-label={`Conversation map: ${nodes.length} hosts, ${edges.length} observed conversations`}
        onMouseLeave={() => setFocusId(null)}
      >
        <g>
          {edges.map((edge, position) => {
            const from = positionOf(edge.source)
            const to = positionOf(edge.target)
            if (!from || !to) return null
            const active =
              focusId === null || edge.source === focusId || edge.target === focusId
            const width = 0.6 + 4.4 * Math.sqrt((edge.bytes || 0) / stats.maxEdgeBytes)
            return (
              <line
                key={`${edge.source}-${edge.target}-${position}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke={active && focusId !== null ? palette.private : tokens.border2}
                strokeWidth={width}
                strokeOpacity={active ? 0.75 : 0.12}
                strokeLinecap="round"
              />
            )
          })}
          {nodes.map((node, position) => {
            const point = positions[position]
            if (!point) return null
            const radius = 4 + 15 * Math.sqrt((node.bytes || 0) / stats.maxBytes)
            const colour = nodeColour(node, palette)
            const active = focusId === null || focusId === node.id
            const related =
              focusId !== null &&
              focusId !== node.id &&
              (neighbours.get(focusId) ?? []).some((entry) => entry.id === node.id)
            return (
              <g
                key={node.id}
                className="cursor-pointer"
                tabIndex={0}
                role="button"
                aria-label={`${node.id}: ${formatNumber(node.packets)} packets, ${formatBytes(node.bytes)}`}
                onMouseEnter={() => setFocusId(node.id)}
                onFocus={() => setFocusId(node.id)}
                onClick={() => onSelect(node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(node.id)
                  }
                }}
              >
                {(focusId === node.id || related) && (
                  <circle cx={point.x} cy={point.y} r={radius + 5} fill="none" stroke={colour} strokeOpacity={0.5} />
                )}
                <circle
                  cx={point.x}
                  cy={point.y}
                  r={radius}
                  fill={colour}
                  fillOpacity={active ? 0.85 : 0.2}
                  stroke={tokens.bg}
                  strokeWidth={1}
                />
                {labelled.has(node.id) || focusId === node.id ? (
                  <text
                    x={point.x}
                    y={point.y - radius - 5}
                    textAnchor="middle"
                    className="mono"
                    fontSize={12}
                    fill={active ? tokens.text : tokens.faint}
                    stroke={tokens.bg}
                    strokeWidth={3}
                    paintOrder="stroke"
                  >
                    {node.label || node.id}
                  </text>
                ) : null}
              </g>
            )
          })}
        </g>
      </svg>

      <div className="pointer-events-none absolute left-3 top-3 flex flex-col gap-1 text-2xs">
        <span className="flex items-center gap-1 text-muted">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette.private }} />
          private
        </span>
        <span className="flex items-center gap-1 text-muted">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette.public }} />
          public
        </span>
        <span className="flex items-center gap-1 text-muted">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette.multicast }} />
          multicast / broadcast
        </span>
        <span className="flex items-center gap-1 text-muted">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette.local }} />
          loopback / link-local
        </span>
        <span className="flex items-center gap-1 text-muted">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: palette.unclassified }} />
          unclassified
        </span>
      </div>

      <div className="pointer-events-none absolute bottom-3 right-3 w-72 rounded border border-border bg-surface/95 p-2 text-2xs">
        {focused ? (
          <div className="flex flex-col gap-1">
            <div className="mono text-sm text-text">{focused.label || focused.id}</div>
            <div className="text-muted">
              {formatNumber(focused.packets)} packets · {formatBytes(focused.bytes)}
              {focused.mac ? ` · ${focused.mac}` : ''}
            </div>
            <div className="text-faint">{scopeLabel(focused)}</div>
            {focusedNeighbours.length > 0 ? (
              <ul className="mt-1 flex flex-col gap-0.5 border-t border-border pt-1">
                {focusedNeighbours.map((entry) => (
                  <li key={entry.id} className="flex items-center gap-1">
                    <span className="mono truncate text-text" title={entry.id}>
                      {entry.id}
                    </span>
                    <span className="ml-auto shrink-0 text-faint">
                      {entry.ports.length > 0 ? `:${entry.ports.slice(0, 3).join(',')}` : ''}
                    </span>
                    <span className="shrink-0 text-muted">{formatBytes(entry.bytes)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="mt-1 border-t border-border pt-1 text-faint">no observed peers</div>
            )}
          </div>
        ) : (
          <div className="text-faint">
            Hover a node for its peers, ports and protocols. Click to open the host.
          </div>
        )}
      </div>

      <div className={clsx('px-1 pt-1 text-2xs text-faint')}>
        Drawn only from connections observed in this capture — this is not a physical network
        topology. {formatNumber(nodes.length)} hosts, {formatNumber(edges.length)} conversations.
      </div>
    </div>
  )
}

export default NetworkMap