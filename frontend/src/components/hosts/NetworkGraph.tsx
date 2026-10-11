/**
 * Observed-connection map for `GET /hosts/graph`.
 *
 * Deliberately dependency-free: the layout is a deterministic concentric
 * arrangement (busiest endpoint at the centre, the rest on rings ordered by
 * measured volume) and the edges are plain SVG lines. There is no force
 * simulation and no physics — the same capture always produces the same picture,
 * which is what a forensic view needs.
 *
 * The map is built **only from conversations observed in this capture**. It is
 * not a network topology: a link that carried no traffic does not exist here, and
 * a node with no edges is still drawn (with a dashed ring) rather than dropped.
 */

import { useMemo, useState } from 'react'
import clsx from 'clsx'
import { Info, Network, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import MonoCell from '@/components/MonoCell'
import { asText } from '@/components/hosts/chips'
import type { HostGraph } from '@/types'
import { EMPTY, formatBytes, formatNumber } from '@/utils/format'

const GRAPH_WIDTH = 960
const GRAPH_HEIGHT = 460
const GRAPH_PADDING = 54
/** Above this many endpoints a 1:1 drawing stops being legible. */
const MAX_DRAWN_NODES = 300
/** Below this many endpoints every label is drawn; above it, only relevant ones. */
const LABEL_ALL_BELOW = 70

const NODE_PRIVATE_FILL = '#3b82f6'
const NODE_PUBLIC_FILL = '#f59e0b'
const NODE_UNKNOWN_FILL = '#64748b'
const EDGE_IDLE = '#2c3c5e'
const EDGE_ACTIVE = '#60a5fa'

interface GraphNode {
  id: string
  label: string
  mac: string | null
  packets: number
  bytes: number
  isPrivate: boolean | null
}

interface GraphEdge {
  source: string
  target: string
  packets: number
  bytes: number
  protocols: string | null
  ports: number[]
}

interface PlacedNode extends GraphNode {
  x: number
  y: number
  radius: number
  degree: number
}

function toNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

/** Coerce the API graph into the local shape, dropping anything unusable. */
function normalise(graph: HostGraph): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const rawNodes = Array.isArray(graph?.nodes) ? graph.nodes : []
  const rawEdges = Array.isArray(graph?.edges) ? graph.edges : []

  const seen = new Set<string>()
  const nodes: GraphNode[] = []
  for (const node of rawNodes) {
    const id = asText(node?.id)
    if (id === null || seen.has(id)) continue
    seen.add(id)
    nodes.push({
      id,
      label: asText(node?.label) ?? id,
      mac: asText(node?.mac),
      packets: toNumber(node?.packets),
      bytes: toNumber(node?.bytes),
      isPrivate:
        node?.is_private === true ? true : node?.is_private === false ? false : null,
    })
  }

  const edges: GraphEdge[] = []
  for (const edge of rawEdges) {
    const source = asText(edge?.source)
    const target = asText(edge?.target)
    if (source === null || target === null || source === target) continue
    if (!seen.has(source) || !seen.has(target)) continue
    edges.push({
      source,
      target,
      packets: toNumber(edge?.packets),
      bytes: toNumber(edge?.bytes),
      protocols: asText(edge?.protocols),
      ports: Array.isArray(edge?.ports)
        ? edge.ports.filter((port): port is number => typeof port === 'number')
        : [],
    })
  }

  return { nodes, edges }
}

function ringCapacity(radius: number, spacing: number): number {
  return Math.max(1, Math.floor((2 * Math.PI * radius) / spacing))
}

/**
 * Concentric placement by measured volume: index 0 (the busiest endpoint by
 * bytes) sits at the centre, the remaining nodes fill rings outward in
 * decreasing-byte order. Ring radii grow with the ring count and the angular
 * spacing shrinks as the node count grows, so every node gets a position.
 */
function computePositions(
  nodes: GraphNode[],
  width: number,
  height: number,
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>()
  if (nodes.length === 0) return positions

  const cx = width / 2
  const cy = height / 2
  positions.set(nodes[0].id, { x: cx, y: cy })
  if (nodes.length === 1) return positions

  const maxRadius = Math.max(60, Math.min(width, height) / 2 - GRAPH_PADDING)
  const spacing = Math.max(14, Math.min(40, 2600 / nodes.length))

  let rings = 1
  while (rings < 18) {
    const radii = Array.from({ length: rings }, (_, index) => (maxRadius * (index + 1)) / rings)
    const capacity = radii.reduce((sum, radius) => sum + ringCapacity(radius, spacing), 0)
    if (capacity >= nodes.length - 1) break
    rings += 1
  }

  let next = 1
  for (let ring = 1; ring <= rings && next < nodes.length; ring += 1) {
    const radius = (maxRadius * ring) / rings
    const available = nodes.length - next
    // The outermost ring absorbs whatever is left, so nothing is dropped.
    const count =
      ring === rings ? available : Math.min(ringCapacity(radius, spacing), available)
    const slots = Math.max(1, count)
    const offset = -Math.PI / 2 + (ring % 2 === 0 ? Math.PI / slots : 0)
    for (let slot = 0; slot < slots && next < nodes.length; slot += 1) {
      const angle = offset + (2 * Math.PI * slot) / slots
      positions.set(nodes[next].id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      })
      next += 1
    }
  }
  return positions
}

function nodeFill(node: GraphNode): string {
  if (node.isPrivate === true) return NODE_PRIVATE_FILL
  if (node.isPrivate === false) return NODE_PUBLIC_FILL
  return NODE_UNKNOWN_FILL
}

function scopeLabel(node: GraphNode): string {
  if (node.isPrivate === true) return 'private'
  if (node.isPrivate === false) return 'public'
  return 'unclassified'
}

function LegendDot({ fill, dashed = false, label, title }: { fill: string; dashed?: boolean; label: string; title: string }) {
  return (
    <span className="flex items-center gap-1 text-2xs text-muted" title={title}>
      <svg width="12" height="12" aria-hidden>
        <circle
          cx="6"
          cy="6"
          r="4"
          fill={fill}
          stroke="#0b1120"
          strokeWidth="1"
          strokeDasharray={dashed ? '2 2' : undefined}
        />
      </svg>
      {label}
    </span>
  )
}

export interface NetworkGraphProps {
  graph: HostGraph
  selectedIp: string | null
  /** Called with the endpoint to open (or `null` to clear the selection). */
  onSelect: (ip: string | null) => void
}

/** Interactive relationship map drawn from observed conversations only. */
export function NetworkGraph({ graph, selectedIp, onSelect }: NetworkGraphProps) {
  const [hovered, setHovered] = useState<string | null>(null)

  const { nodes, edges, hiddenNodes, hiddenEdges } = useMemo(() => {
    const normalised = normalise(graph)
    const ordered = [...normalised.nodes].sort(
      (a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id),
    )
    const drawn = ordered.slice(0, MAX_DRAWN_NODES)
    const drawnIds = new Set(drawn.map((node) => node.id))
    const keptEdges = normalised.edges.filter(
      (edge) => drawnIds.has(edge.source) && drawnIds.has(edge.target),
    )
    const positions = computePositions(drawn, GRAPH_WIDTH, GRAPH_HEIGHT)

    const degree = new Map<string, number>()
    for (const edge of keptEdges) {
      degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
      degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
    }

    const maxBytes = Math.max(1, ...drawn.map((node) => node.bytes))
    const placed: PlacedNode[] = drawn.map((node) => {
      const position = positions.get(node.id) ?? { x: GRAPH_WIDTH / 2, y: GRAPH_HEIGHT / 2 }
      return {
        ...node,
        x: position.x,
        y: position.y,
        radius: 4 + 12 * Math.sqrt(node.bytes / maxBytes),
        degree: degree.get(node.id) ?? 0,
      }
    })

    return {
      nodes: placed,
      edges: keptEdges,
      hiddenNodes: normalised.nodes.length - drawn.length,
      hiddenEdges: normalised.edges.length - keptEdges.length,
    }
  }, [graph])

  const activeId = selectedIp ?? hovered
  const byId = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes])
  const active = activeId !== null ? (byId.get(activeId) ?? null) : null

  const adjacency = useMemo(() => {
    const map = new Map<string, GraphEdge[]>()
    for (const edge of edges) {
      const forSource = map.get(edge.source)
      if (forSource) forSource.push(edge)
      else map.set(edge.source, [edge])
      const forTarget = map.get(edge.target)
      if (forTarget) forTarget.push(edge)
      else map.set(edge.target, [edge])
    }
    return map
  }, [edges])

  const neighbourIds = useMemo(() => {
    if (active === null) return new Set<string>()
    const ids = new Set<string>()
    for (const edge of adjacency.get(active.id) ?? []) {
      ids.add(edge.source === active.id ? edge.target : edge.source)
    }
    return ids
  }, [active, adjacency])

  const maxEdgeBytes = useMemo(
    () => Math.max(1, ...edges.map((edge) => edge.bytes)),
    [edges],
  )
  const totalBytes = useMemo(
    () => nodes.reduce((sum, node) => sum + node.bytes, 0),
    [nodes],
  )

  if (nodes.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No observed connections to map"
        description={
          <>
            The backend returned no graph nodes for this capture. That means no TCP/UDP conversation
            was reassembled and no endpoint could be paired — it does not mean the capture is clean.
            Nothing is inferred here: this map only ever draws connections that were actually
            observed.
          </>
        }
      />
    )
  }

  const showAllLabels = nodes.length <= LABEL_ALL_BELOW

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded border border-border bg-surface2/60 px-3 py-2">
        <span className="flex items-start gap-1.5 text-2xs leading-relaxed text-muted">
          <Info size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <span>
            Drawn <strong className="font-semibold text-text">only from connections observed in
            this capture</strong> (reassembled TCP/UDP conversations). This is not a physical or
            logical topology: links that carried no traffic are absent, and no relationship is
            inferred from names, subnets or ports.
          </span>
        </span>
        <span className="flex flex-wrap items-center gap-3">
          <LegendDot fill={NODE_PRIVATE_FILL} label="private" title="RFC1918 / RFC4193 / loopback / link-local" />
          <LegendDot fill={NODE_PUBLIC_FILL} label="public" title="Routable address" />
          <LegendDot fill={NODE_UNKNOWN_FILL} label="unclassified" title="Address could not be classified" />
          <LegendDot
            fill={NODE_UNKNOWN_FILL}
            dashed
            label="no observed connection"
            title="Node with no edge in this capture; still drawn, never hidden"
          />
          <span className="text-2xs text-faint">node size and line width scale with bytes</span>
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="panel overflow-hidden">
          <svg
            viewBox={`0 0 ${GRAPH_WIDTH} ${GRAPH_HEIGHT}`}
            className="h-[420px] w-full"
            role="group"
            aria-label={`Relationship map of ${nodes.length} endpoints and ${edges.length} observed connections`}
          >
            <rect
              width={GRAPH_WIDTH}
              height={GRAPH_HEIGHT}
              fill="transparent"
              onClick={() => onSelect(null)}
            />
            <g>
              {edges.map((edge) => {
                const from = byId.get(edge.source)
                const to = byId.get(edge.target)
                if (!from || !to) return null
                const touchesActive =
                  active === null || edge.source === active.id || edge.target === active.id
                const width = 1 + 2.5 * Math.sqrt(edge.bytes / maxEdgeBytes)
                return (
                  <line
                    key={`${edge.source}|${edge.target}`}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke={touchesActive && active !== null ? EDGE_ACTIVE : EDGE_IDLE}
                    strokeWidth={width}
                    strokeOpacity={active === null ? 0.85 : touchesActive ? 0.95 : 0.12}
                  >
                    <title>{`${edge.source} ↔ ${edge.target} · ${formatNumber(edge.packets)} packets · ${formatBytes(edge.bytes)}${edge.protocols ? ` · ${edge.protocols}` : ''}${edge.ports.length > 0 ? ` · ports ${edge.ports.join(', ')}` : ''}`}</title>
                  </line>
                )
              })}
            </g>
            <g>
              {nodes.map((node) => {
                const isActive = active !== null && node.id === active.id
                const isNeighbour = active !== null && neighbourIds.has(node.id)
                const dim = active !== null && !isActive && !isNeighbour
                const labelVisible = showAllLabels || isActive || isNeighbour
                const fill = nodeFill(node)
                return (
                  <g
                    key={node.id}
                    tabIndex={0}
                    role="button"
                    aria-label={`${node.label}, ${scopeLabel(node)}, ${formatNumber(node.packets)} packets, ${formatBytes(node.bytes)}, ${node.degree} observed connections`}
                    className="cursor-pointer outline-none"
                    onMouseEnter={() => setHovered(node.id)}
                    onMouseLeave={() => setHovered((current) => (current === node.id ? null : current))}
                    onFocus={() => setHovered(node.id)}
                    onBlur={() => setHovered((current) => (current === node.id ? null : current))}
                    onClick={() => onSelect(selectedIp === node.id ? null : node.id)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        onSelect(selectedIp === node.id ? null : node.id)
                      }
                    }}
                  >
                    {isActive ? (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r={node.radius + 5}
                        fill="none"
                        stroke="#60a5fa"
                        strokeWidth={1}
                      />
                    ) : null}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.radius}
                      fill={fill}
                      fillOpacity={dim ? 0.25 : 0.9}
                      stroke={dim ? '#22304d' : '#0b1120'}
                      strokeWidth={1}
                      strokeDasharray={node.degree === 0 ? '2 2' : undefined}
                    >
                      <title>{`${node.label}\n${scopeLabel(node)}${node.mac ? ` · ${node.mac}` : ''}\n${formatNumber(node.packets)} packets · ${formatBytes(node.bytes)}\n${node.degree === 0 ? 'no observed connection in this capture' : `${node.degree} observed connection(s)`}`}</title>
                    </circle>
                    {labelVisible ? (
                      <text
                        x={node.x}
                        y={node.y + node.radius + 10}
                        textAnchor="middle"
                        fontSize={9}
                        className={clsx('pointer-events-none font-mono')}
                        fill={dim ? '#5a6b88' : isActive ? '#e2e8f0' : '#8296b4'}
                      >
                        {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
                      </text>
                    ) : null}
                  </g>
                )
              })}
            </g>
          </svg>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border px-3 py-2 text-2xs text-faint">
            <span>
              {formatNumber(nodes.length)} endpoints · {formatNumber(edges.length)} observed
              connection(s)
            </span>
            {!showAllLabels ? (
              <span>
                labels are drawn for the hovered/selected endpoint and its neighbours only — hover a
                node to identify it
              </span>
            ) : null}
            {hiddenNodes > 0 ? (
              <span className="text-amber-300">
                drawing the {formatNumber(nodes.length)} highest-volume endpoints;{' '}
                {formatNumber(hiddenNodes)} more node(s) and {formatNumber(hiddenEdges)} edge(s) are
                in the API response but not drawn
              </span>
            ) : null}
            <span className="ml-auto">click a node to focus it · click the background to clear</span>
          </div>
        </div>

        <aside className="panel flex flex-col">
          <header className="panel-header">
            <div>
              <div className="panel-title">{active === null ? 'Endpoint focus' : 'Endpoint detail'}</div>
              <div className="mt-0.5 text-2xs text-faint">
                {active === null ? 'hover or click a node' : scopeLabel(active)}
              </div>
            </div>
            {selectedIp !== null ? (
              <button
                type="button"
                className="btn px-1.5 py-1"
                onClick={() => onSelect(null)}
                title="Clear the selected endpoint"
              >
                <X size={12} aria-hidden />
              </button>
            ) : null}
          </header>

          {active === null ? (
            <div className="px-3 py-4 text-2xs leading-relaxed text-faint">
              Hovering a node highlights its connections and shows its measured traffic here.
              Clicking a node keeps the focus and opens the full host record below the map.
            </div>
          ) : (
            <div className="flex flex-col gap-2 p-3">
              <div className="flex items-center gap-1.5">
                <span className="break-all mono text-xs text-text">{active.id}</span>
                <CopyButton value={active.id} label={`Copy ${active.id}`} />
                {selectedIp === active.id ? (
                  <span className="chip border-accent/40 bg-accent/10 text-accent2">selected</span>
                ) : null}
              </div>
              <dl className="grid grid-cols-2 gap-x-2 gap-y-1 text-2xs">
                <dt className="text-faint">MAC</dt>
                <dd className="mono text-text">
                  <MonoCell maxWidth={130}>{active.mac}</MonoCell>
                </dd>
                <dt className="text-faint">Packets</dt>
                <dd className="mono text-text">{formatNumber(active.packets)}</dd>
                <dt className="text-faint">Bytes</dt>
                <dd className="mono text-text">{formatBytes(active.bytes)}</dd>
                <dt className="text-faint">Share of bytes</dt>
                <dd className="mono text-text">
                  {totalBytes > 0 ? `${((active.bytes / totalBytes) * 100).toFixed(1)}%` : EMPTY}
                </dd>
                <dt className="text-faint">Connections</dt>
                <dd className="mono text-text">{formatNumber(active.degree)}</dd>
              </dl>

              {active.degree === 0 ? (
                <p className="text-2xs leading-relaxed text-muted">
                  No conversation in this capture involves this endpoint. It is still drawn — the map
                  never hides an endpoint the API reported.
                </p>
              ) : (
                <div className="flex flex-col gap-1">
                  <div className="text-2xs uppercase tracking-wider text-faint">Neighbours by bytes</div>
                  <ul className="flex flex-col divide-y divide-border/60">
                    {(adjacency.get(active.id) ?? [])
                      .slice()
                      .sort((a, b) => b.bytes - a.bytes)
                      .slice(0, 6)
                      .map((edge) => {
                        const otherId = edge.source === active.id ? edge.target : edge.source
                        return (
                          <li key={`${edge.source}|${edge.target}`} className="py-1">
                            <button
                              type="button"
                              className="flex w-full items-center gap-1.5 text-left hover:text-accent2"
                              onClick={() => onSelect(otherId)}
                              title={`Focus ${otherId}`}
                            >
                              <span className="min-w-0 flex-1 truncate mono text-2xs text-text">
                                {otherId}
                              </span>
                              <span className="mono text-2xs text-muted">
                                {formatBytes(edge.bytes)}
                              </span>
                            </button>
                            <div className="truncate text-2xs text-faint" title={edge.protocols ?? undefined}>
                              {edge.protocols ?? 'protocols not reported'}
                              {edge.ports.length > 0 ? ` · ports ${edge.ports.join(', ')}` : ''}
                            </div>
                          </li>
                        )
                      })}
                  </ul>
                </div>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

export default NetworkGraph
