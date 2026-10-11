import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { ChevronDown, Info, Layers, X } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import Panel from '@/components/Panel'
import { useThemeTokens } from '@/theme/ThemeProvider'
import type { ThemeTokens } from '@/theme/themes'
import type { Conversation, ConversationState } from '@/types'
import { formatBytes, formatNumber } from '@/utils/format'
import {
  FLOW_COLUMN_LABELS,
  FLOW_COLUMNS,
  FLOW_MAX_SCALE,
  FLOW_MIN_BAND,
  FLOW_MIN_SCALE,
  FLOW_VIEW,
  clampFlowScale,
  flowConversationKey,
  flowFitView,
  formatListWithCount,
  layoutFlow,
  panFlowView,
  planFlowLabels,
  ribbonPath,
  viewToPlot,
  zoomFlowView,
  type FlowBand,
  type FlowColumn,
  type FlowGraph,
  type FlowLabel,
  type FlowNode,
  type FlowPoint,
  type FlowView,
  type PositionedBand,
  type PositionedNode,
} from './flowLayout'



/**
 * State colour, from the active theme. These are labels, not verdicts: the
 * legend always spells the state out in words next to the swatch.
 */
export function stateColour(state: ConversationState, tokens: ThemeTokens): string {
  switch (state) {
    case 'established':
      return tokens.ok
    case 'closed':
      return tokens.muted
    case 'reset':
      return tokens.warn
    case 'half_open':
      return tokens.accent2
    default:
      return tokens.mapUnclassified
  }
}

interface Hover {
  kind: 'node' | 'band'
  id: string
}

export interface ConversationFlowProps {
  /** The five-column graph built from the rows the filter returned. */
  graph: FlowGraph
  /** The same rows, used to open a real conversation when a band is clicked. */
  conversations: Conversation[]
  /** A freshly filtered set is on its way; the drawn one is still the previous. */
  busy?: boolean
  /** The view to start from; `Fit` (the whole diagram) is the default. */
  initialView?: FlowView
  /** Conversation selected through `?stream=`. */
  selectedKey: string | null
  /** Node selected through `?node=`. */
  selectedNodeId: string | null
  onSelectNode: (nodeId: string | null) => void
  /** Expand or collapse one IP group in place. */
  onToggleSubnet: (subnet: string) => void
  /** Open a conversation (sets `?stream=`) so its frames render underneath. */
  onSelectConversation: (conversation: Conversation) => void
  /** Drop the conversation path highlight. */
  onClearPath: () => void
  /** Distinguishes "no conversations at all" from "the filter excluded them". */
  filtered: boolean
  onClearFilters: () => void
}

function BandSwatch({ dashed, label }: { dashed: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1 text-2xs text-muted">
      <svg width="26" height="8" aria-hidden>
        <line
          x1="1"
          y1="4"
          x2="25"
          y2="4"
          stroke="currentColor"
          strokeWidth="3"
          strokeDasharray={dashed ? '6 4' : undefined}
        />
      </svg>
      {label}
    </span>
  )
}

function StateSwatch({ colour, label, detail }: { colour: string; label: string; detail: string }) {
  return (
    <span className="flex items-center gap-1 text-2xs text-muted" title={detail}>
      <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: colour }} />
      {label}
    </span>
  )
}

const FOLD_NOUNS: Record<FlowColumn, string> = {
  source: 'source IP groups',
  sourcePort: 'source ports',
  state: 'states',
  destinationPort: 'destination ports',
  destination: 'destination IP groups',
}

function foldNote(column: FlowColumn, graph: FlowGraph): string | null {
  const meta = graph.meta.columns[column]
  if (!meta || !meta.hasMore) return null
  return (
    formatNumber(meta.shown) +
    ' of ' +
    formatNumber(meta.total) +
    ' ' +
    FOLD_NOUNS[column] +
    ' shown — the rest are folded into one "' +
    String(meta.folded) +
    ' more" node so the spacing never drops below the minimum'
  )
}

function Legend({ graph, tokens, thinnest }: { graph: FlowGraph; tokens: ThemeTokens; thinnest: number }) {
  const thinnestLabel = Number.isFinite(thinnest) ? thinnest.toFixed(1) : 'n/a'
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-border px-3 py-2">
      <BandSwatch dashed={false} label="TCP solid" />
      <BandSwatch dashed={true} label="UDP dashed" />
      <span
        className="text-2xs text-muted"
        title="Five columns: the IP columns group addresses by /24 (IPv4) or /64 (IPv6) so they stay readable; the port columns show every port that appears. Nothing is invented and nothing is dropped."
      >
        source IP → source port → state → destination port → destination IP
      </span>
      <span
        className="text-2xs text-muted"
        title="Band thickness is proportional to the bytes of the conversations it carries, summed across everything that collapses into it. Each layer adds a 1.5 px floor so thin flows stay clickable; a layer carrying more bands than its height can give 1.5 px to is scaled proportionally instead, so thickness always means bytes."
      >
        thickness = bytes · thinnest band here <span className="mono">{thinnestLabel}</span> px (
        <span className="mono">{FLOW_MIN_BAND}</span> px floor)
      </span>
      <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {graph.columns.state.map((node) => (
          <StateSwatch
            key={node.id}
            colour={stateColour(node.state ?? 'unknown', tokens)}
            label={node.label}
            detail={
              formatNumber(node.conversations) +
              ' conversation(s) · ' +
              formatBytes(node.bytes) +
              ' · ' +
              (graph.totals.bytes > 0 ? Math.round((node.bytes / graph.totals.bytes) * 100) : 0) +
              '% of the bytes drawn here'
            }
          />
        ))}
      </span>
      {graph.meta.stackedPairs > 0 ? (
        <span
          className="text-2xs text-muted"
          title="One pair of columns can carry both transports. Such a band is drawn as a solid TCP ribbon stacked with a dashed UDP ribbon rather than blended into one."
        >
          <span className="mono">{graph.meta.stackedPairs}</span> band pair(s) carry both TCP and UDP — solid
          stacked on dashed
        </span>
      ) : null}
      <span className="ml-auto flex items-center gap-1 text-2xs text-faint">
        <Info size={12} aria-hidden />
        drawn only from conversations observed in this capture; unknown is the normal reading for UDP,
        which carries no TCP state to derive
      </span>
    </div>
  )
}

/** Chips for the expanded IP groups and the current selection. */
function SelectionBar({
  graph,
  selectedNode,
  selectedKey,
  onSelectNode,
  onToggleSubnet,
  onSelectKey,
}: {
  graph: FlowGraph
  selectedNode: FlowNode | null
  selectedKey: string | null
  onSelectNode: (nodeId: string | null) => void
  onToggleSubnet: (subnet: string) => void
  onSelectKey: (key: string | null) => void
}) {
  const expanded = graph.meta.expandedSubnets
  if (expanded.length === 0 && selectedNode === null && selectedKey === null) return null
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-1.5">
      {expanded.length > 0 ? (
        <>
          <span className="text-2xs uppercase tracking-wide text-faint">expanded</span>
          {expanded.map((subnet) => (
            <button
              key={subnet}
              type="button"
              className="chip border-border2 bg-surface2 text-text"
              title={`${subnet} is expanded into its individual addresses — click to collapse it`}
              onClick={() => onToggleSubnet(subnet)}
            >
              <ChevronDown size={11} aria-hidden />
              <span>{subnet}</span>
              <X size={11} aria-hidden />
            </button>
          ))}
        </>
      ) : null}
      {selectedNode !== null ? (
        <>
          <span className="text-2xs uppercase tracking-wide text-faint">selection</span>
          <button
            type="button"
            className="chip border-accent/50 bg-accent/10 text-accent2"
            title={`${formatNumber(selectedNode.conversations)} conversation(s) behind this node — click to clear`}
            onClick={() => onSelectNode(null)}
          >
            <Layers size={11} aria-hidden />
            <span>{selectedNode.label}</span>
            <X size={11} aria-hidden />
          </button>
          {selectedNode.expandable ? (
            <span className="text-2xs text-faint">
              click the node again to collapse it, or use the expanded chip above
            </span>
          ) : (
            <span className="text-2xs text-faint">
              the conversations behind it are listed under the diagram
            </span>
          )}
        </>
      ) : null}
      {selectedKey !== null ? (
        <>
          <span className="text-2xs uppercase tracking-wide text-faint">path</span>
          <button
            type="button"
            className="chip border-border2 bg-surface2 text-muted"
            title="the highlighted path follows this conversation — click to clear"
            onClick={() => onSelectKey(null)}
          >
            <span>{selectedKey}</span>
            <X size={11} aria-hidden />
          </button>
        </>
      ) : null}
    </div>
  )
}
/**
 * One label, placed by the engine's collision pass.
 *
 * The font size is in content units but counter-scaled, so a label keeps its
 * size on screen while zooming makes the nodes taller - that is what lets more
 * labels appear as the user zooms in. A label is only drawn when the engine
 * found room for it: a node without one is still hoverable, and its identity
 * still appears in the tooltip and, once selected, in the chip row.
 */
function NodeLabel({
  label,
  node,
  tokens,
  colour,
}: {
  label: FlowLabel
  node: PositionedNode
  tokens: ThemeTokens
  colour: string
}) {
  const mid = label.y + label.height / 2
  const firstBaseline = label.detail ? mid - label.fontSize * 0.1 : mid + label.fontSize * 0.35
  const secondBaseline = mid + label.fontSize * 1.2
  const textX =
    label.anchor === 'start'
      ? label.x
      : label.anchor === 'end'
        ? label.x + label.width
        : label.x + label.width / 2
  /* The bounds are published so the collision invariant is checkable from the
     rendered markup, not just from the plan. */
  const bounds = [label.x, label.y, label.width, label.height]
    .map((value) => Math.round(value * 100) / 100)
    .join(' ')
  return (
    <g data-label={label.nodeId} data-bounds={bounds}>
      {label.halo ? (
        <rect
          x={label.x}
          y={label.y}
          width={label.width}
          height={label.height}
          rx={2}
          fill={tokens.surface}
          fillOpacity={0.85}
        />
      ) : null}
      <text
        x={textX}
        y={firstBaseline}
        textAnchor={label.anchor}
        fontSize={label.fontSize}
        className="mono"
        fill={colour}
      >
        {label.expandable ? <tspan fill={tokens.accent2}>{'+ '}</tspan> : null}
        <tspan>{label.expandable ? label.text.slice(2) : label.text}</tspan>
      </text>
      {label.detail ? (
        <text
          x={textX}
          y={secondBaseline}
          textAnchor={label.anchor}
          fontSize={label.fontSize * 0.9}
          className="mono"
          fill={tokens.muted}
        >
          {formatNumber(node.conversations) + ' conv · ' + formatBytes(node.bytes)}
        </text>
      ) : null}
    </g>
  )
}
interface BandShapeProps {
  band: PositionedBand
  tokens: ThemeTokens
  /** On the hovered path. */
  emphasised: boolean
  /** Something else is emphasised, so this band recedes. */
  dimmed: boolean
  onHover: (hover: Hover | null) => void
  onPick: (band: FlowBand) => void
}

function BandShape({ band, tokens, emphasised, dimmed, onHover, onPick }: BandShapeProps) {
  const colour = stateColour(band.dominantState, tokens)
  const udp = band.transport === 'udp'
  const path = ribbonPath(band)
  const fillOpacity = emphasised ? 0.74 : dimmed ? 0.07 : 0.3
  const strokeOpacity = emphasised ? 0.95 : dimmed ? 0.15 : 0.5
  const hitWidth = Math.min(Math.max(band.thickness + 6, 9), 16)
  return (
    <g onMouseEnter={() => onHover({ kind: 'band', id: band.id })} onMouseLeave={() => onHover(null)}>
      <path
        d={path}
        fill={colour}
        fillOpacity={fillOpacity}
        stroke={colour}
        strokeOpacity={strokeOpacity}
        strokeWidth={udp ? 1 : 1.1}
        strokeDasharray={udp ? '6 4' : undefined}
      />
      <path
        d={path}
        fill="none"
        stroke="transparent"
        strokeWidth={hitWidth}
        pointerEvents="stroke"
        className="cursor-pointer"
        onClick={() => onPick(band)}
      />
    </g>
  )
}

interface NodeShapeProps {
  node: PositionedNode
  tokens: ThemeTokens
  /** The label the collision pass found room for, if any. */
  label?: FlowLabel
  /** This node carries the current selection. */
  selected: boolean
  /** On the hovered path. */
  onPath: boolean
  /** Something else is emphasised, so this node recedes. */
  dimmed: boolean
  onHover: (hover: Hover | null) => void
  onActivate: (node: PositionedNode) => void
}

function NodeShape({
  node,
  tokens,
  label,
  selected,
  onPath,
  dimmed,
  onHover,
  onActivate,
}: NodeShapeProps) {
  const isState = node.column === 'state'
  const colour = isState ? stateColour(node.state ?? 'unknown', tokens) : tokens.muted
  /* Folded remainders are selectable too: their conversations are real, and the
     page resolves a folded node through the graph's own key list. */
  const selectable = node.conversations > 0
  const summary =
    node.label +
    ' (' +
    (node.kind === 'subnet'
      ? node.expandable
        ? 'group of ' + formatNumber(node.memberCount) + ' address(es)'
        : 'the only address seen in ' + (node.subnet ?? 'its group')
      : node.kind === 'more'
        ? 'folded remainder'
        : node.kind === 'port'
          ? 'port'
          : node.kind === 'state'
            ? 'transport state'
            : 'address') +
    '): ' +
    formatNumber(node.conversations) +
    ' conversation(s), ' +
    formatBytes(node.bytes) +
    ', ' +
    formatNumber(node.packets) +
    ' packets' +
    (node.transports.length > 0 ? ', transport ' + node.transports.join(' and ') : '') +
    (node.expandable ? ', click to expand and list its conversations' : '')
  const enter = () => onHover({ kind: 'node', id: node.id })
  const leave = () => onHover(null)
  const stroke = selected ? tokens.accent : onPath ? tokens.accent2 : isState ? colour : tokens.border
  const strokeWidth = selected ? 2 : onPath ? 1.5 : 0.75
  const fillOpacity = isState
    ? onPath || selected
      ? 0.34
      : 0.16
    : dimmed && !onPath && !selected
      ? 0.18
      : onPath || selected
        ? 0.95
        : 0.55
  const hitHeight = Math.max(node.height, FLOW_VIEW.minNodeHeight)

  return (
    <g
      role={selectable ? 'button' : 'img'}
      tabIndex={selectable ? 0 : undefined}
      aria-label={summary}
      aria-pressed={selectable ? selected : undefined}
      className={selectable ? 'cursor-pointer' : undefined}
      onMouseEnter={enter}
      onMouseLeave={leave}
      onFocus={enter}
      onBlur={leave}
      onClick={() => onActivate(node)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onActivate(node)
        }
      }}
    >
      <rect
        x={node.x - 2}
        y={node.y + node.height / 2 - hitHeight / 2}
        width={node.width + 4}
        height={hitHeight}
        fill="transparent"
        pointerEvents="all"
      />
      <rect
        x={node.x}
        y={node.y}
        width={node.width}
        height={node.height}
        rx={isState ? 3 : 2}
        fill={colour}
        fillOpacity={fillOpacity}
        stroke={stroke}
        strokeOpacity={selected || onPath ? 1 : isState ? 0.9 : 0.45}
        strokeWidth={strokeWidth}
        strokeDasharray={node.kind === 'more' ? '3 2' : undefined}
      />
      {label === undefined ? null : (
        <NodeLabel
          label={label}
          node={node}
          tokens={tokens}
          colour={isState || onPath || selected ? tokens.text : tokens.muted}
        />
      )}
    </g>
  )
}
/** Tooltip content for a band: the aggregate of every conversation behind it. */
function BandDetail({ band, graph, tokens }: { band: FlowBand; graph: FlowGraph; tokens: ThemeTokens }) {
  const from = graph.nodes.find((node) => node.id === band.from)
  const to = graph.nodes.find((node) => node.id === band.to)
  return (
    <div className="flex flex-col gap-0.5">
      <div className="text-2xs uppercase tracking-wide text-faint">
        {from ? FLOW_COLUMN_LABELS[from.column] : 'band'} &rarr;{' '}
        {to ? FLOW_COLUMN_LABELS[to.column] : 'band'}
      </div>
      <div className="mono text-2xs text-text">
        {(from?.label ?? band.from) + ' \u2192 ' + (to?.label ?? band.to)}
      </div>
      <div className="text-2xs text-muted">
        {band.conversations === 1
          ? '1 conversation'
          : formatNumber(band.conversations) + ' conversations'}{' '}
        · {formatBytes(band.bytes)} · {formatNumber(band.packets)} packets
      </div>
      <div className="text-2xs text-muted">
        {band.transport.toUpperCase()} {band.transport === 'udp' ? '(dashed)' : '(solid)'}
        {band.states.length > 0 ? ' · state ' + band.states.join(', ') : ''}
      </div>
      <div className="mono mt-1 flex flex-col gap-0.5 border-t border-border pt-1 text-2xs text-faint">
        <span title={band.sourceIps.join('\n')}>
          source IPs {formatListWithCount(band.sourceIps, band.sourceIpCount, 4)}
        </span>
        <span title={band.sourcePorts.join('\n')}>
          source ports {formatListWithCount(band.sourcePorts.map((p) => ':' + String(p)), band.sourcePortCount, 5)}
        </span>
        <span title={band.destinationPorts.join('\n')}>
          destination ports{' '}
          {formatListWithCount(band.destinationPorts.map((p) => ':' + String(p)), band.destinationPortCount, 5)}
        </span>
        <span title={band.destinationIps.join('\n')}>
          destination IPs {formatListWithCount(band.destinationIps, band.destinationIpCount, 4)}
        </span>
      </div>
      <div className="mt-1 border-t border-border pt-1 text-2xs text-faint">
        click to open the largest of these conversations below
      </div>
      <span className="sr-only">{stateColour(band.dominantState, tokens)}</span>
    </div>
  )
}

/** Tooltip content for a node. */
function NodeDetail({ node, graph, tokens }: { node: FlowNode; graph: FlowGraph; tokens: ThemeTokens }) {
  const share = graph.totals.bytes > 0 ? Math.round((node.bytes / graph.totals.bytes) * 100) : 0
  const kind =
    node.kind === 'subnet'
      ? node.expandable
        ? 'group of ' + formatNumber(node.memberCount) + ' address(es)'
        : 'the only address seen in ' + (node.subnet ?? 'its group')
      : node.kind === 'more'
        ? 'folded remainder of ' + formatNumber(node.folded) + ' entities'
        : node.kind === 'port'
          ? 'port'
          : node.kind === 'state'
            ? 'transport state'
            : 'single address'
  return (
    <div className="flex flex-col gap-0.5">
      <div className="text-2xs uppercase tracking-wide text-faint">
        {FLOW_COLUMN_LABELS[node.column]} · {kind}
      </div>
      <div className="mono text-2xs text-text">{node.label}</div>
      <div className="mono text-2xs text-faint">
        {formatBytes(node.bytes)} · {formatNumber(node.packets)} packets ·{' '}
        {formatNumber(node.conversations)} conversation(s) · {share}% of the diagram
      </div>
      <div className="text-2xs text-faint">
        transport{' '}
        {node.transports.length > 0 ? node.transports.map((item) => item.toUpperCase()).join(' + ') : 'none'}
        {node.kind === 'state' ? '' : ' · states present: ' + (node.states.join(', ') || 'none')}
      </div>
      {node.members.length > 1 || (node.members.length === 1 && node.kind !== 'subnet') ? (
        <div className="mono text-2xs text-faint" title={node.members.join('\n')}>
          {node.kind === 'subnet' ? 'addresses' : 'folded'}{' '}
          {formatListWithCount(node.members, node.memberCount, 4)}
        </div>
      ) : null}
      <div className="mt-1 border-t border-border pt-1 text-2xs text-faint">
        {node.kind === 'more'
          ? 'a folded remainder of ' + formatNumber(node.folded) + ' entities — click to list the conversations behind it'
          : node.expandable
            ? 'click to expand this group into its addresses and list its conversations'
            : node.kind === 'subnet'
              ? 'click to list the conversations behind this address below'
              : 'click to list the conversations behind this node below'}
      </div>
      <span className="sr-only">{stateColour(node.state ?? 'unknown', tokens)}</span>
    </div>
  )
}

function Detail({ hover, graph, tokens }: { hover: Hover; graph: FlowGraph; tokens: ThemeTokens }) {
  if (hover.kind === 'band') {
    const band = graph.bands.find((item) => item.id === hover.id)
    return band ? <BandDetail band={band} graph={graph} tokens={tokens} /> : null
  }
  const node = graph.nodes.find((item) => item.id === hover.id)
  return node ? <NodeDetail node={node} graph={graph} tokens={tokens} /> : null
}

function FlowHint() {
  return (
    <div className="text-2xs leading-relaxed text-faint">
      Five stages: source IP, source port, state, destination port, destination IP. Band thickness is the
      bytes behind it, TCP is solid and UDP is dashed. Hover a node or a band to light up its paths;
      click a band to open the largest conversation it carries, or a node to list the conversations
      behind it underneath. A group node marked <span className="mono">+</span> expands into its
      individual addresses.
    </div>
  )
}

/**
 * Five-segment alluvial view of the conversations.
 *
 *   source IP -> source port -> state -> destination port -> destination IP
 *
 * Everything on screen is drawn from the rows matching the current filter, in one
 * request: nothing is invented, node heights and band thicknesses are
 * proportional to the bytes the API reported, and every cap or fold is stated.
 */
export function ConversationFlow({
  graph,
  conversations,
  busy,
  initialView,
  selectedKey,
  selectedNodeId,
  onSelectNode,
  onToggleSubnet,
  onSelectConversation,
  onClearPath,
  filtered,
  onClearFilters,
}: ConversationFlowProps) {
  const tokens = useThemeTokens()
  const [hover, setHover] = useState<Hover | null>(null)

  const layout = useMemo(() => layoutFlow(graph), [graph])
  const nodeById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node] as const)), [graph])
  const conversationByKey = useMemo(
    () => new Map(conversations.map((conversation) => [flowConversationKey(conversation), conversation] as const)),
    [conversations],
  )
  /* Conversation key -> every band that carries it, so hovering one node or band
     can light up the whole route in one lookup. */
  const bandsByKey = useMemo(() => {
    const map = new Map<string, FlowBand[]>()
    for (const band of graph.bands) {
      for (const key of band.keys) {
        const existing = map.get(key)
        if (existing) existing.push(band)
        else map.set(key, [band])
      }
    }
    return map
  }, [graph])

  const emphasis = useMemo(() => {
    const bands = new Set<string>()
    const nodes = new Set<string>()
    const addKeys = (keys: string[]) => {
      for (const key of keys) {
        for (const band of bandsByKey.get(key) ?? []) {
          bands.add(band.id)
          nodes.add(band.from)
          nodes.add(band.to)
        }
      }
    }
    if (hover) {
      const keys =
        hover.kind === 'node'
          ? (nodeById.get(hover.id)?.keys ?? [])
          : (graph.bands.find((band) => band.id === hover.id)?.keys ?? [])
      addKeys(keys)
    } else {
      if (selectedKey !== null) addKeys([selectedKey])
      const selectedNode = selectedNodeId === null ? null : nodeById.get(selectedNodeId)
      if (selectedNode) {
        for (const band of graph.bands) {
          if (band.from === selectedNode.id || band.to === selectedNode.id) {
            bands.add(band.id)
            nodes.add(band.from)
            nodes.add(band.to)
          }
        }
        nodes.add(selectedNode.id)
      }
    }
    return { bands, nodes, active: bands.size > 0 }
  }, [hover, graph, nodeById, bandsByKey, selectedKey, selectedNodeId])

  /* ---- viewport: zoom and pan are a transform, never a re-layout ---------- */
  const svgRef = useRef<SVGSVGElement | null>(null)
  const [view, setView] = useState<FlowView>(() => initialView ?? flowFitView())
  const viewRef = useRef<FlowView>(view)
  const [dragging, setDragging] = useState(false)
  const dragRef = useRef<{ pointerId: number; start: FlowPoint; view: FlowView; moved: boolean } | null>(
    null,
  )
  /* A drag must not also select whatever was under the pointer when it ended. */
  const suppressClick = useRef(false)
  const clipId = 'flow-plot-' + useId().replace(/[^a-zA-Z0-9_-]/g, '')

  /* Which labels fit, at this zoom: a pure function of the layout and the view,
     so the same data and zoom always draw the same labels. */
  const labelPlan = useMemo(() => planFlowLabels(layout, view), [layout, view])
  const labelOf = useMemo(
    () => new Map(labelPlan.labels.map((label) => [label.nodeId, label] as const)),
    [labelPlan],
  )
  const bounds = useMemo(() => ({ width: layout.width, height: layout.plotHeight }), [layout])
  const plotPoint = useCallback(
    (box: FlowPoint): FlowPoint => ({ x: box.x, y: box.y - FLOW_VIEW.headerSpace }),
    [],
  )

  const applyView = useCallback((next: FlowView) => {
    viewRef.current = next
    setView(next)
  }, [])

  const zoomTo = useCallback(
    (scale: number) => {
      const current = viewRef.current
      const centre = { x: layout.width / 2, y: layout.plotHeight / 2 }
      applyView(zoomFlowView(current, scale, centre, bounds))
    },
    [applyView, bounds, layout.plotHeight, layout.width],
  )

  const fit = useCallback(() => applyView(flowFitView()), [applyView])

  /** 100% on screen: one plot unit per CSS pixel, whatever the panel width is. */
  const oneToOne = useCallback(() => {
    const svg = svgRef.current
    const width = svg ? svg.getBoundingClientRect().width : 0
    const scale = width > 0 ? clampFlowScale(FLOW_VIEW.width / width) : 1
    applyView(
      zoomFlowView(viewRef.current, scale, { x: layout.width / 2, y: layout.plotHeight / 2 }, bounds),
    )
  }, [applyView, bounds, layout.plotHeight, layout.width])

  useEffect(() => {
    viewRef.current = view
  }, [view])

  /** The pointer position in the parent viewBox, independent of the transform. */
  const pointerToViewBox = useCallback(
    (svg: SVGSVGElement, clientX: number, clientY: number): FlowPoint | null => {
      const ctm = svg.getScreenCTM()
      if (!ctm) return null
      const point = svg.createSVGPoint()
      point.x = clientX
      point.y = clientY
      const local = point.matrixTransform(ctm.inverse())
      return { x: local.x, y: local.y }
    },
    [],
  )

  /* Wheel zoom is registered natively and non-passively: React's own wheel
     listener is passive, and a zoom that cannot call preventDefault would move
     the page as it zoomed. At either limit nothing is prevented, so the wheel
     scrolls the page normally instead of being swallowed. */
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const onWheel = (event: WheelEvent) => {
      if (event.deltaY === 0) return
      const current = viewRef.current
      const next = clampFlowScale(current.scale * Math.exp(-event.deltaY * 0.0015))
      if (next === current.scale) return
      const box = pointerToViewBox(svg, event.clientX, event.clientY)
      if (box === null) return
      event.preventDefault()
      applyView(zoomFlowView(current, next, viewToPlot(plotPoint(box), current), bounds))
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [applyView, bounds, plotPoint, pointerToViewBox])

  const onPointerDown = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) return
    const box = pointerToViewBox(event.currentTarget, event.clientX, event.clientY)
    if (box === null) return
    suppressClick.current = false
    dragRef.current = { pointerId: event.pointerId, start: box, view: viewRef.current, moved: false }
    event.currentTarget.setPointerCapture(event.pointerId)
  }

  const onPointerMove = (event: React.PointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== event.pointerId) return
    const box = pointerToViewBox(event.currentTarget, event.clientX, event.clientY)
    if (box === null) return
    const dxView = box.x - drag.start.x
    const dyView = box.y - drag.start.y
    if (!drag.moved && Math.hypot(dxView, dyView) * drag.view.scale < 3) return
    if (!drag.moved) {
      drag.moved = true
      setDragging(true)
    }
    applyView(panFlowView(drag.view, dxView / drag.view.scale, dyView / drag.view.scale, bounds))
  }

  const endDrag = (event: React.PointerEvent<SVGSVGElement>) => {
    const drag = dragRef.current
    if (!drag || drag.pointerId !== event.pointerId) return
    if (drag.moved) suppressClick.current = true
    dragRef.current = null
    setDragging(false)
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId)
    }
  }

  /* Selection never reads a screen coordinate: the handlers sit on the shapes,
     so the browser hit-tests the transformed geometry for us. The only thing a
     drag changes here is whether the click that follows it is honoured. */
  const withClickGuard = (action: () => void) => {
    if (suppressClick.current) {
      suppressClick.current = false
      return
    }
    action()
  }

  const onKeyDown = (event: React.KeyboardEvent<SVGSVGElement>) => {
    const step = 40
    const centre = { x: layout.width / 2, y: layout.plotHeight / 2 }
    const current = viewRef.current
    if (event.key === 'ArrowLeft') applyView(panFlowView(current, step, 0, bounds))
    else if (event.key === 'ArrowRight') applyView(panFlowView(current, -step, 0, bounds))
    else if (event.key === 'ArrowUp') applyView(panFlowView(current, 0, step, bounds))
    else if (event.key === 'ArrowDown') applyView(panFlowView(current, 0, -step, bounds))
    else if (event.key === '+' || event.key === '=')
      applyView(zoomFlowView(current, current.scale * 1.25, centre, bounds))
    else if (event.key === '-' || event.key === '_')
      applyView(zoomFlowView(current, current.scale / 1.25, centre, bounds))
    else if (event.key === '0') applyView(flowFitView())
    else return
    event.preventDefault()
  }

  const meta = graph.meta
  const foldNotes = FLOW_COLUMNS.map((column) => foldNote(column, graph)).filter(
    (note): note is string => note !== null,
  )
  const zoomPercent = Math.round(view.scale * 100)
  const tallest = layout.summaries.reduce((max, summary) => Math.max(max, summary.totalHeight), 0)
  const tallestShare = layout.plotHeight > 0 ? Math.round((tallest / layout.plotHeight) * 100) : 0
  const viewTransform = 'translate(' + view.x + ',' + view.y + ') scale(' + view.scale + ')'

  if (graph.totals.conversations === 0) {
    return (
      <EmptyState
        title={filtered ? 'No conversations match the current filters' : 'No conversations in this capture'}
        description={
          filtered
            ? 'The flow diagram only draws conversations that pass the toolbar filters above. Clear or widen them to see the capture again.'
            : 'No conversation was reconstructed from this capture, so there is nothing to draw. This is not an error.'
        }
        action={
          filtered ? (
            <button type="button" className="btn" onClick={onClearFilters}>
              Reset filters
            </button>
          ) : undefined
        }
      />
    )
  }

  /** The band stands for many conversations, so it opens the largest of them. */
  const openLargest = (band: FlowBand) => {
    let largest: Conversation | null = null
    for (const key of band.keys) {
      const conversation = conversationByKey.get(key)
      if (!conversation) continue
      if (largest === null || conversation.bytes_total > largest.bytes_total) largest = conversation
    }
    if (largest !== null) onSelectConversation(largest)
  }

  const activateNode = (node: PositionedNode) => {
    const isSelected = selectedNodeId === node.id
    onSelectNode(isSelected ? null : node.id)
    /* Only a group that really holds several addresses is worth expanding: a
       single-host group is already showing its address. */
    if (node.expandable && node.subnet !== null) onToggleSubnet(node.subnet)
  }

  const thinnest = layout.bands.reduce(
    (minimum, band) => Math.min(minimum, band.thickness),
    Number.POSITIVE_INFINITY,
  )

  const columnNoun = (column: FlowColumn): string => {
    const nodes = graph.columns[column]
    if (column === 'sourcePort' || column === 'destinationPort') return 'ports'
    if (column === 'state') return 'states'
    return nodes.some((node) => node.expandable) ? 'groups' : 'IPs'
  }

  const summary = FLOW_COLUMNS.map(
    (column) => formatNumber(graph.columns[column].length) + ' ' + columnNoun(column),
  ).join(' · ')

  return (
    <Panel
      flush
      title="Conversation flow"
      subtitle={
        meta.conversationCapped
          ? `showing the top ${formatNumber(meta.usedConversations)} of ${formatNumber(meta.filteredTotal)} conversations by bytes · ${summary}`
          : `${formatNumber(graph.totals.conversations)} conversations · ${summary} · ${formatBytes(graph.totals.bytes)}`
      }
      actions={
        <span className="text-2xs text-faint">
          {busy ? 'updating the diagram...' : 'click a band for its conversation, a node for its list'}
        </span>
      }
    >
      <Legend graph={graph} tokens={tokens} thinnest={thinnest} />
      <SelectionBar
        graph={graph}
        selectedNode={selectedNodeId === null ? null : (nodeById.get(selectedNodeId) ?? null)}
        selectedKey={selectedKey}
        onSelectNode={onSelectNode}
        onToggleSubnet={onToggleSubnet}
        onSelectKey={onClearPath}
      />

      <div className="flex flex-wrap items-center gap-1 border-b border-border px-3 py-1.5">
        <button
          type="button"
          className="btn px-2 py-1"
          aria-label="Zoom in"
          title="Zoom in (+)"
          onClick={() => zoomTo(view.scale * 1.25)}
          disabled={view.scale >= FLOW_MAX_SCALE}
        >
          +
        </button>
        <button
          type="button"
          className="btn px-2 py-1"
          aria-label="Zoom out"
          title="Zoom out (-)"
          onClick={() => zoomTo(view.scale / 1.25)}
          disabled={view.scale <= FLOW_MIN_SCALE}
        >
          −
        </button>
        <button
          type="button"
          className="btn px-2 py-1"
          aria-label="Fit diagram to view"
          title="Fit the whole diagram (0)"
          onClick={fit}
        >
          Fit
        </button>
        <button
          type="button"
          className="btn px-2 py-1"
          aria-label="Zoom to actual size"
          title="100%: one diagram unit per screen pixel"
          onClick={oneToOne}
        >
          1:1
        </button>
        <span
          className="mono ml-1 text-2xs text-muted"
          role="status"
          aria-live="polite"
          aria-label={'Zoom ' + String(zoomPercent) + ' percent'}
        >
          {String(zoomPercent) + '%'}
        </span>
        {labelPlan.suppressed > 0 ? (
          <span className="text-2xs text-muted">
            labels shown for the largest <span className="mono">{formatNumber(labelPlan.shown)}</span>{' '}
            nodes — zoom in to reveal the rest (every node still has its tooltip)
          </span>
        ) : null}
        <span className="ml-auto text-2xs text-faint">
          drag to pan · wheel to zoom · arrows pan, +/− zoom, 0 fits
        </span>
      </div>

      <div className="relative">
        <svg
          ref={svgRef}
          viewBox={'0 0 ' + String(layout.width) + ' ' + String(FLOW_VIEW.height)}
          className={
            'h-[30rem] w-full touch-none ' + (dragging ? 'cursor-grabbing' : 'cursor-grab')
          }
          role="img"
          tabIndex={0}
          aria-label={
            'Five column alluvial diagram of ' +
            String(graph.totals.conversations) +
            ' conversations: source IP, source port, transport state, destination port and destination IP; band thickness is proportional to bytes. Drag to pan, wheel to zoom, arrow keys to pan, plus and minus to zoom, zero to fit.'
          }
          onMouseLeave={() => setHover(null)}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          onKeyDown={onKeyDown}
        >
          <defs>
            <clipPath id={clipId}>
              <rect x={0} y={FLOW_VIEW.headerSpace} width={layout.width} height={layout.plotHeight} />
            </clipPath>
          </defs>
          <g aria-hidden>
            {layout.boxes.map((box) => (
              <text
                key={box.column}
                x={box.column === 'source' ? box.centreX - 6 : box.column === 'destination' ? box.centreX + 6 : box.centreX}
                y={14}
                textAnchor={box.column === 'source' ? 'end' : box.column === 'destination' ? 'start' : 'middle'}
                fontSize={10}
                fill={tokens.faint}
                letterSpacing="0.09em"
              >
                {FLOW_COLUMN_LABELS[box.column]}
              </text>
            ))}
          </g>
          {/* Everything plotted lives inside one transform group, so zoom and pan
              are a pure viewport change and the browser hit-tests the moved
              shapes. The headings stay outside it, and outside the clip. */}
          <g clipPath={'url(#' + clipId + ')'}>
            <g transform={'translate(0,' + String(FLOW_VIEW.headerSpace) + ')'}>
              <g transform={viewTransform}>
                {layout.bands.map((band) => (
                  <BandShape
                    key={band.id}
                    band={band}
                    tokens={tokens}
                    emphasised={emphasis.bands.has(band.id)}
                    dimmed={emphasis.active}
                    onHover={setHover}
                    onPick={(picked) => withClickGuard(() => openLargest(picked))}
                  />
                ))}
                {layout.nodes.map((node) => (
                  <NodeShape
                    key={node.id}
                    node={node}
                    tokens={tokens}
                    label={labelOf.get(node.id)}
                    selected={selectedNodeId === node.id}
                    onPath={emphasis.nodes.has(node.id)}
                    dimmed={emphasis.active}
                    onHover={setHover}
                    onActivate={(activated) => withClickGuard(() => activateNode(activated))}
                  />
                ))}
              </g>
            </g>
          </g>
        </svg>

        <div className="pointer-events-none absolute bottom-2 right-2 max-w-[22rem] rounded border border-border bg-surface/95 px-2.5 py-1.5">
          {hover ? <Detail hover={hover} graph={graph} tokens={tokens} /> : <FlowHint />}
        </div>
      </div>

      {foldNotes.length > 0 ? (
        <div className="flex flex-col gap-0.5 border-t border-border px-3 py-1.5 text-2xs text-faint">
          {foldNotes.map((note) => (
            <span key={note}>{note}</span>
          ))}
        </div>
      ) : null}
      {meta.mixedPaths > 0 ? (
        <div className="border-t border-border px-3 py-1.5 text-2xs text-faint">
          <span className="mono">{formatNumber(meta.mixedPaths)}</span> complete path(s) carry both TCP and
          UDP between the same five nodes — each is drawn as a solid ribbon stacked on a dashed one.
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 border-t border-border px-3 py-1.5 text-2xs text-faint">
        <span>
          {formatNumber(meta.nodeBudget)} node slots per column at this panel height ({formatNumber(meta.ipNodeBudget)}{' '}
          for the two IP columns, which are grouped by subnet and would otherwise grow through node count
          rather than bytes); the tallest column uses {String(tallestShare)}% of the plot. A column that
          carries more entities than its budget folds its smallest into one labelled node, never squashing
          the spacing.
        </span>
        <span className="mono">
          {layout.summaries
            .map((summary) => summary.column + ' ' + String(summary.nodeCount))
            .join(' · ')}
        </span>
      </div>
    </Panel>
  )
}

export default ConversationFlow