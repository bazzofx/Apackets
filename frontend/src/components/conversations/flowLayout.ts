import type { Conversation, ConversationState, Transport } from '@/types'

/**
 * Five-segment alluvial model for the conversations view.
 *
 *   source IP -> source port -> state -> destination port -> destination IP
 *
 * All five columns come from one pass over the conversation rows, so a band in
 * any layer stands for the conversations that really took that route. Nothing is
 * invented and nothing is dropped: entities that cannot be drawn inside the
 * vertical budget are folded into a labelled "N more" node and the fold is
 * reported, and every count, byte and packet is a sum over real rows.
 *
 * The engine is pure: no clock, no randomness, no re-sorting on re-render.
 * Identical input (rows plus the expanded-subnet set) always produces
 * byte-identical output, and the order in which rows arrive never matters.
 */

/* ------------------------------------------------------------------ */
/* view geometry                                                       */
/* ------------------------------------------------------------------ */

/**
 * The viewBox the diagram is drawn in. The SVG scales to its container, so the
 * five columns always fit the panel width without horizontal scrolling.
 */
export const FLOW_VIEW = {
  width: 1200,
  height: 520,
  /** Room for the column headings. */
  headerSpace: 22,
  /** Vertical space between two nodes of a column. */
  gap: 4,
  /**
   * Smallest slot a column budgets for a node. It is deliberately a little
   * taller than one label line (13 px on screen), so a node that fills its slot
   * can always carry its own label; spacing is never squashed below that to fit
   * more nodes in, and a column that cannot fit its entities folds them instead.
   */
  minNodeHeight: 14,
  /** Width of an address or port bar, and of the labelled state box. */
  nodeWidth: 11,
  stateWidth: 80,
  /** Room reserved for the outer column labels. */
  gutter: 170,
}

/**
 * How many node slots one column can hold: the port columns can hold far more
 * entities than the panel is tall, so each column is capped to this budget and
 * the tail is folded rather than the spacing squashed.
 */
export function flowNodeBudget(
  height: number = FLOW_VIEW.height - FLOW_VIEW.headerSpace,
  gap: number = FLOW_VIEW.gap,
  minNodeHeight: number = FLOW_VIEW.minNodeHeight,
): number {
  return Math.max(2, Math.floor((height + gap) / (minNodeHeight + gap)))
}

/**
 * Tighter budget for the IP columns.
 *
 * Every column carries the same total bytes, so a column only grows taller than
 * its neighbours through node count: each node adds a minimum height plus a gap.
 * The IP columns are already grouped by subnet, so a long list of addresses adds
 * height without adding information - and an address column that fills the panel
 * reads as a wall of labels instead of a flow. Ports are individual facts and
 * keep the full budget; the IP columns fold sooner, and what they fold is
 * reported and stays reachable through the "N more" node.
 */
export function flowIpNodeBudget(budget: number = flowNodeBudget()): number {
  return Math.max(4, Math.floor(budget / 2))
}

/** The budget a given column is allowed, given the shared node budget. */
export function flowColumnBudget(column: FlowColumn, budget: number): number {
  return column === 'source' || column === 'destination' ? Math.min(budget, flowIpNodeBudget(budget)) : budget
}

/* ------------------------------------------------------------------ */
/* vocabulary                                                          */
/* ------------------------------------------------------------------ */

export type FlowColumn = 'source' | 'sourcePort' | 'state' | 'destinationPort' | 'destination'

/** Left to right, the order the columns are drawn and stacked in. */
export const FLOW_COLUMNS: readonly FlowColumn[] = [
  'source',
  'sourcePort',
  'state',
  'destinationPort',
  'destination',
]

export const FLOW_COLUMN_LABELS: Record<FlowColumn, string> = {
  source: 'SOURCE IP',
  sourcePort: 'SOURCE PORT',
  state: 'STATE',
  destinationPort: 'DESTINATION PORT',
  destination: 'DESTINATION IP',
}

export const FLOW_STATE_ORDER: readonly ConversationState[] = [
  'established',
  'closed',
  'reset',
  'half_open',
  'unknown',
]

export const FLOW_TRANSPORT_ORDER: readonly Transport[] = ['tcp', 'udp']

/** Node id namespace, so a subnet, an address, a port and a state never collide. */
export function flowNodeId(column: FlowColumn, key: string): string {
  return column + ':' + key
}

/* ------------------------------------------------------------------ */
/* row identity                                                        */
/* ------------------------------------------------------------------ */

/** The IP a conversation's A or B side belongs to, falling back to `ip:port`. */
export function flowAddress(conversation: Conversation, side: 'a' | 'b'): string {
  const ip = side === 'a' ? conversation.ip_a : conversation.ip_b
  if (typeof ip === 'string' && ip.trim() !== '') return ip.trim()
  const endpoint = (side === 'a' ? conversation.endpoint_a : conversation.endpoint_b) ?? ''
  const separator = endpoint.lastIndexOf(':')
  if (separator > 0 && endpoint.indexOf(':') === separator) return endpoint.slice(0, separator)
  return endpoint.trim() === '' ? '(unknown address)' : endpoint.trim()
}

/** The port of one side, or null when the row does not carry one. */
export function flowPort(conversation: Conversation, side: 'a' | 'b'): number | null {
  const port = side === 'a' ? conversation.port_a : conversation.port_b
  if (typeof port === 'number' && Number.isFinite(port)) return port
  const endpoint = (side === 'a' ? conversation.endpoint_a : conversation.endpoint_b) ?? ''
  const separator = endpoint.lastIndexOf(':')
  if (separator <= 0 || endpoint.indexOf(':') !== separator) return null
  const parsed = Number(endpoint.slice(separator + 1))
  return Number.isFinite(parsed) ? parsed : null
}

/** Stable identity of a conversation: transport plus stream id. */
export function flowConversationKey(conversation: Conversation): string {
  return conversation.transport + ':' + String(conversation.stream_id)
}

/* ------------------------------------------------------------------ */
/* subnets                                                             */
/* ------------------------------------------------------------------ */

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function ipv6Hextets(address: string): number[] | null {
  const text = address.trim().toLowerCase()
  if (text.indexOf(':') === -1) return null
  const halves = text.split('::')
  if (halves.length > 2) return null
  const parse = (part: string): number[] | null => {
    if (part === '') return []
    const groups = part.split(':')
    const values: number[] = []
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null
      values.push(parseInt(group, 16))
    }
    return values
  }
  const head = parse(halves[0])
  if (head === null) return null
  if (halves.length === 1) return head.length === 8 ? head : null
  const tail = parse(halves[1])
  if (tail === null) return null
  const missing = 8 - head.length - tail.length
  if (missing < 1) return null
  return head.concat(new Array(missing).fill(0), tail)
}

function formatIpv6Prefix(hextets: number[]): string {
  if (hextets.every((value) => value === 0)) return '::'
  const groups = hextets.map((value) => value.toString(16))
  let lastNonZero = groups.length - 1
  while (lastNonZero > 0 && groups[lastNonZero] === '0') lastNonZero -= 1
  const kept = groups.slice(0, lastNonZero + 1)
  return kept.join(':') + (lastNonZero === groups.length - 1 ? ':' : '::')
}

/**
 * The group an address belongs to: its `/24` for IPv4, its `/64` for IPv6.
 *
 * An address that cannot be parsed groups as itself, so an unusual row appears
 * in the diagram under its own name instead of vanishing.
 */
export function subnetOf(address: string): string {
  const text = address.trim()
  const ipv4 = IPV4.exec(text)
  if (ipv4) {
    const octets = [ipv4[1], ipv4[2], ipv4[3]].map((part) => String(Number(part)))
    return octets.join('.') + '.0/24'
  }
  const hextets = ipv6Hextets(text)
  if (hextets) return formatIpv6Prefix(hextets.slice(0, 4)) + '/64'
  return text
}

/** True when a grouping key is a subnetwork rather than a single address. */
export function isSubnetKey(key: string): boolean {
  return key.indexOf('/') !== -1
}
/* ------------------------------------------------------------------ */
/* graph                                                              */
/* ------------------------------------------------------------------ */

/** Distinct values a tooltip may name before it starts counting instead. */
export const FLOW_DETAIL_LIMIT = 24

export interface FlowNode {
  id: string
  column: FlowColumn
  kind: 'subnet' | 'address' | 'port' | 'state' | 'more'
  /** As drawn: a CIDR, an address, `:443`, a state name, or `12 more`. */
  label: string
  /** The `/24` or `/64` this node belongs to; null for ports, states and folds. */
  subnet: string | null
  ip: string | null
  port: number | null
  state: ConversationState | null
  bytes: number
  packets: number
  conversations: number
  /** Conversation keys behind this node, sorted. */
  keys: string[]
  /** Addresses (subnet node) or folded labels (more node) behind this node. */
  members: string[]
  /** How many members there really are, when `members` is capped. */
  memberCount: number
  transports: Transport[]
  states: ConversationState[]
  /** Real entities folded into this node: 1 means it is a single entity. */
  folded: number
  /**
   * True when clicking this node expands it in place, which is only honest for a
   * group that holds two or more observed addresses: a `/24` with a single host
   * *is* that host, so expanding it would change nothing visible.
   */
  expandable: boolean
}

export interface FlowBand {
  /** `layer|from|to|transport`. */
  id: string
  /** 0..3, from the left. */
  layer: number
  from: string
  to: string
  /**
   * Exactly one transport: a band is never a blend, so a pair carrying both TCP
   * and UDP is drawn as two stacked ribbons, one solid and one dashed.
   */
  transport: Transport
  bytes: number
  packets: number
  conversations: number
  /** Conversation keys behind this band, sorted. */
  keys: string[]
  sourceIps: string[]
  sourceIpCount: number
  sourcePorts: number[]
  sourcePortCount: number
  destinationPorts: number[]
  destinationPortCount: number
  destinationIps: string[]
  destinationIpCount: number
  states: ConversationState[]
  /** The state most of this band's bytes are in: its colour. */
  dominantState: ConversationState
}

export interface FlowColumnMeta {
  /** Entities that appeared in the rows this graph was built from. */
  total: number
  /** Entities drawn as their own node. */
  shown: number
  /** Entities folded into the "more" node. */
  folded: number
  /** Conversations behind the folded entities. */
  foldedConversations: number
  /** True when a labelled "N more" node exists in this column. */
  hasMore: boolean
}

export interface FlowGraph {
  nodes: FlowNode[]
  columns: Record<FlowColumn, FlowNode[]>
  bands: FlowBand[]
  /** Bands grouped by layer, left to right. */
  layers: FlowBand[][]
  totals: { conversations: number; bytes: number; packets: number }
  meta: {
    /** Conversations matching the current filter, per the API envelope. */
    filteredTotal: number
    /** Rows actually fed into the diagram. */
    usedConversations: number
    conversationCap: number
    conversationCapped: boolean
    nodeBudget: number
    /** The tighter budget the two IP columns were capped to. */
    ipNodeBudget: number
    expandedSubnets: string[]
    columns: Record<FlowColumn, FlowColumnMeta>
    /** (layer, from, to) pairs carrying both transports: stacked ribbons. */
    stackedPairs: number
    /** Whole five-stage paths carrying both transports. */
    mixedPaths: number
  }
}

export interface BuildFlowOptions {
  /** Subnets drawn as their individual addresses instead of one group node. */
  expandedSubnets?: Iterable<string>
  /** Node slots per column; defaults to what the view height can hold. */
  nodeBudget?: number
  /** Node slots for the two IP columns; defaults to the tighter IP budget. */
  ipNodeBudget?: number
  /** Conversations matching the filter (may exceed the rows given). */
  filteredTotal?: number
  /** Rows the caller fetched; used to report the cap honestly. */
  rowsFetched?: number
}

interface RawGroup {
  key: string
  label: string
  kind: FlowNode['kind']
  subnet: string | null
  ip: string | null
  port: number | null
  state: ConversationState | null
  rows: Conversation[]
}

function limit<T>(values: T[]): { list: T[]; count: number } {
  return { list: values.slice(0, FLOW_DETAIL_LIMIT), count: values.length }
}

function compareLabels(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function sumBytes(rows: Conversation[]): number {
  return rows.reduce((total, row) => total + (row.bytes_total || 0), 0)
}

function sumPackets(rows: Conversation[]): number {
  return rows.reduce((total, row) => total + (row.packets_total || 0), 0)
}

function transportsOf(rows: Conversation[]): Transport[] {
  const found: Transport[] = []
  for (const row of rows) if (!found.includes(row.transport)) found.push(row.transport)
  return found.sort((a, b) => FLOW_TRANSPORT_ORDER.indexOf(a) - FLOW_TRANSPORT_ORDER.indexOf(b))
}

function statesOf(rows: Conversation[]): ConversationState[] {
  const found: ConversationState[] = []
  for (const row of rows) if (!found.includes(row.state)) found.push(row.state)
  return found.sort((a, b) => FLOW_STATE_ORDER.indexOf(a) - FLOW_STATE_ORDER.indexOf(b))
}

function distinctSorted(values: string[]): { list: string[]; count: number } {
  return limit([...new Set(values)].sort(compareLabels))
}

function portKey(port: number | null): string {
  return port === null ? 'unknown' : String(port)
}

function portLabel(port: number | null): string {
  return port === null ? 'unknown' : ':' + String(port)
}

/** Group the rows for one column, before any folding. */
function columnGroups(
  column: FlowColumn,
  rows: Conversation[],
  expanded: Set<string>,
): RawGroup[] {
  const groups = new Map<string, Conversation[]>()
  const meta = new Map<string, RawGroup>()
  for (const row of rows) {
    let group: RawGroup
    if (column === 'source' || column === 'destination') {
      const side = column === 'source' ? 'a' : 'b'
      const address = flowAddress(row, side)
      const subnet = subnetOf(address)
      const useSubnet = !expanded.has(subnet)
      const key = useSubnet ? subnet : address
      group = {
        key,
        label: key,
        kind: useSubnet ? 'subnet' : 'address',
        subnet,
        ip: useSubnet ? null : address,
        port: null,
        state: null,
        rows: [],
      }
    } else if (column === 'sourcePort' || column === 'destinationPort') {
      const side = column === 'sourcePort' ? 'a' : 'b'
      const port = flowPort(row, side)
      group = {
        key: portKey(port),
        label: portLabel(port),
        kind: 'port',
        subnet: null,
        ip: null,
        port,
        state: null,
        rows: [],
      }
    } else {
      group = {
        key: row.state,
        label: row.state,
        kind: 'state',
        subnet: null,
        ip: null,
        port: null,
        state: row.state,
        rows: [],
      }
    }
    const existing = groups.get(group.key)
    if (existing) existing.push(row)
    else {
      groups.set(group.key, [row])
      meta.set(group.key, group)
    }
  }
  const out: RawGroup[] = []
  for (const [key, groupRows] of groups) {
    const base = meta.get(key)
    if (base) out.push({ ...base, rows: groupRows })
  }
  out.sort((left, right) => {
    const byteDiff = sumBytes(right.rows) - sumBytes(left.rows)
    if (byteDiff !== 0) return byteDiff
    if (left.port !== null && right.port !== null && left.port !== right.port) return left.port - right.port
    return compareLabels(left.label, right.label)
  })
  return out
}

function toNode(column: FlowColumn, group: RawGroup): FlowNode {
  const members =
    group.kind === 'subnet'
      ? [...new Set(group.rows.map((row) => flowAddress(row, column === 'source' ? 'a' : 'b')))].sort(compareLabels)
      : []
  const memberDetail = limit(members)
  /* A group holding exactly one observed address is that address: labelling it
     `10.4.10.0/24` would hide the only host behind a click that reveals nothing,
     and the user asked to see the unique IPs. The subnet is kept on the node, so
     the tooltip can still say where the address came from. */
  const singleHost = group.kind === 'subnet' && members.length === 1
  const expandable = group.kind === 'subnet' && members.length > 1
  return {
    id: flowNodeId(column, group.key),
    column,
    kind: group.kind,
    label: singleHost ? members[0] : group.label,
    subnet: group.subnet,
    ip: singleHost ? members[0] : group.ip,
    port: group.port,
    state: group.state,
    bytes: sumBytes(group.rows),
    packets: sumPackets(group.rows),
    conversations: group.rows.length,
    keys: group.rows.map(flowConversationKey).sort(compareLabels),
    members: memberDetail.list,
    memberCount: memberDetail.count,
    transports: transportsOf(group.rows),
    states: statesOf(group.rows),
    folded: 1,
    expandable,
  }
}

function toMoreNode(column: FlowColumn, folded: RawGroup[]): FlowNode {
  const rows = folded.flatMap((group) => group.rows)
  const labels = folded.map((group) => group.label).sort(compareLabels)
  const memberDetail = limit(labels)
  return {
    id: flowNodeId(column, '__more__'),
    column,
    kind: 'more',
    label: String(folded.length) + ' more',
    subnet: null,
    ip: null,
    port: null,
    state: null,
    bytes: sumBytes(rows),
    packets: sumPackets(rows),
    conversations: rows.length,
    keys: rows.map(flowConversationKey).sort(compareLabels),
    members: memberDetail.list,
    memberCount: memberDetail.count,
    transports: transportsOf(rows),
    states: statesOf(rows),
    folded: folded.length,
    expandable: false,
  }
}

function bandFrom(layer: number, from: string, to: string, transport: Transport, rows: Conversation[]): FlowBand {
  const sourceIps = distinctSorted(rows.map((row) => flowAddress(row, 'a')))
  const sourcePorts = limit([...new Set(rows.map((row) => flowPort(row, 'a')).filter((port): port is number => port !== null))].sort((a, b) => a - b))
  const destinationPorts = limit([...new Set(rows.map((row) => flowPort(row, 'b')).filter((port): port is number => port !== null))].sort((a, b) => a - b))
  const destinationIps = distinctSorted(rows.map((row) => flowAddress(row, 'b')))
  return {
    id: layer + '|' + from + '|' + to + '|' + transport,
    layer,
    from,
    to,
    transport,
    bytes: sumBytes(rows),
    packets: sumPackets(rows),
    conversations: rows.length,
    keys: rows.map(flowConversationKey).sort(compareLabels),
    sourceIps: sourceIps.list,
    sourceIpCount: sourceIps.count,
    sourcePorts: sourcePorts.list,
    sourcePortCount: sourcePorts.count,
    destinationPorts: destinationPorts.list,
    destinationPortCount: destinationPorts.count,
    destinationIps: destinationIps.list,
    destinationIpCount: destinationIps.count,
    states: statesOf(rows),
    dominantState: dominantStateOf(rows),
  }
}

/** The state with the most bytes behind it; ties follow the fixed state order. */
function dominantStateOf(rows: Conversation[]): ConversationState {
  const totals = new Map<ConversationState, number>()
  for (const row of rows) totals.set(row.state, (totals.get(row.state) ?? 0) + (row.bytes_total || 0))
  let best: ConversationState = rows[0]?.state ?? 'unknown'
  let bestBytes = -1
  for (const state of FLOW_STATE_ORDER) {
    const bytes = totals.get(state)
    if (bytes === undefined) continue
    if (bytes > bestBytes) {
      best = state
      bestBytes = bytes
    }
  }
  return best
}

/**
 * Build the five columns, the bands and the fold accounting from real rows.
 *
 * Every row lands in exactly one node of every column and in exactly one band of
 * every layer, so each layer carries every conversation exactly once and the
 * sums are checkable. Entities that do not fit a column's vertical budget are
 * folded into one labelled node instead of being dropped or squashed.
 */
export function buildFlowGraph(rows: Conversation[], options: BuildFlowOptions = {}): FlowGraph {
  const budget = Math.max(2, options.nodeBudget ?? flowNodeBudget())
  const ipBudget = Math.max(2, options.ipNodeBudget ?? flowIpNodeBudget(budget))
  const expanded = new Set<string>(options.expandedSubnets ?? [])
  const rowsFetched = options.rowsFetched ?? rows.length
  const filteredTotal = options.filteredTotal ?? rows.length

  const nodeOf: Record<FlowColumn, Map<string, string>> = {
    source: new Map(),
    sourcePort: new Map(),
    state: new Map(),
    destinationPort: new Map(),
    destination: new Map(),
  }
  const columns: Record<FlowColumn, FlowNode[]> = {
    source: [],
    sourcePort: [],
    state: [],
    destinationPort: [],
    destination: [],
  }
  const columnMeta: Record<FlowColumn, FlowColumnMeta> = {
    source: { total: 0, shown: 0, folded: 0, foldedConversations: 0, hasMore: false },
    sourcePort: { total: 0, shown: 0, folded: 0, foldedConversations: 0, hasMore: false },
    state: { total: 0, shown: 0, folded: 0, foldedConversations: 0, hasMore: false },
    destinationPort: { total: 0, shown: 0, folded: 0, foldedConversations: 0, hasMore: false },
    destination: { total: 0, shown: 0, folded: 0, foldedConversations: 0, hasMore: false },
  }

  for (const column of FLOW_COLUMNS) {
    const columnBudget = flowColumnBudget(column, budget) === budget ? budget : ipBudget
    const groups = columnGroups(column, rows, expanded)
    const kept = groups.length > columnBudget ? groups.slice(0, columnBudget - 1) : groups
    const foldedGroups = groups.length > columnBudget ? groups.slice(columnBudget - 1) : []
    for (const group of kept) {
      const node = toNode(column, group)
      columns[column].push(node)
      for (const row of group.rows) nodeOf[column].set(flowConversationKey(row), node.id)
    }
    if (foldedGroups.length > 0) {
      const node = toMoreNode(column, foldedGroups)
      columns[column].push(node)
      for (const group of foldedGroups) {
        for (const row of group.rows) nodeOf[column].set(flowConversationKey(row), node.id)
      }
    }
    columnMeta[column] = {
      total: groups.length,
      shown: kept.length,
      folded: foldedGroups.length,
      foldedConversations: foldedGroups.reduce((total, group) => total + group.rows.length, 0),
      hasMore: foldedGroups.length > 0,
    }
  }

  const buckets = new Map<string, { layer: number; from: string; to: string; transport: Transport; rows: Conversation[] }>()
  const pairTransports = new Map<string, Set<Transport>>()
  const pathTransports = new Map<string, Set<Transport>>()
  for (let layer = 0; layer < FLOW_COLUMNS.length - 1; layer += 1) {
    const fromColumn = FLOW_COLUMNS[layer]
    const toColumn = FLOW_COLUMNS[layer + 1]
    for (const row of rows) {
      const key = flowConversationKey(row)
      const from = nodeOf[fromColumn].get(key)
      const to = nodeOf[toColumn].get(key)
      if (!from || !to) continue
      const id = layer + '|' + from + '|' + to + '|' + row.transport
      const existing = buckets.get(id)
      if (existing) existing.rows.push(row)
      else buckets.set(id, { layer, from, to, transport: row.transport, rows: [row] })
      const pairId = layer + '|' + from + '|' + to
      const seen = pairTransports.get(pairId)
      if (seen) seen.add(row.transport)
      else pairTransports.set(pairId, new Set([row.transport]))
      const pathKey = FLOW_COLUMNS.map((column) => nodeOf[column].get(key)).join('|')
      const pathSeen = pathTransports.get(pathKey)
      if (pathSeen) pathSeen.add(row.transport)
      else pathTransports.set(pathKey, new Set([row.transport]))
    }
  }

  const layers: FlowBand[][] = FLOW_COLUMNS.slice(0, -1).map(() => [])
  const bands: FlowBand[] = []
  for (const bucket of buckets.values()) {
    const band = bandFrom(bucket.layer, bucket.from, bucket.to, bucket.transport, bucket.rows)
    bands.push(band)
    layers[bucket.layer].push(band)
  }
  bands.sort((a, b) => (a.layer !== b.layer ? a.layer - b.layer : compareLabels(a.id, b.id)))
  for (const layer of layers) layer.sort((a, b) => compareLabels(a.id, b.id))

  let stackedPairs = 0
  for (const transports of pairTransports.values()) if (transports.size > 1) stackedPairs += 1
  let mixedPaths = 0
  for (const transports of pathTransports.values()) if (transports.size > 1) mixedPaths += 1

  return {
    nodes: FLOW_COLUMNS.flatMap((column) => columns[column]),
    columns,
    bands,
    layers,
    totals: {
      conversations: rows.length,
      bytes: sumBytes(rows),
      packets: sumPackets(rows),
    },
    meta: {
      filteredTotal,
      usedConversations: rows.length,
      conversationCap: 1000,
      conversationCapped: filteredTotal > rowsFetched,
      nodeBudget: budget,
      ipNodeBudget: ipBudget,
      expandedSubnets: [...expanded].sort(compareLabels),
      columns: columnMeta,
      stackedPairs,
      mixedPaths,
    },
  }
}
/**
 * Does one conversation belong to a node id chosen in the diagram?
 *
 * This is how a selection stored in the URL is turned back into rows: it works
 * for a group (`source:192.168.8.0/24`), a single address, a port, a state and a
 * folded remainder alike, so a selection survives the group being expanded or
 * collapsed underneath it.
 */
export function nodeMatchesConversation(nodeId: string, conversation: Conversation): boolean {
  const separator = nodeId.indexOf(':')
  if (separator <= 0) return false
  const column = nodeId.slice(0, separator)
  const key = nodeId.slice(separator + 1)
  if (key === '' || key === '__more__') return false
  const matchesAddress = (address: string): boolean =>
    isSubnetKey(key) ? subnetOf(address) === key : address === key
  const matchesPort = (port: number | null): boolean =>
    key === 'unknown' ? port === null : port !== null && String(port) === key
  switch (column) {
    case 'source':
      return matchesAddress(flowAddress(conversation, 'a'))
    case 'destination':
      return matchesAddress(flowAddress(conversation, 'b'))
    case 'sourcePort':
      return matchesPort(flowPort(conversation, 'a'))
    case 'destinationPort':
      return matchesPort(flowPort(conversation, 'b'))
    case 'state':
      return conversation.state === key
    default:
      return false
  }
}

/* ------------------------------------------------------------------ */
/* geometry                                                            */
/* ------------------------------------------------------------------ */

/** Smallest on-screen band thickness, so thin flows stay clickable. */
export const FLOW_MIN_BAND = 1.5

export interface PositionedNode extends FlowNode {
  x: number
  width: number
  y: number
  height: number
}

export interface PositionedBand extends FlowBand {
  /** Tail (left) x and where that end starts. */
  fromX: number
  y0: number
  /** Head (right) x and where that end starts. */
  toX: number
  y1: number
  /** A ribbon has ONE thickness: it is identical at both ends. */
  thickness: number
}

export interface FlowColumnBox {
  column: FlowColumn
  /** Left edge of the node bar / box. */
  x: number
  width: number
  /** Centre of the column, where its label and heading are anchored. */
  centreX: number
}

/**
 * How tall one column really is, so the fit of the five columns is checkable:
 * every column carries the same total bytes, so a column only grows taller than
 * its neighbours through node count (each node adds a minimum height plus a gap).
 */
export interface FlowColumnSummary {
  column: FlowColumn
  nodeCount: number
  /** Sum of the node heights: the bytes this column draws. */
  nodeHeightSum: number
  /** Space the gaps between those nodes take. */
  gapTotal: number
  /** `nodeHeightSum + gapTotal`. */
  totalHeight: number
  /** Share of the plotting height the column occupies. */
  share: number
}

export interface FlowLayout {
  width: number
  height: number
  /** Height of the plotting area, below the headings. */
  plotHeight: number
  nodes: PositionedNode[]
  bands: PositionedBand[]
  boxes: FlowColumnBox[]
  /** Per-column node count and height, for the fit report. */
  summaries: FlowColumnSummary[]
  /** Share of each layer's height the drawing actually used (1 = no shrink). */
  factor: number
}

export interface LayoutOptions {
  width?: number
  height?: number
  headerSpace?: number
  gap?: number
  minNodeHeight?: number
  nodeWidth?: number
  stateWidth?: number
  gutter?: number
}

/**
 * One scale for a whole layer, so a ribbon has the same thickness at both ends.
 *
 * `thickness = minimum + bytes * scale`, with the scale chosen so the layer's
 * bands fill the height it was given. Thickness is therefore strictly
 * proportional to bytes above the floor, and the result is a pure function of
 * the bytes. The floor is a readability nicety, never a distortion: when a layer
 * carries so many bands that the floor does not fit, the floor is dropped for
 * that layer and thickness stays proportional (just thinner), because bytes are
 * what the diagram is for.
 */
export function layerThickness(
  values: readonly number[],
  available: number,
  minimum: number,
): number[] {
  const count = values.length
  if (count === 0) return []
  if (available <= 0) return values.map(() => 0)
  const total = values.reduce((sum, value) => sum + Math.max(0, value), 0)
  if (total <= 0) return values.map(() => available / count)
  const floors = minimum * count
  if (floors >= available) {
    return values.map((value) => (available * Math.max(0, value)) / total)
  }
  const scale = (available - floors) / total
  return values.map((value) => minimum + Math.max(0, value) * scale)
}

function transportRank(transport: Transport): number {
  return FLOW_TRANSPORT_ORDER.indexOf(transport)
}

/**
 * Deterministic five-column layout.
 *
 * Node order is fixed by the graph (bytes desc, then label) and every band sits
 * at a computed offset, so identical input always yields identical geometry:
 * no randomness, no animation step, no re-sorting on re-render.
 *
 * The first and last columns are exactly their outgoing and incoming stacks. A
 * middle column is as tall as the taller of its two sides and each side is
 * centred inside it, which is the only place a minimum thickness has to be
 * absorbed - one ribbon cannot be two different thicknesses. If those maximums
 * would overflow the panel, every layer is scaled by one factor until all five
 * columns fit, which keeps thickness proportional to bytes.
 */
export function layoutFlow(graph: FlowGraph, options: LayoutOptions = {}): FlowLayout {
  const width = options.width ?? FLOW_VIEW.width
  const headerSpace = options.headerSpace ?? FLOW_VIEW.headerSpace
  const plotHeight = Math.max(0, (options.height ?? FLOW_VIEW.height) - headerSpace)
  const gap = options.gap ?? FLOW_VIEW.gap
  const nodeWidth = options.nodeWidth ?? FLOW_VIEW.nodeWidth
  const stateWidth = options.stateWidth ?? FLOW_VIEW.stateWidth
  const gutter = options.gutter ?? FLOW_VIEW.gutter

  const plotLeft = gutter
  const plotRight = width - gutter
  const step = (plotRight - plotLeft) / (FLOW_COLUMNS.length - 1)
  const boxes: FlowColumnBox[] = FLOW_COLUMNS.map((column, index) => {
    const centreX = plotLeft + step * index
    const boxWidth = column === 'state' ? stateWidth : nodeWidth
    return { column, x: centreX - boxWidth / 2, width: boxWidth, centreX }
  })
  const boxOf = new Map(boxes.map((box) => [box.column, box] as const))





  /** Per-layer thicknesses for a given share of each layer's height. */
  const thicknessesAt = (factor: number): number[][] =>
    FLOW_COLUMNS.slice(0, -1).map((column, layer) => {
      const nodes = graph.columns[column].length
      const available = Math.max(0, plotHeight - gap * Math.max(0, nodes - 1)) * factor
      return layerThickness(
        (graph.layers[layer] ?? []).map((band) => band.bytes),
        available,
        FLOW_MIN_BAND,
      )
    })

  /** Height one column needs, given a set of per-layer thicknesses. */
  const columnHeight = (columnIndex: number, allocation: number[][]): number => {
    const column = FLOW_COLUMNS[columnIndex]
    const nodes = graph.columns[column]
    if (nodes.length === 0) return 0
    const incoming = columnIndex > 0 ? (graph.layers[columnIndex - 1] ?? []) : []
    const outgoing = columnIndex < FLOW_COLUMNS.length - 1 ? (graph.layers[columnIndex] ?? []) : []
    const incomingThickness = columnIndex > 0 ? (allocation[columnIndex - 1] ?? []) : []
    const outgoingThickness = columnIndex < FLOW_COLUMNS.length - 1 ? (allocation[columnIndex] ?? []) : []
    const totals = new Map<string, number>()
    nodes.forEach((node) => totals.set(node.id, 0))
    incoming.forEach((band, index) => {
      totals.set(band.to, (totals.get(band.to) ?? 0) + (incomingThickness[index] ?? 0))
    })
    const outTotals = new Map<string, number>()
    outgoing.forEach((band, index) => {
      outTotals.set(band.from, (outTotals.get(band.from) ?? 0) + (outgoingThickness[index] ?? 0))
    })
    let sum = 0
    for (const node of nodes) {
      sum += Math.max(totals.get(node.id) ?? 0, outTotals.get(node.id) ?? 0)
    }
    return sum + gap * Math.max(0, nodes.length - 1)
  }

  const fits = (factor: number): boolean => {
    const allocation = thicknessesAt(factor)
    for (let index = 0; index < FLOW_COLUMNS.length; index += 1) {
      if (columnHeight(index, allocation) > plotHeight + 1e-9) return false
    }
    return true
  }

  let factor = 1
  if (!fits(1)) {
    let low = 0.01
    let high = 1
    for (let step2 = 0; step2 < 30; step2 += 1) {
      const mid = (low + high) / 2
      if (fits(mid)) low = mid
      else high = mid
    }
    factor = low
  }

  const allocation = thicknessesAt(factor)
  const needed = graph.nodes.length === 0 ? 0 : Math.max(...FLOW_COLUMNS.map((_, index) => columnHeight(index, allocation)))
  const residual = needed > plotHeight + 1e-9 && needed > 0 ? plotHeight / needed : 1
  const thicknessOf: number[][] = allocation.map((layer) => layer.map((value) => value * residual))

  /* Node heights: the first column is its outgoing stack, the last is its
   * incoming stack, and a middle column is the taller of the two. */
  const inTotal: Record<FlowColumn, Map<string, number>> = {
    source: new Map(),
    sourcePort: new Map(),
    state: new Map(),
    destinationPort: new Map(),
    destination: new Map(),
  }
  const outTotal: Record<FlowColumn, Map<string, number>> = {
    source: new Map(),
    sourcePort: new Map(),
    state: new Map(),
    destinationPort: new Map(),
    destination: new Map(),
  }
  FLOW_COLUMNS.forEach((column, index) => {
    const incoming = index > 0 ? (graph.layers[index - 1] ?? []) : []
    const incomingThickness = index > 0 ? (thicknessOf[index - 1] ?? []) : []
    incoming.forEach((band, bandIndex) => {
      inTotal[column].set(band.to, (inTotal[column].get(band.to) ?? 0) + (incomingThickness[bandIndex] ?? 0))
    })
    const outgoing = index < FLOW_COLUMNS.length - 1 ? (graph.layers[index] ?? []) : []
    const outgoingThickness = index < FLOW_COLUMNS.length - 1 ? (thicknessOf[index] ?? []) : []
    outgoing.forEach((band, bandIndex) => {
      outTotal[column].set(band.from, (outTotal[column].get(band.from) ?? 0) + (outgoingThickness[bandIndex] ?? 0))
    })
  })

  const positionedNodes: PositionedNode[] = []
  const nodePosition = new Map<string, PositionedNode>()
  for (const column of FLOW_COLUMNS) {
    const box = boxOf.get(column)
    if (!box) continue
    let cursor = 0
    for (const node of graph.columns[column]) {
      const height = Math.max(inTotal[column].get(node.id) ?? 0, outTotal[column].get(node.id) ?? 0)
      const positioned: PositionedNode = {
        ...node,
        x: box.x,
        width: box.width,
        y: cursor,
        height,
      }
      positionedNodes.push(positioned)
      nodePosition.set(node.id, positioned)
      cursor += height + gap
    }
  }

  /* Band ends: each column centres the stack of ribbons that arrive at and leave
   * a node inside that node's own height. */
  const positionedBands = new Map<string, PositionedBand>()
  const layerBands = graph.layers
  layerBands.forEach((bands, layer) => {
    const fromColumn = FLOW_COLUMNS[layer]
    const toColumn = FLOW_COLUMNS[layer + 1]
    const fromBox = boxOf.get(fromColumn)
    const toBox = boxOf.get(toColumn)
    if (!fromBox || !toBox) return
    bands.forEach((band, index) => {
      positionedBands.set(band.id, {
        ...band,
        fromX: fromBox.x + fromBox.width,
        toX: toBox.x,
        y0: 0,
        y1: 0,
        thickness: thicknessOf[layer]?.[index] ?? 0,
      })
    })
  })

  const rankOf = (column: FlowColumn, id: string): number =>
    graph.columns[column].findIndex((node) => node.id === id)

  layerBands.forEach((bands, layer) => {
    const fromColumn = FLOW_COLUMNS[layer]
    const toColumn = FLOW_COLUMNS[layer + 1]
    /* Tail ends: stacked inside each node of the left column of this layer. */
    for (const node of graph.columns[fromColumn]) {
      const positioned = nodePosition.get(node.id)
      if (!positioned) continue
      const mine = bands
        .filter((band) => band.from === node.id)
        .sort((a, b) => {
          const peerDiff = rankOf(toColumn, a.to) - rankOf(toColumn, b.to)
          if (peerDiff !== 0) return peerDiff
          const transportDiff = transportRank(a.transport) - transportRank(b.transport)
          if (transportDiff !== 0) return transportDiff
          return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
        })
      const total = mine.reduce((sum, band) => sum + (positionedBands.get(band.id)?.thickness ?? 0), 0)
      let cursor = positioned.y + Math.max(0, positioned.height - total) / 2
      for (const band of mine) {
        const target = positionedBands.get(band.id)
        if (!target) continue
        target.y0 = cursor
        cursor += target.thickness
      }
    }
    /* Head ends: the same ribbons stacked inside each node of the right column. */
    for (const node of graph.columns[toColumn]) {
      const positioned = nodePosition.get(node.id)
      if (!positioned) continue
      const mine = bands
        .filter((band) => band.to === node.id)
        .sort((a, b) => {
          const peerDiff = rankOf(fromColumn, a.from) - rankOf(fromColumn, b.from)
          if (peerDiff !== 0) return peerDiff
          const transportDiff = transportRank(a.transport) - transportRank(b.transport)
          if (transportDiff !== 0) return transportDiff
          return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
        })
      const total = mine.reduce((sum, band) => sum + (positionedBands.get(band.id)?.thickness ?? 0), 0)
      let cursor = positioned.y + Math.max(0, positioned.height - total) / 2
      for (const band of mine) {
        const target = positionedBands.get(band.id)
        if (!target) continue
        target.y1 = cursor
        cursor += target.thickness
      }
    }
  })

  const summaries: FlowColumnSummary[] = boxes.map((box) => {
    const columnNodes = positionedNodes.filter((node) => node.column === box.column)
    const nodeHeightSum = columnNodes.reduce((total, node) => total + node.height, 0)
    const gapTotal = gap * Math.max(0, columnNodes.length - 1)
    return {
      column: box.column,
      nodeCount: columnNodes.length,
      nodeHeightSum,
      gapTotal,
      totalHeight: nodeHeightSum + gapTotal,
      share: plotHeight > 0 ? (nodeHeightSum + gapTotal) / plotHeight : 0,
    }
  })

  return {
    width,
    height: plotHeight,
    plotHeight,
    nodes: positionedNodes,
    bands: [...positionedBands.values()],
    boxes,
    summaries,
    factor: factor * residual,
  }
}

/** Cubic ribbon between two vertical segments of equal thickness. */
export function ribbonPath(band: PositionedBand): string {
  const midX = (band.fromX + band.toX) / 2
  const top = band.y0
  const bottom = band.y0 + band.thickness
  const topTarget = band.y1
  const bottomTarget = band.y1 + band.thickness
  return [
    'M ' + band.fromX + ' ' + top,
    'C ' + midX + ' ' + top + ', ' + midX + ' ' + topTarget + ', ' + band.toX + ' ' + topTarget,
    'L ' + band.toX + ' ' + bottomTarget,
    'C ' + midX + ' ' + bottomTarget + ', ' + midX + ' ' + bottom + ', ' + band.fromX + ' ' + bottom,
    'Z',
  ].join(' ')
}

/* ------------------------------------------------------------------ */
/* labels                                                              */
/* ------------------------------------------------------------------ */

/** Shorten a label by cutting its middle, so both ends stay recognisable. */
export function shortenMiddle(text: string, max: number): string {
  if (text.length <= max) return text
  if (max <= 3) return text.slice(0, max)
  const head = Math.ceil((max - 1) / 2)
  const tail = max - 1 - head
  return text.slice(0, head) + '\u2026' + text.slice(text.length - tail)
}

/**
 * Shorten a subnet label without ever hiding its prefix length.
 *
 * `2001:db8:1234:5678::/64` becomes `2001:db8:12…::/64`, never `…5678::/64`
 * losing the `/64`: the prefix length is the part that says how much of the
 * address is a group, so it is the address that gives way.
 */
export function shortenSubnet(label: string, max: number): string {
  const separator = label.lastIndexOf('/')
  if (separator <= 0 || label.length <= max) return shortenMiddle(label, max)
  const suffix = label.slice(separator)
  const room = max - suffix.length
  if (room <= 1) return '\u2026' + suffix
  return shortenMiddle(label.slice(0, separator), room) + suffix
}

/** `41051, 41471, 59658`, or `1, 2, 3 +N more` once a list is long. */
export function formatList(values: readonly (string | number)[], max = 8): string {
  if (values.length === 0) return 'none'
  if (values.length <= max) return values.join(', ')
  return values.slice(0, max).join(', ') + ' +' + String(values.length - max) + ' more'
}

/** How many distinct values a capped detail list really holds. */
export function formatListWithCount(values: readonly (string | number)[], count: number, max = 8): string {
  if (count === 0) return 'none'
  if (count <= values.length) return formatList(values, max)
  const shown = formatList(values, max)
  const hidden = count - values.length
  return shown + ' (+' + String(hidden) + ' more)'
}
/* ------------------------------------------------------------------ */
/* view transform                                                      */
/* ------------------------------------------------------------------ */

/**
 * The diagram is zoomed and panned with a viewport transform - scale and
 * translation only, applied to one `<g>` that wraps every band and every node.
 *
 * Nothing here touches the layout: thickness still means bytes at any zoom,
 * because the geometry is computed once and then moved. It also keeps hit
 * testing honest, because the browser hit-tests the transformed shapes itself:
 * the click handlers read the element that was clicked, never a screen
 * coordinate, so no screen-space arithmetic can drift out of step with the
 * picture.
 */
export interface FlowView {
  /** Uniform scale, clamped to the zoom limits. */
  scale: number
  /** Translation in plot units, clamped so the diagram cannot leave the view. */
  x: number
  y: number
}

export interface FlowBounds {
  width: number
  height: number
}

export interface FlowPoint {
  x: number
  y: number
}

export const FLOW_MIN_SCALE = 0.4
export const FLOW_MAX_SCALE = 4

/** How much of the diagram may be pulled past the edge of the view. */
export const FLOW_PAN_MARGIN = 24

/** The starting view, and what `Fit` returns to: the whole diagram. */
export function flowFitView(): FlowView {
  return { scale: 1, x: 0, y: 0 }
}

export function clampFlowScale(scale: number): number {
  if (!Number.isFinite(scale)) return 1
  return Math.min(FLOW_MAX_SCALE, Math.max(FLOW_MIN_SCALE, scale))
}

function clampAxis(offset: number, scaled: number, viewport: number): number {
  if (!Number.isFinite(offset)) return 0
  if (scaled <= viewport) {
    /* Smaller than the view: keep it centred, with only the margin of slack. */
    const centred = (viewport - scaled) / 2
    return Math.min(Math.max(offset, centred - FLOW_PAN_MARGIN), centred + FLOW_PAN_MARGIN)
  }
  /* Larger than the view: the diagram always covers the viewport, give or take
   * the margin, so it can never be dragged out of sight. */
  return Math.min(Math.max(offset, viewport - scaled - FLOW_PAN_MARGIN), FLOW_PAN_MARGIN)
}

export function clampFlowView(view: FlowView, bounds: FlowBounds): FlowView {
  const scale = clampFlowScale(view.scale)
  return {
    scale,
    x: clampAxis(view.x, bounds.width * scale, bounds.width),
    y: clampAxis(view.y, bounds.height * scale, bounds.height),
  }
}

/** Plot coordinates -> the viewBox the plot group is drawn into. */
export function plotToView(point: FlowPoint, view: FlowView): FlowPoint {
  return { x: view.x + point.x * view.scale, y: view.y + point.y * view.scale }
}

/** The viewBox -> the plot coordinates under it. */
export function viewToPlot(point: FlowPoint, view: FlowView): FlowPoint {
  if (view.scale === 0) return { x: 0, y: 0 }
  return { x: (point.x - view.x) / view.scale, y: (point.y - view.y) / view.scale }
}

/** Zoom about a plot-space anchor, so the point under the cursor stays put. */
export function zoomFlowView(
  view: FlowView,
  nextScale: number,
  anchor: FlowPoint,
  bounds: FlowBounds,
): FlowView {
  const scale = clampFlowScale(nextScale)
  if (scale === view.scale) return view
  const ratio = scale / view.scale
  return clampFlowView(
    {
      scale,
      x: anchor.x - (anchor.x - view.x) * ratio,
      y: anchor.y - (anchor.y - view.y) * ratio,
    },
    bounds,
  )
}

/** Pan by a delta in plot units. */
export function panFlowView(
  view: FlowView,
  dx: number,
  dy: number,
  bounds: FlowBounds,
): FlowView {
  return clampFlowView({ scale: view.scale, x: view.x + dx, y: view.y + dy }, bounds)
}

/**
 * The node whose drawn rectangle contains a point in plot coordinates.
 *
 * This models the *drawn* geometry (the DOM adds a little padding so thin nodes
 * stay clickable), and it exists so the suites can check that a click lands on
 * the node that is drawn there at any zoom or pan. The component itself does not
 * need it: its handlers sit on the shapes, so the browser resolves the target.
 */
export function nodeAtPlot(layout: FlowLayout, point: FlowPoint): PositionedNode | null {
  let found: PositionedNode | null = null
  for (const node of layout.nodes) {
    const inside =
      point.x >= node.x &&
      point.x <= node.x + node.width &&
      point.y >= node.y &&
      point.y <= node.y + node.height
    if (!inside) continue
    if (found === null || node.height < found.height) found = node
  }
  return found
}
/* ------------------------------------------------------------------ */
/* labels                                                             */
/* ------------------------------------------------------------------ */

/**
 * Labels are drawn at a constant size *on screen*, so zooming in gives the nodes
 * more room and reveals more of them - which is what zoom is for. Their
 * content-space size therefore shrinks as the scale grows.
 */
export const FLOW_LABEL_PX = 10

/** Screen height one label line needs, halo padding included. */
export const FLOW_LABEL_SCREEN_HEIGHT = 13

/**
 * Headroom a node must have over one label line before it is allowed to carry a
 * label: a node that exactly matches a line height would leave the text touching
 * its neighbours, so eligibility asks for 15% more.
 */
export const FLOW_LABEL_HEADROOM = 1.15

/** Screen padding between two accepted label boxes, so neighbours never touch. */
export const FLOW_LABEL_PADDING = 1

/** Fewer characters than this say nothing useful, so the label is not drawn. */
export const FLOW_LABEL_MIN_CHARS = 4

/** Monospace advance width, as a fraction of the font size. */
export const FLOW_LABEL_CHAR_RATIO = 0.6

export interface FlowLabel {
  nodeId: string
  column: FlowColumn
  /** Final text, already truncated (or carrying a `+ ` group marker). */
  text: string
  /** True when the node is tall enough to carry its numbers on a second line. */
  detail: boolean
  /** Content-space bounds of the whole block: this is what may not overlap. */
  x: number
  y: number
  width: number
  height: number
  anchor: 'start' | 'middle' | 'end'
  /** True when the label sits beside its bar and needs a halo to stay readable. */
  halo: boolean
  /** True for a subnet group, whose label carries the expand marker. */
  expandable: boolean
  /** Font size in content units: `FLOW_LABEL_PX` once scaled. */
  fontSize: number
}

/** Why a label was not drawn. A collision can only ever push out a smaller node. */
export type FlowLabelSuppression = 'slot' | 'width' | 'viewBox' | 'collision'

export interface FlowLabelPlan {
  labels: FlowLabel[]
  shown: number
  suppressed: number
  /** Nodes whose label did not fit, the largest node first. */
  suppressedIds: string[]
  /** The same nodes with the reason their label was dropped. */
  suppressedReasons: { nodeId: string; reason: FlowLabelSuppression }[]
}

export interface LabelOptions {
  /** Smallest useful label, in characters. */
  minChars?: number
}

interface LabelSpace {
  x: number
  anchor: FlowLabel['anchor']
  available: number
  halo: boolean
}

function labelSpaceOf(node: PositionedNode, layout: FlowLayout): LabelSpace {
  const boxOf = (column: FlowColumn) => layout.boxes.find((box) => box.column === column)
  switch (node.column) {
    case 'source':
      return { x: node.x - 6, anchor: 'end', available: Math.max(0, node.x - 6), halo: false }
    case 'destination': {
      const x = node.x + node.width + 6
      return { x, anchor: 'start', available: Math.max(0, layout.width - x), halo: false }
    }
    case 'sourcePort': {
      const x = node.x + node.width + 5
      const stateBox = boxOf('state')
      const limit = stateBox === undefined ? layout.width : stateBox.x - 8
      return { x, anchor: 'start', available: Math.max(0, limit - x), halo: true }
    }
    case 'destinationPort': {
      const x = node.x - 5
      const stateBox = boxOf('state')
      const limit = stateBox === undefined ? 0 : stateBox.x + stateBox.width + 8
      return { x, anchor: 'end', available: Math.max(0, x - limit), halo: true }
    }
    default:
      return {
        x: node.x + node.width / 2,
        anchor: 'middle',
        available: Math.max(0, node.width - 8),
        halo: false,
      }
  }
}

function labelsCollide(a: FlowLabel, b: FlowLabel, padding: number): boolean {
  return (
    a.x - padding < b.x + b.width &&
    b.x - padding < a.x + a.width &&
    a.y - padding < b.y + b.height &&
    b.y - padding < a.y + a.height
  )
}

/**
 * The text a node may show, or null when nothing useful fits.
 *
 * Ports and state names are never cut - a clipped `:443` or `establ…` says
 * nothing - while an address or a subnet shortens by its middle, keeping the
 * part that identifies it (`/24`, `/64`). A port is never part of an address
 * label here, so the digits can never be the part that gives way.
 */
function truncateLabel(node: PositionedNode, maxChars: number, minChars: number): string | null {
  if (maxChars < minChars) return null
  if (node.column === 'state' || node.kind === 'port') {
    return node.label.length <= maxChars ? node.label : null
  }
  if (node.kind === 'subnet') return shortenSubnet(node.label, maxChars)
  return shortenMiddle(node.label, maxChars)
}

/**
 * Which labels to draw, and where.
 *
 * Deterministic collision avoidance in content space: within a column the node
 * with more bytes claims its label first (ties break on the node id, so the
 * result never flickers), a label is only drawn when its node is tall enough to
 * hold it *on screen* at the current zoom, and a label that would leave the
 * viewBox or overlap an already placed one is dropped rather than allowed to
 * bleed into its neighbour. Zooming in enlarges every node without enlarging the
 * labels, so more of them qualify - the suppressed ones stay reachable through
 * the tooltip and the selection chips.
 */
export function planFlowLabels(
  layout: FlowLayout,
  view: FlowView,
  options: LabelOptions = {},
): FlowLabelPlan {
  const minChars = Math.max(1, options.minChars ?? FLOW_LABEL_MIN_CHARS)
  const scale = clampFlowScale(view.scale)
  const fontSize = FLOW_LABEL_PX / scale
  const charWidth = fontSize * FLOW_LABEL_CHAR_RATIO
  const lineHeight = FLOW_LABEL_SCREEN_HEIGHT / scale
  /* A label needs its own line plus headroom on screen, and boxes are compared
     with a screen pixel of padding so two accepted labels never even touch. */
  const requiredHeight = lineHeight * FLOW_LABEL_HEADROOM
  const padding = FLOW_LABEL_PADDING / scale
  const labels: FlowLabel[] = []
  const suppressedIds: string[] = []
  const suppressedReasons: { nodeId: string; reason: FlowLabelSuppression }[] = []

  for (const column of FLOW_COLUMNS) {
    const nodes = layout.nodes
      .filter((node) => node.column === column)
      .slice()
      .sort((a, b) =>
        b.bytes !== a.bytes ? b.bytes - a.bytes : a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
      )
    const placed: FlowLabel[] = []
    for (const node of nodes) {
      const space = labelSpaceOf(node, layout)
      /* Only a genuinely expandable group carries the `+` marker, so the marker
         budget is only reserved for those. */
      const marker = node.expandable ? 2 : 0
      const lines = node.column === 'state' && node.height >= lineHeight * 2 ? 2 : 1
      const height = lineHeight * lines
      const budget = Math.floor(space.available / charWidth) - marker
      const text = truncateLabel(node, Math.max(0, budget), minChars)
      const full = text === null ? null : node.expandable ? '+ ' + text : text
      const width = full === null ? 0 : full.length * charWidth
      const y = node.y + node.height / 2 - height / 2
      const x =
        space.anchor === 'start'
          ? space.x
          : space.anchor === 'end'
            ? space.x - width
            : space.x - width / 2
      const label: FlowLabel = {
        nodeId: node.id,
        column: node.column,
        text: full === null ? '' : full,
        detail: lines === 2,
        x,
        y,
        width,
        height,
        anchor: space.anchor,
        halo: space.halo,
        expandable: node.expandable,
        fontSize,
      }
      const reason: FlowLabelSuppression | null =
        full === null
          ? 'width'
          : requiredHeight > node.height + 1e-9
            ? 'slot'
            : x < -1e-9 || x + width > layout.width + 1e-9
              ? 'viewBox'
              : placed.some((other) => labelsCollide(label, other, padding))
                ? 'collision'
                : null
      if (reason !== null) {
        suppressedIds.push(node.id)
        suppressedReasons.push({ nodeId: node.id, reason })
        continue
      }
      placed.push(label)
      labels.push(label)
    }
  }

  return {
    labels,
    shown: labels.length,
    suppressed: suppressedIds.length,
    suppressedIds,
    suppressedReasons,
  }
}