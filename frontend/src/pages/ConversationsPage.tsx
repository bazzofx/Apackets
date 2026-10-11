import { useCallback, useEffect, useMemo, useRef } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { ArrowLeftRight, Info } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import ConversationFlow from '@/components/conversations/ConversationFlow'
import FlowSelectionFallback from '@/components/conversations/FlowSelectionFallback'
import { toConversationAlerts } from '@/components/conversations/alertOverlay'
import {
  buildFlowGraph,
  flowNodeBudget,
  flowSelectionState,
  nodeMatchesConversation,
} from '@/components/conversations/flowLayout'
import {
  FilterField,
  FilterStrip,
  ResetFiltersButton,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import { digitsOnly } from '@/components/packets/PacketFilters'
import { ConversationDetail, type ConversationTarget } from '@/components/streams/ConversationDetail'
import {
  ConversationTable,
  conversationKey,
  parseConversationKey,
} from '@/components/streams/ConversationTable'
import { useAnalysis } from '@/hooks/useAnalysis'
import { alertsApi, conversationsApi, type ConversationListParams } from '@/services/api'
import type {
  Conversation,
  ConversationsListResponse,
  SortOrder,
  StreamMode,
  Transport,
} from '@/types'
import { formatBytes, formatNumber } from '@/utils/format'

/**
 * Conversations — every TCP/UDP flow the analysis derived.
 *
 * Two tabs share one filter toolbar and one URL:
 *
 *  - **Flow** (the default, and the first thing the section shows) draws the
 *    five-stage diagram: source IP, source port, state, destination port,
 *    destination IP. Band thickness is the bytes behind it, TCP is solid and UDP
 *    is dashed, and the IP columns group addresses by `/24` (or `/64` for IPv6)
 *    until a group is expanded in place.
 *  - **Info** holds the dense table with sorting, paging and the details pane —
 *    exactly what this page showed before the diagram existed.
 *
 * The row, the packet list, the stream and the diagram selection are addressed
 * separately in the URL (`stream=tcp:0`, `smode=hex`, `tab=flow`, `node=…`,
 * `expand=…`), so an investigation step can be shared. UDP conversations
 * deliberately never call the stream endpoint: TShark cannot reassemble UDP and
 * the backend refuses to make an ordering up.
 */

const DEFAULT_PAGE_SIZE = 100

/** Largest `page_size` the conversations endpoint accepts, used by the diagram. */
const FLOW_PAGE_SIZE = 1000

/** Sort columns the conversations endpoint allows (contract §5). */
const CONVERSATION_SORT_COLUMNS = [
  { value: 'bytes_total', label: 'total bytes' },
  { value: 'packets_total', label: 'packets' },
  { value: 'start_time', label: 'start time' },
  { value: 'duration', label: 'duration' },
  { value: 'endpoint_a', label: 'endpoint A' },
]

/** Every query-string key this page owns. */
const CONVERSATION_URL_KEYS = [
  'transport',
  'ip',
  'port',
  'search',
  'sort',
  'order',
  'page',
  'page_size',
  'stream',
  'smode',
  'alerts',
  'tab',
  'node',
  'expand',
]

type ConversationsTab = 'flow' | 'info'

const CONVERSATIONS_TABS: { value: ConversationsTab; label: string; hint: string }[] = [
  {
    value: 'flow',
    label: 'Flow',
    hint: 'source IP -> source port -> state -> destination port -> destination IP, thickness = bytes',
  },
  { value: 'info', label: 'Info', hint: 'the dense table: sorting, paging and the full detail pane' },
]



/** Response envelope plus the live-only whole-analysis counter. */
type ConversationsListWithTotals = ConversationsListResponse & { total_conversations?: number }

/**
 * Local ordering of the rows behind a diagram selection.
 *
 * The Info tab's order is applied by the backend over the whole set; this only
 * re-orders the rows the diagram already fetched, so both panels agree on the
 * sort key and direction without a second request. Missing values sort last in
 * either direction, so an em dash never leads the list.
 */
function compareRows(a: Conversation, b: Conversation, sort: string, order: SortOrder): number {
  const left = (a as unknown as Record<string, unknown>)[sort]
  const right = (b as unknown as Record<string, unknown>)[sort]
  const leftMissing = left === null || left === undefined
  const rightMissing = right === null || right === undefined
  if (leftMissing && rightMissing) return 0
  if (leftMissing) return 1
  if (rightMissing) return -1
  let base: number
  if (typeof left === 'number' && typeof right === 'number') base = left - right
  else base = String(left) < String(right) ? -1 : String(left) > String(right) ? 1 : 0
  return order === 'asc' ? base : -base
}

/** `192.168.8.0/24` list held in one URL value. */
function parseSubnets(raw: string): string[] {
  return [...new Set(raw.split(',').map((part) => part.trim()).filter((part) => part !== ''))].sort()
}
function ConversationsContent() {
  const { analysisId } = useAnalysis()
  const navigate = useNavigate()
  const url = useUrlFilters(CONVERSATION_URL_KEYS, DEFAULT_PAGE_SIZE)

  const rawTransport = url.get('transport')
  const transport: Transport | undefined =
    rawTransport === 'tcp' || rawTransport === 'udp' ? rawTransport : undefined
  const ip = url.get('ip')
  const rawPort = url.get('port')
  const port = rawPort.trim() === '' ? undefined : Number(rawPort)
  const search = url.get('search')

  const rawSort = url.get('sort')
  const sort = CONVERSATION_SORT_COLUMNS.some((column) => column.value === rawSort)
    ? rawSort
    : 'bytes_total'
  const order: SortOrder = url.get('order') === 'asc' ? 'asc' : 'desc'
  const page = Math.max(1, Math.floor(url.getNumber('page', 1)))
  const pageSize = Math.max(1, Math.floor(url.getNumber('page_size', DEFAULT_PAGE_SIZE)))

  const rawMode = url.get('smode')
  const mode: StreamMode = rawMode === 'hex' || rawMode === 'raw' ? rawMode : 'ascii'

  /** Flow is the primary tab of this section, so it is the fallback value. */
  const tab: ConversationsTab = url.get('tab') === 'info' ? 'info' : 'flow'

  const selectedNodeId = url.get('node').trim() === '' ? null : url.get('node').trim()
  const expandedSubnets = useMemo(() => parseSubnets(url.get('expand')), [url])

  const streamKey = url.get('stream')
  const target: ConversationTarget | null = useMemo(() => {
    if (streamKey === '') return null
    const parsed = parseConversationKey(streamKey)
    return parsed === null ? null : { transport: parsed.transport, streamId: parsed.streamId }
  }, [streamKey])

  /** The toolbar filters, shared by the table query and the diagram query. */
  const filters = useMemo(
    () => ({
      transport,
      ip: ip.trim() || undefined,
      port: port !== undefined && Number.isFinite(port) ? port : undefined,
      search: search.trim() || undefined,
    }),
    [transport, ip, port, search],
  )

  const listParams: ConversationListParams = useMemo(
    () => ({ ...filters, sort, order, page, page_size: pageSize }),
    [filters, sort, order, page, pageSize],
  )

  /**
   * The diagram needs every conversation the filter matches, not one page of
   * them, in one request: `page_size` is the endpoint's maximum. Rows come back
   * largest first, so a cap that did bite keeps the heaviest flows.
   */
  const flowParams: ConversationListParams = useMemo(
    () => ({ ...filters, sort: 'bytes_total', order: 'desc', page: 1, page_size: FLOW_PAGE_SIZE }),
    [filters],
  )

  const list = useQuery({
    queryKey: ['conversations', analysisId, listParams],
    queryFn: () => conversationsApi.list(analysisId as string, listParams),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const flow = useQuery({
    queryKey: ['conversations-flow', analysisId, flowParams],
    queryFn: () => conversationsApi.list(analysisId as string, flowParams),
    enabled: Boolean(analysisId) && tab === 'flow',
    placeholderData: keepPreviousData,
  })

  /**
   * Alerts tied to conversations, for the overlay.
   *
   * Fetched only while the Flow tab is open, which is the only place the control
   * is on screen: the Info tab never draws the diagram, so it never needs this.
   * The default threshold is the endpoint's own (`medium`, i.e. high + medium).
   */
  const alertsQuery = useQuery({
    queryKey: ['conversation-alerts', analysisId],
    queryFn: () => alertsApi.conversations(analysisId as string),
    enabled: Boolean(analysisId) && tab === 'flow',
    retry: false,
    placeholderData: keepPreviousData,
  })

  const alerts = useMemo(
    () => (alertsQuery.data === undefined ? null : toConversationAlerts(alertsQuery.data)),
    [alertsQuery.data],
  )
  const alertsError = useMemo(() => {
    const error = alertsQuery.error
    if (error === null || error === undefined) return null
    return error instanceof Error ? error.message : String(error)
  }, [alertsQuery.error])

  /** The layer is a URL flag, so a flagged view is shareable and survives reload. */
  const alertsOn = url.get('alerts') === '1'
  const toggleAlerts = useCallback(() => {
    url.patch({ alerts: alertsOn ? null : '1' }, { resetPage: false })
  }, [alertsOn, url])

  const items: Conversation[] = list.data?.items ?? []
  const total = list.data?.total ?? 0
  const flowItems: Conversation[] = flow.data?.items ?? []
  const flowTotal = flow.data?.total ?? 0

  /**
   * The alerts filter.
   *
   * With the layer on the diagram is FILTERED rather than highlighted: only the
   * conversations the alert endpoint tied to a finding are drawn, so there is
   * nothing to point at and no colour, outline or animation rules to get wrong.
   * The key is `transport:stream_id` - the same identity the alert map, the table
   * and the URL already use.
   */
  const alertedKeys = useMemo(() => {
    if (!alertsOn || alerts === null) return null
    return new Set(Object.keys(alerts.byConversation))
  }, [alertsOn, alerts])
  /* The flow fetch holds up to 1,000 rows and the largest capture in the library
     holds 195 conversations, so the cap cannot hide a match today. If it ever
     could, `visibleTotal` exceeds the rows on hand and the diagram's own
     "showing the top N of M" line says so instead of dropping matches silently. */
  const visibleFlowItems = useMemo(
    () =>
      alertedKeys === null
        ? flowItems
        : flowItems.filter((conversation) => alertedKeys.has(conversationKey(conversation))),
    [flowItems, alertedKeys],
  )
  const visibleTotal = alertedKeys === null ? flowTotal : alertedKeys.size

  const activeFilterCount = [transport, ip.trim(), rawPort.trim(), search.trim()].filter(
    (value) => value !== undefined && value !== '',
  ).length
  // The live endpoint also returns a whole-analysis `total_conversations`;
  // `types/index.ts` models only `total_bytes`, so it is declared here.
  const responseTotals = list.data as ConversationsListWithTotals | undefined
  const allBytes = responseTotals?.total_bytes ?? null
  const allConversations = responseTotals?.total_conversations ?? null

  /* The diagram holds every filtered row, so a selected conversation is always
     in it; the table only holds the current page, which is why the detail pane
     has always tolerated a null row. */
  const selectedConversation = useMemo(
    () =>
      (tab === 'flow' ? visibleFlowItems : items).find(
        (conversation) => conversationKey(conversation) === streamKey,
      ) ?? null,
    [tab, visibleFlowItems, items, streamKey],
  )

  /** The five-column graph, built once per filtered set and shared with the diagram. */
  const graph = useMemo(
    () =>
      buildFlowGraph(visibleFlowItems, {
        expandedSubnets,
        nodeBudget: flowNodeBudget(),
        filteredTotal: visibleTotal,
        rowsFetched: visibleFlowItems.length,
      }),
    [visibleFlowItems, expandedSubnets, visibleTotal],
  )

  /**
   * Rows behind the node chosen in the diagram, in the page's order.
   *
   * The graph resolves the selection exactly, including a folded remainder that
   * no single row can be matched against. When the node is not in the current
   * graph - a subnet whose group was just expanded, say - the pattern matcher
   * answers instead, so the selection survives that.
   */
  const selectionRows = useMemo(() => {
    if (selectedNodeId === null) return [] as Conversation[]
    const node = graph.nodes.find((item) => item.id === selectedNodeId)
    const keys = node === undefined ? null : new Set(node.keys)
    const rows = visibleFlowItems.filter((conversation) =>
      keys === null
        ? nodeMatchesConversation(selectedNodeId, conversation)
        : keys.has(conversationKey(conversation)),
    )
    return [...rows].sort((left, right) => compareRows(left, right, sort, order))
  }, [visibleFlowItems, graph, selectedNodeId, sort, order])

  const selectionBytes = useMemo(
    () => selectionRows.reduce((sum, conversation) => sum + (conversation.bytes_total || 0), 0),
    [selectionRows],
  )
  const selectionPackets = useMemo(
    () => selectionRows.reduce((sum, conversation) => sum + (conversation.packets_total || 0), 0),
    [selectionRows],
  )

  const selectionSignature = selectedNodeId ?? ''
  const handledSelection = useRef<string | null>(null)

  /* Choosing a node reveals its frames straight away by opening the largest
     conversation behind it, and never overrides a conversation the user opened
     by hand while the selection has not changed. */
  useEffect(() => {
    if (tab !== 'flow') return
    if (handledSelection.current === selectionSignature) return
    if (selectionRows.length === 0) return
    handledSelection.current = selectionSignature
    if (selectionRows.some((conversation) => conversationKey(conversation) === streamKey)) return
    let largest = selectionRows[0]
    for (const candidate of selectionRows) {
      if (candidate.bytes_total > largest.bytes_total) largest = candidate
    }
    url.patch({ stream: conversationKey(largest), smode: null }, { resetPage: false })
  }, [tab, selectionSignature, selectionRows, streamKey, url])

  const selectConversation = useCallback(
    (conversation: Conversation) => {
      url.patch({ stream: conversationKey(conversation) }, { resetPage: false })
    },
    [url],
  )

  const selectNode = useCallback(
    (nodeId: string | null) => {
      url.patch({ node: nodeId }, { resetPage: false })
    },
    [url],
  )
  /* A selection that is no longer one of the graph's nodes is dropped: node ids
     change when a filter regroups the columns (a `/24` group becomes the single
     address it holds), and collapsing the page around an unresolvable selection
     is a dead end. A selection that is still valid is left untouched, so tweaking
     a filter never loses it. The ref makes the drop happen once per stale id. */
  const droppedSelection = useRef<string | null>(null)
  useEffect(() => {
    if (selectedNodeId === null) {
      droppedSelection.current = null
      return
    }
    /* Only the Flow tab draws the diagram, and only once rows have arrived: an
       empty graph would make every selection look stale. */
    if (tab !== 'flow' || flow.data === undefined) return
    if (flowSelectionState(graph, selectedNodeId, flowItems) !== 'stale') return
    if (droppedSelection.current === selectedNodeId) return
    droppedSelection.current = selectedNodeId
    selectNode(null)
  }, [graph, selectedNodeId, tab, flow.data, selectNode])

  const toggleSubnet = useCallback(
    (subnet: string) => {
      const next = expandedSubnets.includes(subnet)
        ? expandedSubnets.filter((item) => item !== subnet)
        : [...expandedSubnets, subnet].sort()
      url.patch({ expand: next.length === 0 ? null : next.join(',') }, { resetPage: false })
    },
    [expandedSubnets, url],
  )

  const clearPath = useCallback(() => {
    url.patch({ stream: null, smode: null }, { resetPage: false })
  }, [url])

  const closeConversation = useCallback(() => {
    url.patch({ stream: null, smode: null }, { resetPage: false })
  }, [url])

  const openPacketsForStream = useCallback(() => {
    if (target === null) return
    navigate(`/packets?mode=basic&stream_id=${target.streamId}`)
  }, [navigate, target])

  const openPacket = useCallback(
    (packetNumber: number) => {
      if (target === null) return
      navigate(`/packets?mode=basic&stream_id=${target.streamId}&sel=${packetNumber}`)
    },
    [navigate, target],
  )

  const changeSort = useCallback(
    (key: string) => {
      url.patch({ sort: key, order: sort === key && order === 'desc' ? 'asc' : 'desc' })
    },
    [order, sort, url],
  )

  const changeTab = useCallback(
    (next: ConversationsTab) => {
      url.patch({ tab: next }, { resetPage: false })
    },
    [url],
  )

  const clearFilters = useCallback(() => {
    /* The alerts filter is cleared along with the rest when it is on: otherwise the
       empty state would offer a button that leaves the view exactly as empty. */
    url.patch({ transport: null, ip: null, port: null, search: null, ...(alertsOn ? { alerts: null } : {}) })
  }, [url, alertsOn])

  const activeTab = CONVERSATIONS_TABS.find((item) => item.value === tab) ?? CONVERSATIONS_TABS[0]

  const selectionTitle =
    selectedNodeId === null
      ? 'Conversations behind the selection'
      : 'Conversations behind ' + selectedNodeId.slice(selectedNodeId.indexOf(':') + 1)

  const selectionSubtitle = [
    formatNumber(selectionRows.length) +
      ' conversation(s) · ' +
      formatBytes(selectionBytes) +
      ' · ' +
      formatNumber(selectionPackets) +
      ' packets',
    `sorted here by ${CONVERSATION_SORT_COLUMNS.find((column) => column.value === sort)?.label ?? sort} ${order}`,
    flowTotal > flowItems.length
      ? `the diagram fetched the ${formatNumber(flowItems.length)} largest of ${formatNumber(flowTotal)} matching conversations`
      : null,
  ]
    .filter((part): part is string => part !== null)
    .join(' · ')

  /* One detail pane for both tabs: the same conversation row, frame list and
     TCP stream view this page has always rendered, never a second renderer. */
  const detailPanel =
    target === null ? null : (
      <ConversationDetail
        analysisId={analysisId as string}
        conversation={selectedConversation}
        target={target}
        mode={mode}
        onModeChange={(next) =>
          url.patch({ smode: next === 'ascii' ? null : next }, { resetPage: false })
        }
        onOpenPackets={openPacketsForStream}
        onOpenPacket={openPacket}
        onClose={closeConversation}
      />
    )
  const selectedStateNode = selectedNodeId !== null && selectedNodeId.indexOf('state:') === 0

  return (
    <div className="flex flex-col gap-3">
      <Panel flush>
        <FilterStrip
          actions={
            <>
              <span className="mono text-2xs text-faint">
                {allConversations === null
                  ? ''
                  : `${formatNumber(allConversations)} conversations in this analysis`}
                {allBytes !== null ? ` · ${formatBytes(allBytes)} total` : ''}
              </span>
              <ResetFiltersButton onClick={clearFilters} disabled={activeFilterCount === 0 && !alertsOn} />
            </>
          }
        >
          <FilterField label="transport" width="w-24">
            <select
              className="select w-full py-1"
              value={transport ?? ''}
              onChange={(event) => url.patch({ transport: event.target.value || null })}
            >
              <option value="">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
          </FilterField>
          <TextFilter
            label="ip"
            value={ip}
            onChange={(value) => url.patch({ ip: value })}
            placeholder="10.0.0.10"
            width="w-32"
            title="Either endpoint matches this address exactly"
          />
          <FilterField label="port" width="w-24" title="Either endpoint port equals this value">
            <input
              className="input py-1"
              value={rawPort}
              inputMode="numeric"
              autoComplete="off"
              placeholder="80"
              onChange={(event) => url.patch({ port: digitsOnly(event.target.value, 5) || null })}
            />
          </FilterField>
          <TextFilter
            label="search"
            value={search}
            onChange={(value) => url.patch({ search: value })}
            placeholder="http, 51000"
            width="w-40"
            title="Substring match over the conversation id, both endpoints and the observed protocols"
          />
          <FilterField label="sort" width="w-40">
            <select
              className="select w-full py-1"
              value={sort}
              onChange={(event) => url.patch({ sort: event.target.value, order })}
            >
              {CONVERSATION_SORT_COLUMNS.map((column) => (
                <option key={column.value} value={column.value}>
                  {column.label}
                </option>
              ))}
            </select>
          </FilterField>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => url.patch({ sort, order: order === 'asc' ? 'desc' : 'asc' })}
            title={order === 'desc' ? 'Descending — click for ascending' : 'Ascending — click for descending'}
          >
            {order}
          </button>
        </FilterStrip>

        <div className="flex flex-wrap items-center gap-1 border-b border-border px-2 pt-1">
          {CONVERSATIONS_TABS.map((item) => {
            const active = item.value === tab
            return (
              <button
                key={item.value}
                type="button"
                className={clsx(
                  '-mb-px border-b-2 px-2.5 py-1.5 text-xs font-medium transition-colors',
                  active ? 'border-accent text-text' : 'border-transparent text-muted hover:text-text',
                )}
                aria-current={active ? 'page' : undefined}
                title={item.hint}
                onClick={() => changeTab(item.value)}
              >
                {item.label}
              </button>
            )
          })}
          <span className="ml-auto hidden items-center gap-1 pr-1 text-2xs text-faint sm:flex">
            <Info size={12} aria-hidden />
            {activeTab.hint}
          </span>
        </div>
      </Panel>

      {tab === 'flow' ? (
        flow.error ? (
          <ErrorState
            error={flow.error}
            title="Could not load the conversations for the diagram"
            onRetry={() => void flow.refetch()}
          />
        ) : flow.isLoading && !flow.data ? (
          <Panel flush>
            <LoadingState label="Loading the conversations for the diagram..." rows={8} />
          </Panel>
        ) : (
          <>
            <ConversationFlow
              graph={graph}
              conversations={visibleFlowItems}
              busy={flow.isFetching}
              selectedKey={streamKey === '' ? null : streamKey}
              selectedNodeId={selectedNodeId}
              onSelectNode={selectNode}
              onToggleSubnet={toggleSubnet}
              onSelectConversation={selectConversation}
              onClearPath={clearPath}
              alerts={alerts}
              alertsOn={alertsOn}
              alertsBusy={alertsQuery.isFetching}
              alertsError={alertsError}
              onToggleAlerts={toggleAlerts}
              onRetryAlerts={() => void alertsQuery.refetch()}
              filtered={activeFilterCount > 0 || alertsOn}
              onClearFilters={clearFilters}
            />

            {selectedNodeId !== null ? (
              selectionRows.length > 0 ? (
                <Panel
                  flush
                  title={selectionTitle}
                  subtitle={selectionSubtitle}
                  actions={
                    <button
                      type="button"
                      className="btn px-1.5 py-1"
                      onClick={() => selectNode(null)}
                      title="Clear the diagram selection; the toolbar filters stay as they are"
                    >
                      Clear selection
                    </button>
                  }
                >
                  <div className="max-h-[24rem] overflow-auto border-t border-border">
                    <ConversationTable
                      items={selectionRows}
                      selectedKey={target === null ? null : `${target.transport}:${target.streamId}`}
                      onSelect={selectConversation}
                      sort={sort}
                      order={order}
                      onSort={changeSort}
                      busy={flow.isFetching}
                    />
                  </div>
                  <div className="border-t border-border px-3 py-1 text-2xs text-faint">
                    Click a row to open that conversation&apos;s frames and, for TCP, the stream TShark
                    reassembled. Sorting here is applied to the rows the diagram already fetched; the
                    Info tab sorts the whole set on the backend.
                  </div>
                </Panel>
              ) : (
                <FlowSelectionFallback
                  nodeId={selectedNodeId}
                  onClearSelection={() => selectNode(null)}
                  onResetFilters={clearFilters}
                />
              )
            ) : (
              <p className="px-1 text-2xs leading-relaxed text-faint">
                Click a band to open the largest conversation it carries, or a node to list every
                conversation behind it — the frames and, for TCP, the reassembled stream render below in
                the same pane the Info tab uses. Group nodes marked <span className="mono">+</span> expand
                into their individual addresses.
              </p>
            )}

            {target !== null ? detailPanel : null}
          </>
        )
      ) : (
        <>
          {selectedStateNode ? (
            <div className="flex flex-wrap items-center gap-2 rounded border border-border bg-surface2 px-3 py-2 text-2xs text-muted">
              <Info size={12} aria-hidden />
              <span>
                <span className="mono text-text">{selectedNodeId?.slice('state:'.length)}</span> is
                selected from the Flow tab. The conversations endpoint has no state filter, so this table
                is not filtered by state.
              </span>
              <button
                type="button"
                className="btn btn-ghost ml-auto px-1.5 py-1"
                onClick={() => selectNode(null)}
              >
                Clear
              </button>
            </div>
          ) : null}

          {list.error ? (
            <ErrorState
              error={list.error}
              title="Could not load the conversations"
              onRetry={() => void list.refetch()}
            />
          ) : (
            <Panel flush>
              {list.isLoading && !list.data ? (
                <LoadingState label="Loading conversations..." rows={8} />
              ) : items.length === 0 ? (
                <EmptyState
                  icon={ArrowLeftRight}
                  variant="plain"
                  title={
                    activeFilterCount > 0
                      ? '0 conversations match this filter'
                      : 'No conversations were derived from this capture'
                  }
                  description={
                    activeFilterCount > 0 ? (
                      <>
                        The filter is valid and the request succeeded — there simply is no TCP/UDP flow
                        in this capture with those endpoint values. This is an empty result, not an
                        error.
                      </>
                    ) : (
                      <>
                        The conversation analyzer found no TCP or UDP flow. A capture that carries only
                        ARP, ICMP or other non-TCP/UDP traffic produces no conversations; the frames
                        themselves are still in the packet browser.
                      </>
                    )
                  }
                  action={
                    activeFilterCount > 0 ? (
                      <button type="button" className="btn btn-primary" onClick={clearFilters}>
                        Clear the filter
                      </button>
                    ) : (
                      <button type="button" className="btn" onClick={() => navigate('/packets')}>
                        Open the packet browser
                      </button>
                    )
                  }
                />
              ) : (
                <>
                  <ConversationTable
                    items={items}
                    selectedKey={target === null ? null : `${target.transport}:${target.streamId}`}
                    onSelect={selectConversation}
                    sort={sort}
                    order={order}
                    onSort={changeSort}
                    busy={list.isFetching}
                  />
                  <Pagination
                    page={list.data?.page ?? page}
                    pageSize={list.data?.page_size ?? pageSize}
                    total={total}
                    disabled={list.isFetching}
                    onPageChange={(next) => url.patch({ page: next }, { resetPage: false })}
                    onPageSizeChange={(next) =>
                      url.patch({ page_size: next, page: null }, { resetPage: false })
                    }
                  />
                </>
              )}
            </Panel>
          )}

          <p className="px-1 text-2xs leading-relaxed text-faint">
            Sort order is applied by the backend over the whole conversation set, and the conversation
            totals above describe the analysis rather than the filtered page. Selecting a row expands the
            flow; TCP conversations additionally load TShark&apos;s reassembled stream.
          </p>

          {target !== null ? (
            detailPanel
          ) : (
            <EmptyState
              icon={ArrowLeftRight}
              variant="plain"
              title="No conversation selected"
              description="Select a conversation to see the frames it contains and, for TCP, the payload TShark reassembles from the retained capture."
            />
          )}
        </>
      )}
    </div>
  )
}

/** Conversations and stream follow-up view. */
export function ConversationsPage() {
  return (
    <AnalysisGuard
      emptyDescription={
        <>
          Conversations are derived per analysis. Upload a PCAP/PCAPNG capture or pick an existing
          analysis in the top bar to see the TCP/UDP flows it contains.
        </>
      }
    >
      <ConversationsContent />
    </AnalysisGuard>
  )
}

export default ConversationsPage