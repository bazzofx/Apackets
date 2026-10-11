import { useCallback, useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { ArrowLeftRight } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import {
  FilterField,
  FilterStrip,
  ResetFiltersButton,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import { digitsOnly } from '@/components/packets/PacketFilters'
import { ConversationDetail, type ConversationTarget } from '@/components/streams/ConversationDetail'
import { ConversationTable, conversationKey, parseConversationKey } from '@/components/streams/ConversationTable'
import { useAnalysis } from '@/hooks/useAnalysis'
import { conversationsApi, type ConversationListParams } from '@/services/api'
import type { Conversation, ConversationsListResponse, SortOrder, StreamMode, Transport } from '@/types'
import { formatBytes, formatNumber } from '@/utils/format'

/**
 * Conversations — every TCP/UDP flow the analysis derived, with the packets that
 * make it up and, for TCP, TShark's reassembled stream.
 *
 * The row, the packet list and the stream are addressed separately in the URL
 * (`stream=tcp:0`, `smode=hex`), so a conversation view can be shared the same
 * way a packet filter can. UDP conversations deliberately never call the stream
 * endpoint: TShark cannot reassemble UDP and the backend refuses to make an
 * ordering up.
 */

const DEFAULT_PAGE_SIZE = 100

/** Response envelope plus the live-only whole-analysis counter. */
type ConversationsListWithTotals = ConversationsListResponse & { total_conversations?: number }

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
]

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

  const streamKey = url.get('stream')
  const target: ConversationTarget | null = useMemo(() => {
    if (streamKey === '') return null
    const parsed = parseConversationKey(streamKey)
    return parsed === null ? null : { transport: parsed.transport, streamId: parsed.streamId }
  }, [streamKey])

  const listParams: ConversationListParams = useMemo(
    () => ({
      transport,
      ip: ip.trim() || undefined,
      port: port !== undefined && Number.isFinite(port) ? port : undefined,
      search: search.trim() || undefined,
      sort,
      order,
      page,
      page_size: pageSize,
    }),
    [transport, ip, port, search, sort, order, page, pageSize],
  )

  const list = useQuery({
    queryKey: ['conversations', analysisId, listParams],
    queryFn: () => conversationsApi.list(analysisId as string, listParams),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const items: Conversation[] = list.data?.items ?? []
  const total = list.data?.total ?? 0
  const activeFilterCount = [transport, ip.trim(), rawPort.trim(), search.trim()].filter(
    (value) => value !== undefined && value !== '',
  ).length
  // The live endpoint also returns a whole-analysis `total_conversations`;
  // `types/index.ts` models only `total_bytes`, so it is declared here.
  const responseTotals = list.data as ConversationsListWithTotals | undefined
  const allBytes = responseTotals?.total_bytes ?? null
  const allConversations = responseTotals?.total_conversations ?? null

  const selectedConversation = useMemo(
    () => items.find((conversation) => conversationKey(conversation) === streamKey) ?? null,
    [items, streamKey],
  )

  const selectConversation = useCallback(
    (conversation: Conversation) => {
      url.patch({ stream: conversationKey(conversation) }, { resetPage: false })
    },
    [url],
  )

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

  const clearFilters = useCallback(() => {
    url.patch({ transport: null, ip: null, port: null, search: null })
  }, [url])

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
              <ResetFiltersButton onClick={clearFilters} disabled={activeFilterCount === 0} />
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
      </Panel>

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
                  <button
                    type="button"
                    className="btn"
                    onClick={() => navigate('/packets')}
                  >
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
      ) : (
        <EmptyState
          icon={ArrowLeftRight}
          variant="plain"
          title="No conversation selected"
          description="Select a conversation to see the frames it contains and, for TCP, the payload TShark reassembles from the retained capture."
        />
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