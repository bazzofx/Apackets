import { useCallback, useMemo, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Info, List, Search } from 'lucide-react'
import pageBackground from '@/assets/pacets_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import { useUrlFilters } from '@/components/protocols/ProtocolFilters'
import { DownloadButton } from '@/components/packets/DownloadAction'
import {
  InvalidFilterState,
  ZeroMatchState,
  filterDiagnostics,
} from '@/components/packets/FilterStateNotice'
import {
  EMPTY_PACKET_FILTERS,
  PACKET_FILTER_URL_KEYS,
  PACKET_SORT_COLUMNS,
  PacketFilterBar,
  activeFilterCount,
  packetFilterParams,
  packetFilterUrlPatch,
  readPacketFilters,
  type PacketFilterState,
  type PacketListParamsWithStream,
} from '@/components/packets/PacketFilters'
import { PacketDetailPanel } from '@/components/packets/PacketDetailPanel'
import { PacketNavigator } from '@/components/packets/PacketNavigator'
import { PacketTable } from '@/components/packets/PacketTable'
import { useAnalysis } from '@/hooks/useAnalysis'
import { packetsApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { PacketDetail, SortOrder } from '@/types'
import { formatNumber } from '@/utils/format'

/**
 * Packet browser — the core investigative view.
 *
 * * a dense packet table (selectable, sortable, copyable) backed by
 *   `GET /api/analyses/{id}/packets`;
 * * two filter modes that are never conflated: typed fields (SQL) and a raw
 *   Wireshark display filter (TShark), with **invalid filter** and
 *   **zero matches** rendered as two different states;
 * * the whole filter lives in the URL, so an investigation step can be shared;
 * * next/previous matching-packet navigation via the neighbours endpoint;
 * * CSV export of exactly the current filter;
 * * packet detail with the protocol layer tree and a hex + ASCII dump.
 */

const DEFAULT_PAGE_SIZE = 100


function describeFilter(filters: PacketFilterState, activeCount: number): string {
  if (filters.mode === 'advanced') {
    return `The display filter ${filters.displayFilter.trim() || '(empty)'} was accepted by TShark but matched no frames.`
  }
  return `${activeCount} basic filter${activeCount === 1 ? '' : 's'} ${activeCount === 1 ? 'is' : 'are'} active and none of the indexed packets match.`
}

function PacketsContent() {
  const { analysisId, selected: analysis } = useAnalysis()
  const url = useUrlFilters(PACKET_FILTER_URL_KEYS, DEFAULT_PAGE_SIZE)

  const filters = useMemo(() => readPacketFilters(url.get), [url.get])

  // The sort value is validated against the endpoint's allow-list before it is
  // sent: a hand-edited URL must not turn into a `400 invalid_sort`.
  const rawSort = url.get('sort')
  const sort = PACKET_SORT_COLUMNS.some((column) => column.value === rawSort) ? rawSort : 'number'
  const order: SortOrder = url.get('order') === 'desc' ? 'desc' : 'asc'
  const page = Math.max(1, Math.floor(url.getNumber('page', 1)))
  const pageSize = Math.max(1, Math.floor(url.getNumber('page_size', DEFAULT_PAGE_SIZE)))
  const selectedParam = url.getNumber('sel', 0)
  const selectedNumber = selectedParam > 0 ? selectedParam : null

  const [exportReport, setExportReport] = useState<string | null>(null)
  const [exportTruncated, setExportTruncated] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const filterParams = useMemo(() => packetFilterParams(filters), [filters])
  const activeCount = activeFilterCount(filters)

  const listParams: PacketListParamsWithStream = useMemo(
    () => ({ ...filterParams, page, page_size: pageSize, sort, order }),
    [filterParams, page, pageSize, sort, order],
  )

  const list = useQuery({
    queryKey: ['packets', analysisId, listParams],
    queryFn: () => packetsApi.list(analysisId as string, listParams),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const detail = useQuery<PacketDetail>({
    queryKey: ['packet', analysisId, selectedNumber],
    queryFn: () => packetsApi.detail(analysisId as string, selectedNumber as number),
    enabled: Boolean(analysisId) && selectedNumber !== null,
    retry: false,
  })

  const csvUrl = useMemo(
    () =>
      analysisId
        ? packetsApi.exportCsvUrl(analysisId, { ...filterParams, sort, order })
        : '',
    [analysisId, filterParams, sort, order],
  )

  const patchFilters = useCallback(
    (patch: Partial<PacketFilterState>) => {
      // `useUrlFilters.patch` drops empty values and resets `page`, so a filter
      // change always starts at page 1 while the selection is preserved (the
      // detail pane is loaded by frame number, not from the page).
      url.patch(packetFilterUrlPatch({ ...filters, ...patch }))
    },
    [filters, url],
  )

  const clearFilters = useCallback(() => {
    url.patch(packetFilterUrlPatch({ ...EMPTY_PACKET_FILTERS, mode: filters.mode }))
  }, [filters.mode, url])

  const resetEverything = useCallback(() => {
    /* `clear()` resets filters only, so the paging, sorting and selected packet
       this button used to reset as a side effect are asked for explicitly. */
    url.clear()
    url.patch(
      { sel: null, page: null, page_size: null, sort: null, order: null },
      { resetPage: false },
    )
  }, [url])

  const selectPacket = useCallback(
    (packetNumber: number) => {
      url.patch({ sel: packetNumber }, { resetPage: false })
    },
    [url],
  )

  const closeDetail = useCallback(() => {
    url.patch({ sel: null }, { resetPage: false })
  }, [url])

  const changeSort = useCallback(
    (key: string) => {
      url.patch({ sort: key, order: sort === key && order === 'asc' ? 'desc' : 'asc' })
    },
    [order, sort, url],
  )

  const diagnostics = filterDiagnostics(
    list.error ?? null,
    list.data?.filter_valid ?? true,
    list.data?.filter_error ?? null,
  )
  const otherError = list.error && !diagnostics.invalid ? list.error : null
  const items = list.data?.items ?? []
  const total = list.data?.total ?? null
  const capturePackets = analysis?.packet_count ?? null
  const selectionOnPage = selectedNumber !== null && items.some((item) => item.number === selectedNumber)

  return (
    <div className="flex flex-col gap-3">
      <Panel flush>
        <PacketFilterBar
          filters={filters}
          onChange={patchFilters}
          onReset={resetEverything}
          total={diagnostics.invalid || otherError ? null : total}
          selectedNumber={selectedNumber}
          disabled={list.isFetching}
          actions={
            <>
              <PacketNavigator
                analysisId={analysisId as string}
                filters={filters}
                current={selectedNumber}
                filteredTotal={diagnostics.invalid ? null : total}
                onSelect={selectPacket}
                listBusy={list.isFetching}
              />
              <DownloadButton
                url={csvUrl}
                label="CSV"
                disabled={csvUrl === '' || diagnostics.invalid}
                title="Download every packet matching the current filter as CSV (the backend caps the export)"
                onReport={(report) => {
                  setExportError(null)
                  setExportTruncated(report.truncated)
                  const parts: string[] = []
                  if (report.rows !== null && report.total !== null) {
                    parts.push(`exported ${formatNumber(report.rows)} of ${formatNumber(report.total)} matching rows`)
                  } else {
                    parts.push('exported a CSV file')
                  }
                  if (report.filename) parts.push(report.filename)
                  setExportReport(parts.join(' · '))
                }}
                onError={(message) => {
                  setExportReport(null)
                  setExportTruncated(false)
                  setExportError(message)
                }}
              />
            </>
          }
        />
      </Panel>

      {exportReport || exportError ? (
        <div
          className={
            exportError || exportTruncated
              ? 'flex items-center gap-2 rounded border border-warn/40 bg-warn/10 px-3 py-1.5 text-2xs text-warn'
              : 'flex items-center gap-2 rounded border border-border bg-surface px-3 py-1.5 text-2xs text-muted'
          }
          role={exportError ? 'alert' : undefined}
        >
          <Info size={12} aria-hidden />
          <span className="mono break-all">
            {exportError ??
              `${exportReport}${exportTruncated ? ' — the backend capped this export; widen the filter or page through the table for the rest' : ''}`}
          </span>
        </div>
      ) : null}

      {diagnostics.invalid ? (
        <InvalidFilterState
          diagnostics={diagnostics}
          expression={filters.mode === 'advanced' ? filters.displayFilter : undefined}
          onClear={clearFilters}
        />
      ) : otherError ? (
        <ErrorState
          error={otherError}
          title="Could not load the packet list"
          onRetry={() => void list.refetch()}
        />
      ) : null}

      {!diagnostics.invalid && !otherError ? (
        <Panel flush>
          {list.isLoading && !list.data ? (
            <LoadingState label="Loading packets…" rows={8} />
          ) : items.length === 0 ? (
            <ZeroMatchState
              description={
                activeCount > 0
                  ? describeFilter(filters, activeCount)
                  : 'No packets came back for this analysis with no filter applied, while the capture row reports indexed packets. Re-run the analysis if this persists.'
              }
              onClear={clearFilters}
              captureEmpty={capturePackets === 0}
              packetCount={capturePackets}
            />
          ) : (
            <>
              <PacketTable
                items={items}
                selected={selectedNumber}
                onSelect={selectPacket}
                sort={sort}
                order={order}
                onSort={changeSort}
                busy={list.isFetching}
              />
              <Pagination
                page={list.data?.page ?? page}
                pageSize={list.data?.page_size ?? pageSize}
                total={total ?? items.length}
                disabled={list.isFetching}
                onPageChange={(next) => url.patch({ page: next }, { resetPage: false })}
                onPageSizeChange={(next) =>
                  url.patch({ page_size: next, page: null }, { resetPage: false })
                }
              />
            </>
          )}
        </Panel>
      ) : null}

      {!diagnostics.invalid && selectedNumber !== null && !selectionOnPage && items.length > 0 ? (
        <div className="flex items-center gap-2 rounded border border-border bg-surface px-3 py-1.5 text-2xs text-muted">
          <Search size={12} aria-hidden />
          <span>
            Packet {formatNumber(selectedNumber)} is not on this page — the detail below is loaded by
            frame number from the capture, so it is still accurate.
          </span>
        </div>
      ) : null}

      {selectedNumber !== null ? (
        <PacketDetailPanel
          packetNumber={selectedNumber}
          detail={detail.data}
          isLoading={detail.isLoading}
          error={detail.error}
          onRetry={() => void detail.refetch()}
          onClose={closeDetail}
        />
      ) : (
        <EmptyState
          icon={List}
          variant="plain"
          title="No packet selected"
          description="Click a row in the packet list to decode it: every layer is read again from the retained capture, so the layers and bytes below come from TShark, not from the index."
        />
      )}
    </div>
  )
}

/** Packet browser. */
export function PacketsPage() {
  return (
    <Page section={SECTIONS.packets} headerImage={pageBackground}>
      <AnalysisGuard
        emptyDescription={
          <>
            The packet browser reads the indexed frames of one analysis. Upload a PCAP/PCAPNG capture
            or pick an existing analysis in the top bar.
          </>
        }
      >
        <PacketsContent />
      </AnalysisGuard>
    </Page>
  )
}

export default PacketsPage
