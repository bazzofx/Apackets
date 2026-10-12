import { useCallback, useMemo } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Loader2, RefreshCw, ShieldQuestion } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import { SectionNote, ScopeNote } from '@/components/protocols/ProtocolDetail'
import {
  CheckFilter,
  FilterStrip,
  ResetFiltersButton,
  SelectFilter,
  SortSelect,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import { FlagLegend, LeadFlagList } from '@/components/protocols/ProtocolFlags'
import SessionDetail from '@/components/protocols/SessionDetail'
import {
  FAMILY_PROTOCOLS,
  FAMILY_SCOPE,
  PROTOCOL_LABELS,
  SESSION_FLAG_CATALOG,
  SESSION_FLAG_KEYS,
  sessionSummary,
} from '@/components/protocols/sessionCatalog'
import { useAnalysis } from '@/hooks/useAnalysis'
import { protocolsApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import type { ProtocolFamily, ProtocolSessionRow } from '@/types'

/**
 * Email, SSH, FTP, VoIP and SMB — one page, five sections (docs/PROTOCOLS.md).
 *
 * The five sections are one component with a different `family`, because the five protocols
 * are one shape in the database: a session with endpoints, times, volume by direction, a
 * per-protocol `detail` object and lead flags. What differs — which protocols a family
 * covers, what to call them, what each page can and cannot read — lives in
 * `components/protocols/sessionCatalog.ts`, so a fix here is a fix in all five pages and
 * the five cannot drift apart.
 *
 * Nothing on this page re-reads the capture: it is SQL over `protocol_sessions`. The one
 * exception is the rescan control, which exists because that table is filled by a pipeline
 * stage — an analysis indexed before this section existed holds no rows, and the page offers
 * to re-read it rather than reporting an empty capture as a clean one.
 */

/** Sort columns the endpoint allows (contract §5.1). */
const SORT_COLUMNS = [
  { value: 'start_time', label: 'time' },
  { value: 'bytes', label: 'bytes' },
  { value: 'packets', label: 'packets' },
  { value: 'duration', label: 'duration' },
]

/** Every query-string key this page owns. */
const URL_KEYS = ['protocol', 'search', 'flagged', 'sort', 'order', 'page', 'page_size', 'sel']

/** The backend's own flag thresholds, quoted so the legend's numbers are explained. */
const THRESHOLD_NOTE = (
  <>
    The thresholds quoted here are the defaults this backend uses (
    <span className="mono">large_transfer ≥ 10 MiB</span>,{' '}
    <span className="mono">many_commands ≥ 40</span>,{' '}
    <span className="mono">long_session ≥ 1 h</span>). They are configurable, and the detail view
    always shows which of them fired for a session.
  </>
)

/** A one-line, protocol-aware summary of what the session said, for the table. */
function summaryTitle(row: ProtocolSessionRow): string {
  const entries = Object.entries(row.detail ?? {})
  if (entries.length === 0) return 'No protocol fields were dissected for this session.'
  return entries
    .filter(([name]) => !name.endsWith('_truncated'))
    .map(([name, value]) => {
      if (Array.isArray(value)) {
        if (value.length > 0 && value[0] !== null && typeof value[0] === 'object') {
          return `${name}: ${value
            .map((item) => Object.values(item as Record<string, unknown>).join(' '))
            .join(' | ')}`
        }
        return `${name}: ${value.join(', ')}`
      }
      if (value !== null && typeof value === 'object') {
        return `${name}: ${Object.entries(value as Record<string, number>)
          .map(([key, count]) => `${key}×${String(count)}`)
          .join(', ')}`
      }
      return `${name}: ${String(value)}`
    })
    .join('\n')
}

interface SessionsContentProps {
  family: ProtocolFamily
}

function SessionsContent({ family }: SessionsContentProps) {
  const { analysisId } = useAnalysis()
  const filters = useUrlFilters(URL_KEYS, 100)
  const queryClient = useQueryClient()

  const familyProtocols = FAMILY_PROTOCOLS[family]
  const protocolRaw = filters.get('protocol')
  const protocol = familyProtocols.includes(protocolRaw as never) ? protocolRaw : ''
  const search = filters.get('search')
  const flagged = filters.getBool('flagged')
  const sortRaw = filters.get('sort')
  const sort = SORT_COLUMNS.some((column) => column.value === sortRaw) ? sortRaw : 'start_time'
  /* The direction is a real parameter, not decoration: the sort control offers both and the
     endpoint defaults to descending, so the newest session comes first until asked otherwise. */
  const order = filters.get('order') === 'asc' ? 'asc' : 'desc'
  const page = filters.getNumber('page', 1)
  const pageSize = filters.getNumber('page_size', 100)
  const selectedId = filters.getNumber('sel', 0)

  const params = useMemo(
    () => ({
      family,
      protocol: protocol === '' ? undefined : protocol,
      q: search === '' ? undefined : search,
      flagged: flagged ? true : undefined,
      sort,
      order,
      page,
      page_size: pageSize,
    }),
    [family, protocol, search, flagged, sort, order, page, pageSize],
  )

  const query = useQuery({
    queryKey: ['protocol-sessions', analysisId, params],
    queryFn: () => protocolsApi.list(analysisId as string, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const summary = useQuery({
    queryKey: ['protocol-summary', analysisId],
    queryFn: () => protocolsApi.summary(analysisId as string),
    enabled: Boolean(analysisId),
  })

  const rescan = useMutation({
    mutationFn: () => protocolsApi.rescan(analysisId as string),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['protocol-sessions', analysisId] })
      void queryClient.invalidateQueries({ queryKey: ['protocol-summary', analysisId] })
    },
  })

  const detail = useQuery({
    queryKey: ['protocol-session', analysisId, selectedId],
    queryFn: () => protocolsApi.get(analysisId as string, selectedId),
    enabled: Boolean(analysisId) && selectedId > 0,
  })

  const data = query.data
  const rows = data?.rows ?? []
  const totals = data?.counts
  const scope = FAMILY_SCOPE[family]

  const setSort = useCallback(
    (nextSort: string, nextOrder: string) =>
      filters.patch({ sort: nextSort, order: nextOrder === 'asc' ? 'asc' : 'desc' }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [filters],
  )

  const flaggedOnPage = rows.filter((row) => (row.flags?.length ?? 0) > 0).length

  const rescanButton = (
    <button
      type="button"
      className="btn"
      onClick={() => rescan.mutate()}
      disabled={rescan.isPending || !analysisId}
      title="Re-run the protocol extraction for this capture (POST /protocols/rescan). It rewrites only protocol_sessions."
    >
      {rescan.isPending ? (
        <Loader2 size={13} className="animate-spin" aria-hidden />
      ) : (
        <RefreshCw size={13} aria-hidden />
      )}
      {rescan.isPending ? 'Re-reading the capture…' : 'Re-read protocols'}
    </button>
  )

  return (
    <div className="flex flex-col gap-3">
      <ScopeNote title={scope.title} items={scope.items} caveat={scope.caveat} collapsible defaultOpen={false} />

      <FlagLegend
        catalog={SESSION_FLAG_CATALOG}
        keys={SESSION_FLAG_KEYS}
        title={`How to read ${SECTIONS[family].label} lead flags`}
        defaultOpen={false}
        note={THRESHOLD_NOTE}
      />

      {query.isLoading && !data ? (
        <LoadingState label="Reading the protocol sessions…" rows={6} />
      ) : query.error ? (
        <ErrorState
          error={query.error}
          title="Could not load the protocol sessions"
          onRetry={() => void query.refetch()}
        />
      ) : data && !data.extracted ? (
        /* The table is empty *and* nothing was ever extracted for this analysis: a capture
           indexed before this section existed. Reported as such, with the control that
           fixes it, rather than as an empty capture. */
        <Panel title="This capture has not been read for these protocols" actions={rescanButton}>
          <div className="flex flex-col gap-2 p-3">
            <p className="text-xs leading-relaxed text-muted">
              The analysis holds no protocol session rows at all. That means the extraction stage has not
              run for it — not that the capture is free of {SECTIONS[family].label.toLowerCase()} traffic.
              Re-reading dissects the stored capture again and fills this table; it changes no other table.
            </p>
            {rescan.error ? (
              <SectionNote tone="warn">
                {`The re-read request failed: ${String(
                  (rescan.error as { message?: string }).message ?? rescan.error,
                )}. Nothing was changed.`}
              </SectionNote>
            ) : null}
            {rescan.data ? (
              <SectionNote>
                {typeof rescan.data.job_id === 'string' && rescan.data.job_id !== ''
                  ? `Re-reading started as job ${rescan.data.job_id}. The table fills in as the extraction finishes.`
                  : 'Re-reading started. The table fills in as the extraction finishes.'}
              </SectionNote>
            ) : null}
            {summary.data?.note ? <p className="text-2xs text-faint">{summary.data.note}</p> : null}
          </div>
        </Panel>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 px-1">
            <span className="text-2xs text-faint">
              {familyProtocols.map((name) => PROTOCOL_LABELS[name]).join(' · ')}
            </span>
            {totals ? (
              <span className="text-2xs text-muted">
                <span className="mono text-text">{formatNumber(totals.sessions)}</span> session(s),{' '}
                <span className="mono text-text">{formatNumber(totals.flagged)}</span> flagged,{' '}
                <span className="mono text-text">{formatBytes(totals.bytes)}</span>
              </span>
            ) : null}
          </div>

          <Panel
            title={`${SECTIONS[family].label} sessions`}
            subtitle={
              data
                ? `${formatNumber(data.total)} matching session${data.total === 1 ? '' : 's'}${
                    filters.any ? ' (filters active)' : ''
                  }`
                : undefined
            }
            actions={rescanButton}
          >
            <FilterStrip
              actions={
                <>
                  <SortSelect columns={SORT_COLUMNS} sort={sort} order={order} onChange={setSort} />
                  <ResetFiltersButton onClick={filters.clear} disabled={!filters.any} />
                </>
              }
            >
              {familyProtocols.length > 1 ? (
                <SelectFilter
                  label="protocol"
                  value={protocol}
                  anyLabel="all"
                  options={familyProtocols.map((name) => ({
                    value: name,
                    label: PROTOCOL_LABELS[name],
                  }))}
                  onChange={(value) => filters.patch({ protocol: value || null })}
                  width="w-24"
                />
              ) : null}
              <TextFilter
                label="search"
                value={search}
                placeholder="address, share, file name, user…"
                onChange={(value) => filters.patch({ search: value || null })}
                width="w-56"
                title="Case-insensitive substring over endpoints, server and share names, file names, paths, user names and command arguments"
              />
              <CheckFilter
                label="flagged only"
                checked={flagged}
                onChange={(next) => filters.patch({ flagged: next ? 'true' : null })}
                title="Only sessions carrying at least one lead flag"
              />
            </FilterStrip>

            {rows.length === 0 ? (
              <EmptyState
                icon={ShieldQuestion}
                title={
                  flagged
                    ? `No ${SECTIONS[family].label} session carries a lead flag`
                    : filters.any
                      ? 'No session matches these filters'
                      : `No ${SECTIONS[family].label} session in this capture`
                }
                description={
                  filters.any
                    ? 'The extraction ran and these filters excluded everything it found. Clearing them shows the whole table.'
                    : `TShark dissected no ${familyProtocols
                        .map((name) => PROTOCOL_LABELS[name])
                        .join(', ')} session in this capture. An empty table is a statement about this capture, not a statement that none of it happened: a session taken mid-flight, a non-standard port the dissector was not told to read, or traffic inside a tunnel will not appear here.`
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="dt">
                  <thead>
                    <tr>
                      <th>start</th>
                      <th>protocol</th>
                      <th>client</th>
                      <th>server</th>
                      <th>duration</th>
                      <th>packets</th>
                      <th>bytes (→ / ←)</th>
                      <th>what it said</th>
                      <th>flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr
                        key={row.id}
                        className={clsx(row.id === selectedId && 'selected', 'cursor-pointer')}
                        onClick={() => filters.patch({ sel: row.id === selectedId ? null : row.id })}
                      >
                        <td>{formatTimestamp(row.start_time)}</td>
                        <td>{PROTOCOL_LABELS[row.protocol] ?? row.protocol}</td>
                        <td>
                          <MonoCell maxWidth={170}>
                            {`${row.client_ip ?? '—'}:${String(row.client_port ?? '—')}`}
                          </MonoCell>
                        </td>
                        <td>
                          <MonoCell maxWidth={170}>
                            {`${row.server_ip ?? '—'}:${String(row.server_port ?? '—')}`}
                          </MonoCell>
                        </td>
                        <td>{formatDuration(row.duration)}</td>
                        <td className="text-right">{formatNumber(row.packets)}</td>
                        <td>
                          {`${formatBytes(row.client_bytes)} / ${formatBytes(row.server_bytes)}`}
                        </td>
                        <td>
                          <span className="block max-w-[26rem] truncate" title={summaryTitle(row)}>
                            {sessionSummary(row.protocol, row.detail ?? {}) || '—'}
                          </span>
                        </td>
                        <td>
                          <LeadFlagList
                            flags={row.flags}
                            catalog={SESSION_FLAG_CATALOG}
                            emptyText="—"
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {data?.capped ? (
              <SectionNote tone="warn">
                {`This analysis holds ${formatNumber(data.stored_rows)} session(s) and this response could carry ${formatNumber(
                  data.session_cap,
                )}. Narrow the filters — a protocol, a search term or the flagged-only switch — to reach the rest; nothing is hidden, and the count above is the table's own.`}
              </SectionNote>
            ) : null}

            {data ? (
              <Pagination
                page={data.page}
                pageSize={data.page_size}
                total={data.total}
                onPageChange={(next) => filters.patch({ page: next }, { resetPage: false })}
                onPageSizeChange={(next) => filters.patch({ page_size: next })}
                disabled={query.isFetching}
              />
            ) : null}

            <SectionNote>
              {`One row per ${SECTIONS[family].label} session, with the endpoints, times and volume in each direction. ${
                flaggedOnPage > 0
                  ? `${formatNumber(flaggedOnPage)} row(s) on this page carry a lead flag: open a row for what fired and what it does not prove.`
                  : 'No row on this page carries a lead flag.'
              } Every number is read from this analysis' indexed tables — the capture is not dissected again to draw this page.`}
            </SectionNote>
          </Panel>

          {selectedId > 0 ? (
            detail.isLoading ? (
              <LoadingState label="Reading this session…" rows={4} />
            ) : detail.error ? (
              <ErrorState
                error={detail.error}
                title="Could not load this session"
                onRetry={() => void detail.refetch()}
              />
            ) : detail.data ? (
              <SessionDetail
                session={detail.data}
                onClose={() => filters.patch({ sel: null })}
              />
            ) : null
          ) : null}
        </>
      )}
    </div>
  )
}

/** One of the five protocol-session pages. */
export function ProtocolSessionsPage({ family }: { family: ProtocolFamily }) {
  const section = SECTIONS[family]
  return (
    <Page section={section}>
      <AnalysisGuard
        emptyDescription={`Upload a PCAP/PCAPNG capture or select an existing analysis in the top bar to read its ${section.label} sessions. This section reads only tables that already exist, so it needs a finished analysis.`}
      >
        <SessionsContent family={family} />
      </AnalysisGuard>
    </Page>
  )
}

export default ProtocolSessionsPage
