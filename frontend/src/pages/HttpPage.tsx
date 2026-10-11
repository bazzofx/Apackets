import { useCallback, useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Copy, Globe, RefreshCw, X } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import { BodyPreview, HeadersTable } from '@/components/protocols/HeadersTable'
import { DetailGrid, DetailItem, ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import {
  CheckFilter,
  FilterStrip,
  ResetFiltersButton,
  SelectFilter,
  SortSelect,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import {
  FlagExplanations,
  FlagLegend,
  HTTP_FLAG_CATALOG,
  HTTP_FLAG_KEYS,
  LeadFlagList,
} from '@/components/protocols/ProtocolFlags'
import { useAnalysis } from '@/hooks/useAnalysis'
import { httpApi, type HttpListParams } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { HttpTransaction, SortOrder } from '@/types'
import { EMPTY, formatBytes, formatNumber, formatTimestamp } from '@/utils/format'

/** Sort columns the HTTP endpoint allows (contract §5). */
const SORT_COLUMNS = [
  { value: 'time_epoch', label: 'time' },
  { value: 'method', label: 'method' },
  { value: 'host', label: 'host' },
  { value: 'uri', label: 'uri' },
  { value: 'status_code', label: 'status' },
  { value: 'response_len', label: 'response length' },
]

/** Every query-string key this page owns. */
const URL_KEYS = [
  'method',
  'host',
  'uri',
  'status',
  'client_ip',
  'server_ip',
  'user_agent',
  'search',
  'interesting',
  'sort',
  'order',
  'page',
  'page_size',
  'tx',
]

/** Statuses rendered with a colour; informational only, not a verdict. */
function statusTone(code: number | null): string {
  if (code === null) return 'text-faint'
  if (code >= 500) return 'text-red-300'
  if (code >= 400) return 'text-warn'
  if (code >= 300) return 'text-accent2'
  if (code >= 200) return 'text-ok'
  return 'text-muted'
}

function endpoint(ip: string | null, port: number | null): string {
  if (ip === null) return EMPTY
  return port === null ? ip : `${ip}:${port}`
}

/* ------------------------------------------------------------------ */
/* Detail                                                              */
/* ------------------------------------------------------------------ */

interface TransactionDetailProps {
  analysisId: string
  transactionId: number
  onClose: () => void
}

/** Full request/response view for one transaction (`GET /http/{id}`). */
function TransactionDetail({ analysisId, transactionId, onClose }: TransactionDetailProps) {
  const query = useQuery<HttpTransaction>({
    queryKey: ['http-detail', analysisId, transactionId],
    queryFn: () => httpApi.get(analysisId, transactionId),
  })

  return (
    <Panel
      title="Transaction detail"
      subtitle={`${analysisId.slice(0, 12)}… · transaction ${transactionId}`}
      flush
      actions={
        <>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => void query.refetch()}
            disabled={query.isFetching}
            title="Re-read this transaction"
          >
            <RefreshCw size={12} aria-hidden />
            Refresh
          </button>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={onClose}
            title="Close the detail view"
          >
            <X size={12} aria-hidden />
            Close
          </button>
        </>
      }
    >
      {query.isLoading ? (
        <LoadingState label="Loading transaction…" rows={4} />
      ) : query.error ? (
        <ErrorState
          error={query.error}
          title="Could not load the transaction"
          onRetry={() => void query.refetch()}
        />
      ) : !query.data ? (
        <div className="px-3 py-6">
          <SectionNote>The backend returned no transaction for this id.</SectionNote>
        </div>
      ) : (
        <TransactionDetailBody transaction={query.data} />
      )}
    </Panel>
  )
}

function TransactionDetailBody({ transaction: tx }: { transaction: HttpTransaction }) {
  const delay =
    tx.response_time !== null && tx.time_epoch !== null ? tx.response_time - tx.time_epoch : null
  const requestLine = `${tx.method ?? '?'} ${tx.uri ?? '/'} ${tx.version ?? ''}`.trim()
  const statusLine =
    tx.status_code === null
      ? null
      : `${tx.status_code}${tx.status_text ? ` ${tx.status_text}` : ''}`

  return (
    <div className="flex flex-col divide-y divide-border">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2">
        <span className="mono text-xs text-text">{requestLine}</span>
        <CopyButton value={tx.full_uri ?? tx.uri ?? requestLine} label="Copy the request line" />
        <span className={clsx('mono text-xs', statusTone(tx.status_code))}>
          {statusLine ?? <span className="text-faint">no response status dissected</span>}
        </span>
        {tx.full_uri ? (
          <span className="chip border-border2 bg-surface2 text-muted" title="full_uri">
            {tx.full_uri}
          </span>
        ) : null}
        <CopyButton value={transactionText(tx)} label="Copy the whole transaction as text" />
      </div>

      <div className="p-3">
        <DetailGrid columns={3}>
          <DetailItem label="Time" value={formatTimestamp(tx.time_epoch)} />
          <DetailItem
            label="Response time"
            value={formatTimestamp(tx.response_time)}
            unavailableReason="No response packet was matched to this request in the capture."
          />
          <DetailItem
            label="Response delay"
            value={delay === null ? null : `${delay.toFixed(6)} s`}
            unavailableReason="Both a request and a matching response time are needed to compute a delay."
          />
          <DetailItem label="Client" value={endpoint(tx.client_ip, tx.client_port)} />
          <DetailItem label="Server" value={endpoint(tx.server_ip, tx.server_port)} />
          <DetailItem label="Stream" value={tx.stream_id} />
          <DetailItem label="Method" value={tx.method} />
          <DetailItem label="Host" value={tx.host} unavailableReason="No Host header was dissected for this request." />
          <DetailItem label="Version" value={tx.version} />
          <DetailItem label="Status code" value={tx.status_code} tone={tx.status_code === null ? 'default' : 'warn'} />
          <DetailItem label="Status phrase" value={tx.status_text} />
          <DetailItem label="Content-Type" value={tx.content_type} />
          <DetailItem label="Full URI" value={tx.full_uri} unavailableReason="No host was available, so no full URI could be built." />
          <DetailItem label="User-Agent" value={tx.user_agent} unavailableReason="The request carried no User-Agent header." />
          <DetailItem label="Referer" value={tx.referer} unavailableReason="The request carried no Referer header." />
          <DetailItem label="Server header" value={tx.server_header} />
          <DetailItem label="Request length" value={formatBytes(tx.request_len)} />
          <DetailItem label="Response length" value={formatBytes(tx.response_len)} />
          <DetailItem
            label="Request body"
            value={tx.request_body_size === null ? null : formatBytes(tx.request_body_size)}
          />
          <DetailItem
            label="Response body"
            value={tx.response_body_size === null ? null : formatBytes(tx.response_body_size)}
          />
          <DetailItem
            label="Response truncated"
            mono={false}
            tone={tx.response_body_truncated ? 'warn' : 'default'}
            value={tx.response_body_truncated === null ? null : tx.response_body_truncated ? 'yes' : 'no'}
          />
          <DetailItem label="Request packet" value={tx.request_packet} />
          <DetailItem label="Response packet" value={tx.response_packet} />
        </DetailGrid>
      </div>

      <div className="flex flex-col gap-2 p-3">
        <span className="text-2xs uppercase tracking-wider text-muted">Lead flags</span>
        <FlagExplanations
          flags={tx.flags}
          catalog={HTTP_FLAG_CATALOG}
          intro="Recorded by the HTTP analyser from the fields below. Each one is something to check against the rest of the capture."
        />
      </div>

      <div className="grid grid-cols-1 gap-3 p-3 xl:grid-cols-2">
        <div className="flex flex-col gap-2">
          <HeadersTable
            headers={tx.request_headers}
            label="Request headers"
            emptyText="No request headers are stored for this transaction."
          />
          <BodyPreview
            label="Request body"
            body={tx.request_body}
            size={tx.request_body_size}
            contentType={tx.request_headers?.['Content-Type'] ?? null}
            emptyText="This request carried no body."
          />
        </div>
        <div className="flex flex-col gap-2">
          <HeadersTable
            headers={tx.response_headers}
            label="Response headers"
            emptyText="No response headers are stored for this transaction."
          />
          <BodyPreview
            label="Response body"
            body={tx.response_body}
            size={tx.response_body_size}
            truncated={tx.response_body_truncated}
            contentType={tx.content_type}
            emptyText="This response carried no body."
          />
        </div>
      </div>
    </div>
  )
}

/** Plain-text rendering of a transaction, for the clipboard. */
function transactionText(tx: HttpTransaction): string {
  const lines: string[] = []
  lines.push(`${tx.method ?? '?'} ${tx.uri ?? '/'} ${tx.version ?? ''}`.trim())
  for (const [name, value] of Object.entries(tx.request_headers ?? {})) {
    lines.push(`${name}: ${value}`)
  }
  if (tx.request_body) lines.push('', tx.request_body)
  lines.push('', '---', '')
  lines.push(
    tx.status_code === null
      ? 'no response status'
      : `${tx.version ?? 'HTTP'} ${tx.status_code} ${tx.status_text ?? ''}`.trim(),
  )
  for (const [name, value] of Object.entries(tx.response_headers ?? {})) {
    lines.push(`${name}: ${value}`)
  }
  if (tx.response_body) lines.push('', tx.response_body)
  return lines.join('\n')
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

function HttpContent() {
  const { analysisId } = useAnalysis()
  const filters = useUrlFilters(URL_KEYS, 100)

  const page = filters.getNumber('page', 1)
  const pageSize = filters.getNumber('page_size', 100)
  const sort = filters.get('sort') || 'time_epoch'
  const order = (filters.get('order') || 'asc') as SortOrder
  const status = filters.get('status')
  const interesting = filters.getBool('interesting')

  const params = useMemo<HttpListParams>(
    () => ({
      page,
      page_size: pageSize,
      sort,
      order,
      method: filters.get('method') || undefined,
      host: filters.get('host') || undefined,
      uri: filters.get('uri') || undefined,
      status: status || undefined,
      client_ip: filters.get('client_ip') || undefined,
      server_ip: filters.get('server_ip') || undefined,
      user_agent: filters.get('user_agent') || undefined,
      search: filters.get('search') || undefined,
      interesting: interesting ? true : undefined,
    }),
    // The filter helpers are re-derived from the URL on every render, so this
    // object is rebuilt whenever the component renders. react-query hashes the
    // query key structurally, so an unchanged query string still produces no new
    // request.
    [filters, page, pageSize, sort, order, status, interesting],
  )

  const query = useQuery({
    queryKey: ['http', analysisId, params],
    queryFn: () => httpApi.list(analysisId as string, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const selectedId = filters.getNumber('tx', 0)
  const data = query.data
  const items = data?.items ?? []
  const methods = data?.methods ?? []
  const hosts = data?.hosts ?? []
  const statusClasses = data?.status_classes ?? {}
  const flaggedOnPage = items.filter((item) => (item.flags?.length ?? 0) > 0).length

  const setSort = useCallback(
    (nextSort: string, nextOrder: string) => filters.patch({ sort: nextSort, order: nextOrder }),
    [filters],
  )

  const flagLegendNote =
    'Status codes are facts about the response. The flags above are patterns matched in the request fields — a 4xx alone, or a literal IP Host header alone, is not evidence of anything.'

  return (
    <div className="flex flex-col gap-3">
      <ScopeNote
        title="What this page can and cannot show"
        items={[
          { can: true, text: 'Every HTTP request and response TShark dissected from this capture: method, host, URI, version, status, headers and message lengths.' },
          { can: true, text: 'Request and response body previews where the stream could be reassembled and every message aligned with its row.' },
          { can: true, text: 'Lead flags recorded by the analyser, with the reasoning for each one.' },
          { can: false, text: 'HTTPS traffic. TLS payloads are not decrypted anywhere in this app, so encrypted requests and responses never appear on this page.' },
          { can: false, text: 'Message lengths and bodies for streams that could not be reassembled cleanly: those fields stay empty rather than being estimated.' },
          { can: false, text: 'Anything past the configured body preview limit, and header fields TShark did not dissect.' },
        ]}
        caveat={
          <>
            An empty table means no cleartext HTTP was found in this capture — it is not a statement
            that the capture is clean. Most web traffic is HTTPS, whose payloads this app does not
            decrypt.
          </>
        }
      />

      <Panel
        title="Status summary"
        subtitle="counts over every HTTP transaction in this analysis (not the current filter)"
        actions={
          <>
            {query.isFetching ? (
              <span className="text-2xs text-faint" aria-live="polite">
                updating…
              </span>
            ) : null}
            <button
              type="button"
              className="btn px-1.5 py-1"
              onClick={() => void query.refetch()}
              title="Re-read the transaction list"
            >
              <RefreshCw size={12} aria-hidden />
              Refresh
            </button>
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-1.5">
          {(data?.total ?? 0) === 0 && Object.keys(statusClasses).length === 0 ? (
            <span className="text-xs text-faint">No transactions stored for this analysis.</span>
          ) : null}
          {Object.entries(statusClasses).map(([cls, count]) => (
            <button
              key={cls}
              type="button"
              className={clsx(
                'chip',
                status === cls
                  ? 'border-accent/60 bg-accent/20 text-accent2'
                  : 'border-border2 bg-surface2 text-muted hover:border-accent/50',
              )}
              title={`Show only ${cls} responses`}
              onClick={() => filters.patch({ status: status === cls ? null : cls })}
            >
              {cls} · {formatNumber(count)}
            </button>
          ))}
          {status !== '' ? (
            <button
              type="button"
              className="chip border-accent/60 bg-accent/20 text-accent2"
              title="Clear the status filter"
              onClick={() => filters.patch({ status: null })}
            >
              status = {status} <X size={10} aria-hidden />
            </button>
          ) : null}
          <span className="ml-2 text-2xs text-faint">
            {formatNumber(methods.length)} method{methods.length === 1 ? '' : 's'} ·{' '}
            {formatNumber(hosts.length)} host{hosts.length === 1 ? '' : 's'} observed
            {items.length > 0 ? ` · ${formatNumber(flaggedOnPage)} of ${formatNumber(items.length)} rows on this page carry lead flags` : ''}
          </span>
        </div>
      </Panel>

      <FlagLegend catalog={HTTP_FLAG_CATALOG} keys={HTTP_FLAG_KEYS} note={flagLegendNote} />

      <Panel
        title="HTTP transactions"
        subtitle={
          data
            ? `${formatNumber(data.total)} matching transaction${data.total === 1 ? '' : 's'}${filters.any ? ' (filters active)' : ''}`
            : 'loading…'
        }
        flush
      >
        <FilterStrip
          actions={
            <>
              <SortSelect columns={SORT_COLUMNS} sort={sort} order={order} onChange={setSort} />
              <ResetFiltersButton onClick={filters.clear} disabled={!filters.any} />
            </>
          }
        >
          <SelectFilter
            label="Method"
            value={filters.get('method')}
            options={methods.map((method) => ({ value: method, label: method }))}
            onChange={(value) => filters.patch({ method: value })}
            width="w-28"
            title="Exact method match. Values are the methods actually stored in this analysis."
          />
          <TextFilter
            label="Host"
            value={filters.get('host')}
            placeholder="any host"
            listId="http-hosts"
            onChange={(value) => filters.patch({ host: value })}
            title="Substring match on the Host header."
          />
          <datalist id="http-hosts">
            {hosts.map((host) => (
              <option key={host} value={host} />
            ))}
          </datalist>
          <TextFilter
            label="URI"
            value={filters.get('uri')}
            placeholder="/path"
            onChange={(value) => filters.patch({ uri: value })}
            title="Substring match on the request URI."
          />
          <TextFilter
            label="Status"
            value={status}
            placeholder="404 or 4xx"
            listId="http-status-classes"
            width="w-32"
            onChange={(value) => filters.patch({ status: value })}
            title="An exact status code (404) or a class (4xx). The backend supports both."
          />
          <datalist id="http-status-classes">
            {Object.keys(statusClasses).map((cls) => (
              <option key={cls} value={cls} />
            ))}
          </datalist>
          <TextFilter
            label="Client IP"
            value={filters.get('client_ip')}
            placeholder="any"
            width="w-36"
            onChange={(value) => filters.patch({ client_ip: value })}
            title="Exact client IP match."
          />
          <TextFilter
            label="Server IP"
            value={filters.get('server_ip')}
            placeholder="any"
            width="w-36"
            onChange={(value) => filters.patch({ server_ip: value })}
            title="Exact server IP match."
          />
          <TextFilter
            label="User-Agent"
            value={filters.get('user_agent')}
            placeholder="any substring"
            width="w-44"
            onChange={(value) => filters.patch({ user_agent: value })}
            title="Substring match on the User-Agent header."
          />
          <TextFilter
            label="Search"
            value={filters.get('search')}
            placeholder="URI, host or user agent"
            width="w-48"
            onChange={(value) => filters.patch({ search: value })}
            title="Substring over the request URI, the Host header, the User-Agent and the full URI."
          />
          <CheckFilter
            label="Interesting only"
            checked={interesting}
            onChange={(checked) => filters.patch({ interesting: checked ? true : null })}
            title="Only transactions that carry at least one lead flag."
          />
        </FilterStrip>

        {query.isLoading ? (
          <LoadingState label="Loading HTTP transactions…" rows={6} />
        ) : query.error ? (
          <ErrorState
            error={query.error}
            title="Could not load HTTP transactions"
            onRetry={() => void query.refetch()}
          />
        ) : items.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={Globe}
            title={filters.any ? 'No transactions match these filters' : 'No HTTP transactions in this analysis'}
            description={
              filters.any ? (
                <>
                  No transaction in this analysis satisfies every filter at once. Widen the filters,
                  or reset them to see everything the analyser stored. The “interesting only” toggle
                  is the usual culprit: most transactions carry no lead flags.
                </>
              ) : (
                <>
                  TShark dissected no cleartext HTTP messages in this capture. HTTPS traffic is not
                  decrypted by this app, so an encrypted-only capture legitimately shows nothing
                  here.
                </>
              )
            }
            action={
              filters.any ? <ResetFiltersButton onClick={filters.clear} /> : undefined
            }
          />
        ) : (
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Client</th>
                  <th>Server</th>
                  <th>Method</th>
                  <th>Host</th>
                  <th>URI</th>
                  <th>Ver</th>
                  <th className="text-right">Status</th>
                  <th>User-Agent</th>
                  <th>Referer</th>
                  <th>Content-Type</th>
                  <th className="text-right">Req</th>
                  <th className="text-right">Resp</th>
                  <th>Lead flags</th>
                </tr>
              </thead>
              <tbody>
                {items.map((tx) => (
                  <tr
                    key={tx.id}
                    className={clsx('cursor-pointer', tx.id === selectedId && 'selected')}
                    tabIndex={0}
                    onClick={() => filters.patch({ tx: tx.id })}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        filters.patch({ tx: tx.id })
                      }
                    }}
                    title="Open the request and response detail"
                  >
                    <td>{formatTimestamp(tx.time_epoch)}</td>
                    <td>
                      <MonoCell maxWidth={150}>{endpoint(tx.client_ip, tx.client_port)}</MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={150}>{endpoint(tx.server_ip, tx.server_port)}</MonoCell>
                    </td>
                    <td className={tx.method === null ? 'text-faint' : 'text-text'}>
                      <MonoCell>{tx.method}</MonoCell>
                    </td>
                    <td className="text-muted">
                      <MonoCell maxWidth={180}>{tx.host}</MonoCell>
                    </td>
                    <td className="text-text">
                      <MonoCell maxWidth={260}>{tx.uri}</MonoCell>
                    </td>
                    <td className="text-muted">
                      <MonoCell>{tx.version}</MonoCell>
                    </td>
                    <td className={clsx('text-right', statusTone(tx.status_code))}>
                      {tx.status_code === null ? <span className="text-faint">{EMPTY}</span> : tx.status_code}
                    </td>
                    <td className="text-muted">
                      <MonoCell maxWidth={220}>{tx.user_agent}</MonoCell>
                    </td>
                    <td className="text-muted">
                      <MonoCell maxWidth={160}>{tx.referer}</MonoCell>
                    </td>
                    <td className="text-muted">
                      <MonoCell maxWidth={160}>{tx.content_type}</MonoCell>
                    </td>
                    <td className="text-right">{formatBytes(tx.request_len)}</td>
                    <td className="text-right">{formatBytes(tx.response_len)}</td>
                    <td>
                      <LeadFlagList flags={tx.flags} catalog={HTTP_FLAG_CATALOG} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {data && items.length > 0 ? (
          <Pagination
            page={data.page}
            pageSize={data.page_size}
            total={data.total}
            disabled={query.isFetching}
            onPageChange={(next) => filters.patch({ page: next })}
            onPageSizeChange={(next) => filters.patch({ page_size: next, page: 1 })}
          />
        ) : null}
      </Panel>

      {selectedId > 0 && analysisId ? (
        <TransactionDetail
          analysisId={analysisId}
          transactionId={selectedId}
          onClose={() => filters.patch({ tx: null })}
        />
      ) : items.length > 0 ? (
        <FilterStrip className="rounded border border-border bg-surface">
          <Copy size={12} className="text-faint" aria-hidden />
          <span className="text-2xs text-faint">
            Select a row to open its request and response headers, body previews and lead flags.
            Bodies are previews: the stored text can be cut at the backend&apos;s preview limit.
          </span>
        </FilterStrip>
      ) : null}

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <Globe size={12} aria-hidden />
        <span>
          Cleartext HTTP only — TLS payloads are never decrypted. Values shown as {EMPTY} are absent
          from the capture, never guessed. Hover a column header or a flag badge for what it means.
        </span>
      </div>
    </div>
  )
}

/** HTTP analysis — cleartext request/response transactions. */
export function HttpPage() {
  return (
    <Page section={SECTIONS.http}>
      <AnalysisGuard>
        <HttpContent />
      </AnalysisGuard>
    </Page>
  )
}

export default HttpPage
