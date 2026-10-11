import { useCallback, useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Network, RefreshCw, X } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import { DnsAnswers, DnsShapeMetrics } from '@/components/protocols/DnsAnswers'
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
  DNS_FLAG_CATALOG,
  DNS_FLAG_KEYS,
  FlagExplanations,
  FlagLegend,
  LeadFlagList,
} from '@/components/protocols/ProtocolFlags'
import { useAnalysis } from '@/hooks/useAnalysis'
import { dnsApi, type DnsListParams } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { DnsDomainRow, DnsQuery, SortOrder } from '@/types'
import { EMPTY, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'

/** Sort columns the DNS endpoint allows (contract §5). */
const SORT_COLUMNS = [
  { value: 'time_epoch', label: 'time' },
  { value: 'query_name', label: 'query name' },
  { value: 'query_type', label: 'query type' },
  { value: 'rcode_name', label: 'response code' },
  { value: 'response_delay', label: 'response delay' },
]

/** Every query-string key this page owns. */
const URL_KEYS = [
  'view',
  'domain',
  'client_ip',
  'server_ip',
  'qtype',
  'rcode',
  'search',
  'unanswered',
  'nxdomain',
  'suspicious',
  'sort',
  'order',
  'page',
  'page_size',
  'sel',
  'dsearch',
  'dsort',
]

/** The backend's own `dns_high_volume` rule default, quoted so the number is explained. */
const HIGH_VOLUME_THRESHOLD = 100

type View = 'queries' | 'domains'
type DomainSort = 'queries' | 'name' | 'clients' | 'last_seen'

function rcodeTone(rcode: string | null): string {
  if (rcode === null) return 'text-faint'
  const upper = rcode.toUpperCase()
  if (upper === 'NOERROR') return 'text-ok'
  if (upper === 'NXDOMAIN' || upper === 'SERVFAIL' || upper === 'REFUSED') return 'text-warn'
  return 'text-muted'
}

/** Tooltip summarising the parsed answer records of a row. */
function answerSummary(row: DnsQuery): string {
  const records = row.answers ?? []
  if (records.length === 0) {
    return row.rcode_name && row.rcode_name !== 'NOERROR'
      ? `No answer records stored (response code ${row.rcode_name}).`
      : 'No answer records stored for this row.'
  }
  return records
    .map((record) => {
      if (record !== null && typeof record === 'object' && !Array.isArray(record)) {
        return Object.entries(record as Record<string, unknown>)
          .map(([key, value]) => `${key}=${String(value)}`)
          .join(' ')
      }
      return String(record)
    })
    .join('\n')
}

/* ------------------------------------------------------------------ */
/* Detail                                                              */
/* ------------------------------------------------------------------ */

interface QueryDetailProps {
  analysisId: string
  rowId: number
  onClose: () => void
}

/** One stored DNS row with parsed answers and the computed name shape. */
function QueryDetail({ analysisId, rowId, onClose }: QueryDetailProps) {
  const query = useQuery<DnsQuery>({
    queryKey: ['dns-detail', analysisId, rowId],
    queryFn: () => dnsApi.get(analysisId, rowId),
  })

  return (
    <Panel
      title="Query detail"
      subtitle={`${analysisId.slice(0, 12)}… · row ${rowId}`}
      flush
      actions={
        <>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => void query.refetch()}
            disabled={query.isFetching}
            title="Re-read this row"
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
        <LoadingState label="Loading DNS row…" rows={4} />
      ) : query.error ? (
        <ErrorState
          error={query.error}
          title="Could not load the DNS row"
          onRetry={() => void query.refetch()}
        />
      ) : !query.data ? (
        <div className="px-3 py-6">
          <SectionNote>The backend returned no DNS row for this id.</SectionNote>
        </div>
      ) : (
        <QueryDetailBody row={query.data} />
      )}
    </Panel>
  )
}

function QueryDetailBody({ row }: { row: DnsQuery }) {
  return (
    <div className="flex flex-col divide-y divide-border">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2">
        <span className="mono text-xs text-text" title={row.query_name ?? undefined}>
          {row.query_name ?? EMPTY}
        </span>
        <CopyButton value={row.query_name} label="Copy the query name" />
        <span className="chip border-border2 bg-surface2 text-muted">
          {row.query_type ?? 'type ?'}
        </span>
        <span className={clsx('chip border-border2 bg-surface2', rcodeTone(row.rcode_name))}>
          {row.rcode_name ?? (row.rcode === null ? 'no rcode' : String(row.rcode))}
        </span>
      </div>

      <div className="p-3">
        <DetailGrid columns={3}>
          <DetailItem label="Time" value={formatTimestamp(row.time_epoch)} />
          <DetailItem label="Client" value={row.client_ip} />
          <DetailItem label="DNS server" value={row.server_ip} />
          <DetailItem label="Query packet" value={row.packet_number} />
          <DetailItem
            label="Response packet"
            value={row.response_packet}
            unavailableReason="No response for this query appears in the capture, so the query is unanswered within this file."
          />
          <DetailItem label="Response time" value={formatTimestamp(row.response_time)} />
          <DetailItem
            label="Response delay"
            value={row.response_delay === null ? null : `${row.response_delay.toFixed(6)} s`}
          />
          <DetailItem label="DNS transaction id" value={row.dns_id} />
          <DetailItem
            label="Row is"
            mono={false}
            value={row.is_response === null ? null : row.is_response ? 'response' : 'query'}
          />
          <DetailItem label="Response code" value={row.rcode_name} />
          <DetailItem label="Rcode value" value={row.rcode} />
          <DetailItem
            label="Authoritative"
            mono={false}
            value={row.authoritative === null ? null : row.authoritative ? 'yes' : 'no'}
          />
          <DetailItem
            label="Truncated (TC bit)"
            mono={false}
            tone={row.truncated ? 'warn' : 'default'}
            value={row.truncated === null ? null : row.truncated ? 'yes — answer cut short' : 'no'}
          />
          <DetailItem
            label="Minimum TTL"
            value={row.min_ttl === null ? null : `${formatNumber(row.min_ttl)} s`}
          />
        </DetailGrid>
      </div>

      <div className="p-3">
        <DnsAnswers
          answers={row.answers}
          answerIps={row.answer_ips}
          cnames={row.cnames}
          minTtl={row.min_ttl}
          rcodeName={row.rcode_name}
          queryType={row.query_type}
        />
      </div>

      <div className="p-3">
        <DnsShapeMetrics
          nameLength={row.name_length}
          labelCount={row.label_count}
          longestLabel={row.longest_label}
          entropy={row.entropy}
          recordedFlags={row.flags}
        />
      </div>

      <div className="flex flex-col gap-2 p-3">
        <span className="text-2xs uppercase tracking-wider text-muted">Lead flags on this row</span>
        <FlagExplanations
          flags={row.flags}
          catalog={DNS_FLAG_CATALOG}
          intro="Recorded by the DNS analyser from the fields above. Read each one as a question to check, not as an answer."
        />
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Panels                                                              */
/* ------------------------------------------------------------------ */

interface TopClientsPanelProps {
  clients: { client_ip: string; count: number }[]
  /** Unfiltered query count for the analysis, or null when it could not be read. */
  totalQueries: number | null
  selected: string
  onSelect: (clientIp: string) => void
  loading: boolean
}

/** Noisiest clients by query count, with the volume rule's own threshold quoted. */
function TopClientsPanel({
  clients,
  totalQueries,
  selected,
  onSelect,
  loading,
}: TopClientsPanelProps) {
  const busiest = clients.length > 0 ? clients[0] : null
  return (
    <Panel
      title="Noisiest clients"
      subtitle="top 10 by query count over the whole analysis — the table filters below do not apply here"
      flush
    >
      {loading ? (
        <LoadingState label="Loading client counts…" rows={3} />
      ) : clients.length === 0 ? (
        <div className="px-3 py-6 text-center text-2xs text-faint">
          No DNS query had a client address recorded, so no query volume could be attributed.
        </div>
      ) : (
        <>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Client</th>
                  <th className="text-right">Queries</th>
                  <th className="text-right">Share</th>
                  <th className="text-right">Volume</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((client) => {
                  const share =
                    totalQueries !== null && totalQueries > 0 ? client.count / totalQueries : null
                  return (
                    <tr
                      key={client.client_ip}
                      className={clsx('cursor-pointer', client.client_ip === selected && 'selected')}
                      onClick={() => onSelect(client.client_ip === selected ? '' : client.client_ip)}
                      title="Filter the query table to this client"
                    >
                      <td>
                        <MonoCell maxWidth={180}>{client.client_ip}</MonoCell>
                      </td>
                      <td className="text-right">{formatNumber(client.count)}</td>
                      <td className="text-right text-muted">
                        {share === null ? EMPTY : `${(share * 100).toFixed(1)}%`}
                      </td>
                      <td className="text-right">
                        {client.count >= HIGH_VOLUME_THRESHOLD ? (
                          <span className="chip border-warn/40 bg-warn/10 text-warn">
                            ≥ {HIGH_VOLUME_THRESHOLD} queries
                          </span>
                        ) : (
                          <span className="text-faint">below {HIGH_VOLUME_THRESHOLD}</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <div className="border-t border-border px-3 py-2">
            <SectionNote>
              {totalQueries === null
                ? 'The total number of queries in this analysis is still loading, or could not be read — no share is shown until it is known.'
                : `This analysis holds ${formatNumber(totalQueries)} DNS queries in total.`}
              {busiest
                ? ` The busiest client, ${busiest.client_ip}, accounts for ${formatNumber(
                    busiest.count,
                  )} of them.`
                : ''}{' '}
              The backend&apos;s <span className="mono">dns_high_volume</span> rule fires at{' '}
              {HIGH_VOLUME_THRESHOLD} queries from one client by default. A high count alone is not
              evidence of abuse — update checks, telemetry agents and monitoring all look like this —
              so read the names and the timing before drawing a conclusion.
            </SectionNote>
          </div>
        </>
      )}
    </Panel>
  )
}

interface DomainsPanelProps {
  domains: DnsDomainRow[]
  loading: boolean
  error: unknown
  onRetry: () => void
  search: string
  onSearch: (value: string) => void
  sort: DomainSort
  onSort: (value: DomainSort) => void
}

/** Aggregated per-domain view (`GET /dns/domains`). */
function DomainsPanel({
  domains,
  loading,
  error,
  onRetry,
  search,
  onSearch,
  sort,
  onSort,
}: DomainsPanelProps) {
  const needle = search.trim().toLowerCase()
  const rows = useMemo(() => {
    const filtered =
      needle === '' ? domains : domains.filter((row) => row.query_name.toLowerCase().includes(needle))
    const sorted = [...filtered]
    sorted.sort((a, b) => {
      if (sort === 'name') return a.query_name.localeCompare(b.query_name)
      if (sort === 'clients') return b.clients - a.clients || a.query_name.localeCompare(b.query_name)
      if (sort === 'last_seen') return (b.last_seen ?? 0) - (a.last_seen ?? 0)
      return b.queries - a.queries || a.query_name.localeCompare(b.query_name)
    })
    return sorted
  }, [domains, needle, sort])

  const atLimit = domains.length >= 500

  return (
    <Panel
      title="Domains"
      subtitle={`${formatNumber(rows.length)} of ${formatNumber(domains.length)} aggregated names${
        needle === '' ? '' : ' (filtered in the browser)'
      }`}
      flush
    >
      <FilterStrip>
        <TextFilter
          label="Domain"
          value={search}
          placeholder="substring"
          width="w-56"
          onChange={onSearch}
          title="Filters the aggregated rows already returned for this analysis; the aggregation itself is not re-run."
        />
        <SelectFilter
          label="Sort"
          value={sort === 'queries' ? '' : sort}
          anyLabel="queries (most first)"
          options={[
            { value: 'name', label: 'query name' },
            { value: 'clients', label: 'clients' },
            { value: 'last_seen', label: 'last seen' },
          ]}
          onChange={(value) => onSort((value || 'queries') as DomainSort)}
          width="w-40"
        />
      </FilterStrip>

      {loading ? (
        <LoadingState label="Loading the per-domain aggregation…" rows={6} />
      ) : error ? (
        <ErrorState error={error} title="Could not load the domain aggregation" onRetry={onRetry} />
      ) : rows.length === 0 ? (
        <EmptyState
          variant="plain"
          icon={Network}
          title={
            domains.length === 0 ? 'No domains in this analysis' : 'No domain matches that filter'
          }
          description={
            domains.length === 0
              ? 'No DNS query names were stored for this capture, so there is nothing to aggregate.'
              : 'The aggregation was returned, but no query name contains that substring.'
          }
        />
      ) : (
        <div className="overflow-auto">
          <table className="dt">
            <thead>
              <tr>
                <th>Query name</th>
                <th className="text-right">Queries</th>
                <th className="text-right">Clients</th>
                <th className="text-right">Answered</th>
                <th className="text-right">NXDOMAIN</th>
                <th>Response codes</th>
                <th>Resolved IPs</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.query_name}>
                  <td>
                    <MonoCell maxWidth={340}>{row.query_name}</MonoCell>
                  </td>
                  <td className="text-right">{formatNumber(row.queries)}</td>
                  <td className="text-right">{formatNumber(row.clients)}</td>
                  <td className="text-right text-muted">
                    {row.answered === undefined ? EMPTY : formatNumber(row.answered)}
                  </td>
                  <td
                    className={clsx('text-right', (row.nxdomain ?? 0) > 0 ? 'text-warn' : 'text-muted')}
                  >
                    {row.nxdomain === undefined ? EMPTY : formatNumber(row.nxdomain)}
                  </td>
                  <td className="text-muted">
                    {Object.entries(row.rcodes ?? {}).length === 0
                      ? EMPTY
                      : Object.entries(row.rcodes ?? {})
                          .map(([code, count]) => `${code}×${count}`)
                          .join(' ')}
                  </td>
                  <td className="text-muted">
                    <MonoCell maxWidth={300}>{(row.ips ?? []).join(', ')}</MonoCell>
                  </td>
                  <td>{formatTimestamp(row.first_seen)}</td>
                  <td>{formatTimestamp(row.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="border-t border-border px-3 py-2">
        <SectionNote>
          Aggregated by the backend from the stored query rows: one row per distinct query name with
          its query count, distinct clients, response-code breakdown, every resolved IP seen for the
          name, and the first and last observation times.
          {atLimit
            ? ' The backend returned its maximum of 500 names, so more distinct names exist in this capture and are not listed here.'
            : ' Every distinct name in this capture is listed.'}
        </SectionNote>
      </div>
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

function ViewToggle({ view, onChange }: { view: View; onChange: (view: View) => void }) {
  return (
    <div className="flex items-center gap-1 rounded border border-border bg-surface px-1.5 py-1">
      <span className="text-2xs uppercase tracking-wider text-faint">View</span>
      {(['queries', 'domains'] as const).map((option) => (
        <button
          key={option}
          type="button"
          className={clsx('btn px-2 py-1', view === option && 'btn-primary')}
          onClick={() => onChange(option)}
          title={
            option === 'queries'
              ? 'One row per DNS query, with the matching response merged in'
              : 'One row per distinct query name, aggregated by the backend'
          }
        >
          {option}
        </button>
      ))}
    </div>
  )
}

function DnsContent() {
  const { analysisId } = useAnalysis()
  const filters = useUrlFilters(URL_KEYS, 100)

  /* `clear()` keeps non-filter state, and the per-domain search is a
     client-side list filter rather than a server one, so it is cleared here. */
  const resetFilters = useCallback(() => {
    filters.clear()
    filters.patch({ dsearch: null, dsort: null }, { resetPage: false })
  }, [filters])

  const view: View = filters.get('view') === 'domains' ? 'domains' : 'queries'
  const page = filters.getNumber('page', 1)
  const pageSize = filters.getNumber('page_size', 100)
  const sort = filters.get('sort') || 'time_epoch'
  const order = (filters.get('order') || 'asc') as SortOrder
  const qtype = filters.get('qtype')
  const rcode = filters.get('rcode')
  const unanswered = filters.getBool('unanswered')
  const nxdomain = filters.getBool('nxdomain')
  const suspicious = filters.getBool('suspicious')

  const params = useMemo<DnsListParams>(
    () => ({
      page,
      page_size: pageSize,
      sort,
      order,
      domain: filters.get('domain') || undefined,
      client_ip: filters.get('client_ip') || undefined,
      server_ip: filters.get('server_ip') || undefined,
      qtype: qtype || undefined,
      rcode: rcode || undefined,
      search: filters.get('search') || undefined,
      unanswered: unanswered ? true : undefined,
      nxdomain: nxdomain ? true : undefined,
      suspicious: suspicious ? true : undefined,
    }),
    [filters, page, pageSize, sort, order, qtype, rcode, unanswered, nxdomain, suspicious],
  )

  const query = useQuery({
    queryKey: ['dns', analysisId, params],
    queryFn: () => dnsApi.list(analysisId as string, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  // `top_clients` is always computed over the whole analysis, so an unfiltered
  // total is needed in order to state a share honestly.
  const totalsQuery = useQuery({
    queryKey: ['dns-totals', analysisId],
    queryFn: () => dnsApi.list(analysisId as string, { page: 1, page_size: 1 }),
    enabled: Boolean(analysisId) && filters.any,
  })

  const domainsQuery = useQuery({
    queryKey: ['dns-domains', analysisId],
    queryFn: () => dnsApi.domains(analysisId as string),
    enabled: Boolean(analysisId) && view === 'domains',
  })

  const data = query.data
  const items = data?.items ?? []
  const qtypes = data?.qtypes ?? []
  const rcodes = data?.rcodes ?? []
  const topClients = data?.top_clients ?? []
  const selectedId = filters.getNumber('sel', 0)
  const selectedClient = filters.get('client_ip')

  const unfilteredTotal = filters.any ? (totalsQuery.data?.total ?? null) : (data?.total ?? null)

  const setSort = useCallback(
    (nextSort: string, nextOrder: string) => filters.patch({ sort: nextSort, order: nextOrder }),
    [filters],
  )

  const dsortRaw = filters.get('dsort')
  const dsort: DomainSort =
    dsortRaw === 'name' || dsortRaw === 'clients' || dsortRaw === 'last_seen' ? dsortRaw : 'queries'

  const flaggedOnPage = items.filter((item) => (item.flags?.length ?? 0) > 0).length

  return (
    <div className="flex flex-col gap-3">
      <ScopeNote
        title="What this page can and cannot show"
        items={[
          {
            can: true,
            text: 'Every DNS query TShark dissected, with the matching response merged into the same row by transaction id and client/server pair.',
          },
          {
            can: true,
            text: 'Response code, address and CNAME answers, minimum TTL, response delay, and the computed shape of the query name.',
          },
          {
            can: true,
            text: 'Lead flags recorded by the analyser, each shown with the threshold that produced it.',
          },
          {
            can: false,
            text: 'Answer data of types other than A, AAAA and CNAME — TXT text and similar record data are not stored on these rows.',
          },
          {
            can: false,
            text: 'Queries or responses whose packets are not in this capture: a query with no response in the file is reported as unanswered, which can simply mean the response was missed.',
          },
          {
            can: false,
            text: 'Encrypted DNS (DoH or DoT): those queries travel inside TLS or HTTPS and are not decrypted by this app.',
          },
        ]}
        caveat={
          <>
            An unusual-looking name is not a finding. Long labels, random-looking strings, large
            answer sets and TXT queries are produced by CDNs, cloud platforms, anti-abuse systems and
            telemetry just as readily as by abuse. Use the flags to decide what to read next, then
            decide from the evidence.
          </>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <ViewToggle view={view} onChange={(next) => filters.patch({ view: next })} />
        <span className="text-2xs text-faint">
          {view === 'queries'
            ? 'One row per query, with the response merged in.'
            : 'One row per distinct query name, aggregated by the backend.'}
        </span>
      </div>

      {view === 'queries' ? (
        <>
          <TopClientsPanel
            clients={topClients}
            totalQueries={unfilteredTotal}
            selected={selectedClient}
            loading={query.isLoading}
            onSelect={(clientIp) => filters.patch({ client_ip: clientIp || null })}
          />

          <FlagLegend
            catalog={DNS_FLAG_CATALOG}
            keys={DNS_FLAG_KEYS}
            title="How to read DNS lead flags"
            note={
              <>
                The thresholds quoted here are the defaults this backend uses (
                <span className="mono">long_label ≥ 40</span>,{' '}
                <span className="mono">long_name ≥ 100</span>,{' '}
                <span className="mono">entropy &gt; 3.8</span> with at least 3 labels,{' '}
                <span className="mono">many_ips ≥ 4</span>). They are configurable, and the detail
                view always shows which of them actually fired for a row.
              </>
            }
          />

          <Panel
            title="DNS queries"
            subtitle={
              data
                ? `${formatNumber(data.total)} matching quer${data.total === 1 ? 'y' : 'ies'}${
                    filters.any ? ' (filters active)' : ''
                  }`
                : 'loading…'
            }
            flush
          >
            <FilterStrip
              actions={
                <>
                  <SortSelect columns={SORT_COLUMNS} sort={sort} order={order} onChange={setSort} />
                  <ResetFiltersButton onClick={resetFilters} disabled={!filters.any} />
                </>
              }
            >
              <TextFilter
                label="Domain"
                value={filters.get('domain')}
                placeholder="substring of the name"
                width="w-48"
                onChange={(value) => filters.patch({ domain: value })}
                title="Substring match on the query name."
              />
              <TextFilter
                label="Client IP"
                value={selectedClient}
                placeholder="any"
                width="w-36"
                listId="dns-clients"
                onChange={(value) => filters.patch({ client_ip: value })}
                title="Exact client IP match. Click a row in the noisiest-clients panel to load one here."
              />
              <datalist id="dns-clients">
                {topClients.map((client) => (
                  <option key={client.client_ip} value={client.client_ip} />
                ))}
              </datalist>
              <TextFilter
                label="Server IP"
                value={filters.get('server_ip')}
                placeholder="any"
                width="w-36"
                onChange={(value) => filters.patch({ server_ip: value })}
                title="Exact DNS server IP match."
              />
              <SelectFilter
                label="Type"
                value={qtype}
                options={qtypes.map((type) => ({ value: type, label: type }))}
                onChange={(value) => filters.patch({ qtype: value })}
                width="w-24"
                title="Query types actually stored in this analysis."
              />
              <SelectFilter
                label="Rcode"
                value={rcode}
                options={rcodes.map((code) => ({ value: code, label: code }))}
                onChange={(value) => filters.patch({ rcode: value })}
                width="w-32"
                title="Response codes actually stored in this analysis."
              />
              <TextFilter
                label="Search"
                value={filters.get('search')}
                placeholder="name, answers or type"
                width="w-48"
                onChange={(value) => filters.patch({ search: value })}
                title="Substring over the query name, the stored answers and the query type."
              />
              <CheckFilter
                label="Unanswered only"
                checked={unanswered}
                onChange={(checked) => filters.patch({ unanswered: checked ? true : null })}
                title="Only queries with no matching response in this capture."
              />
              <CheckFilter
                label="NXDOMAIN only"
                checked={nxdomain}
                onChange={(checked) => filters.patch({ nxdomain: checked ? true : null })}
                title="Only queries the resolver answered with rcode 3 — the name does not exist."
              />
              <CheckFilter
                label="Flagged only"
                checked={suspicious}
                onChange={(checked) => filters.patch({ suspicious: checked ? true : null })}
                title="Only queries carrying at least one lead flag."
              />
            </FilterStrip>

            {query.isLoading ? (
              <LoadingState label="Loading DNS queries…" rows={6} />
            ) : query.error ? (
              <ErrorState
                error={query.error}
                title="Could not load DNS queries"
                onRetry={() => void query.refetch()}
              />
            ) : items.length === 0 ? (
              <EmptyState
                variant="plain"
                icon={Network}
                title={
                  filters.any ? 'No queries match these filters' : 'No DNS queries in this analysis'
                }
                description={
                  filters.any ? (
                    <>
                      No stored DNS row satisfies every filter at once. Reset the filters, or relax
                      the one you just added — the “unanswered only” and “NXDOMAIN only” filters in
                      particular can legitimately match nothing in a clean capture.
                    </>
                  ) : (
                    <>
                      TShark dissected no DNS messages in this capture. If it uses encrypted DNS
                      (DoH or DoT), the queries are inside TLS and are not decrypted by this app.
                    </>
                  )
                }
                action={filters.any ? <ResetFiltersButton onClick={resetFilters} /> : undefined}
              />
            ) : (
              <div className="overflow-auto">
                <table className="dt">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Client</th>
                      <th>DNS server</th>
                      <th>Query name</th>
                      <th>Type</th>
                      <th>Rcode</th>
                      <th className="text-right">Answers</th>
                      <th>Answer IPs</th>
                      <th className="text-right">Min TTL</th>
                      <th className="text-right">Delay</th>
                      <th>Lead flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((row) => (
                      <tr
                        key={row.id}
                        className={clsx('cursor-pointer', row.id === selectedId && 'selected')}
                        tabIndex={0}
                        onClick={() => filters.patch({ sel: row.id })}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            filters.patch({ sel: row.id })
                          }
                        }}
                        title="Open the answers, the name shape and the lead flags for this query"
                      >
                        <td>{formatTimestamp(row.time_epoch)}</td>
                        <td>
                          <MonoCell maxWidth={140}>{row.client_ip}</MonoCell>
                        </td>
                        <td>
                          <MonoCell maxWidth={140}>{row.server_ip}</MonoCell>
                        </td>
                        <td className="text-text">
                          <MonoCell maxWidth={340}>{row.query_name}</MonoCell>
                        </td>
                        <td className="text-accent2">
                          <MonoCell>{row.query_type}</MonoCell>
                        </td>
                        <td className={rcodeTone(row.rcode_name)}>
                          <MonoCell>{row.rcode_name}</MonoCell>
                        </td>
                        <td className="text-right" title={answerSummary(row)}>
                          {row.answers === null ? (
                            <span className="text-faint">{EMPTY}</span>
                          ) : (
                            formatNumber(row.answers.length)
                          )}
                        </td>
                        <td className="text-muted">
                          <MonoCell maxWidth={240}>{row.answer_ips}</MonoCell>
                        </td>
                        <td className="text-right">
                          {row.min_ttl === null ? (
                            <span className="text-faint">{EMPTY}</span>
                          ) : (
                            `${formatNumber(row.min_ttl)} s`
                          )}
                        </td>
                        <td className="text-right text-muted">
                          {row.response_delay === null ? (
                            <span
                              className="text-faint"
                              title="No response was matched to this query, so no delay can be measured."
                            >
                              {EMPTY}
                            </span>
                          ) : (
                            formatDuration(row.response_delay)
                          )}
                        </td>
                        <td>
                          <LeadFlagList flags={row.flags} catalog={DNS_FLAG_CATALOG} />
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

            {items.length > 0 ? (
              <div className="border-t border-border px-3 py-2">
                <SectionNote>
                  {formatNumber(flaggedOnPage)} of the {formatNumber(items.length)} rows on this page
                  carry at least one lead flag. Select a row for the merged answers, the name shape
                  and the reasoning behind each flag.
                </SectionNote>
              </div>
            ) : null}
          </Panel>

          {selectedId > 0 && analysisId ? (
            <QueryDetail
              analysisId={analysisId}
              rowId={selectedId}
              onClose={() => filters.patch({ sel: null })}
            />
          ) : null}
        </>
      ) : (
        <DomainsPanel
          domains={domainsQuery.data?.items ?? []}
          loading={domainsQuery.isLoading}
          error={domainsQuery.error}
          onRetry={() => void domainsQuery.refetch()}
          search={filters.get('dsearch')}
          onSearch={(value) => filters.patch({ dsearch: value })}
          sort={dsort}
          onSort={(value) => filters.patch({ dsort: value === 'queries' ? null : value })}
        />
      )}

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <Network size={12} aria-hidden />
        <span>
          Values shown as {EMPTY} were absent from the capture or were not dissected — nothing on this
          page is estimated or filled in.
        </span>
      </div>
    </div>
  )
}

/** DNS analysis — queries, answers, name shape and the per-domain aggregation. */
export function DnsPage() {
  return (
    <Page section={SECTIONS.dns}>
      <AnalysisGuard>
        <DnsContent />
      </AnalysisGuard>
    </Page>
  )
}

export default DnsPage
