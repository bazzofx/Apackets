/**
 * Hosts — `/hosts`
 *
 * Endpoint inventory (`GET /hosts`), per-endpoint detail (`GET /hosts/{ip}`) and
 * the observed-connection map (`GET /hosts/graph`).
 *
 * All filter, sort, pagination, view and selection state lives in the URL query
 * string, so a filtered view can be bookmarked or pasted to a colleague:
 *
 *   ?ip=&search=&is_private=&protocol=&sort=&order=&page=&page_size=&view=&host=
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowDown,
  ArrowUp,
  HardDrive,
  ListFilter,
  Network,
  RefreshCw,
  Search,
  Server,
  X,
} from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import StatCard from '@/components/StatCard'
import Toolbar from '@/components/Toolbar'
import HostDetailPanel from '@/components/hosts/HostDetailPanel'
import HostsTable, {
  HOST_SORT_KEYS,
  HOST_SORT_LABELS,
  isHostSortKey,
  type HostSortKey,
} from '@/components/hosts/HostsTable'
import NetworkGraph from '@/components/hosts/NetworkGraph'
import { useAnalysis } from '@/hooks/useAnalysis'
import { hostsApi, type HostListParams } from '@/services/api'
import type { SortOrder } from '@/types'
import { formatNumber } from '@/utils/format'

const PAGE_SIZES = [50, 100, 250, 500, 1000]

/** Sort keys where descending is the useful default (largest first). */
const DESC_FIRST: ReadonlySet<HostSortKey> = new Set<HostSortKey>([
  'packets_sent',
  'bytes_sent',
  'bytes_received',
  'last_seen',
  'peer_count',
])

function positiveInt(raw: string | null, fallback: number): number {
  if (raw === null) return fallback
  const value = Number.parseInt(raw, 10)
  return Number.isFinite(value) && value > 0 ? value : fallback
}

/* ------------------------------------------------------------------ */
/* URL-bound filter controls                                           */
/* ------------------------------------------------------------------ */

interface TextFilterProps {
  label: string
  value: string
  placeholder: string
  hint: string
  onCommit: (value: string) => void
}

/** Debounced text filter; the URL is updated 300 ms after typing stops. */
function TextFilter({ label, value, placeholder, hint, onCommit }: TextFilterProps) {
  const [draft, setDraft] = useState(value)

  useEffect(() => {
    setDraft(value)
  }, [value])

  useEffect(() => {
    if (draft === value) return
    const timer = window.setTimeout(() => onCommit(draft), 300)
    return () => window.clearTimeout(timer)
  }, [draft, value, onCommit])

  return (
    <label className="flex items-center gap-1.5" title={hint}>
      <span className="text-2xs text-faint">{label}</span>
      <input
        type="text"
        className="input w-40 py-1 text-2xs"
        value={draft}
        placeholder={placeholder}
        onChange={(event) => setDraft(event.target.value)}
        aria-label={label}
      />
      {draft !== '' ? (
        <button
          type="button"
          className="btn px-1 py-0.5"
          onClick={() => setDraft('')}
          title={`Clear the ${label.toLowerCase()} filter`}
        >
          <X size={11} aria-hidden />
        </button>
      ) : null}
    </label>
  )
}

function SelectFilter({
  label,
  value,
  hint,
  options,
  onChange,
}: {
  label: string
  value: string
  hint: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
}) {
  return (
    <label className="flex items-center gap-1.5" title={hint}>
      <span className="text-2xs text-faint">{label}</span>
      <select
        className="select py-1 text-2xs"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-label={label}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  )
}

/* ------------------------------------------------------------------ */
/* page                                                                */
/* ------------------------------------------------------------------ */

function HostsContent() {
  const { analysisId } = useAnalysis()
  const ready = Boolean(analysisId)
  const [searchParams, setSearchParams] = useSearchParams()

  const view = searchParams.get('view') === 'graph' ? 'graph' : 'inventory'
  const ipFilter = searchParams.get('ip') ?? ''
  const searchFilter = searchParams.get('search') ?? ''
  const protocolFilter = searchParams.get('protocol') ?? ''
  const scopeParam = searchParams.get('is_private') === 'true'
    ? 'true'
    : searchParams.get('is_private') === 'false'
      ? 'false'
      : ''
  const sortRaw = searchParams.get('sort')
  const sort: HostSortKey = isHostSortKey(sortRaw) ? sortRaw : 'ip'
  const order: SortOrder = searchParams.get('order') === 'desc' ? 'desc' : 'asc'
  const page = positiveInt(searchParams.get('page'), 1)
  const pageSizeRaw = positiveInt(searchParams.get('page_size'), 100)
  const pageSize = PAGE_SIZES.includes(pageSizeRaw) ? pageSizeRaw : 100
  const selectedIp = searchParams.get('host')

  const updateParams = useCallback(
    (patch: Record<string, string | null>, resetPage = true) => {
      setSearchParams(
        (previous) => {
          const next = new URLSearchParams(previous)
          for (const [key, value] of Object.entries(patch)) {
            if (value === null || value === '') next.delete(key)
            else next.set(key, value)
          }
          if (resetPage) next.delete('page')
          return next
        },
        { replace: true },
      )
    },
    [setSearchParams],
  )

  const onIpCommit = useCallback((value: string) => updateParams({ ip: value }), [updateParams])
  const onSearchCommit = useCallback(
    (value: string) => updateParams({ search: value }),
    [updateParams],
  )
  const onProtocolCommit = useCallback(
    (value: string) => updateParams({ protocol: value }),
    [updateParams],
  )

  const listParams: HostListParams = {
    page,
    page_size: pageSize,
    sort,
    order,
    ip: ipFilter,
    search: searchFilter,
    protocol: protocolFilter,
    is_private: scopeParam === '' ? undefined : scopeParam === 'true',
  }

  const hostsQuery = useQuery({
    queryKey: [
      'hosts',
      analysisId,
      ipFilter,
      searchFilter,
      protocolFilter,
      scopeParam,
      sort,
      order,
      page,
      pageSize,
    ],
    queryFn: () => hostsApi.list(analysisId as string, listParams),
    enabled: ready,
    placeholderData: keepPreviousData,
  })

  const graphQuery = useQuery({
    queryKey: ['host-graph', analysisId],
    queryFn: () => hostsApi.graph(analysisId as string),
    enabled: ready,
  })

  const detailRef = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    if (selectedIp === null) return
    detailRef.current?.scrollIntoView({ block: 'start' })
  }, [selectedIp])

  const data = hostsQuery.data
  const hosts = useMemo(() => data?.items ?? [], [data])
  const total = data?.total ?? 0
  const totalBytes = data?.total_bytes ?? null
  const totalHosts = data ? (data.total_hosts ?? data.total) : null
  const graphNodes = graphQuery.data?.nodes?.length ?? null
  const graphEdges = graphQuery.data?.edges?.length ?? null

  const activeFilters = [ipFilter, searchFilter, protocolFilter, scopeParam].filter(
    (value) => value !== '',
  ).length

  const clearFilters = useCallback(() => {
    setSearchParams(
      (previous) => {
        const next = new URLSearchParams(previous)
        for (const key of ['ip', 'search', 'protocol', 'is_private', 'page']) next.delete(key)
        return next
      },
      { replace: true },
    )
  }, [setSearchParams])

  const onSort = useCallback(
    (key: HostSortKey) => {
      const nextOrder: SortOrder =
        key === sort ? (order === 'asc' ? 'desc' : 'asc') : DESC_FIRST.has(key) ? 'desc' : 'asc'
      updateParams({ sort: key, order: nextOrder })
    },
    [order, sort, updateParams],
  )

  const onSelect = useCallback(
    (ip: string | null) => updateParams({ host: ip }, false),
    [updateParams],
  )

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatCard
          label="Endpoints observed"
          value={totalHosts}
          icon={Server}
          hint="Rows in the host table for this analysis (total_hosts), unfiltered"
        />
        <StatCard
          label="Matching filters"
          value={data ? total : null}
          icon={ListFilter}
          sublabel={activeFilters > 0 ? `${activeFilters} filter(s) active` : 'no filters active'}
          hint="total for the current filters"
        />
        <StatCard
          label="Bytes sent by hosts"
          value={totalBytes}
          format="bytes"
          icon={HardDrive}
          hint="total_bytes: SUM(bytes_sent) over every host in this analysis, unfiltered"
        />
        <StatCard
          label="Map endpoints"
          value={graphNodes}
          icon={Network}
          sublabel={graphEdges !== null ? `${formatNumber(graphEdges)} observed connection(s)` : null}
          hint="Nodes in GET /hosts/graph — every endpoint that appears in an observed conversation"
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1">
          <button
            type="button"
            className={clsx('btn', view === 'inventory' && 'btn-primary')}
            onClick={() => updateParams({ view: null })}
          >
            <Server size={13} aria-hidden />
            Inventory
          </button>
          <button
            type="button"
            className={clsx('btn', view === 'graph' && 'btn-primary')}
            onClick={() => updateParams({ view: 'graph' })}
          >
            <Network size={13} aria-hidden />
            Network map
          </button>
        </div>
        <span className="text-2xs text-faint">
          {view === 'graph'
            ? 'relationship map of observed conversations'
            : 'one row per observed IP address'}
        </span>
        <button
          type="button"
          className="btn ml-auto"
          onClick={() => {
            void hostsQuery.refetch()
            void graphQuery.refetch()
          }}
          title="Re-read the host inventory and the graph"
        >
          <RefreshCw size={13} aria-hidden />
          Refresh
        </button>
      </div>

      {view === 'graph' ? (
        graphQuery.isLoading ? (
          <LoadingState label="Loading the observed-connection map…" rows={6} />
        ) : graphQuery.error ? (
          <ErrorState
            error={graphQuery.error}
            title="Could not load the network map"
            onRetry={() => void graphQuery.refetch()}
          />
        ) : graphQuery.data ? (
          <NetworkGraph graph={graphQuery.data} selectedIp={selectedIp} onSelect={onSelect} />
        ) : (
          <EmptyState
            icon={Network}
            title="No graph data"
            description="The backend returned no graph payload for this analysis."
          />
        )
      ) : (
        <Panel
          title="Host inventory"
          subtitle={
            data
              ? `${formatNumber(total)} endpoint(s) match · sorted by ${HOST_SORT_LABELS[sort].toLowerCase()} ${order}`
              : 'GET /hosts'
          }
          flush
          actions={
            hostsQuery.isFetching ? (
              <span className="text-2xs text-faint" aria-live="polite">
                updating…
              </span>
            ) : null
          }
        >
          <Toolbar
            actions={
              activeFilters > 0 ? (
                <button type="button" className="btn" onClick={clearFilters}>
                  <X size={13} aria-hidden />
                  Clear filters
                </button>
              ) : null
            }
          >
            <TextFilter
              label="IP"
              value={ipFilter}
              placeholder="10.0.0."
              hint="Substring match on the endpoint address (ip=)"
              onCommit={onIpCommit}
            />
            <TextFilter
              label="Search"
              value={searchFilter}
              placeholder="example.com"
              hint="Matches the address, MAC, protocol map, DNS names and TLS SNI (search=)"
              onCommit={onSearchCommit}
            />
            <SelectFilter
              label="Scope"
              value={scopeParam}
              hint="Private = RFC1918/4193, loopback, link-local (is_private=)"
              options={[
                { value: '', label: 'any' },
                { value: 'true', label: 'private only' },
                { value: 'false', label: 'public only' },
              ]}
              onChange={(value) => updateParams({ is_private: value })}
            />
            <TextFilter
              label="Protocol"
              value={protocolFilter}
              placeholder="HTTP"
              hint="Exact display-protocol key in the host's protocol map, e.g. HTTP (protocol=)"
              onCommit={onProtocolCommit}
            />
            <SelectFilter
              label="Sort"
              value={sort}
              hint="Allow-listed sort columns only; the backend rejects anything else"
              options={HOST_SORT_KEYS.map((key) => ({ value: key, label: HOST_SORT_LABELS[key] }))}
              onChange={(value) => {
                const key: HostSortKey = isHostSortKey(value) ? value : 'ip'
                updateParams({ sort: key, order: DESC_FIRST.has(key) ? 'desc' : 'asc' })
              }}
            />
            <button
              type="button"
              className="btn px-1.5 py-1"
              onClick={() => updateParams({ order: order === 'asc' ? 'desc' : 'asc' })}
              title={`Currently ${order === 'asc' ? 'ascending' : 'descending'} — switch to ${order === 'asc' ? 'descending' : 'ascending'}`}
            >
              {order === 'asc' ? <ArrowUp size={12} aria-hidden /> : <ArrowDown size={12} aria-hidden />}
              {order}
            </button>
          </Toolbar>

          {hostsQuery.isLoading ? (
            <LoadingState label="Loading host inventory…" rows={8} />
          ) : hostsQuery.error ? (
            <ErrorState
              error={hostsQuery.error}
              title="Could not load the host inventory"
              onRetry={() => void hostsQuery.refetch()}
            />
          ) : hosts.length === 0 ? (
            activeFilters > 0 ? (
              <EmptyState
                icon={Search}
                title="No endpoint matches these filters"
                description="The filters are valid — the backend simply returned no rows for them. Nothing is shown rather than a guessed row."
                action={
                  <button type="button" className="btn btn-primary" onClick={clearFilters}>
                    <X size={13} aria-hidden />
                    Clear filters
                  </button>
                }
                variant="plain"
              />
            ) : (
              <EmptyState
                icon={Server}
                title="No endpoints were observed"
                description="No IP address was indexed for this capture. A capture with only non-IP traffic (for example pure ARP) produces an empty host inventory, and that is reported here as empty rather than filled in."
                variant="plain"
              />
            )
          ) : (
            <>
              <HostsTable
                hosts={hosts}
                selectedIp={selectedIp}
                onSelect={onSelect}
                sort={sort}
                order={order}
                onSort={onSort}
              />
              <Pagination
                page={page}
                pageSize={pageSize}
                total={total}
                pageSizeOptions={PAGE_SIZES}
                disabled={hostsQuery.isFetching}
                onPageChange={(next) => updateParams({ page: String(next) }, false)}
                onPageSizeChange={(next) => updateParams({ page_size: String(next) })}
              />
              <div className="border-t border-border px-3 py-2 text-2xs text-faint">
                Ports are shown as <span className="mono">port · packets</span>; names with a blue
                border are TLS SNI values, grey ones are DNS query names. Every column comes from the
                backend — nothing is inferred or filled in.
              </div>
            </>
          )}
        </Panel>
      )}

      {selectedIp !== null ? (
        <div ref={detailRef} className="scroll-mt-4">
          <HostDetailPanel
            analysisId={analysisId as string}
            ip={selectedIp}
            onClose={() => updateParams({ host: null }, false)}
          />
        </div>
      ) : null}
    </div>
  )
}

/** Hosts — inventory, detail and the observed-connection map. */
export function HostsPage() {
  return (
    <AnalysisGuard>
      <HostsContent />
    </AnalysisGuard>
  )
}

export default HostsPage
