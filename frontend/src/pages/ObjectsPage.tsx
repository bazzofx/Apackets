/**
 * Files and Objects — `/objects`
 *
 * Everything here comes from `GET /objects`, `GET /objects/{id}/export` and
 * `POST /objects/extract`. Nothing is fabricated: a row exists only because
 * TShark's `--export-objects` actually wrote a file, and a refused object is shown
 * as `failed` with the backend's own explanation rather than hidden.
 *
 * Safety posture (see the banner at the top of the page):
 *   * every name, hash and note is capture-derived and is rendered as text;
 *   * downloads are addressed by the server-generated object `id` only — never by
 *     a filename from the capture;
 *   * object content is never fetched into this page, never executed and never
 *     rendered as HTML.
 */

import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  Download,
  FileWarning,
  HardDrive,
  Info,
  Loader2,
  Package,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
  XCircle,
} from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import StatCard from '@/components/StatCard'
import Toolbar from '@/components/Toolbar'
import { useAnalysis } from '@/hooks/useAnalysis'
import { objectsApi, toApiError, type ObjectListParams } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { CaptureObject, ObjectStatus, SortOrder } from '@/types'
import { formatBytes, formatNumber, truncate } from '@/utils/format'

/* ------------------------------------------------------------------ */
/* shapes the live API adds on top of the frozen ones                  */
/* ------------------------------------------------------------------ */

/**
 * `GET /objects` also returns a `totals` object for the whole analysis
 * (`{objects, bytes, complete, partial, failed}`). It is not in
 * `src/types/index.ts`, so it is declared here rather than assumed.
 */
interface ObjectTotals {
  objects: number
  bytes: number
  complete: number
  partial: number
  failed: number
}

interface ObjectsEnvelope {
  items: CaptureObject[]
  total?: number
  page?: number
  page_size?: number
  pages?: number
  totals?: ObjectTotals
}

/**
 * `POST /objects/extract` returns `{ok, extracted}` per contract §5 and the live
 * API adds `objects`, `by_status`, `bytes`, `warning` and `seconds`.
 */
interface ExtractResult {
  ok: boolean
  extracted: number
  objects?: number
  by_status?: { complete?: number; partial?: number; failed?: number }
  bytes?: number
  warning?: string | null
  seconds?: number
}

/** The live list endpoint also accepts a `status` filter. */
interface ObjectQueryParams extends ObjectListParams {
  status?: string
}

const PAGE_SIZES = [50, 100, 250, 500, 1000]

const SORT_OPTIONS = [
  { value: '', label: 'backend default' },
  { value: 'filename', label: 'file name' },
  { value: 'size', label: 'size' },
  { value: 'created_at', label: 'extracted at' },
  { value: 'status', label: 'status' },
  { value: 'content_type', label: 'content type' },
]

const STATUS_OPTIONS = [
  { value: '', label: 'any status' },
  { value: 'complete', label: 'complete' },
  { value: 'partial', label: 'partial' },
  { value: 'failed', label: 'failed' },
]

const HASH_ALGORITHMS = ['sha256', 'sha1', 'md5'] as const

function positiveInt(raw: string | null, fallback: number): number {
  if (raw === null) return fallback
  const value = Number.parseInt(raw, 10)
  return Number.isFinite(value) && value > 0 ? value : fallback
}

/* ------------------------------------------------------------------ */
/* status presentation                                                 */
/* ------------------------------------------------------------------ */

const STATUS_CLASS: Record<ObjectStatus, string> = {
  complete: 'border-ok/50 bg-ok/15 text-ok',
  partial: 'border-warn/60 bg-warn/20 text-amber-300',
  failed: 'border-danger/50 bg-danger/15 text-red-300',
}

const STATUS_LABEL: Record<ObjectStatus, string> = {
  complete: 'complete',
  partial: 'partial',
  failed: 'failed',
}

const STATUS_MEANING: Record<ObjectStatus, string> = {
  complete:
    'Extracted bytes match the body size the HTTP transaction reports for this object.',
  partial:
    'Only part of the object was reconstructed — the export is shorter than the body size recorded in the transaction.',
  failed:
    'The object was identified but not stored, so there is nothing to download and no hashes were computed.',
}

/** Status is the first thing an analyst needs to see, so it never softens. */
function ObjectStatusBadge({ status, className }: { status: ObjectStatus; className?: string }) {
  const Icon =
    status === 'complete' ? CheckCircle2 : status === 'partial' ? AlertTriangle : XCircle
  return (
    <span
      className={clsx('chip', STATUS_CLASS[status] ?? 'border-border2 bg-surface2 text-muted', className)}
      title={STATUS_MEANING[status] ?? 'Status reported by the backend.'}
    >
      <Icon size={11} aria-hidden />
      {STATUS_LABEL[status] ?? status}
    </span>
  )
}

/* ------------------------------------------------------------------ */
/* local filter control                                                */
/* ------------------------------------------------------------------ */

function SearchFilter({
  value,
  onCommit,
}: {
  value: string
  onCommit: (value: string) => void
}) {
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
    <label className="flex items-center gap-1.5" title="Substring match on the displayed file name and the original exported name (search=)">
      <span className="text-2xs text-faint">Search</span>
      <input
        type="text"
        className="input w-52 py-1 text-2xs"
        value={draft}
        placeholder="report.pdf"
        onChange={(event) => setDraft(event.target.value)}
        aria-label="Search file name"
      />
      {draft !== '' ? (
        <button
          type="button"
          className="btn px-1 py-0.5"
          onClick={() => setDraft('')}
          title="Clear the search"
        >
          <X size={11} aria-hidden />
        </button>
      ) : null}
    </label>
  )
}

/* ------------------------------------------------------------------ */
/* page                                                                */
/* ------------------------------------------------------------------ */

function ObjectsContent() {
  const { analysisId } = useAnalysis()
  const ready = Boolean(analysisId)
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()

  const search = searchParams.get('search') ?? ''
  const statusRaw = searchParams.get('status') ?? ''
  const status = STATUS_OPTIONS.some((option) => option.value === statusRaw && statusRaw !== '')
    ? statusRaw
    : ''
  const sortRaw = searchParams.get('sort') ?? ''
  const sort = SORT_OPTIONS.some((option) => option.value === sortRaw) ? sortRaw : ''
  const order: SortOrder = searchParams.get('order') === 'desc' ? 'desc' : 'asc'
  const page = positiveInt(searchParams.get('page'), 1)
  const pageSizeRaw = positiveInt(searchParams.get('page_size'), 100)
  const pageSize = PAGE_SIZES.includes(pageSizeRaw) ? pageSizeRaw : 100

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

  const onSearchCommit = useCallback(
    (value: string) => updateParams({ search: value }),
    [updateParams],
  )

  const listParams: ObjectQueryParams = {
    page,
    page_size: pageSize,
    search,
    status: status === '' ? undefined : status,
    sort: sort === '' ? undefined : sort,
    order: sort === '' ? undefined : order,
  }

  const objectsQuery = useQuery({
    queryKey: ['objects', analysisId, search, status, sort, order, page, pageSize],
    queryFn: () => objectsApi.list(analysisId as string, listParams),
    enabled: ready,
    placeholderData: keepPreviousData,
  })

  const extractMutation = useMutation<ExtractResult, unknown, void>({
    mutationFn: () => objectsApi.extract(analysisId as string),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['objects', analysisId] })
    },
  })

  const data = objectsQuery.data as ObjectsEnvelope | undefined
  const objects = useMemo(() => data?.items ?? [], [data])
  const totals = data?.totals
  const total = data?.total ?? 0
  const activeFilters = [search, status].filter((value) => value !== '').length

  const clearFilters = useCallback(() => {
    setSearchParams(
      (previous) => {
        const next = new URLSearchParams(previous)
        for (const key of ['search', 'status', 'page']) next.delete(key)
        return next
      },
      { replace: true },
    )
  }, [setSearchParams])

  /** Honest summary of what a re-extraction actually did. */
  const extractionReport = useMemo(() => {
    if (extractMutation.error) {
      const apiError = toApiError(extractMutation.error)
      return {
        tone: 'danger' as const,
        text: `Re-extraction failed: ${apiError.message} (${apiError.code}${
          apiError.status ? ` · HTTP ${apiError.status}` : ''
        }). The table still shows the previous extraction.`,
      }
    }
    const result = extractMutation.data
    if (!result) return null

    const byStatus = result.by_status
    const detail = byStatus
      ? ` · complete ${byStatus.complete ?? 0} · partial ${byStatus.partial ?? 0} · failed ${
          byStatus.failed ?? 0
        }`
      : ''
    const bytes = typeof result.bytes === 'number' ? ` · ${formatBytes(result.bytes)} stored` : ''

    if (result.warning) {
      return {
        tone: 'warn' as const,
        text: `Re-extraction finished with a warning: ${result.warning}`,
      }
    }
    if (result.extracted === 0 && (result.objects ?? 0) === 0) {
      return {
        tone: 'info' as const,
        text:
          'Re-extraction finished: no HTTP object was found in this capture. Object export currently covers HTTP bodies only (TShark --export-objects http); HTTPS payloads are not decrypted.',
      }
    }
    if (result.extracted === 0) {
      return {
        tone: 'warn' as const,
        text: `Re-extraction found ${formatNumber(result.objects ?? 0)} object(s) but stored none of them${detail}. Each refusal is listed below with the backend's reason.`,
      }
    }
    return {
      tone: 'ok' as const,
      text: `Re-extraction finished: ${formatNumber(result.extracted)} object(s) stored${bytes}${detail}${
        result.seconds !== undefined ? ` in ${result.seconds.toFixed(2)} s` : ''
      }. The list below has been refreshed.`,
    }
  }, [extractMutation.data, extractMutation.error])

  const extractButton = (
    <button
      type="button"
      className="btn"
      onClick={() => extractMutation.mutate()}
      disabled={extractMutation.isPending}
      title="Re-run TShark --export-objects http for this analysis (POST /objects/extract)"
    >
      {extractMutation.isPending ? (
        <Loader2 size={13} className="animate-spin" aria-hidden />
      ) : (
        <RefreshCw size={13} aria-hidden />
      )}
      {extractMutation.isPending ? 'Re-extracting…' : 'Re-extract objects'}
    </button>
  )

  return (
    <div className="flex flex-col gap-3">
      <section className="panel border-warn/60 bg-warn/[0.07] px-3 py-2.5">
        <div className="flex items-start gap-2">
          <ShieldAlert size={16} className="mt-0.5 shrink-0 text-amber-300" aria-hidden />
          <div className="min-w-0">
            <div className="text-xs font-semibold text-amber-200">
              Extracted content is untrusted — handle it as potentially malicious
            </div>
            <p className="mt-1 text-2xs leading-relaxed text-muted">
              Every file listed here was carved out of the capture. APackets stores it inside the
              local analysis directory on this machine, <strong className="text-text">never
              executes it</strong>, never previews it as HTML and never builds a download link from a
              capture-supplied file name — downloads use the server-generated object id only. Object
              bytes are not fetched into this page: only names, sizes, hashes and endpoints are
              shown. A file name or content type in the table is itself an untrusted string from the
              capture. Content may be malware, a script, an exploit or a malformed archive; open an
              exported file only in a sandboxed environment you are prepared to lose. Files stay
              inside the local analysis directory until you explicitly export them.
            </p>
          </div>
        </div>
      </section>

      <div className="flex flex-col gap-1.5">
        <div className="text-2xs text-faint">
          Whole analysis, unfiltered — these five numbers come from the API's own{' '}
          <span className="mono">totals</span> object, not from the rows on this page. The filtered
          count is shown on the table below.
        </div>
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-5">
          <StatCard
            label="Objects extracted"
            value={totals?.objects ?? null}
            icon={Package}
            hint="objects: rows in the objects table for this analysis, unfiltered"
          />
          <StatCard
            label="Stored bytes"
            value={totals?.bytes ?? null}
            format="bytes"
            icon={HardDrive}
            hint="bytes: sum of the stored object sizes, unfiltered"
          />
          <StatCard
            label="Complete"
            value={totals?.complete ?? null}
            icon={CheckCircle2}
            hint="Objects whose stored bytes match the body size the capture reports"
          />
          <StatCard
            label="Partial"
            value={totals?.partial ?? null}
            icon={AlertTriangle}
            hint="Objects that were only partially reconstructed"
          />
          <StatCard
            label="Failed"
            value={totals?.failed ?? null}
            icon={FileWarning}
            hint="Objects refused or not stored — each one carries the backend's reason in the note column"
          />
        </div>
      </div>

      {extractionReport ? (
        <div
          className={clsx(
            'panel px-3 py-2 text-2xs leading-relaxed',
            extractionReport.tone === 'ok' && 'border-ok/50 bg-ok/10 text-ok',
            extractionReport.tone === 'warn' && 'border-warn/60 bg-warn/10 text-amber-200',
            extractionReport.tone === 'danger' && 'border-danger/50 bg-danger/10 text-red-300',
            extractionReport.tone === 'info' && 'border-border2 bg-surface2 text-muted',
          )}
          role="status"
        >
          {extractionReport.text}
        </div>
      ) : null}

      <Panel
        title="Recovered files and objects"
        subtitle={
          data
            ? `${formatNumber(total)} object(s) match · object export covers HTTP bodies (TShark --export-objects http)`
            : 'GET /objects'
        }
        flush
        actions={
          <>
            {objectsQuery.isFetching ? (
              <span className="text-2xs text-faint" aria-live="polite">
                updating…
              </span>
            ) : null}
            {extractButton}
          </>
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
          <SearchFilter value={search} onCommit={onSearchCommit} />
          <label className="flex items-center gap-1.5" title="Only show objects with this extraction status (status=)">
            <span className="text-2xs text-faint">Status</span>
            <select
              className="select py-1 text-2xs"
              value={status}
              onChange={(event) => updateParams({ status: event.target.value })}
              aria-label="Status"
            >
              {STATUS_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1.5" title="Allow-listed sort columns: filename, size, created_at, status, content_type">
            <span className="text-2xs text-faint">Sort</span>
            <select
              className="select py-1 text-2xs"
              value={sort}
              onChange={(event) => updateParams({ sort: event.target.value })}
              aria-label="Sort"
            >
              {SORT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="btn px-1.5 py-1"
            disabled={sort === ''}
            onClick={() => updateParams({ order: order === 'asc' ? 'desc' : 'asc' })}
            title={
              sort === ''
                ? 'Pick an explicit sort column first (the backend default has its own order)'
                : `Currently ${order === 'asc' ? 'ascending' : 'descending'} — switch to ${order === 'asc' ? 'descending' : 'ascending'}`
            }
          >
            {order === 'asc' ? <ArrowUp size={12} aria-hidden /> : <ArrowDown size={12} aria-hidden />}
            {order}
          </button>
          <span className="ml-auto flex items-center gap-1 text-2xs text-faint">
            <Info size={11} aria-hidden />
            hashes are computed locally by the backend from the stored bytes
          </span>
        </Toolbar>

        {objectsQuery.isLoading ? (
          <LoadingState label="Loading extracted objects…" rows={6} />
        ) : objectsQuery.error ? (
          <ErrorState
            error={objectsQuery.error}
            title="Could not load the extracted objects"
            onRetry={() => void objectsQuery.refetch()}
          />
        ) : objects.length === 0 ? (
          activeFilters > 0 ? (
            <EmptyState
              icon={Search}
              title="No object matches these filters"
              description="The filters are valid — the backend returned no rows for them. Try clearing the status filter or the search term."
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
              icon={Package}
              title="No objects were extracted from this capture"
              description="Object extraction covers HTTP bodies only (TShark --export-objects http). A capture with no HTTP, or with HTTPS only, legitimately yields nothing here — and HTTPS payloads are not decrypted, so absence of objects is not evidence of absence."
              action={extractButton}
              variant="plain"
            />
          )
        ) : (
          <>
            <div className="max-h-[36rem] overflow-auto">
              <table className="dt">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>File name</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Content type</th>
                    <th className="text-right">Size</th>
                    <th>Stream / frames</th>
                    <th>Hashes</th>
                    <th>Note</th>
                    <th>Export</th>
                  </tr>
                </thead>
                <tbody>
                  {objects.map((row) => {
                    const frames = row.packet_numbers ?? []
                    const downloadable = row.status !== 'failed' && row.size !== null
                    return (
                      <Fragment key={row.id}>
                        <tr>
                          <td>
                            <ObjectStatusBadge status={row.status} />
                          </td>
                          <td>
                            <MonoCell
                              maxWidth={200}
                              title={
                                row.original_filename && row.original_filename !== row.filename
                                  ? `${row.filename} (exported as ${row.original_filename})`
                                  : row.filename
                              }
                            >
                              {row.filename}
                            </MonoCell>
                          </td>
                          <td>
                            <MonoCell
                              maxWidth={170}
                              title={
                                row.src_ip === null
                                  ? 'not correlated to an endpoint'
                                  : `${row.src_ip}${row.src_port === null ? '' : `:${row.src_port}`}`
                              }
                            >
                              {row.src_ip === null
                                ? null
                                : `${row.src_ip}${row.src_port === null ? '' : `:${row.src_port}`}`}
                            </MonoCell>
                          </td>
                          <td>
                            <MonoCell
                              maxWidth={170}
                              title={
                                row.dst_ip === null
                                  ? 'not correlated to an endpoint'
                                  : `${row.dst_ip}${row.dst_port === null ? '' : `:${row.dst_port}`}`
                              }
                            >
                              {row.dst_ip === null
                                ? null
                                : `${row.dst_ip}${row.dst_port === null ? '' : `:${row.dst_port}`}`}
                            </MonoCell>
                          </td>
                          <td>
                            <span className="text-muted">{row.protocol ?? '—'}</span>
                          </td>
                          <td>
                            <MonoCell maxWidth={170}>{row.content_type}</MonoCell>
                          </td>
                          <td className="text-right" title={row.size === null ? 'size not recorded' : `${formatNumber(row.size)} bytes`}>
                            {formatBytes(row.size)}
                          </td>
                          <td>
                            <span className="flex flex-col gap-0.5 text-2xs">
                              <span className="mono text-text">
                                {row.stream_id === null ? '—' : `stream ${row.stream_id}`}
                              </span>
                              <span
                                className="mono text-faint"
                                title={frames.length > 0 ? frames.join(', ') : 'no frames recorded'}
                              >
                                {frames.length === 0
                                  ? 'no frames recorded'
                                  : `${formatNumber(frames.length)} frame(s)`}
                              </span>
                            </span>
                          </td>
                          <td>
                            <span className="flex flex-col gap-0.5">
                              {HASH_ALGORITHMS.map((algorithm) => {
                                const value = row[algorithm]
                                return (
                                  <span key={algorithm} className="flex items-center gap-1">
                                    <span className="w-11 shrink-0 text-2xs uppercase text-faint">
                                      {algorithm}
                                    </span>
                                    <span
                                      className={clsx(
                                        'min-w-0 max-w-[13rem] truncate mono text-2xs',
                                        value === null ? 'text-faint' : 'text-text',
                                      )}
                                      title={
                                        value ??
                                        'No hash is recorded — the file was refused or not stored.'
                                      }
                                    >
                                      {value ?? '—'}
                                    </span>
                                    <CopyButton
                                      value={value}
                                      label={`Copy ${algorithm} of ${row.filename}`}
                                    />
                                  </span>
                                )
                              })}
                            </span>
                          </td>
                          <td>
                            <span
                              className={clsx(
                                'block max-w-[18rem] truncate text-2xs',
                                row.note ? 'text-muted' : 'text-faint',
                              )}
                              title={row.note ?? 'No note was recorded for this object.'}
                            >
                              {row.note ? truncate(row.note, 120) : '—'}
                            </span>
                          </td>
                          <td>
                            {downloadable ? (
                              <a
                                className="btn px-1.5 py-1"
                                href={objectsApi.exportUrl(analysisId as string, row.id)}
                                title={`Download ${row.filename} as an attachment (addressed by object id ${row.id})`}
                                rel="noopener noreferrer"
                              >
                                <Download size={13} aria-hidden />
                                Download
                              </a>
                            ) : (
                              <span
                                className="btn cursor-not-allowed px-1.5 py-1 opacity-50"
                                title="Nothing to download: the object was not stored, so the export endpoint has no file for it."
                              >
                                <Download size={13} aria-hidden />
                                Download
                              </span>
                            )}
                          </td>
                        </tr>
                        {row.status !== 'complete' ? (
                          <tr className={clsx(row.status === 'failed' ? 'bg-danger/[0.08]' : 'bg-warn/[0.08]')}>
                            <td colSpan={11} className="whitespace-normal">
                              <span className="flex flex-wrap items-start gap-2 text-2xs leading-relaxed">
                                <ObjectStatusBadge status={row.status} />
                                <span
                                  className={clsx(
                                    'min-w-0 flex-1',
                                    row.status === 'failed' ? 'text-red-300' : 'text-amber-200',
                                  )}
                                >
                                  {row.note ??
                                    (row.status === 'partial'
                                      ? 'This object is only partially reconstructed; the backend recorded no further detail.'
                                      : 'This object was not stored; the backend recorded no further detail.')}
                                </span>
                                <span className="mono text-faint" title={row.stored_path}>
                                  {row.stored_path}
                                </span>
                              </span>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              pageSizeOptions={PAGE_SIZES}
              disabled={objectsQuery.isFetching}
              onPageChange={(next) => updateParams({ page: String(next) }, false)}
              onPageSizeChange={(next) => updateParams({ page_size: String(next) })}
            />
            <div className="border-t border-border px-3 py-2 text-2xs text-faint">
              `stored_path` is shown for reference only — it is a path inside the analysis directory
              and is never turned into a URL by this page. Downloads are addressed by the object id
              the API returned.
            </div>
          </>
        )}
      </Panel>
    </div>
  )
}

/** Files and Objects — extracted content, hashes, export and re-extraction. */
export function ObjectsPage() {
  return (
    <Page section={SECTIONS.objects}>
      <AnalysisGuard>
        <ObjectsContent />
      </AnalysisGuard>
    </Page>
  )
}

export default ObjectsPage
