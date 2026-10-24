import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
} from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  AlertTriangle,
  Ban,
  FolderOpen,
  Play,
  RefreshCw,
  Scale,
  Trash2,
  Upload,
  X,
} from 'lucide-react'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import StatusChip from '@/components/StatusChip'
import Toolbar from '@/components/Toolbar'
import { useAnalysis } from '@/hooks/useAnalysis'
import {
  ALLOWED_CAPTURE_EXTENSIONS,
  analysesApi,
  baselineApi,
  isAllowedCaptureFile,
  uploadAnalysis,
  type UploadProgress,
} from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { Analysis } from '@/types'
import {
  formatBytes,
  formatDuration,
  formatNumber,
  formatRelativeTime,
  formatTimestamp,
  truncate,
} from '@/utils/format'

interface UploadState {
  filename: string
  percent: number
  loaded: number
  total: number
}

function ProgressBar({ percent, tone = 'accent' }: { percent: number; tone?: 'accent' | 'danger' }) {
  const clamped = Math.max(0, Math.min(100, percent))
  return (
    <div className="h-1.5 w-full overflow-hidden rounded bg-surface2">
      <div
        className={clsx('h-full', tone === 'accent' ? 'bg-accent' : 'bg-danger')}
        style={{ width: `${clamped}%` }}
        role="progressbar"
        aria-valuenow={Math.round(clamped)}
        aria-valuemin={0}
        aria-valuemax={100}
      />
    </div>
  )
}

function ConfirmDialog({
  analysis,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  analysis: Analysis
  busy: boolean
  error: unknown
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4">
      <div className="panel w-full max-w-md" role="dialog" aria-modal="true">
        <div className="panel-header">
          <span className="panel-title">Delete analysis</span>
          <button type="button" className="btn btn-ghost px-1.5 py-1" onClick={onCancel} title="Close">
            <X size={13} aria-hidden />
          </button>
        </div>
        <div className="flex flex-col gap-2 p-3 text-xs text-muted">
          <p>
            Delete{' '}
            <span className="mono text-text" title={analysis.original_filename}>
              {truncate(analysis.original_filename, 64)}
            </span>{' '}
            and every row derived from it (packets, conversations, findings, extracted objects)?
          </p>
          <p className="text-faint">
            The database rows are removed and the analysis directory is deleted from disk. This
            cannot be undone — re-upload the capture to analyse it again.
          </p>
          {error ? <ErrorState error={error} variant="plain" className="py-2" /> : null}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-3 py-2">
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" onClick={onConfirm} disabled={busy}>
            <Trash2 size={13} aria-hidden />
            {busy ? 'Deleting…' : 'Delete permanently'}
          </button>
        </div>
      </div>
    </div>
  )
}

/** PCAP files: upload, watch progress, open or delete analyses. */
export function PcapFilesPage() {
  const navigate = useNavigate()
  const { analyses, isLoading, error, refresh, setAnalysisId, analysisId } = useAnalysis()

  const [dragging, setDragging] = useState(false)
  const [upload, setUpload] = useState<UploadState | null>(null)
  const [uploadError, setUploadError] = useState<unknown>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Analysis | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  const deleteMutation = useMutation({
    mutationFn: (id: string) => analysesApi.remove(id),
    onSuccess: (_result, id) => {
      setPendingDelete(null)
      if (id === analysisId) setAnalysisId(null)
      refresh()
    },
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => analysesApi.cancel(id),
    onSuccess: () => refresh(),
  })

  /* The baseline: one global capture every later analysis is compared against.
     Selecting a row here is the whole control surface - the checkbox says which
     capture describes the network, and baseline mode says whether that comparison
     is in force. Both live behind /api/baseline so the top bar and this table
     always agree about it. */
  const queryClient = useQueryClient()
  const baseline = useQuery({
    queryKey: ['baseline'],
    queryFn: () => baselineApi.status(),
    staleTime: 10_000,
    /* A change sweeps the whole library in the background, so poll while it runs and
       stop the moment it is done: this page is the one that started it. */
    refetchInterval: (query) => (query.state.data?.recalc?.running ? 1000 : false),
  })

  /* The sweep rewrites the baseline findings of every analysis, so a finished sweep
     invalidates what those findings feed: the finding lists, their counts and the
     dashboard summary. Tracked across renders because the truth arrives by polling. */
  const recalcRunning = baseline.data?.recalc?.running === true
  const recalcWasRunning = useRef(false)
  useEffect(() => {
    if (recalcWasRunning.current && !recalcRunning) {
      void queryClient.invalidateQueries({ queryKey: ['findings'] })
      void queryClient.invalidateQueries({ queryKey: ['findings-counts'] })
      void queryClient.invalidateQueries({ queryKey: ['summary'] })
      void queryClient.invalidateQueries({ queryKey: ['baseline-compare'] })
    }
    recalcWasRunning.current = recalcRunning
  }, [recalcRunning, queryClient])

  const invalidateBaseline = () => {
    void queryClient.invalidateQueries({ queryKey: ['baseline'] })
    void queryClient.invalidateQueries({ queryKey: ['findings'] })
    void queryClient.invalidateQueries({ queryKey: ['findings-counts'] })
  }
  const setBaseline = useMutation({
    mutationFn: (payload: { analysis_id?: string | null; enabled?: boolean }) =>
      baselineApi.update(payload),
    onSuccess: (status) => {
      setNotice(
        status.baseline
          ? 'Baseline network: ' +
            status.baseline.original_filename +
            (status.active
              ? ' - baseline mode is on, so new analyses are compared against it.'
              : ' - baseline mode is off.') +
            (status.recalc?.running
              ? ' Recalculating the baseline findings for ' +
                String(status.recalc.total) +
                ' analyses…'
              : '')
          : 'Baseline cleared. Baseline mode is off.' +
            (status.recalc?.running ? ' Its findings are being removed.' : ''),
      )
      invalidateBaseline()
    },
  })
  const recalculate = useMutation({
    mutationFn: () => baselineApi.recalculate(),
    onSuccess: (status) => {
      setNotice(
        status.recalc?.running
          ? 'Recalculating the baseline findings for ' + String(status.recalc.total) + ' analyses…'
          : 'Baseline findings are already being recalculated, or recalculation is switched off for this installation.',
      )
      invalidateBaseline()
    },
  })
  const baselineId = baseline.data?.baseline?.analysis_id ?? null
  const recalc = baseline.data?.recalc

  const startUpload = useCallback(
    async (file: File) => {
      setNotice(null)
      setUploadError(null)
      const controller = new AbortController()
      abortRef.current = controller
      setUpload({ filename: file.name, percent: 0, loaded: 0, total: file.size })
      try {
        const created = await uploadAnalysis(file, {
          signal: controller.signal,
          onProgress: (progress: UploadProgress) => {
            setUpload({
              filename: file.name,
              percent: progress.percent,
              loaded: progress.loaded,
              total: progress.total || file.size,
            })
          },
        })
        setUpload(null)
        setAnalysisId(created.id)
        refresh()
      } catch (cause) {
        setUpload(null)
        setUploadError(cause)
      } finally {
        abortRef.current = null
      }
    },
    [refresh, setAnalysisId],
  )

  const handleFiles = useCallback(
    (files: FileList | null) => {
      if (!files || files.length === 0) return
      if (files.length > 1) {
        setNotice('Upload one capture at a time — the backend accepts a single file per request.')
        return
      }
      const file = files[0]
      if (!isAllowedCaptureFile(file.name)) {
        setNotice(
          `"${file.name}" is not a supported capture. Allowed extensions: ${ALLOWED_CAPTURE_EXTENSIONS.join(', ')}.`,
        )
        return
      }
      void startUpload(file)
    },
    [startUpload],
  )

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragging(false)
    handleFiles(event.dataTransfer?.files ?? null)
  }

  const onPick = (event: ChangeEvent<HTMLInputElement>) => {
    handleFiles(event.target.files)
    event.target.value = ''
  }

  const hasActive = analyses.some(
    (analysis) => analysis.status === 'pending' || analysis.status === 'processing',
  )

  if (error) {
    return <ErrorState error={error} onRetry={refresh} title="Could not load analyses" />
  }

  return (
    <Page
      section={SECTIONS.files}
      aside={
        <span className="chip border-border2 bg-surface2 text-muted">
          {isLoading
            ? '…'
            : `${formatNumber(analyses.length)} capture${analyses.length === 1 ? '' : 's'}`}
        </span>
      }
    >
      <div
        className={clsx(
          'panel flex flex-col items-center justify-center gap-2 border-dashed px-4 py-6 text-center transition-colors',
          dragging ? 'border-accent bg-accent/10' : 'border-border2',
        )}
        onDragOver={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <Upload size={20} className={dragging ? 'text-accent2' : 'text-faint'} aria-hidden />
        <div className="text-sm text-text">Drop a capture here</div>
        <div className="text-2xs text-muted">
          Accepted: {ALLOWED_CAPTURE_EXTENSIONS.join(', ')} — parsed locally by TShark, nothing
          leaves this machine.
        </div>
        <div className="mt-1 flex items-center gap-2">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => fileInput.current?.click()}
            disabled={upload !== null}
          >
            <FolderOpen size={13} aria-hidden />
            Select capture
          </button>
          {upload ? (
            <button type="button" className="btn btn-danger" onClick={() => abortRef.current?.abort()}>
              <X size={13} aria-hidden />
              Cancel upload
            </button>
          ) : null}
        </div>
        <input
          ref={fileInput}
          type="file"
          className="hidden"
          accept=".pcap,.pcapng,.cap"
          onChange={onPick}
        />

        {upload ? (
          <div className="mt-3 w-full max-w-xl">
            <div className="mb-1 flex items-center justify-between gap-2 text-2xs text-muted">
              <span className="truncate mono" title={upload.filename}>
                {upload.filename}
              </span>
              <span className="mono shrink-0">
                {upload.percent.toFixed(0)}% · {formatBytes(upload.loaded)} /{' '}
                {upload.total > 0 ? formatBytes(upload.total) : 'unknown size'}
              </span>
            </div>
            <ProgressBar percent={upload.percent} />
          </div>
        ) : null}
      </div>

      {notice ? (
        <div className="panel flex items-start gap-2 border-warn/40 px-3 py-2 text-xs text-warn">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden />
          <span className="flex-1">{notice}</span>
          <button type="button" className="btn btn-ghost px-1 py-0.5" onClick={() => setNotice(null)}>
            <X size={12} aria-hidden />
          </button>
        </div>
      ) : null}

      {uploadError ? (
        <ErrorState error={uploadError} title="Upload failed" onRetry={() => setUploadError(null)} />
      ) : null}

      {cancelMutation.error ? (
        <ErrorState
          error={cancelMutation.error}
          title="Could not cancel the analysis"
          onRetry={() => cancelMutation.reset()}
        />
      ) : null}

      <Panel
        title="Analyses"
        subtitle={
          hasActive
            ? 'analysis in progress — refreshing every 2 seconds'
            : `${analyses.length} capture${analyses.length === 1 ? '' : 's'}` +
              (baseline.data?.active ? ' · baseline mode on' : '')
        }
        flush
        actions={
          <div className="flex items-center gap-2">
            <label
              className="flex items-center gap-1.5 text-2xs text-muted"
              title={
                baseline.data?.baseline
                  ? 'Compare every analysis against ' +
                    baseline.data.baseline.original_filename
                  : 'Choose a capture in the Baseline column first'
              }
            >
              <input
                type="checkbox"
                checked={Boolean(baseline.data?.enabled)}
                disabled={!baseline.data?.baseline || setBaseline.isPending}
                onChange={(event) =>
                  setBaseline.mutate({ enabled: event.target.checked })
                }
              />
              Baseline mode
              <span
                className={clsx(
                  'chip',
                  baseline.data?.active
                    ? 'border-warn/60 bg-warn/15 text-warn'
                    : 'border-border2 bg-surface2 text-faint',
                )}
              >
                {baseline.data?.active ? 'on' : 'off'}
              </span>
            </label>
            <button type="button" className="btn" onClick={refresh} title="Reload the list">
              <RefreshCw size={13} aria-hidden />
              Refresh
            </button>
          </div>
        }
      >
        {baseline.data?.configured ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-muted">
            <Scale size={13} className="mt-0.5 shrink-0 text-warn" aria-hidden />
            <span className="flex-1">
              Baseline network: <span className="mono">{baseline.data.baseline?.original_filename}</span>
              {' '}({formatNumber(baseline.data.baseline?.packet_count ?? 0)} frames).{' '}
              {baseline.data.active
                ? 'Every analysis is compared against it: entities this capture never contained are reported as findings.'
                : 'Baseline mode is off, so nothing is compared until you switch it on.'}{' '}
              Choosing or clearing the baseline recomputes its findings for every analysis in the background, so the
              findings on the other pages match it without anyone pressing anything.
            </span>
          </div>
        ) : (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-faint">
            <Scale size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span className="flex-1">
              No baseline network is set. Tick a completed capture in the Baseline column and every
              later analysis will be compared against it - new addresses, destinations, services,
              names and TLS fingerprints become findings.
            </span>
          </div>
        )}

        {recalc !== undefined ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs">
            <RefreshCw
              size={13}
              className={clsx(
                'mt-0.5 shrink-0',
                recalcRunning ? 'animate-spin text-warn' : 'text-faint',
              )}
              aria-hidden
            />
            <span className="flex-1 text-muted">
              {recalcRunning ? (
                <>
                  <span className="text-text">Recalculating the baseline findings.</span>{' '}
                  {formatNumber(recalc.done)} of {formatNumber(recalc.total)} analyses done
                  {recalc.current !== null ? (
                    <>
                      {' — '}
                      <span className="mono">{recalc.current}</span>
                    </>
                  ) : null}
                  . The findings on every page update when it finishes.
                </>
              ) : recalc.finished_at !== null ? (
                <>
                  <span className="text-text">Baseline findings recalculated</span> for{' '}
                  {formatNumber(recalc.done)} analyses
                  {recalc.findings > 0 ? <> — {formatNumber(recalc.findings)} findings</> : null}
                  {recalc.seconds !== null ? <> in {recalc.seconds.toFixed(1)} s</> : null}
                  {', '}
                  {formatRelativeTime(recalc.finished_at)}
                  {recalc.errors.length > 0 ? (
                    <span className="text-red-300" title={recalc.errors.join('; ')}>
                      {' '}
                      — {formatNumber(recalc.errors.length)} analysis(es) could not be recalculated
                    </span>
                  ) : null}
                  .
                </>
              ) : recalc.auto ? (
                <>Choosing a baseline recomputes the baseline findings for every analysis automatically.</>
              ) : (
                <>Automatic recalculation is switched off on this installation (
                  <span className="mono">SHADOWPACKETS_BASELINE_AUTO_RECALC=0</span>).</>
              )}
            </span>
            <button
              type="button"
              className="btn-tab shrink-0"
              disabled={recalcRunning || !recalc.auto || recalculate.isPending}
              onClick={() => recalculate.mutate()}
              title="Re-run the seven baseline rules over every analysis now"
            >
              Recalculate
            </button>
          </div>
        ) : null}
        {isLoading ? (
          <LoadingState label="Loading analyses…" rows={4} />
        ) : analyses.length === 0 ? (
          <div className="px-3 py-10 text-center text-xs text-muted">
            No captures have been uploaded yet. Drop a file above to start an analysis.
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>File</th>
                  <th title="The one capture that describes the network">Baseline</th>
                  <th className="text-right">Size</th>
                  <th>Status</th>
                  <th className="text-right">Packets</th>
                  <th>Capture start</th>
                  <th>Capture end</th>
                  <th className="text-right">Duration</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((analysis) => {
                  const inFlight =
                    analysis.status === 'pending' || analysis.status === 'processing'
                  const percent =
                    analysis.progress === null || analysis.progress === undefined
                      ? 0
                      : analysis.progress <= 1
                        ? analysis.progress * 100
                        : analysis.progress
                  return (
                    <tr key={analysis.id} className={clsx(analysis.id === analysisId && 'selected')}>
                      <td>
                        <div className="flex items-center gap-2">
                          <MonoCell maxWidth={260} title={analysis.original_filename}>
                            {analysis.original_filename}
                          </MonoCell>
                          {analysis.id === analysisId ? (
                            <span className="chip border-accent/50 bg-accent/15 text-accent2">
                              active
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5">
                          <input
                            type="checkbox"
                            checked={baselineId === analysis.id}
                            disabled={analysis.status !== 'completed' || setBaseline.isPending}
                            onChange={(event) => {
                              if (event.target.checked) {
                                setBaseline.mutate({
                                  analysis_id: analysis.id,
                                  enabled: true,
                                })
                              } else {
                                setBaseline.mutate({ analysis_id: null })
                              }
                            }}
                            title={
                              analysis.status !== 'completed'
                                ? 'A baseline must be a completed analysis'
                                : baselineId === analysis.id
                                  ? 'Stop using this capture as the baseline network'
                                  : 'Use this capture as the baseline network every new analysis is compared against'
                            }
                            aria-label={
                              'Use ' + analysis.original_filename + ' as the baseline network'
                            }
                          />
                          {baselineId === analysis.id ? (
                            <span
                              className="chip border-warn/60 bg-warn/15 text-warn"
                              title={
                                baseline.data?.active
                                  ? 'Every analysis is compared against this capture'
                                  : 'Selected as the baseline, but baseline mode is off'
                              }
                            >
                              <Scale size={10} aria-hidden />
                              baseline
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td className="text-right">{formatBytes(analysis.file_size)}</td>
                      <td>
                        <div className="flex flex-col gap-1">
                          <StatusChip status={analysis.status} />
                          {inFlight ? (
                            <div className="w-36">
                              <ProgressBar percent={percent} />
                              <div className="mt-0.5 flex justify-between text-2xs text-faint">
                                <span className="truncate" title={analysis.stage ?? undefined}>
                                  {analysis.stage ?? 'waiting'}
                                </span>
                                <span>{percent.toFixed(0)}%</span>
                              </div>
                            </div>
                          ) : null}
                          {analysis.error ? (
                            <span
                              className="max-w-40 truncate text-2xs text-danger"
                              title={analysis.error}
                            >
                              {truncate(analysis.error, 40)}
                            </span>
                          ) : null}
                          {analysis.job_status && !inFlight ? (
                            <span className="text-2xs text-faint">job {analysis.job_status}</span>
                          ) : null}
                        </div>
                      </td>
                      <td className="text-right">{formatNumber(analysis.packet_count)}</td>
                      <td>{formatTimestamp(analysis.capture_start)}</td>
                      <td>{formatTimestamp(analysis.capture_end)}</td>
                      <td className="text-right">{formatDuration(analysis.duration)}</td>
                      <td title={formatTimestamp(analysis.created_at)}>
                        {formatRelativeTime(analysis.created_at)}
                      </td>
                      <td>
                        <div className="flex items-center gap-1">
                          <button
                            type="button"
                            className="btn px-1.5 py-1"
                            title="Make active and open the dashboard"
                            disabled={analysis.status !== 'completed'}
                            onClick={() => {
                              setAnalysisId(analysis.id)
                              navigate('/')
                            }}
                          >
                            <Play size={12} aria-hidden />
                            Open
                          </button>
                          {inFlight ? (
                            <button
                              type="button"
                              className="btn px-1.5 py-1"
                              title="Request cancellation"
                              disabled={cancelMutation.isPending}
                              onClick={() => cancelMutation.mutate(analysis.id)}
                            >
                              <Ban size={12} aria-hidden />
                              Cancel
                            </button>
                          ) : null}
                          <button
                            type="button"
                            className="btn btn-danger px-1.5 py-1"
                            title="Delete this analysis and all derived rows"
                            onClick={() => setPendingDelete(analysis)}
                          >
                            <Trash2 size={12} aria-hidden />
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Toolbar className="rounded border border-border bg-surface">
        <span className="text-2xs text-faint">
          Analyses run locally through TShark. Deleting an analysis removes its derived rows and the
          stored capture from <span className="mono">data/analyses/&lt;id&gt;/</span>.
        </span>
      </Toolbar>

      {pendingDelete ? (
        <ConfirmDialog
          analysis={pendingDelete}
          busy={deleteMutation.isPending}
          error={deleteMutation.error}
          onCancel={() => {
            deleteMutation.reset()
            setPendingDelete(null)
          }}
          onConfirm={() => deleteMutation.mutate(pendingDelete.id)}
        />
      ) : null}
    </Page>
  )
}

export default PcapFilesPage
