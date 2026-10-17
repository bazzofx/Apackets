import { useMemo, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Ban,
  CheckCircle2,
  Download,
  FileUp,
  Info,
  Pencil,
  Play,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  TriangleAlert,
  Trash2,
  X,
  XCircle,
} from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import Toolbar from '@/components/Toolbar'
import { useAnalysis } from '@/hooks/useAnalysis'
import { suricataApi, toApiError, type UploadProgress } from '@/services/api'
import type { SuricataRule, SuricataRunResult } from '@/types'
import { formatDuration, formatNumber, formatTimestamp } from '@/utils/format'

const PAGE_SIZES = [25, 50, 100, 250]
const SEVERITY_OPTIONS = ['', 'high', 'medium', 'low', 'informational']

interface EditorState {
  rule: SuricataRule
  text: string
}

function RuleEditor({
  state,
  busy,
  error,
  onClose,
  onSave,
}: {
  state: EditorState
  busy: boolean
  error: unknown
  onClose: () => void
  onSave: (text: string) => void
}) {
  const [text, setText] = useState(state.text)
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4">
      <div className="panel flex max-h-[90vh] w-full max-w-4xl flex-col" role="dialog" aria-modal="true">
        <div className="panel-header">
          <div className="min-w-0">
            <div className="panel-title">Edit rule sid {state.rule.sid}</div>
            <div className="mt-0.5 truncate text-2xs text-faint">{state.rule.msg}</div>
          </div>
          <button type="button" className="btn btn-ghost px-1.5 py-1" onClick={onClose} title="Close">
            <X size={13} aria-hidden />
          </button>
        </div>
        <div className="flex min-h-0 flex-1 flex-col gap-2 p-3">
          <p className="text-2xs text-faint">
            The rule is stored verbatim. The sid must stay {state.rule.sid} - a rule cannot be moved
            to another sid. Saving re-parses the signature and recalculates what the matcher can
            evaluate.
          </p>
          <textarea
            className="input min-h-[8rem] flex-1 whitespace-pre font-mono text-2xs leading-relaxed"
            spellCheck={false}
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
          {error ? <ErrorState error={error} variant="plain" className="py-2" /> : null}
        </div>
        <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2">
          <span className="text-2xs text-faint">{text.length} characters</span>
          <div className="flex items-center gap-2">
            <button type="button" className="btn" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onSave(text.trim())}
              disabled={busy || text.trim() === state.text.trim()}
            >
              <Save size={13} aria-hidden />
              {busy ? 'Saving...' : 'Save rule'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function RunSummary({ result, analysisName }: { result: SuricataRunResult; analysisName: string }) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2 text-2xs">
      <CheckCircle2 size={14} className="text-ok" aria-hidden />
      <span className="text-text">
        Matched {formatNumber(result.rules_matched)} rule(s) against {analysisName} in{' '}
        {formatDuration(result.seconds ?? null)} - {formatNumber(result.findings)} finding(s)
      </span>
      <span className="text-muted">
        {formatNumber(result.rules_evaluated)} rules evaluated (
        {formatNumber(result.rules_packet_scope ?? 0)} packet,{' '}
        {formatNumber(result.rules_http_scope ?? 0)} HTTP)
      </span>
      <div className="flex items-center gap-1">
        <SeverityBadge severity="high" count={result.by_severity?.high ?? 0} />
        <SeverityBadge severity="medium" count={result.by_severity?.medium ?? 0} />
        <SeverityBadge severity="low" count={result.by_severity?.low ?? 0} />
        <SeverityBadge severity="informational" count={result.by_severity?.informational ?? 0} />
      </div>
      <Link to="/findings" className="btn ml-auto">
        <ShieldAlert size={12} aria-hidden />
        Open findings
      </Link>
    </div>
  )
}
/** Suricata-compatible detection rules: browse, upload, edit, disable, remove. */
export function SuricataRulesPanel() {
  const queryClient = useQueryClient()
  const { analysisId, selected } = useAnalysis()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  // The finding overview links here with ?sid=<n> to jump straight to the rule.
  const [searchParams] = useSearchParams()
  const [search, setSearch] = useState(() => searchParams.get('sid') ?? '')
  const [severity, setSeverity] = useState('')
  const [enabledFilter, setEnabledFilter] = useState<'' | 'true' | 'false'>('')
  const [supportedFilter, setSupportedFilter] = useState<'' | 'true' | 'false'>('')
  const [source, setSource] = useState('')
  const [editor, setEditor] = useState<EditorState | null>(null)
  const [pendingDelete, setPendingDelete] = useState<SuricataRule | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [uploadPercent, setUploadPercent] = useState<number | null>(null)
  const [runResult, setRunResult] = useState<SuricataRunResult | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  const listParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      search: search.trim() || undefined,
      severity: severity || undefined,
      enabled: enabledFilter === '' ? undefined : enabledFilter === 'true',
      supported: supportedFilter === '' ? undefined : supportedFilter === 'true',
      source: source || undefined,
      analysis_id: analysisId ?? undefined,
      sort: 'severity',
      order: 'asc' as const,
    }),
    [page, pageSize, search, severity, enabledFilter, supportedFilter, source, analysisId],
  )

  const rules = useQuery({
    queryKey: ['suricata-rules', listParams],
    queryFn: () => suricataApi.rules(listParams),
  })
  const stats = useQuery({ queryKey: ['suricata-stats'], queryFn: () => suricataApi.stats() })
  const config = useQuery({ queryKey: ['suricata-config'], queryFn: () => suricataApi.config() })

  const invalidateRules = () => {
    void queryClient.invalidateQueries({ queryKey: ['suricata-rules'] })
    void queryClient.invalidateQueries({ queryKey: ['suricata-stats'] })
  }

  const seedMutation = useMutation({
    mutationFn: () => suricataApi.seedRules(),
    onSuccess: (result) => {
      setNotice(
        'Bundled rules imported: ' +
          formatNumber(result.imported) +
          ' new, ' +
          formatNumber(result.updated) +
          ' refreshed from ' +
          result.files +
          ' file(s).',
      )
      invalidateRules()
    },
  })

  const importMutation = useMutation({
    mutationFn: (files: File[]) =>
      suricataApi.importRules(files, {
        onProgress: (progress: UploadProgress) => setUploadPercent(progress.percent),
      }),
    onSuccess: (result) => {
      setUploadPercent(null)
      setNotice(
        'Imported ' +
          formatNumber(result.imported) +
          ' new and updated ' +
          formatNumber(result.updated) +
          ' rule(s)' +
          (result.errors.length > 0
            ? ' - ' + result.errors.length + ' line(s) could not be parsed.'
            : '.'),
      )
      invalidateRules()
    },
  })

  const updateMutation = useMutation({
    mutationFn: (payload: { sid: number; enabled?: boolean; raw?: string }) =>
      suricataApi.updateRule(payload.sid, { enabled: payload.enabled, raw: payload.raw }),
    onSuccess: () => {
      setEditor(null)
      invalidateRules()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (sid: number) => suricataApi.deleteRule(sid),
    onSuccess: () => {
      setPendingDelete(null)
      invalidateRules()
    },
  })

  /**
   * Put a rule back to the definition the vendored tree carries: its text, its
   * revision and its enabled state. Rules that are not vendored have no default,
   * so the action is not offered for them - the API answers 404
   * `no_bundled_default` and this panel never asks.
   */
  const restoreMutation = useMutation({
    mutationFn: (rule: SuricataRule) => suricataApi.restoreRule(rule.sid),
    onSuccess: (rule) => {
      setNotice('Sid ' + rule.sid + ' restored to its vendored default: ' + rule.msg)
      invalidateRules()
    },
  })

  const runMutation = useMutation({
    mutationFn: (target: string) => suricataApi.run(target),
    onSuccess: (result) => {
      setRunResult(result)
      if (analysisId) {
        void queryClient.invalidateQueries({ queryKey: ['suricata-rules'] })
        void queryClient.invalidateQueries({ queryKey: ['findings', analysisId] })
        void queryClient.invalidateQueries({ queryKey: ['findings-counts', analysisId] })
        void queryClient.invalidateQueries({ queryKey: ['summary', analysisId] })
      }
    },
  })

  const items = rules.data?.items ?? []
  const engine = config.data?.engine
  const analysisName = selected?.original_filename ?? 'the selected capture'

  const onPickFiles = (files: FileList | null) => {
    if (!files || files.length === 0) return
    const list = Array.from(files)
    const good = list.filter((file) => file.name.toLowerCase().endsWith('.rules'))
    const bad = list.filter((file) => !file.name.toLowerCase().endsWith('.rules'))
    if (bad.length > 0) {
      setNotice(
        'Skipped ' +
          bad.map((file) => file.name).join(', ') +
          ' - upload Suricata .rules files (plain text).',
      )
    }
    if (good.length > 0) importMutation.mutate(good)
  }

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Suricata rules"
        subtitle="signature-based detections evaluated against this capture's indexed fields"
        flush
        actions={
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              className="btn"
              onClick={() => seedMutation.mutate()}
              disabled={seedMutation.isPending}
              title="Import the rule sets vendored under backend/rules/"
            >
              <Download size={13} aria-hidden />
              {seedMutation.isPending ? 'Importing...' : 'Import bundled'}
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => fileInput.current?.click()}
              disabled={importMutation.isPending}
              title="Upload one or more .rules files"
            >
              <FileUp size={13} aria-hidden />
              {importMutation.isPending ? 'Uploading...' : 'Upload .rules'}
            </button>
            <input
              ref={fileInput}
              type="file"
              accept=".rules,.txt"
              multiple
              className="hidden"
              onChange={(event) => {
                onPickFiles(event.target.files)
                event.target.value = ''
              }}
            />
            <button
              type="button"
              className="btn btn-primary"
              disabled={!analysisId || runMutation.isPending}
              onClick={() => analysisId && runMutation.mutate(analysisId)}
              title={
                analysisId
                  ? 'Evaluate every enabled rule against ' + analysisName
                  : 'Select an analysis first'
              }
            >
              <Play size={13} aria-hidden />
              {runMutation.isPending ? 'Running...' : 'Run on capture'}
            </button>
          </div>
        }
      >
        {stats.data ? (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-3 py-2 text-2xs">
            <span className="text-text">
              <span className="mono">{formatNumber(stats.data.total)}</span> rules
            </span>
            <span className="text-muted">
              <span className="mono">{formatNumber(stats.data.enabled)}</span> enabled
            </span>
            <span className="text-muted">
              <span className="mono">{formatNumber(stats.data.supported)}</span> evaluable
            </span>
            <span
              className="text-warn"
              title="Rules whose options need features ShinboShark cannot honour (flowbits, thresholds, raw payload buffers, undissected protocols). They are stored and listed but skipped when matching."
            >
              <span className="mono">{formatNumber(stats.data.unsupported)}</span> skipped by the matcher
            </span>
            {stats.data.modified ? (
              <span
                className="text-warn"
                title="Rules that are not running the definition the vendored rule tree carries: their text was edited, their revision differs, or they are switched off. Tinted rows in the table are these rules; each can be put back with Restore."
              >
                <span className="mono">{formatNumber(stats.data.modified)}</span> not at defaults
              </span>
            ) : null}
            <div className="flex items-center gap-1">
              <SeverityBadge severity="high" count={stats.data.severities.high} />
              <SeverityBadge severity="medium" count={stats.data.severities.medium} />
              <SeverityBadge severity="low" count={stats.data.severities.low} />
              <SeverityBadge severity="informational" count={stats.data.severities.informational} />
            </div>
            {stats.data.sources.length > 0 ? (
              <span className="ml-auto text-faint">
                sources:{' '}
                {stats.data.sources
                  .slice(0, 4)
                  .map((entry) => entry.source + ' (' + formatNumber(entry.rules) + ')')
                  .join(' | ')}
              </span>
            ) : null}
          </div>
        ) : null}

        {engine ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-muted">
            <Info size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            <span>
              Engine: <span className="mono">{engine.engine}</span> - {engine.note} Patterns are
              matched against TShark-extracted fields (URI, host, method, headers, bodies, DNS name,
              TLS SNI); rules that need raw packet payloads are skipped rather than approximated.
            </span>
          </div>
        ) : null}

        {stats.data && stats.data.modified ? (
          <div className="flex items-start gap-2 border-b border-border bg-warn/[0.05] px-3 py-2 text-2xs text-warn">
            <TriangleAlert size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span>
              {formatNumber(stats.data.modified)} rule(s) are not running their vendored default -
              their text, revision or enabled state differs from the file under the bundled rule
              tree. They are tinted below; <span className="font-semibold">Restore</span> puts one
              back.
            </span>
          </div>
        ) : null}

        {notice ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-accent2">
            <Info size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span className="flex-1">{notice}</span>
            <button type="button" className="btn btn-ghost px-1 py-0.5" onClick={() => setNotice(null)}>
              <X size={12} aria-hidden />
            </button>
          </div>
        ) : null}

        {uploadPercent !== null ? (
          <div className="border-b border-border px-3 py-2">
            <div className="mb-1 flex justify-between text-2xs text-muted">
              <span>Uploading rule file...</span>
              <span className="mono">{uploadPercent.toFixed(0)}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded bg-surface2">
              <div className="h-full bg-accent" style={{ width: uploadPercent + '%' }} />
            </div>
          </div>
        ) : null}

        {runResult ? <RunSummary result={runResult} analysisName={analysisName} /> : null}
        <Toolbar>
          <input
            className="input w-64"
            placeholder="search message, sid or rule text..."
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setPage(1)
            }}
          />
          <select
            className="select"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value)
              setPage(1)
            }}
            title="Severity"
          >
            {SEVERITY_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option === '' ? 'all severities' : option}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={enabledFilter}
            onChange={(event) => {
              setEnabledFilter(event.target.value as '' | 'true' | 'false')
              setPage(1)
            }}
            title="Enabled state"
          >
            <option value="">enabled + disabled</option>
            <option value="true">enabled only</option>
            <option value="false">disabled only</option>
          </select>
          <select
            className="select"
            value={supportedFilter}
            onChange={(event) => {
              setSupportedFilter(event.target.value as '' | 'true' | 'false')
              setPage(1)
            }}
            title="Matcher support"
          >
            <option value="">all rules</option>
            <option value="true">evaluable by the matcher</option>
            <option value="false">skipped by the matcher</option>
          </select>
          {stats.data && stats.data.sources.length > 0 ? (
            <select
              className="select max-w-48"
              value={source}
              onChange={(event) => {
                setSource(event.target.value)
                setPage(1)
              }}
              title="Rule source"
            >
              <option value="">all sources</option>
              {stats.data.sources.map((entry) => (
                <option key={entry.source} value={entry.source}>
                  {entry.source} ({entry.rules})
                </option>
              ))}
            </select>
          ) : null}
          <button type="button" className="btn" onClick={() => void rules.refetch()} title="Reload rules">
            <RefreshCw size={13} aria-hidden />
            Refresh
          </button>
        </Toolbar>

        {seedMutation.error ? (
          <ErrorState
            error={seedMutation.error}
            variant="plain"
            title="Could not import the bundled rules"
            className="py-3"
          />
        ) : null}
        {importMutation.error ? (
          <ErrorState
            error={importMutation.error}
            variant="plain"
            title="Rule upload failed"
            className="py-3"
          />
        ) : null}
        {runMutation.error ? (
          <ErrorState
            error={runMutation.error}
            variant="plain"
            title="Could not run the rules"
            className="py-3"
          />
        ) : null}
        {restoreMutation.error ? (
          <ErrorState
            error={restoreMutation.error}
            variant="plain"
            title="Could not restore the rule"
            className="py-3"
          />
        ) : null}

        {rules.isLoading ? (
          <LoadingState label="Loading rules..." rows={5} />
        ) : rules.error ? (
          <ErrorState
            error={rules.error}
            variant="plain"
            title="Could not load Suricata rules"
            onRetry={() => void rules.refetch()}
          />
        ) : items.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={ShieldAlert}
            title={stats.data && stats.data.total > 0 ? 'No rules match these filters' : 'No rules loaded'}
            description={
              stats.data && stats.data.total > 0
                ? 'Adjust the search or filters, or import another rule file.'
                : 'Import the bundled rule sets (daffainfo + OISF) or upload your own .rules file to start matching signatures.'
            }
            className="py-8"
          />
        ) : (
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>SID</th>
                  <th>Severity</th>
                  <th>Proto</th>
                  <th>Action</th>
                  <th>Message</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th className="text-right">Hits</th>
                  <th>State</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((rule) => (
                  <tr
                    key={rule.sid}
                    className={clsx(!rule.enabled && 'opacity-60', rule.modified && 'bg-warn/[0.07]')}
                  >
                    <td className="text-right">{rule.sid}</td>
                    <td>
                      <SeverityBadge severity={rule.severity} showLabel />
                    </td>
                    <td className="text-muted">{rule.protocol}</td>
                    <td className="text-muted">{rule.action}</td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <MonoCell maxWidth={420} title={rule.msg}>
                          {rule.msg}
                        </MonoCell>
                        {!rule.supported ? (
                          <span
                            className="chip border-warn/50 bg-warn/15 text-warn"
                            title={
                              'Skipped by the matcher: ' +
                              (rule.unsupported.join(', ') || 'unsupported options')
                            }
                          >
                            <Ban size={10} aria-hidden />
                            skipped
                          </span>
                        ) : null}
                        {rule.approximate ? (
                          <span
                            className="chip border-border2 bg-surface2 text-muted"
                            title="Matched against extracted fields rather than raw payload bytes"
                          >
                            field match
                          </span>
                        ) : null}
                        {rule.modified ? (
                          <span
                            className="chip border-warn/60 bg-warn/15 text-warn"
                            title={
                              'Not the vendored default: ' +
                              (rule.differs && rule.differs.length > 0
                                ? rule.differs.join(', ')
                                : 'differs') +
                              (rule.restorable
                                ? '. Use Restore to put it back.'
                                : '. This rule is not vendored, so there is no default to restore.')
                            }
                          >
                            <TriangleAlert size={10} aria-hidden />
                            modified
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <MonoCell maxWidth={170} title={rule.category ?? undefined}>
                        {rule.category ?? '-'}
                      </MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={150} title={rule.source}>
                        {rule.source}
                      </MonoCell>
                    </td>
                    <td className="text-right">
                      {rule.hits === null || rule.hits === undefined ? '-' : formatNumber(rule.hits)}
                    </td>
                    <td>
                      <button
                        type="button"
                        className={clsx('btn px-1.5 py-1', rule.enabled && 'btn-primary')}
                        title={rule.enabled ? 'Disable this rule' : 'Enable this rule'}
                        disabled={updateMutation.isPending}
                        onClick={() => updateMutation.mutate({ sid: rule.sid, enabled: !rule.enabled })}
                      >
                        {rule.enabled ? (
                          <CheckCircle2 size={12} aria-hidden />
                        ) : (
                          <XCircle size={12} aria-hidden />
                        )}
                        {rule.enabled ? 'enabled' : 'disabled'}
                      </button>
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          className="btn px-1.5 py-1"
                          title="Edit the rule text"
                          onClick={() => setEditor({ rule, text: rule.raw })}
                        >
                          <Pencil size={12} aria-hidden />
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn px-1.5 py-1"
                          disabled={!rule.modified || !rule.restorable || restoreMutation.isPending}
                          title={
                            !rule.modified
                              ? 'This rule is already running its vendored definition'
                              : rule.restorable
                                ? 'Put this rule back to the text and state its bundled file defines'
                                : 'This rule is not vendored, so there is no default to restore'
                          }
                          onClick={() => restoreMutation.mutate(rule)}
                        >
                          <RotateCcw size={12} aria-hidden />
                          Restore
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger px-1.5 py-1"
                          title="Remove this rule"
                          onClick={() => setPendingDelete(rule)}
                        >
                          <Trash2 size={12} aria-hidden />
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {rules.data ? (
          <Pagination
            page={page}
            pageSize={pageSize}
            total={rules.data.total}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size)
              setPage(1)
            }}
            pageSizeOptions={PAGE_SIZES}
            disabled={rules.isFetching}
          />
        ) : null}
      </Panel>

      {config.data ? (
        <Panel title="Matcher scope" subtitle="what the built-in matcher evaluates">
          <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs md:grid-cols-[12rem_1fr]">
            <dt className="text-faint">HOME_NET</dt>
            <dd className="mono text-text">{config.data.home_net.join(', ')}</dd>
            <dt className="text-faint">Bundled rule files</dt>
            <dd className="mono text-text">
              {(config.data.bundled_files ?? 0) + ' file(s) in ' + (config.data.bundled_rules_dir ?? '-')}
            </dd>
            <dt className="text-faint">Findings per rule</dt>
            <dd className="mono text-text">
              at most {formatNumber(config.data.max_findings_per_rule)} grouped findings per rule per capture
            </dd>
            <dt className="text-faint">Suricata binary</dt>
            <dd className="mono text-text">
              {engine?.suricata_binary ?? 'not used - matches run in-process over TShark output'}
            </dd>
            <dt className="text-faint">Unsupported options</dt>
            <dd className="text-muted">
              {config.data.include_unsupported
                ? 'included (rules without support are matched on their supported options only)'
                : 'rules needing them are skipped and flagged in the table'}
            </dd>
          </dl>
        </Panel>
      ) : null}

      {editor ? (
        <RuleEditor
          state={editor}
          busy={updateMutation.isPending}
          error={updateMutation.error ? toApiError(updateMutation.error) : null}
          onClose={() => {
            updateMutation.reset()
            setEditor(null)
          }}
          onSave={(text) => updateMutation.mutate({ sid: editor.rule.sid, raw: text })}
        />
      ) : null}

      {pendingDelete ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4">
          <div className="panel w-full max-w-lg" role="dialog" aria-modal="true">
            <div className="panel-header">
              <span className="panel-title">Remove rule sid {pendingDelete.sid}</span>
              <button
                type="button"
                className="btn btn-ghost px-1.5 py-1"
                onClick={() => setPendingDelete(null)}
                title="Close"
              >
                <X size={13} aria-hidden />
              </button>
            </div>
            <div className="flex flex-col gap-2 p-3 text-xs text-muted">
              <p className="text-text">{pendingDelete.msg}</p>
              <p>
                Imported {formatTimestamp(pendingDelete.created_at)} from{' '}
                <span className="mono">{pendingDelete.source}</span>. Deleting removes the rule and its
                stored text; findings already produced by it stay in the analysis.
              </p>
              {deleteMutation.error ? (
                <ErrorState error={deleteMutation.error} variant="plain" className="py-2" />
              ) : null}
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-border px-3 py-2">
              <button type="button" className="btn" onClick={() => setPendingDelete(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={deleteMutation.isPending}
                onClick={() => deleteMutation.mutate(pendingDelete.sid)}
              >
                <Trash2 size={13} aria-hidden />
                {deleteMutation.isPending ? 'Removing...' : 'Remove rule'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default SuricataRulesPanel