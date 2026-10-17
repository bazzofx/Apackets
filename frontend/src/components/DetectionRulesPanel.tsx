import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  CheckCircle2,
  Info,
  ListTree,
  Pencil,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  TriangleAlert,
  X,
  XCircle,
} from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import Toolbar from '@/components/Toolbar'
import { useAnalysis } from '@/hooks/useAnalysis'
import { detectionApi, findingsApi, suricataApi, toApiError } from '@/services/api'
import type { DetectionRule, DetectionRuleUpdate } from '@/types'
import { formatNumber } from '@/utils/format'

const SEVERITY_OPTIONS = ['', 'high', 'medium', 'low', 'informational']

/**
 * The threshold keys the editor renders.
 *
 * Two keys are deliberately not offered:
 *  - 'enabled' is the rule's switch, not a threshold, and the API rejects it
 *    inside the thresholds object;
 *  - 'max_mb' is a mirror of 'max_bytes' that the engine always derives, so
 *    editing it directly would be overwritten. The editor edits megabytes under
 *    the 'max_bytes' key's row instead.
 */
function fieldKeys(rule: DetectionRule): string[] {
  return Object.keys(rule.defaults).filter((key) => key !== 'max_mb' && key !== 'enabled')
}

/** What a threshold counts, said in words next to its input. */
function unitFor(key: string): string {
  if (key === 'max_bytes') return 'megabytes'
  if (key === 'common_ports') return 'ports, comma separated'
  if (key.endsWith('_s')) return 'seconds'
  if (key === 'syn_ratio') return 'ratio, 0 to 1'
  if (key === 'median_multiplier') return 'times the median sender'
  if (key.endsWith('_bytes')) return 'bytes'
  if (key.startsWith('min_') || key.startsWith('max_')) return 'count'
  return ''
}

/** The value the editor starts from, as the string a text input shows. */
function initialValue(rule: DetectionRule, key: string): string {
  if (key === 'max_bytes') {
    const megabytes = rule.thresholds.max_mb
    const bytes = rule.thresholds.max_bytes
    const value =
      typeof megabytes === 'number'
        ? megabytes
        : typeof bytes === 'number'
          ? bytes / (1024 * 1024)
          : null
    return value === null ? '' : String(Math.round(value * 100) / 100)
  }
  const value = rule.thresholds[key]
  if (Array.isArray(value)) return value.join(', ')
  if (value === null || value === undefined) return ''
  return String(value)
}

/** The documented default, shown beside the input so drift is visible. */
function defaultText(rule: DetectionRule, key: string): string {
  if (key === 'max_bytes') {
    const megabytes = rule.defaults.max_mb
    if (typeof megabytes === 'number') return String(megabytes) + ' mb'
    return 'no limit'
  }
  const value = rule.defaults[key]
  if (value === null) return 'the built-in list'
  if (Array.isArray(value)) return value.join(', ')
  return String(value)
}

/** True when the rule's effective value differs from its documented default. */
function isCustomised(rule: DetectionRule, key: string): boolean {
  if (key === 'max_bytes') {
    return typeof rule.thresholds.max_bytes === 'number' &&
      typeof rule.defaults.max_bytes === 'number'
      ? rule.thresholds.max_bytes !== rule.defaults.max_bytes
      : false
  }
  const current = rule.thresholds[key]
  const original = rule.defaults[key]
  if (Array.isArray(current) || Array.isArray(original)) {
    return JSON.stringify(current ?? null) !== JSON.stringify(original ?? null)
  }
  return String(current ?? '') !== String(original ?? '')
}

/** How a deviation is named in the interface, key by key. */
const DIFFERS_LABEL: Record<string, string> = { enabled: 'switched off' }

/** "switched off, min_nxdomain" — what moved, for the row's tooltip. */
function describeDiffers(rule: DetectionRule): string {
  const keys = rule.differs ?? []
  if (keys.length === 0) return 'differs from the defaults'
  return keys.map((key) => DIFFERS_LABEL[key] ?? key).join(', ')
}

/**
 * The threshold editor for one built-in rule.
 *
 * There is no rule text to edit here, because these rules are code. What the form
 * changes is the configuration the code reads, and each field is checked against
 * the same shape the API validates so a rejected value is explained in place
 * rather than only after the round trip.
 */
function RuleEditor({
  rule,
  busy,
  error,
  onClose,
  onSave,
  onReset,
}: {
  rule: DetectionRule
  busy: boolean
  error: unknown
  onClose: () => void
  onSave: (payload: DetectionRuleUpdate) => void
  onReset: () => void
}) {
  const keys = fieldKeys(rule)
  const [enabled, setEnabled] = useState(rule.enabled)
  const [values, setValues] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {}
    for (const key of keys) out[key] = initialValue(rule, key)
    return out
  })
  const [localError, setLocalError] = useState<string | null>(null)

  const changedKeys = keys.filter((key) => values[key] !== initialValue(rule, key))
  const dirty = changedKeys.length > 0 || enabled !== rule.enabled

  const submit = () => {
    const thresholds: Record<string, unknown> = {}
    for (const key of changedKeys) {
      const text = String(values[key] ?? '').trim()
      if (key === 'common_ports') {
        if (!text) {
          thresholds[key] = null
          continue
        }
        const ports = text.split(/[,\s]+/).filter(Boolean).map(Number)
        if (ports.some((port) => !Number.isInteger(port) || port < 0 || port > 65535)) {
          setLocalError('Common ports must be whole numbers between 0 and 65535.')
          return
        }
        thresholds[key] = ports
        continue
      }
      if (key === 'max_bytes') {
        const megabytes = Number(text)
        if (!Number.isFinite(megabytes) || megabytes <= 0) {
          setLocalError('The volume limit must be a positive number of megabytes.')
          return
        }
        thresholds.max_mb = megabytes
        continue
      }
      const number = Number(text)
      if (!Number.isFinite(number) || number <= 0) {
        setLocalError('"' + key + '" must be a positive number.')
        return
      }
      thresholds[key] = number
    }

    const payload: DetectionRuleUpdate = {}
    if (enabled !== rule.enabled) payload.enabled = enabled
    if (Object.keys(thresholds).length > 0) payload.thresholds = thresholds
    setLocalError(null)
    onSave(payload)
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4">
      <div className="panel flex max-h-[90vh] w-full max-w-3xl flex-col" role="dialog" aria-modal="true">
        <div className="panel-header">
          <div className="min-w-0">
            <div className="panel-title">{rule.title}</div>
            <div className="mt-0.5 truncate text-2xs text-faint">
              <span className="mono">{rule.rule_id}</span> · {rule.severity} rule
            </div>
          </div>
          <button type="button" className="btn btn-ghost px-1.5 py-1" onClick={onClose} title="Close">
            <X size={13} aria-hidden />
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto p-3">
          <p className="text-2xs leading-relaxed text-faint">
            This rule is code, not a signature: its matching logic is fixed. What can be tuned
            here is whether it runs and the numbers it compares against, and the threshold
            sentence below is regenerated from those numbers.
          </p>

          <div className="rounded border border-border bg-bg p-2 text-2xs leading-relaxed text-text">
            <span className="mr-1 font-semibold uppercase tracking-wider text-faint">Fires when</span>
            {rule.threshold}
          </div>

          <label className="flex items-center gap-2 text-xs text-text">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
            />
            Run this rule during analysis
          </label>

          {keys.length === 0 ? (
            <p className="text-2xs text-muted">
              This rule has no tunable thresholds - it can only be enabled or disabled.
            </p>
          ) : (
            <div className="overflow-auto rounded border border-border">
              <table className="dt">
                <thead>
                  <tr>
                    <th>Threshold</th>
                    <th>Value</th>
                    <th>Default</th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((key) => (
                    <tr key={key}>
                      <td>
                        <div className="mono text-text">{key}</div>
                        <div className="text-2xs text-faint">{unitFor(key)}</div>
                      </td>
                      <td>
                        <input
                          className="input w-32"
                          inputMode="decimal"
                          value={values[key] ?? ''}
                          placeholder={defaultText(rule, key)}
                          onChange={(event) =>
                            setValues((previous) => ({ ...previous, [key]: event.target.value }))
                          }
                        />
                      </td>
                      <td>
                        <span className="mono text-faint">{defaultText(rule, key)}</span>
                        {isCustomised(rule, key) ? (
                          <span className="chip ml-1 border-accent/50 bg-accent/15 text-accent2">
                            tuned
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {rule.notes ? (
            <p className="text-2xs leading-relaxed text-muted">{rule.notes}</p>
          ) : null}

          {localError ? <ErrorState error={localError} variant="plain" className="py-2" /> : null}
          {error ? <ErrorState error={toApiError(error)} variant="plain" className="py-2" /> : null}
        </div>

        <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2">
          <button
            type="button"
            className="btn"
            onClick={onReset}
            disabled={busy}
            title="Restore the documented defaults for this rule"
          >
            <RotateCcw size={13} aria-hidden />
            Restore defaults
          </button>
          <div className="flex items-center gap-2">
            <button type="button" className="btn" onClick={onClose} disabled={busy}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={submit}
              disabled={busy || !dirty}
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

/**
 * Built-in detection rules: what the detection stage runs, what each rule counts,
 * and the thresholds it counts against.
 *
 * These are the heuristics that produce most findings in a capture (NXDOMAIN
 * bursts, outbound volume, rare destination ports, ...). They were previously
 * configurable only through the backend settings row; this panel is the interface
 * for that configuration, and it is deliberately honest about its limits: the
 * matching logic is code, so a rule can be switched off and re-tuned, not
 * rewritten.
 */
export function DetectionRulesPanel() {
  const queryClient = useQueryClient()
  const { analysisId, selected } = useAnalysis()
  const [searchParams] = useSearchParams()

  const [search, setSearch] = useState(() => searchParams.get('rule') ?? '')
  const [severity, setSeverity] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')
  const [editorFor, setEditorFor] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const rules = useQuery({
    queryKey: ['detection-rules', analysisId],
    queryFn: () => detectionApi.rules(analysisId),
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['detection-rules'] })
    void queryClient.invalidateQueries({ queryKey: ['finding-context'] })
    void queryClient.invalidateQueries({ queryKey: ['finding-rules', analysisId] })
    void queryClient.invalidateQueries({ queryKey: ['findings', analysisId] })
    void queryClient.invalidateQueries({ queryKey: ['findings-counts', analysisId] })
    void queryClient.invalidateQueries({ queryKey: ['summary', analysisId] })
  }

  const updateMutation = useMutation({
    mutationFn: (input: { ruleId: string; payload: DetectionRuleUpdate }) =>
      detectionApi.update(input.ruleId, input.payload, analysisId),
    onSuccess: (rule, variables) => {
      setEditorFor(null)
      setNotice(
        variables.payload.reset
          ? rule.title + ' restored to its defaults: ' + rule.threshold
          : rule.title + ' updated: ' + rule.threshold,
      )
      invalidate()
    },
  })

  /**
   * The detection engine rewrites every finding row for the analysis, so the
   * Suricata matcher has to run afterwards - the same order the Findings page
   * uses. Without this the new thresholds would only apply to future captures.
   */
  const rerun = useMutation({
    mutationFn: async () => {
      const built = await findingsApi.rescan(analysisId as string)
      const suricata = await suricataApi.run(analysisId as string)
      return { built, suricata }
    },
    onSuccess: ({ built, suricata }) => {
      setNotice(
        'Re-ran ' + formatNumber(built.rules_run) + ' built-in rule(s) -> ' +
          formatNumber(built.findings) + ' finding(s); Suricata matched ' +
          formatNumber(suricata.rules_matched) + ' rule(s) -> ' +
          formatNumber(suricata.findings) + ' finding(s).',
      )
      invalidate()
    },
  })

  const items = rules.data?.items ?? []
  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    return items.filter((rule) => {
      if (severity && rule.severity !== severity) return false
      if (enabledFilter === 'true' && !rule.enabled) return false
      if (enabledFilter === 'false' && rule.enabled) return false
      if (!term) return true
      return (
        rule.rule_id.toLowerCase().includes(term) ||
        rule.title.toLowerCase().includes(term) ||
        rule.threshold.toLowerCase().includes(term) ||
        rule.description.toLowerCase().includes(term)
      )
    })
  }, [items, search, severity, enabledFilter])

  const editorRule = editorFor ? items.find((rule) => rule.rule_id === editorFor) ?? null : null
  const analysisName = selected?.original_filename ?? 'the selected capture'
  const modifiedCount = items.filter((rule) => rule.modified).length

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Detection rules"
        subtitle="built-in heuristics run over every capture - view, enable/disable and tune thresholds"
        flush
        actions={
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              className="btn"
              onClick={() => void rules.refetch()}
              disabled={rules.isFetching}
              title="Reload the rule configuration"
            >
              <RefreshCw size={13} aria-hidden />
              Refresh
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!analysisId || rerun.isPending}
              onClick={() => analysisId && rerun.mutate()}
              title={
                analysisId
                  ? 'Re-run the built-in rules and the Suricata matcher against ' + analysisName
                  : 'Select an analysis first'
              }
            >
              <ListTree size={13} aria-hidden />
              {rerun.isPending ? 'Re-running...' : 'Re-run on capture'}
            </button>
          </div>
        }
      >
        {rules.data ? (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-3 py-2 text-2xs">
            <span className="text-text">
              <span className="mono">{formatNumber(rules.data.total)}</span> rules
            </span>
            <span className="text-muted">
              <span className="mono">{formatNumber(rules.data.enabled)}</span> enabled
            </span>
            <div className="flex items-center gap-1">
              <SeverityBadge severity="high" count={rules.data.severities.high} />
              <SeverityBadge severity="medium" count={rules.data.severities.medium} />
              <SeverityBadge severity="low" count={rules.data.severities.low} />
              <SeverityBadge severity="informational" count={rules.data.severities.informational} />
            </div>
            {modifiedCount > 0 ? (
              <span
                className="text-warn"
                title="Rules whose switch or thresholds differ from the documented defaults. Tinted rows below are these rules; each can be put back with Restore."
              >
                <span className="mono">{formatNumber(modifiedCount)}</span> not at defaults
              </span>
            ) : null}
            <span className="ml-auto text-faint">
              {analysisId
                ? 'hit counts are for ' + analysisName
                : 'select an analysis to see hit counts'}
            </span>
          </div>
        ) : null}

        <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-muted">
          <Info size={13} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <span>
            These rules are code, not signatures: the matching logic is fixed and the
            configuration below is what it reads. A change applies to the next analysis, and to
            an existing one only after "Re-run on capture", because stored findings keep the
            thresholds they ran with.
          </span>
        </div>

        {notice ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-accent2">
            <CheckCircle2 size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span className="flex-1">{notice}</span>
            <button type="button" className="btn btn-ghost px-1 py-0.5" onClick={() => setNotice(null)}>
              <X size={12} aria-hidden />
            </button>
          </div>
        ) : null}

        <Toolbar>
          <input
            className="input w-64"
            placeholder="search rule id, title or threshold..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <select
            className="select"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
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
            onChange={(event) => setEnabledFilter(event.target.value)}
            title="Enabled state"
          >
            <option value="">enabled + disabled</option>
            <option value="true">enabled only</option>
            <option value="false">disabled only</option>
          </select>
          <span className="text-2xs text-faint">
            {search || severity || enabledFilter
              ? formatNumber(filtered.length) + ' of ' + formatNumber(items.length) + ' shown'
              : null}
          </span>
        </Toolbar>

        {rerun.error ? (
          <ErrorState
            error={toApiError(rerun.error)}
            variant="plain"
            title="Could not re-run the rules"
            className="py-3"
          />
        ) : null}

        {rules.isLoading ? (
          <LoadingState label="Loading detection rules..." rows={4} />
        ) : rules.error ? (
          <ErrorState
            error={rules.error}
            variant="plain"
            title="Could not load the detection rules"
            onRetry={() => void rules.refetch()}
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={ShieldAlert}
            title={items.length > 0 ? 'No rules match these filters' : 'No built-in rules available'}
            description={
              items.length > 0
                ? 'Adjust the search or filters.'
                : 'The detection stage is not available in this build.'
            }
            className="py-8"
          />
        ) : (
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Fires when</th>
                  <th className="text-right">Hits</th>
                  <th>State</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => (
                  <tr
                    key={rule.rule_id}
                    className={clsx(
                      !rule.enabled && 'opacity-60',
                      rule.modified && 'bg-warn/[0.07]',
                    )}
                  >
                    <td>
                      <SeverityBadge severity={rule.severity} showLabel />
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5">
                        <span className="text-text">{rule.title}</span>
                        {rule.modified ? (
                          <span
                            className="chip border-warn/60 bg-warn/15 text-warn"
                            title={
                              'Not at its defaults: ' + describeDiffers(rule) + '. Use Restore.'
                            }
                          >
                            <TriangleAlert size={10} aria-hidden />
                            modified
                          </span>
                        ) : null}
                      </div>
                      <div className="mono text-2xs text-faint">{rule.rule_id}</div>
                    </td>
                    <td>
                      <MonoCell maxWidth={460} title={rule.threshold}>
                        {rule.threshold}
                      </MonoCell>
                    </td>
                    <td className="text-right">{formatNumber(rule.hits)}</td>
                    <td>
                      <button
                        type="button"
                        className={clsx('btn px-1.5 py-1', rule.enabled && 'btn-primary')}
                        title={rule.enabled ? 'Disable this rule' : 'Enable this rule'}
                        disabled={updateMutation.isPending}
                        onClick={() =>
                          updateMutation.mutate({
                            ruleId: rule.rule_id,
                            payload: { enabled: !rule.enabled },
                          })
                        }
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
                          title="Edit this rule's thresholds"
                          onClick={() => {
                            updateMutation.reset()
                            setEditorFor(rule.rule_id)
                          }}
                        >
                          <Pencil size={12} aria-hidden />
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn px-1.5 py-1"
                          disabled={!rule.modified || updateMutation.isPending}
                          title={
                            rule.modified
                              ? 'Put this rule back to its documented defaults'
                              : 'This rule is already at its defaults'
                          }
                          onClick={() =>
                            updateMutation.mutate({ ruleId: rule.rule_id, payload: { reset: true } })
                          }
                        >
                          <RotateCcw size={12} aria-hidden />
                          Restore
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {updateMutation.error && !editorRule ? (
          <ErrorState
            error={toApiError(updateMutation.error)}
            variant="plain"
            title="Could not update the rule"
            className="py-3"
          />
        ) : null}
      </Panel>

      {editorRule ? (
        <RuleEditor
          rule={editorRule}
          busy={updateMutation.isPending}
          error={updateMutation.error}
          onClose={() => {
            updateMutation.reset()
            setEditorFor(null)
          }}
          onSave={(payload) => updateMutation.mutate({ ruleId: editorRule.rule_id, payload })}
          onReset={() =>
            updateMutation.mutate({ ruleId: editorRule.rule_id, payload: { reset: true } })
          }
        />
      ) : null}
    </div>
  )
}

export default DetectionRulesPanel
