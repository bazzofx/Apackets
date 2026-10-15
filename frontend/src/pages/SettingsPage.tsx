import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  CheckCircle2,
  Database,
  HardDrive,
  Plus,
  Save,
  ShieldCheck,
  Terminal,
  Trash2,
  XCircle,
} from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import SuricataRulesPanel from '@/components/SuricataRulesPanel'
import ThemePanel from '@/components/ThemePanel'
import Toolbar from '@/components/Toolbar'
import { ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import { settingsApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { Indicator, IndicatorType, Settings, SettingsUpdate } from '@/types'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'

const INDICATOR_TYPES: IndicatorType[] = ['ip', 'domain', 'port', 'ja3', 'ja4', 'ua', 'sha256']

const INDICATOR_HINTS: Record<IndicatorType, string> = {
  ip: '10.0.0.9',
  domain: 'c2.example.net',
  port: '4444',
  ja3: '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0',
  ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  ua: 'Mozilla/5.0 (compatible; suspicious-agent)',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}

interface FormState {
  max_upload_mb: string
  retain_uploads: boolean
  max_object_bytes: string
  body_preview_bytes: string
  tshark_timeout_s: string
}

const EMPTY_FORM: FormState = {
  max_upload_mb: '',
  retain_uploads: true,
  max_object_bytes: '',
  body_preview_bytes: '',
  tshark_timeout_s: '',
}

/* ------------------------------------------------------------------ */
/* Credential discovery (docs/CREDENTIALS.md §7)                       */
/* ------------------------------------------------------------------ */

/**
 * The protocols the credential scanner can read, in the contract's own order (§2).
 * These five are the whole vocabulary: `credential_protocols` selects among them and
 * never invents a sixth.
 */
const CREDENTIAL_PROTOCOLS = ['http', 'ftp', 'smtp', 'pop3', 'imap']

const CREDENTIAL_PROTOCOL_LABELS: Record<string, string> = {
  http: 'HTTP',
  ftp: 'FTP',
  smtp: 'SMTP',
  pop3: 'POP3',
  imap: 'IMAP',
}

interface CredentialFormState {
  enabled: boolean
  protocols: string[]
}

/**
 * `credential_config` as the settings API reports it (§7).
 *
 * Both keys are read from the payload and neither is assumed when both are absent: a
 * backend that does not expose them gets a block that says so, because showing the
 * contract's defaults would be a claim about this installation rather than about the
 * contract. When one key is present and the other is not, the missing one falls back to
 * its documented default.
 */
function fromSettingsCredentials(settings: Settings): CredentialFormState | null {
  const enabled = settings.credential_scan_enabled
  const protocols = settings.credential_protocols
  if (enabled === undefined && protocols === undefined) return null
  return {
    enabled: enabled ?? true,
    protocols: Array.isArray(protocols) ? protocols : [...CREDENTIAL_PROTOCOLS],
  }
}

function fromSettings(settings: Settings): FormState {
  return {
    max_upload_mb: String(settings.max_upload_mb ?? ''),
    retain_uploads: Boolean(settings.retain_uploads),
    max_object_bytes: String(settings.max_object_bytes ?? ''),
    body_preview_bytes: String(settings.body_preview_bytes ?? ''),
    tshark_timeout_s: String(settings.tshark_timeout_s ?? ''),
  }
}

function Field({ label, value, mono = true }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <>
      <dt className="text-faint">{label}</dt>
      <dd
        className={clsx('min-w-0 truncate text-text', mono && 'mono')}
        title={typeof value === 'string' ? value : undefined}
      >
        {value}
      </dd>
    </>
  )
}

function NumberField({
  label,
  hint,
  value,
  onChange,
  suffix,
}: {
  label: string
  hint?: string
  value: string
  onChange: (value: string) => void
  suffix?: string
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-2xs font-semibold uppercase tracking-wider text-muted">{label}</span>
      <span className="flex items-center gap-1">
        <input
          className="input w-40"
          inputMode="numeric"
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
        {suffix ? <span className="text-2xs text-faint">{suffix}</span> : null}
      </span>
      {hint ? <span className="text-2xs text-faint">{hint}</span> : null}
    </label>
  )
}

function SettingsContent() {
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: ['settings'], queryFn: () => settingsApi.get() })
  const indicators = useQuery({
    queryKey: ['indicators'],
    queryFn: () => settingsApi.indicators.list(),
  })

  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [formError, setFormError] = useState<string | null>(null)
  const [savedAt, setSavedAt] = useState<number | null>(null)
  const initialized = useRef(false)

  const [newType, setNewType] = useState<IndicatorType>('ip')
  const [newValue, setNewValue] = useState('')
  const [newNote, setNewNote] = useState('')
  const [indicatorError, setIndicatorError] = useState<string | null>(null)

  /* The credential block is its own form: it is saved by its own button so that editing one
     setting can never submit the other block's fields. What the server holds is read from the
     settings payload on every render and only an *edit* is state, so the block draws the real
     configuration on the first frame rather than after an effect has run, and an edit that
     toggles a switch back leaves the form clean again. */
  const [credentialEdit, setCredentialEdit] = useState<CredentialFormState | null>(null)
  const [credentialSavedAt, setCredentialSavedAt] = useState<number | null>(null)

  const credentialStored = settings.data ? fromSettingsCredentials(settings.data) : null
  const credentialForm = credentialEdit ?? credentialStored

  useEffect(() => {
    if (!settings.data || initialized.current) return
    initialized.current = true
    setForm(fromSettings(settings.data))
  }, [settings.data])

  const updateMutation = useMutation({
    mutationFn: (payload: SettingsUpdate) => settingsApi.update(payload),
    onSuccess: (data) => {
      // PUT /api/settings answers { ok, changed, settings }.
      setForm(fromSettings(data.settings))
      setFormError(null)
      setSavedAt(Date.now() / 1000)
      void queryClient.invalidateQueries({ queryKey: ['settings'] })
      void queryClient.invalidateQueries({ queryKey: ['health'] })
    },
  })

  /**
   * The credential settings' own save (§7).
   *
   * It sends only the two credential keys, so it can never carry the numeric fields above.
   * The response is the whole effective settings view, so it is written straight into the
   * settings query's cache and then the query is invalidated: the block shows the values the
   * server actually stored, with no frame in which the old ones are drawn again.
   */
  const credentialMutation = useMutation({
    mutationFn: (payload: SettingsUpdate) => settingsApi.update(payload),
    onSuccess: (data) => {
      setCredentialEdit(null)
      setCredentialSavedAt(Date.now() / 1000)
      queryClient.setQueryData(['settings'], data.settings)
      void queryClient.invalidateQueries({ queryKey: ['settings'] })
      void queryClient.invalidateQueries({ queryKey: ['health'] })
    },
  })

  const createIndicator = useMutation({
    mutationFn: () =>
      settingsApi.indicators.create({
        type: newType,
        value: newValue.trim(),
        note: newNote.trim() || null,
      }),
    onSuccess: () => {
      setNewValue('')
      setNewNote('')
      setIndicatorError(null)
      void queryClient.invalidateQueries({ queryKey: ['indicators'] })
    },
  })

  const deleteIndicator = useMutation({
    mutationFn: (id: number) => settingsApi.indicators.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['indicators'] })
    },
  })

  const onSave = () => {
    const parsed: SettingsUpdate = {}
    const numeric: Array<[keyof FormState, keyof SettingsUpdate, string]> = [
      ['max_upload_mb', 'max_upload_mb', 'Max upload'],
      ['max_object_bytes', 'max_object_bytes', 'Max object size'],
      ['body_preview_bytes', 'body_preview_bytes', 'Body preview'],
      ['tshark_timeout_s', 'tshark_timeout_s', 'TShark timeout'],
    ]
    for (const [formKey, apiKey, label] of numeric) {
      const raw = String(form[formKey]).trim()
      const value = Number(raw)
      if (raw === '' || !Number.isFinite(value) || value <= 0 || !Number.isInteger(value)) {
        setFormError(`${label} must be a positive whole number (no decimals, no units).`)
        return
      }
      ;(parsed as Record<string, number>)[apiKey as string] = value
    }
    parsed.retain_uploads = form.retain_uploads
    setFormError(null)
    updateMutation.mutate(parsed)
  }

  const onAddIndicator = () => {
    const value = newValue.trim()
    if (value === '') {
      setIndicatorError('An indicator needs a value.')
      return
    }
    if (newType === 'port') {
      const port = Number(value)
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setIndicatorError('A port indicator must be an integer between 1 and 65535.')
        return
      }
    }
    if (newType === 'ip' && value.includes(' ')) {
      setIndicatorError('An IP indicator must not contain spaces.')
      return
    }
    setIndicatorError(null)
    createIndicator.mutate()
  }

  const onSaveCredentials = () => {
    if (credentialForm === null) return
    credentialMutation.mutate({
      credential_scan_enabled: credentialForm.enabled,
      credential_protocols: credentialForm.protocols,
    })
  }

  /**
   * Dirty is exact, not a "has been touched" flag: the edit is compared against what the
   * settings payload currently holds, so a change that is undone by hand leaves the save
   * button disabled again.
   */
  const credentialsDirty =
    credentialEdit !== null &&
    credentialStored !== null &&
    (credentialEdit.enabled !== credentialStored.enabled ||
      credentialEdit.protocols.join(',') !== credentialStored.protocols.join(','))

  const toggleCredentialProtocol = (name: string, checked: boolean) => {
    setCredentialEdit((previous) => {
      const current = previous ?? credentialStored
      if (current === null) return previous
      /* The order is the order the block draws, so a saved list reads in that order rather
         than in the order the boxes happened to be clicked. */
      const offered = settings.data?.credential_protocols_available ?? CREDENTIAL_PROTOCOLS
      const rank = (entry: string) => {
        const index = offered.indexOf(entry)
        return index === -1 ? offered.length + CREDENTIAL_PROTOCOLS.indexOf(entry) : index
      }
      const protocols = checked
        ? [...current.protocols.filter((entry) => entry !== name), name].sort(
            (a, b) => rank(a) - rank(b),
          )
        : current.protocols.filter((entry) => entry !== name)
      return { ...current, protocols }
    })
  }

  if (settings.isLoading) return <LoadingState label="Loading settings…" rows={5} />

  if (settings.error) {
    return (
      <ErrorState
        error={settings.error}
        title="Could not load settings"
        onRetry={() => void settings.refetch()}
      />
    )
  }

  const data = settings.data
  if (!data) {
    return (
      <EmptyState
        title="No settings returned"
        description="The backend returned an empty settings payload."
      />
    )
  }

  const tshark = data.tshark
  const items: Indicator[] = indicators.data?.items ?? []

  return (
    <div className="flex flex-col gap-3">
      <ThemePanel />

      <Panel
        title="Effective settings"
        subtitle="read from the backend configuration and the persisted settings table"
      >
        <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs md:grid-cols-[11rem_1fr]">
          <Field label="Data directory" value={data.data_dir} />
          <Field label="Uploads directory" value={data.uploads_dir ?? '—'} />
          <Field label="Analyses directory" value={data.analyses_dir ?? '—'} />
          <Field label="Exports directory" value={data.exports_dir ?? '—'} />
          <Field label="Max upload" value={`${formatNumber(data.max_upload_mb)} MB`} />
          <Field
            label="Retain uploads"
            value={data.retain_uploads ? 'yes — captures kept on disk' : 'no — captures discarded'}
          />
          <Field label="Max object size" value={formatBytes(data.max_object_bytes)} />
          <Field label="Body preview limit" value={formatBytes(data.body_preview_bytes)} />
          <Field label="TShark timeout" value={formatDuration(data.tshark_timeout_s)} />
          <Field
            label="Max packet rows"
            value={data.max_packet_rows === undefined ? '—' : formatNumber(data.max_packet_rows)}
          />
          <Field
            label="Max DNS rows"
            value={data.max_dns_rows === undefined ? '—' : formatNumber(data.max_dns_rows)}
          />
          <Field
            label="Worker threads"
            value={data.worker_threads === undefined ? '—' : formatNumber(data.worker_threads)}
          />
          <Field
            label="Bind address"
            value={
              data.host !== undefined && data.port !== undefined
                ? `${data.host}:${data.port}`
                : '—'
            }
          />
          <Field label="Log level" value={data.log_level ?? '—'} />
          <Field label="Backend version" value={data.version ?? '—'} />
          <dt className="text-faint">TShark</dt>
          <dd className="flex items-center gap-2">
            {tshark.available ? (
              <span className="chip border-ok/50 bg-ok/15 text-ok">
                <CheckCircle2 size={11} aria-hidden />
                available {tshark.version ?? ''}
              </span>
            ) : (
              <span className="chip border-danger/50 bg-danger/15 text-red-300">
                <XCircle size={11} aria-hidden />
                unavailable
              </span>
            )}
            <MonoCell maxWidth={520} className="text-xs">
              {tshark.path ?? 'not resolved — set a path or add tshark to PATH'}
            </MonoCell>
          </dd>
        </dl>
      </Panel>

      <Panel
        title="Editable settings"
        subtitle="PUT /api/settings — persisted to the settings table and applied to new analyses"
        actions={
          <button
            type="button"
            className="btn btn-primary"
            onClick={onSave}
            disabled={updateMutation.isPending}
          >
            <Save size={13} aria-hidden />
            {updateMutation.isPending ? 'Saving…' : 'Save settings'}
          </button>
        }
      >
        <div className="flex flex-wrap items-start gap-4">
          <NumberField
            label="Max upload"
            suffix="MB"
            value={form.max_upload_mb}
            onChange={(value) => setForm((prev) => ({ ...prev, max_upload_mb: value }))}
            hint="larger uploads are rejected with 413"
          />
          <NumberField
            label="Max object size"
            suffix="bytes"
            value={form.max_object_bytes}
            onChange={(value) => setForm((prev) => ({ ...prev, max_object_bytes: value }))}
            hint="bigger objects are recorded as partial"
          />
          <NumberField
            label="Body preview"
            suffix="bytes"
            value={form.body_preview_bytes}
            onChange={(value) => setForm((prev) => ({ ...prev, body_preview_bytes: value }))}
            hint="HTTP body preview kept per transaction"
          />
          <NumberField
            label="TShark timeout"
            suffix="seconds"
            value={form.tshark_timeout_s}
            onChange={(value) => setForm((prev) => ({ ...prev, tshark_timeout_s: value }))}
            hint="a slower TShark call returns 504"
          />
          <label className="flex flex-col gap-1">
            <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
              Retain uploads
            </span>
            <span className="flex items-center gap-2 py-1 text-xs text-text">
              <input
                type="checkbox"
                checked={form.retain_uploads}
                onChange={(event) =>
                  setForm((prev) => ({ ...prev, retain_uploads: event.target.checked }))
                }
              />
              keep capture files after analysis
            </span>
          </label>
        </div>

        {formError ? <div className="mt-3 text-xs text-danger">{formError}</div> : null}
        {updateMutation.error ? (
          <ErrorState
            error={updateMutation.error}
            variant="plain"
            title="Save failed"
            className="mt-2 py-3"
          />
        ) : null}
        {savedAt !== null && !updateMutation.isPending && !updateMutation.error ? (
          <div className="mt-3 text-2xs text-ok">Saved at {formatTimestamp(savedAt)}</div>
        ) : null}
      </Panel>

      <Panel
        title="Users & Passwords discovery"
        subtitle="the cleartext credential stage's own switch and protocol selection (docs/CREDENTIALS.md §7)"
        actions={
          credentialForm === null ? undefined : (
            <button
              type="button"
              className="btn btn-primary"
              onClick={onSaveCredentials}
              disabled={!credentialsDirty || credentialMutation.isPending}
              title={
                credentialsDirty
                  ? 'Save credential_scan_enabled and credential_protocols (PUT /api/settings)'
                  : 'The Users & Passwords settings are unchanged'
              }
            >
              <Save size={13} aria-hidden />
              {credentialMutation.isPending ? 'Saving…' : 'Save Users & Passwords settings'}
            </button>
          )
        }
      >
        {credentialForm === null ? (
          <SectionNote tone="warn">
            {`The settings API returned neither `}
            <span className="mono">credential_scan_enabled</span>
            {` nor `}
            <span className="mono">credential_protocols</span>
            {`, so this block can neither show nor change the credential scanner's configuration. It reports that absence instead of filling in the contract's defaults, which would describe the contract rather than this installation. `}
            {settings.isFetching ? 'The settings are being reloaded.' : 'Reload the page after the backend exposes them.'}
          </SectionNote>
        ) : (
          <div className="flex flex-wrap items-start gap-6">
            <label className="flex flex-col gap-1">
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Discovery
              </span>
              <span className="flex items-center gap-2 py-1 text-xs text-text">
                <input
                  type="checkbox"
                  checked={credentialForm.enabled}
                  onChange={(event) =>
                    setCredentialEdit((previous) => {
                      const current = previous ?? credentialStored
                      if (current === null) return previous
                      return { ...current, enabled: event.target.checked }
                    })
                  }
                />
                search new analyses for cleartext credentials
              </span>
              <span className="text-2xs text-faint">
                <span className="mono">credential_scan_enabled</span> — off means the pipeline skips
                the stage and writes no rows
              </span>
            </label>

            <div className="flex flex-col gap-1">
              <span className="text-2xs font-semibold uppercase tracking-wider text-muted">
                Protocols inspected
              </span>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 py-1">
                {(data.credential_protocols_available ?? CREDENTIAL_PROTOCOLS).map((name) => (
                  <label
                    key={name}
                    className="flex items-center gap-1.5 text-xs text-text"
                    title={`Read the locations §2 records for ${CREDENTIAL_PROTOCOL_LABELS[name] ?? name}. Unticking it leaves that protocol's rows unread, whatever the ports in the capture say.`}
                  >
                    <input
                      type="checkbox"
                      checked={credentialForm.protocols.includes(name)}
                      onChange={(event) => toggleCredentialProtocol(name, event.target.checked)}
                    />
                    {CREDENTIAL_PROTOCOL_LABELS[name] ?? name}
                  </label>
                ))}
              </div>
              <span className="text-2xs text-faint">
                <span className="mono">credential_protocols</span> — an empty selection means none,
                and the Credentials page says so rather than showing an empty table as a clean
                capture
              </span>
            </div>
          </div>
        )}

        {credentialMutation.error ? (
          <ErrorState
            error={credentialMutation.error}
            variant="plain"
            title="Could not save the Users & Passwords settings"
            className="mt-2 py-3"
          />
        ) : null}
        {credentialForm !== null && credentialsDirty && !credentialMutation.isPending ? (
          <div className="mt-3 text-2xs text-warn">
            Unsaved change — the pipeline keeps using the settings below until{' '}
            <span className="mono">Save Users &amp; Passwords settings</span> is pressed.
          </div>
        ) : null}
        {credentialSavedAt !== null && !credentialMutation.isPending && !credentialMutation.error ? (
          <div className="mt-3 text-2xs text-ok">
            Saved at {formatTimestamp(credentialSavedAt)} — applied to analyses started after the
            save; what was already found is untouched.
          </div>
        ) : null}
      </Panel>

      <ScopeNote
        title="What switching Users & Passwords discovery off does, and does not do"
        collapsible
        defaultOpen={false}
        items={[
          {
            can: true,
            text: (
              <>
                The switch governs <strong>future analyses</strong>: with{' '}
                <span className="mono">credential_scan_enabled</span> off, the pipeline skips the
                stage entirely and writes no rows at all.
              </>
            ),
          },
          {
            can: true,
            text: (
              <>
                The protocol selection narrows where the scanner looks: HTTP, FTP, SMTP, POP3 and
                IMAP are the only locations §2 defines, so a protocol left unticked is never read,
                whatever ports the capture uses.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>Nothing is deleted.</strong> Turning the scan off does not remove what an
                earlier run already found: those rows stay in the analysis and stay readable on the
                Credentials page, which reports the setting's state beside them so the two can never
                be confused.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>It cannot read anything encrypted.</strong> TLS, HTTPS, SSH, SMB signing and
                STARTTLS/STLS sessions are never decrypted — not with the scan on. Nothing here
                implies a TLS session holds no credentials.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>It is not a new capture pass.</strong> The scanner reads the rows the other
                analysers already stored, so a body the earlier stage truncated is out of reach, and
                the Credentials page&apos;s <span className="mono">Scan now</span> re-reads those rows
                rather than the wire.
              </>
            ),
          },
        ]}
        caveat={
          <>
            A finding is a lead, not a verdict: a value in a field called{' '}
            <span className="mono">password</span> crossed the wire, which is not proof that it
            worked, that it is current, or that it is not a test value.
          </>
        }
      />

      <Panel
        title="Indicators"
        subtitle="analyst-supplied indicators matched by the indicator_match rule (global scope)"
        flush
        actions={
          <span className="chip border-border2 bg-surface2 text-muted" title="Total indicators">
            {items.length}
          </span>
        }
      >
        <Toolbar>
          <select
            className="select"
            value={newType}
            onChange={(event) => setNewType(event.target.value as IndicatorType)}
            title="Indicator type"
          >
            {INDICATOR_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
          <input
            className="input w-80"
            placeholder={INDICATOR_HINTS[newType]}
            value={newValue}
            onChange={(event) => setNewValue(event.target.value)}
          />
          <input
            className="input w-56"
            placeholder="note (optional, shown in the finding)"
            value={newNote}
            onChange={(event) => setNewNote(event.target.value)}
          />
          <button
            type="button"
            className="btn btn-primary"
            onClick={onAddIndicator}
            disabled={createIndicator.isPending}
          >
            <Plus size={13} aria-hidden />
            Add indicator
          </button>
        </Toolbar>

        {indicatorError ? <div className="px-3 py-2 text-xs text-danger">{indicatorError}</div> : null}
        {createIndicator.error ? (
          <ErrorState
            error={createIndicator.error}
            variant="plain"
            title="Could not add the indicator"
            className="py-3"
          />
        ) : null}
        {deleteIndicator.error ? (
          <ErrorState
            error={deleteIndicator.error}
            variant="plain"
            title="Could not delete the indicator"
            className="py-3"
          />
        ) : null}

        {indicators.isLoading ? (
          <LoadingState label="Loading indicators…" rows={3} />
        ) : indicators.error ? (
          <ErrorState
            error={indicators.error}
            variant="plain"
            title="Could not load indicators"
            onRetry={() => void indicators.refetch()}
          />
        ) : items.length === 0 ? (
          <div className="px-3 py-8 text-center text-xs text-muted">
            No indicators defined. Indicators you add here are matched against every analysis.
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Note</th>
                  <th>Scope</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((indicator) => (
                  <tr key={indicator.id}>
                    <td>
                      <span className="chip border-accent/50 bg-accent/15 text-accent2">
                        {indicator.type}
                      </span>
                    </td>
                    <td>
                      <MonoCell maxWidth={360}>{indicator.value}</MonoCell>
                    </td>
                    <td className="font-sans">
                      <span
                        className="block max-w-72 truncate text-muted"
                        title={indicator.note ?? undefined}
                      >
                        {indicator.note ?? '—'}
                      </span>
                    </td>
                    <td className="text-muted">{indicator.analysis_id ?? 'global'}</td>
                    <td>{formatTimestamp(indicator.created_at)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-danger px-1.5 py-1"
                        title="Delete this indicator"
                        disabled={deleteIndicator.isPending}
                        onClick={() => deleteIndicator.mutate(indicator.id)}
                      >
                        <Trash2 size={12} aria-hidden />
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <SuricataRulesPanel />

      <Panel
        title="Local-only operation"
        bodyClassName="flex flex-col gap-2 p-3 text-xs text-muted"
      >
        <div className="flex items-start gap-2">
          <ShieldCheck size={14} className="mt-0.5 shrink-0 text-ok" aria-hidden />
          <p className="leading-relaxed">
            APackets runs entirely on this machine. Capture files, decoded packets, extracted
            objects, hashes and findings never leave it: the frontend talks only to the local
            backend on <span className="mono">127.0.0.1</span> through{' '}
            <span className="mono">/api</span>.
          </p>
        </div>
        <div className="flex items-start gap-2">
          <HardDrive size={14} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <p className="leading-relaxed">
            There is no telemetry, no analytics and no update check. The only outbound behaviour is
            whatever your own TShark configuration does, which APackets does not modify.
          </p>
        </div>
        <div className="flex items-start gap-2">
          <Database size={14} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <p className="leading-relaxed">
            Derived data is stored in SQLite under <span className="mono">{data.data_dir}</span> and
            can be removed per analysis from the PCAP Files page.
          </p>
        </div>
        <div className="flex items-start gap-2">
          <Terminal size={14} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <p className="leading-relaxed">
            TShark is invoked with an argument list (<span className="mono">shell=False</span>) —
            capture content is never interpolated into a command line.
          </p>
        </div>
      </Panel>
    </div>
  )
}

/** Settings: effective configuration, mutable keys and analyst indicators. */
export function SettingsPage() {
  return (
    <Page section={SECTIONS.settings}>
      <SettingsContent />
    </Page>
  )
}

export default SettingsPage
