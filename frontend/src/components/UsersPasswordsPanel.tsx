import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Save } from 'lucide-react'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Panel from '@/components/Panel'
import { ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import { settingsApi } from '@/services/api'
import type { Settings, SettingsUpdate } from '@/types'
import { formatTimestamp } from '@/utils/format'

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

/**
 * The cleartext credential stage's own switch and protocol selection.
 *
 * This lives on the Alert Settings page rather than in Settings because it is not a
 * property of the installation: it decides whether a detection stage runs at all, which
 * is the same kind of decision the rule tables above it make. Its state is read from the
 * settings payload on every render and only an *edit* is state, so the block draws the
 * real configuration on the first frame rather than after an effect has run, and an edit
 * that toggles a switch back leaves the form clean again.
 */
export function UsersPasswordsPanel() {
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: ['settings'], queryFn: () => settingsApi.get() })

  const [credentialEdit, setCredentialEdit] = useState(null as CredentialFormState | null)
  const [credentialSavedAt, setCredentialSavedAt] = useState(null as number | null)

  const data = settings.data
  const credentialStored = data ? fromSettingsCredentials(data) : null
  const credentialForm = credentialEdit ?? credentialStored

  /**
   * The credential settings' own save (§7).
   *
   * It sends only the two credential keys. The response is the whole effective settings
   * view, so it is written straight into the settings query's cache and then the query is
   * invalidated: the block shows the values the server actually stored, with no frame in
   * which the old ones are drawn again.
   */
  const credentialMutation = useMutation({
    mutationFn: (payload: SettingsUpdate) => settingsApi.update(payload),
    onSuccess: (response) => {
      setCredentialEdit(null)
      setCredentialSavedAt(Date.now() / 1000)
      queryClient.setQueryData(['settings'], response.settings)
      void queryClient.invalidateQueries({ queryKey: ['settings'] })
      void queryClient.invalidateQueries({ queryKey: ['health'] })
    },
  })

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
      const offered = data?.credential_protocols_available ?? CREDENTIAL_PROTOCOLS
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

  const onSaveCredentials = () => {
    if (credentialForm === null) return
    credentialMutation.mutate({
      credential_scan_enabled: credentialForm.enabled,
      credential_protocols: credentialForm.protocols,
    })
  }

  if (settings.isLoading) return <LoadingState label="Loading Users & Passwords settings…" rows={3} />

  if (settings.error) {
    return (
      <ErrorState
        error={settings.error}
        title="Could not load the Users & Passwords settings"
        onRetry={() => void settings.refetch()}
      />
    )
  }

  return (
    <div className="flex flex-col gap-3">
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
                {(data?.credential_protocols_available ?? CREDENTIAL_PROTOCOLS).map((name) => (
                  <label
                    key={name}
                    className="flex items-center gap-1.5 text-xs text-text"
                    title={`Read the locations §2 records for ` + (CREDENTIAL_PROTOCOL_LABELS[name] ?? name) + `. Unticking it leaves that protocol's rows unread, whatever the ports in the capture say.`}
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
    </div>
  )
}

export default UsersPasswordsPanel
