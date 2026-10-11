import { useState } from 'react'
import clsx from 'clsx'
import { Globe, Lock, Search } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import { CopyButton } from '@/components'
import { formatBytes, formatClockTime, formatDuration } from '@/utils/format'
import type { DnsQuery, HttpTransaction, TlsSession } from '@/types'

/**
 * The context endpoint adds `body_preview_truncated` to its HTTP rows; the
 * shared HttpTransaction type is owned by the HTTP page work, so read it
 * defensively instead of widening the shared interface.
 */
function bodyWasTrimmed(transaction: HttpTransaction): boolean {
  return Boolean((transaction as unknown as { body_preview_truncated?: boolean }).body_preview_truncated)
}

function HeaderTable({ title, headers }: { title: string; headers: Record<string, string> | null }) {
  const entries = Object.entries(headers ?? {})
  if (entries.length === 0) return null
  return (
    <div className="flex flex-col gap-1">
      <div className="text-2xs uppercase tracking-wider text-faint">{title}</div>
      <div className="flex flex-col">
        {entries.map(([name, value]) => (
          <div key={name} className="flex gap-2 border-b border-border/40 py-0.5 last:border-0">
            <span className="w-44 shrink-0 truncate text-2xs text-muted" title={name}>
              {name}
            </span>
            <span className="mono break-all text-2xs text-text">{String(value)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function BodyPreview({ label, body, truncated }: { label: string; body: string | null; truncated: boolean }) {
  if (!body) return null
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span className="text-2xs uppercase tracking-wider text-faint">{label}</span>
        <CopyButton value={body} label={`Copy ${label}`} />
        {truncated ? <span className="text-2xs text-warn">truncated for this view</span> : null}
      </div>
      <pre className="mono max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-bg p-2 text-2xs text-text">
        {body}
      </pre>
    </div>
  )
}

export interface FindingAppLayerProps {
  http: HttpTransaction[]
  dns: DnsQuery[]
  tls: TlsSession[]
}

/** Whatever the capture's application layer recorded for this alert. */
export function FindingAppLayer({ http, dns, tls }: FindingAppLayerProps) {
  const [transaction, setTransaction] = useState<number | null>(http[0]?.id ?? null)
  const [session, setSession] = useState<number | null>(tls[0]?.id ?? null)

  if (http.length === 0 && dns.length === 0 && tls.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={Globe}
        title="No application-layer record for this alert"
        description="The rule matched at the packet level, or the traffic is not HTTP, DNS or TLS. Encrypted payloads are never decrypted, so an HTTPS alert stops at the handshake."
        className="py-8"
      />
    )
  }

  const current = http.find((item) => item.id === transaction) ?? null
  const activeTls = tls.find((item) => item.id === session) ?? null

  return (
    <div className="flex flex-col gap-3 p-3">
      {http.length > 0 ? (
        <Panel flush title="HTTP transactions" subtitle={`${http.length} in this alert`}>
          <div className="max-h-64 overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Host</th>
                  <th>URI</th>
                  <th className="text-right">Status</th>
                  <th className="text-right">Req</th>
                  <th className="text-right">Resp</th>
                </tr>
              </thead>
              <tbody>
                {http.map((item) => (
                  <tr
                    key={item.id}
                    className={clsx('cursor-pointer', transaction === item.id && 'selected')}
                    onClick={() => setTransaction(item.id)}
                  >
                    <td>{formatClockTime(item.time_epoch)}</td>
                    <td className="text-muted">{item.method ?? '-'}</td>
                    <td>
                      <MonoCell maxWidth={220}>{item.host}</MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={320} title={item.uri ?? undefined}>
                        {item.uri}
                      </MonoCell>
                    </td>
                    <td className="text-right">{item.status_code ?? '-'}</td>
                    <td className="text-right">{formatBytes(item.request_len)}</td>
                    <td className="text-right">{formatBytes(item.response_len)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {current ? (
            <div className="flex flex-col gap-3 border-t border-border px-3 py-3">
              <div className="flex items-center gap-2 text-2xs text-muted">
                <span className="mono">
                  {current.method} {current.full_uri ?? current.uri}
                </span>
                <span className="mono">{current.version}</span>
                <span className="mono">
                  {current.status_code ?? '-'} {current.status_text ?? ''}
                </span>
              </div>
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                <HeaderTable title="Request headers" headers={current.request_headers} />
                <HeaderTable title="Response headers" headers={current.response_headers} />
              </div>
              <BodyPreview
                label="Request body"
                body={current.request_body}
                truncated={bodyWasTrimmed(current)}
              />
              <BodyPreview
                label="Response body"
                body={current.response_body}
                truncated={bodyWasTrimmed(current) || Boolean(current.response_body_truncated)}
              />
            </div>
          ) : null}
        </Panel>
      ) : null}

      {dns.length > 0 ? (
        <Panel flush title="DNS" subtitle={`${dns.length} quer${dns.length === 1 ? 'y' : 'ies'} in this alert`}>
          <div className="max-h-64 overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Client</th>
                  <th>Query</th>
                  <th>Type</th>
                  <th>Rcode</th>
                  <th>Answers</th>
                  <th className="text-right">Delay</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {dns.map((item) => (
                  <tr key={item.id}>
                    <td>{formatClockTime(item.time_epoch)}</td>
                    <td>
                      <MonoCell maxWidth={180}>{item.client_ip}</MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={300} title={item.query_name ?? undefined}>
                        {item.query_name}
                      </MonoCell>
                    </td>
                    <td className="text-muted">{item.query_type ?? '-'}</td>
                    <td className="text-muted">{item.rcode_name ?? '-'}</td>
                    <td>
                      <MonoCell maxWidth={260} title={item.answer_ips ?? undefined}>
                        {item.answer_ips ?? item.answers ? item.answer_ips ?? 'see row' : null}
                      </MonoCell>
                    </td>
                    <td className="text-right">
                      {item.response_delay === null || item.response_delay === undefined
                        ? '-'
                        : formatDuration(item.response_delay)}
                    </td>
                    <td>
                      <MonoCell maxWidth={220}>{(item.flags ?? []).join(', ')}</MonoCell>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}

      {tls.length > 0 ? (
        <Panel flush title="TLS sessions" subtitle={`${tls.length} in this alert`}>
          <div className="max-h-64 overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>SNI</th>
                  <th>Version</th>
                  <th>Cipher</th>
                  <th>ALPN</th>
                  <th>Handshake</th>
                  <th>JA3</th>
                </tr>
              </thead>
              <tbody>
                {tls.map((item) => (
                  <tr
                    key={item.id}
                    className={clsx('cursor-pointer', session === item.id && 'selected')}
                    onClick={() => setSession(item.id)}
                  >
                    <td>{formatClockTime(item.time_epoch)}</td>
                    <td>
                      <MonoCell maxWidth={220}>{item.sni}</MonoCell>
                    </td>
                    <td className="text-muted">{item.version ?? '-'}</td>
                    <td>
                      <MonoCell maxWidth={200} title={item.cipher_suite ?? undefined}>
                        {item.cipher_suite}
                      </MonoCell>
                    </td>
                    <td className="text-muted">{item.selected_alpn ?? item.alpn ?? '-'}</td>
                    <td className="text-muted">{item.handshake_status ?? '-'}</td>
                    <td>
                      <MonoCell maxWidth={160} title={item.ja3 ?? undefined}>
                        {item.ja3}
                      </MonoCell>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {activeTls ? (
            <div className="flex flex-col gap-2 border-t border-border px-3 py-3 text-2xs">
              <div className="flex items-center gap-1 text-accent2">
                <Lock size={11} aria-hidden />
                <span className="uppercase tracking-wider">Certificate</span>
              </div>
              {activeTls.cert_subject || activeTls.cert_issuer ? (
                <dl className="grid grid-cols-1 gap-x-4 gap-y-1 md:grid-cols-[10rem_1fr]">
                  <dt className="text-faint">Subject</dt>
                  <dd className="mono break-all text-text">{activeTls.cert_subject ?? '—'}</dd>
                  <dt className="text-faint">Issuer</dt>
                  <dd className="mono break-all text-text">{activeTls.cert_issuer ?? '—'}</dd>
                  <dt className="text-faint">Valid from</dt>
                  <dd className="mono text-text">{activeTls.cert_not_before ?? '—'}</dd>
                  <dt className="text-faint">Valid until</dt>
                  <dd className="mono text-text">{activeTls.cert_not_after ?? '—'}</dd>
                  <dt className="text-faint">Serial</dt>
                  <dd className="mono break-all text-text">{activeTls.cert_serial ?? '—'}</dd>
                  <dt className="text-faint">Fingerprints</dt>
                  <dd className="mono break-all text-text">
                    {['ja3', 'ja3s', 'ja4']
                      .filter((key) => (activeTls as unknown as Record<string, unknown>)[key])
                      .map((key) => `${key}=${String((activeTls as unknown as Record<string, unknown>)[key])}`)
                      .join('  ') || '—'}
                  </dd>
                </dl>
              ) : (
                <div className="text-faint">
                  No certificate was captured for this session (client hello only, or the handshake
                  happened before the capture started).
                </div>
              )}
              {activeTls.alert ? (
                <div className="text-danger">TLS alert: {activeTls.alert}</div>
              ) : null}
            </div>
          ) : null}
        </Panel>
      ) : null}

      <div className="flex items-center gap-1 text-2xs text-faint">
        <Search size={11} aria-hidden />
        <span>
          Values come from the dissectors that ran during analysis. Encrypted payloads are never
          decrypted, so HTTPS content stays invisible here.
        </span>
      </div>
    </div>
  )
}

export default FindingAppLayer