/**
 * Everything the API attributes to one endpoint: `GET /hosts/{ip}`.
 *
 * The detail lists (`conversations`, `dns_queries`, `http_transactions`,
 * `tls_sessions`) are capped by the backend at `detail_limit` rows each; that cap
 * is stated in the UI rather than hidden, so a truncated list is never mistaken
 * for the whole truth.
 */

import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ExternalLink, Info, Network, RefreshCw, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import {
  ChipList,
  NameChips,
  PeerChip,
  ProtocolChips,
  ScopeChip,
  asText,
  parsePorts,
  parseProtocols,
  parseStringList,
  type ChipItem,
} from '@/components/hosts/chips'
import HostLookupPanel from '@/components/hosts/HostLookupPanel'
import { flowAddress, flowPort } from '@/components/conversations/flowLayout'
import { buildQuery, hostsApi } from '@/services/api'
import type { Conversation, DnsQuery, HttpTransaction, TlsSession } from '@/types'
import {
  EMPTY,
  formatBytes,
  formatClockTime,
  formatDuration,
  formatNumber,
  formatTimestamp,
} from '@/utils/format'

/* ------------------------------------------------------------------ */
/* small building blocks                                               */
/* ------------------------------------------------------------------ */

function Field({ label, children, title }: { label: string; children: ReactNode; title?: string }) {
  return (
    <div className="min-w-0">
      <div className="text-2xs uppercase tracking-wider text-faint">{label}</div>
      <div className="mt-0.5 break-words text-xs text-text" title={title}>
        {children}
      </div>
    </div>
  )
}

interface Column<T> {
  key: string
  header: string
  align?: 'right'
  render: (row: T) => ReactNode
}

function MiniTable<T>({
  rows,
  columns,
  rowKey,
  empty,
}: {
  rows: T[]
  columns: Column<T>[]
  rowKey: (row: T, index: number) => string
  empty: string
}) {
  if (rows.length === 0) {
    return <div className="px-3 py-4 text-center text-2xs text-faint">{empty}</div>
  }
  return (
    <div className="max-h-56 overflow-auto">
      <table className="dt">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} className={column.align === 'right' ? 'text-right' : undefined}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={rowKey(row, index)}>
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={clsx('whitespace-normal', column.align === 'right' && 'text-right')}
                >
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Clock({ value }: { value: number | null }) {
  if (value === null || value === undefined) return <span className="text-faint">{EMPTY}</span>
  return (
    <span className="mono" title={formatTimestamp(value)}>
      {formatClockTime(value)}
    </span>
  )
}

function SectionPanel({
  title,
  subtitle,
  children,
  actions,
}: {
  title: string
  subtitle: string
  children: ReactNode
  actions?: ReactNode
}) {
  return (
    <section className="panel">
      <header className="panel-header">
        <div className="min-w-0">
          <div className="panel-title">{title}</div>
          <div className="panel-subtitle" title={subtitle}>
            {subtitle}
          </div>
        </div>
        {actions}
      </header>
      {children}
    </section>
  )
}

/** Pivot into the page that owns the relevant rows, using documented filters. */
function pivotsFor(ip: string): { label: string; to: string; title: string }[] {
  return [
    {
      label: 'Packets',
      to: `/packets${buildQuery({ ip })}`,
      title: 'Packets whose source or destination is this IP (?ip=)',
    },
    {
      label: 'HTTP as client',
      to: `/http${buildQuery({ client_ip: ip })}`,
      title: 'HTTP transactions where this IP is the client (?client_ip=)',
    },
    {
      label: 'HTTP as server',
      to: `/http${buildQuery({ server_ip: ip })}`,
      title: 'HTTP transactions where this IP is the server (?server_ip=)',
    },
    {
      label: 'DNS as client',
      to: `/dns${buildQuery({ client_ip: ip })}`,
      title: 'DNS queries sent by this IP (?client_ip=)',
    },
    {
      label: 'DNS as server',
      to: `/dns${buildQuery({ server_ip: ip })}`,
      title: 'DNS queries sent to this IP (?server_ip=)',
    },
    {
      label: 'TLS',
      to: `/tls${buildQuery({ ip })}`,
      title: 'TLS sessions where this IP is either endpoint (?ip=)',
    },
    {
      label: 'Conversations',
      to: `/conversations${buildQuery({ ip })}`,
      title: 'Conversations involving this IP (?ip=)',
    },
  ]
}

/* ------------------------------------------------------------------ */
/* panel                                                               */
/* ------------------------------------------------------------------ */

export interface HostDetailPanelProps {
  analysisId: string
  ip: string
  onClose: () => void
}

/** Side panel with the full host record, its capped row lists and its pivots. */
export function HostDetailPanel({ analysisId, ip, onClose }: HostDetailPanelProps) {
  const detail = useQuery({
    queryKey: ['host-detail', analysisId, ip],
    queryFn: () => hostsApi.get(analysisId, ip),
    enabled: Boolean(analysisId && ip),
    retry: false,
  })

  if (detail.isLoading) {
    return (
      <section className="panel p-0">
        <LoadingState label={`Loading host ${ip}…`} rows={5} />
      </section>
    )
  }

  if (detail.error) {
    return (
      <section className="panel p-0">
        <ErrorState
          error={detail.error}
          title="Could not load this host"
          onRetry={() => void detail.refetch()}
        />
        <div className="border-t border-border px-3 py-2 text-right">
          <button type="button" className="btn" onClick={onClose}>
            <X size={13} aria-hidden />
            Clear selection
          </button>
        </div>
      </section>
    )
  }

  const host = detail.data
  if (!host) {
    return (
      <EmptyState
        title="No host data"
        description={`The backend returned no record for ${ip}.`}
        variant="panel"
      />
    )
  }

  const ports = parsePorts(host.ports)
  const protocols = parseProtocols(host.protocols)
  const dnsNames = parseStringList(host.dns_names)
  const tlsSni = parseStringList(host.tls_sni)
  const peers = parseStringList(host.peers)
  const limit = host.detail_limit ?? 50
  const conversations = host.conversations ?? []
  const dnsQueries = host.dns_queries ?? []
  const httpTransactions = host.http_transactions ?? []
  const tlsSessions = host.tls_sessions ?? []
  const capped =
    conversations.length >= limit ||
    dnsQueries.length >= limit ||
    httpTransactions.length >= limit ||
    tlsSessions.length >= limit

  const allPortChips: ChipItem[] = ports.map((entry) => ({
    key: String(entry.port),
    label: entry.count !== null ? `${entry.port} · ${entry.count}` : String(entry.port),
    title: `Port ${entry.port}${
      entry.count !== null ? ` · ${entry.count} packets` : ''
    }${entry.directions.length > 0 ? ` · direction ${entry.directions.join('/')}` : ''}`,
    tone: 'default',
  }))

  const allNameChips: ChipItem[] = [
    ...dnsNames.map((name) => ({
      key: `dns:${name}`,
      label: name,
      title: `DNS name associated with this host: ${name}`,
      tone: 'default' as const,
    })),
    ...tlsSni.map((name) => ({
      key: `sni:${name}`,
      label: name,
      title: `TLS SNI offered by this host: ${name}`,
      tone: 'sni' as const,
    })),
  ]

  const allPeerChips: ChipItem[] = peers.map((peer) => ({
    key: peer,
    label: peer,
    title: `Conversation peer observed in this capture: ${peer}`,
    tone: 'default',
  }))

  return (
    <section className="panel">
      {/* The identity block carries the address, and only it: the tables below
          name other addresses, so a right click there must not be read as a
          right click on this host. */}
      <header className="panel-header items-start">
        <div className="min-w-0" data-ip={host.ip}>
          <div className="flex items-center gap-1.5">
            <span className="break-all mono text-sm text-text">{host.ip}</span>
            <CopyButton value={host.ip} label={`Copy ${host.ip}`} />
            <ScopeChip isPrivate={host.is_private} />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-faint">
            <span>
              MAC <MonoCell className="inline-block max-w-[10rem] align-bottom">{host.mac}</MonoCell>
            </span>
            <span>IP version {formatNumber(host.ip_version)}</span>
            <span>first seen {formatTimestamp(host.first_seen)}</span>
            <span>last seen {formatTimestamp(host.last_seen)}</span>
          </div>
        </div>
        <button
          type="button"
          className="btn shrink-0"
          onClick={onClose}
          title="Close the host detail"
        >
          <X size={13} aria-hidden />
          Close
        </button>
      </header>

      {/* Two cards side by side, each the full width of its column from `xl` up:
          what the capture recorded for this endpoint, and registration data for
          the address. Below `xl` they stack rather than squeeze. The record
          tables are their own full-width section underneath, so a wide screen
          is not spent on four half-width tables. */}
      <div className="grid grid-cols-1 gap-3 p-3 xl:grid-cols-[minmax(0,1fr)_23rem]">
        <section className="host-card" data-host-info>
          <header className="host-card-head">
            <div className="host-card-title">
              <Network size={13} aria-hidden />
              Host info
            </div>
            <div className="host-card-sub">
              {host.ip} — counters, chips and pivots from this capture
            </div>
          </header>

          <div className="host-card-body">
        <div className="grid grid-cols-2 gap-x-3 gap-y-2">
          <Field label="Packets sent" title="Frames in which this IP is the source">
            <span className="mono">{formatNumber(host.packets_sent)}</span>
          </Field>
          <Field label="Packets received" title="Frames in which this IP is the destination">
            <span className="mono">{formatNumber(host.packets_received)}</span>
          </Field>
          <Field label="Bytes sent" title="Sum of frame lengths sent">
            <span className="mono">{formatBytes(host.bytes_sent)}</span>
          </Field>
          <Field label="Bytes received" title="Sum of frame lengths received">
            <span className="mono">{formatBytes(host.bytes_received)}</span>
          </Field>
          <Field
            label="Packets involving this IP"
            title="Counted from the packet index: src_ip or dst_ip equals this address"
          >
            <span className="mono">{formatNumber(host.packet_count)}</span>
          </Field>
          <Field label="Peers" title="Distinct conversation peers observed">
            <span className="mono">{formatNumber(host.peer_count)}</span>
          </Field>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {pivotsFor(host.ip).map((pivot) => (
            <Link key={pivot.label} to={pivot.to} className="btn" title={pivot.title}>
              <ExternalLink size={12} aria-hidden />
              {pivot.label}
            </Link>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-2 border-t border-border pt-3">
          <div>
            <div className="mb-1 text-2xs uppercase tracking-wider text-faint">
              Ports ({ports.length})
            </div>
            <ChipList chips={allPortChips} max={12} emptyLabel="no TCP/UDP ports observed" />
          </div>
          <div>
            <div className="mb-1 text-2xs uppercase tracking-wider text-faint">
              Protocols ({protocols.length})
            </div>
            <ProtocolChips protocols={protocols} max={12} />
          </div>
          <div>
            <div className="mb-1 text-2xs uppercase tracking-wider text-faint">
              Names ({allNameChips.length})
            </div>
            <NameChips dnsNames={dnsNames} tlsSni={tlsSni} max={12} />
          </div>
          <div>
            <div className="mb-1 text-2xs uppercase tracking-wider text-faint">
              Peers ({peers.length || (host.peer_count ?? 0)})
            </div>
            {allPeerChips.length > 0 ? (
              <ChipList chips={allPeerChips} max={12} />
            ) : (
              <PeerChip peers={peers} peerCount={host.peer_count} />
            )}
          </div>
        </div>

        {capped ? (
          <div className="flex items-start gap-1.5 text-2xs leading-relaxed text-muted">
            <Info size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            <span>
              Each list below is capped at {formatNumber(limit)} rows by the API. A list showing{' '}
              {formatNumber(limit)} rows may have more — use the pivots above for the complete set.
            </span>
          </div>
        ) : null}
          </div>
        </section>

        <HostLookupPanel analysisId={analysisId} ip={host.ip} />
      </div>

      {/* The four capped record tables: one full-width section, each table still
          its own panel with its own cap note. */}
      <div className="flex flex-col gap-3 border-t border-border p-3" data-host-records>
        <SectionPanel
          title="Conversations"
          subtitle={`${conversations.length} of at most ${limit} reassembled streams involving this IP`}
        >
          <MiniTable<Conversation>
            rows={conversations}
            rowKey={(row) => row.conv_id}
            empty="No conversations involving this host were reassembled from this capture."
            columns={[
              {
                key: 'a',
                header: 'Endpoint A',
                render: (row) => (
                  <span
                    data-ip={flowAddress(row, 'a')}
                    data-ip-transport={row.transport}
                    data-ip-stream={row.stream_id}
                    data-ip-port={flowPort(row, 'a') ?? undefined}
                  >
                    <MonoCell maxWidth={190}>{row.endpoint_a}</MonoCell>
                  </span>
                ),
              },
              {
                key: 'b',
                header: 'Endpoint B',
                render: (row) => (
                  <span
                    data-ip={flowAddress(row, 'b')}
                    data-ip-transport={row.transport}
                    data-ip-stream={row.stream_id}
                    data-ip-port={flowPort(row, 'b') ?? undefined}
                  >
                    <MonoCell maxWidth={190}>{row.endpoint_b}</MonoCell>
                  </span>
                ),
              },
              {
                key: 'transport',
                header: 'Transport',
                render: (row) => (
                  <span className="text-muted">
                    {asText(row.transport) ?? EMPTY} #{formatNumber(row.stream_id)}
                  </span>
                ),
              },
              {
                key: 'packets',
                header: 'Packets',
                align: 'right',
                render: (row) => formatNumber(row.packets_total),
              },
              {
                key: 'bytes',
                header: 'Bytes',
                align: 'right',
                render: (row) => formatBytes(row.bytes_total),
              },
              {
                key: 'duration',
                header: 'Duration',
                align: 'right',
                render: (row) => formatDuration(row.duration),
              },
              {
                key: 'state',
                header: 'State',
                render: (row) => <span className="text-muted">{asText(row.state) ?? EMPTY}</span>,
              },
              {
                key: 'protocols',
                header: 'Protocols',
                render: (row) => (
                  <span className="text-muted" title={row.protocols ?? undefined}>
                    {asText(row.protocols) ?? EMPTY}
                  </span>
                ),
              },
            ]}
          />
        </SectionPanel>

        <SectionPanel
          title="HTTP transactions"
          subtitle={`${httpTransactions.length} of at most ${limit} transactions where this IP is client or server`}
        >
          <MiniTable<HttpTransaction>
            rows={httpTransactions}
            rowKey={(row) => String(row.id)}
            empty="No HTTP transaction was attributed to this host in this capture."
            columns={[
              { key: 'time', header: 'Time', render: (row) => <Clock value={row.time_epoch} /> },
              {
                key: 'method',
                header: 'Method',
                render: (row) => <span className="text-muted">{asText(row.method) ?? EMPTY}</span>,
              },
              {
                key: 'host',
                header: 'Host',
                render: (row) => <MonoCell maxWidth={180}>{row.host}</MonoCell>,
              },
              {
                key: 'uri',
                header: 'URI',
                render: (row) => (
                  <MonoCell maxWidth={220} title={row.full_uri ?? row.uri ?? undefined}>
                    {row.uri}
                  </MonoCell>
                ),
              },
              {
                key: 'status',
                header: 'Status',
                align: 'right',
                render: (row) => formatNumber(row.status_code),
              },
              {
                key: 'direction',
                header: 'Role',
                render: (row) => (
                  <span className="text-muted">
                    {row.client_ip === host.ip ? 'client' : row.server_ip === host.ip ? 'server' : EMPTY}
                  </span>
                ),
              },
            ]}
          />
        </SectionPanel>

        <SectionPanel
          title="DNS queries"
          subtitle={`${dnsQueries.length} of at most ${limit} queries where this IP is client or server`}
        >
          <MiniTable<DnsQuery>
            rows={dnsQueries}
            rowKey={(row) => String(row.id)}
            empty="No DNS query was attributed to this host in this capture."
            columns={[
              { key: 'time', header: 'Time', render: (row) => <Clock value={row.time_epoch} /> },
              {
                key: 'name',
                header: 'Query name',
                render: (row) => (
                  <MonoCell maxWidth={240} title={row.query_name ?? undefined}>
                    {row.query_name}
                  </MonoCell>
                ),
              },
              {
                key: 'type',
                header: 'Type',
                render: (row) => <span className="text-muted">{asText(row.query_type) ?? EMPTY}</span>,
              },
              {
                key: 'rcode',
                header: 'Rcode',
                render: (row) => <span className="text-muted">{asText(row.rcode_name) ?? EMPTY}</span>,
              },
              {
                key: 'delay',
                header: 'Response',
                align: 'right',
                render: (row) =>
                  row.response_packet === null ? (
                    <span className="text-faint">unanswered</span>
                  ) : (
                    <span className="mono">{formatDuration(row.response_delay)}</span>
                  ),
              },
              {
                key: 'answers',
                header: 'Answers',
                render: (row) => (
                  <MonoCell maxWidth={200} title={row.answer_ips ?? undefined}>
                    {row.answer_ips}
                  </MonoCell>
                ),
              },
            ]}
          />
        </SectionPanel>

        <SectionPanel
          title="TLS sessions"
          subtitle={`${tlsSessions.length} of at most ${limit} sessions where this IP is client or server`}
        >
          <MiniTable<TlsSession>
            rows={tlsSessions}
            rowKey={(row) => String(row.id)}
            empty="No TLS session was attributed to this host in this capture."
            columns={[
              { key: 'time', header: 'Time', render: (row) => <Clock value={row.time_epoch} /> },
              {
                key: 'sni',
                header: 'SNI',
                render: (row) => (
                  <MonoCell maxWidth={220} title={row.sni ?? undefined}>
                    {row.sni}
                  </MonoCell>
                ),
              },
              {
                key: 'version',
                header: 'Version',
                render: (row) => <span className="text-muted">{asText(row.version) ?? EMPTY}</span>,
              },
              {
                key: 'server',
                header: 'Server',
                render: (row) => (
                  <MonoCell maxWidth={170} title={`${row.server_ip ?? ''}:${row.server_port ?? ''}`}>
                    {row.server_ip === null
                      ? EMPTY
                      : `${row.server_ip}:${row.server_port ?? ''}`}
                  </MonoCell>
                ),
              },
              {
                key: 'handshake',
                header: 'Handshake',
                render: (row) => (
                  <span className="text-muted">{asText(row.handshake_status) ?? EMPTY}</span>
                ),
              },
              {
                key: 'cipher',
                header: 'Cipher suite',
                render: (row) => (
                  <MonoCell maxWidth={200} title={row.cipher_suite ?? undefined}>
                    {row.cipher_suite}
                  </MonoCell>
                ),
              },
            ]}
          />
        </SectionPanel>

        <div className="flex items-center gap-2 text-2xs text-faint">
          <RefreshCw size={11} aria-hidden />
          <span>
            Values shown as {EMPTY} were not reported by the backend; nothing here is inferred.
            Capture-derived names and SNI values are rendered as plain text.
          </span>
        </div>
      </div>
    </section>
  )
}

export default HostDetailPanel
