import { useCallback, useMemo } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Fingerprint, Lock, RefreshCw, X } from 'lucide-react'
import AnalysisGuard from '@/components/AnalysisGuard'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import { CertificatePanel, certificateSummary, hasCertificate } from '@/components/protocols/CertificatePanel'
import {
  ColumnHeader,
  DetailGrid,
  DetailItem,
  SectionNote,
} from '@/components/protocols/ProtocolDetail'
import {
  FilterStrip,
  ResetFiltersButton,
  SelectFilter,
  SortSelect,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import {
  FlagExplanations,
  FlagLegend,
  LeadFlagList,
  TLS_FLAG_CATALOG,
  TLS_FLAG_KEYS,
} from '@/components/protocols/ProtocolFlags'
import { useAnalysis } from '@/hooks/useAnalysis'
import { tlsApi, type TlsListParams } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import type { SortOrder, TlsFingerprintRow, TlsSession } from '@/types'
import { EMPTY, formatNumber, formatTimestamp } from '@/utils/format'

/** Sort columns the TLS endpoint allows (contract §5). */
const SORT_COLUMNS = [
  { value: 'time_epoch', label: 'time' },
  { value: 'sni', label: 'SNI' },
  { value: 'version', label: 'version' },
  { value: 'server_port', label: 'server port' },
  { value: 'cipher_suite', label: 'cipher suite' },
]

/** Every query-string key this page owns. */
const URL_KEYS = [
  'view',
  'sni',
  'version',
  'ip',
  'port',
  'alpn',
  'ja3',
  'has_cert',
  'sort',
  'order',
  'page',
  'page_size',
  'sel',
  'ftype',
  'fsearch',
]

type View = 'sessions' | 'fingerprints'
type FingerprintType = '' | 'ja3' | 'ja3s' | 'ja4'

/** How to read the handshake status column. */
const HANDSHAKE_HELP: Record<string, string> = {
  complete: 'Both a ClientHello and a ServerHello were seen in this capture.',
  client_hello_only:
    'Only the client side of the handshake is in this capture. The server flight may be missing from the file, or absent entirely.',
  server_hello_only: 'Only the server side of the handshake was seen.',
  alert: 'The session ends with a TLS alert record rather than a completed handshake.',
  unknown: 'The handshake could not be classified from what TShark dissected.',
}

/**
 * Standard TLS alert descriptions (RFC 8446 §6.2 / RFC 5246 §7.2). The API
 * stores the numeric description from the capture; the name is looked up here
 * from the registry, never inferred from the traffic.
 */
const ALERT_DESCRIPTIONS: Record<string, string> = {
  '0': 'close_notify',
  '10': 'unexpected_message',
  '20': 'bad_record_mac',
  '21': 'decryption_failed',
  '22': 'record_overflow',
  '30': 'decompression_failure',
  '40': 'handshake_failure',
  '42': 'bad_certificate',
  '43': 'unsupported_certificate',
  '44': 'certificate_revoked',
  '45': 'certificate_expired',
  '46': 'certificate_unknown',
  '47': 'illegal_parameter',
  '48': 'unknown_ca',
  '49': 'access_denied',
  '50': 'decode_error',
  '51': 'decrypt_error',
  '60': 'export_restriction',
  '70': 'protocol_version',
  '71': 'insufficient_security',
  '80': 'internal_error',
  '86': 'inappropriate_fallback',
  '90': 'user_canceled',
  '100': 'no_renegotiation',
  '109': 'missing_extension',
  '110': 'unsupported_extension',
  '112': 'unrecognized_name',
  '113': 'bad_certificate_status_response',
  '115': 'unknown_psk_identity',
}

/**
 * A small set of well-known IANA cipher suite codes, used only to label the hex
 * value the capture actually carried (`0xc02f` -> its registry name).
 */
const CIPHER_SUITES: Record<string, string> = {
  '0x1301': 'TLS_AES_128_GCM_SHA256',
  '0x1302': 'TLS_AES_256_GCM_SHA384',
  '0x1303': 'TLS_CHACHA20_POLY1305_SHA256',
  '0x009c': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  '0x009d': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  '0xc02b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  '0xc02c': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  '0xc02f': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  '0xc030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  '0xc013': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  '0xc014': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  '0xcca8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  '0xcca9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  '0x000a': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  '0x002f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
  '0x0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
}

function cipherLabel(value: string | null): string | null {
  if (!value) return null
  return CIPHER_SUITES[value.trim().toLowerCase()] ?? null
}

function alertLabel(value: string | null): string | null {
  if (!value) return null
  const name = ALERT_DESCRIPTIONS[value.trim()]
  return name ? `alert ${value.trim()} — ${name}` : `alert ${value.trim()}`
}

function splitList(value: string | null): string[] {
  if (!value) return []
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

/* ------------------------------------------------------------------ */
/* Detail                                                              */
/* ------------------------------------------------------------------ */

interface SessionDetailProps {
  analysisId: string
  sessionId: number
  onFilterFingerprint: (fingerprint: string) => void
  onClose: () => void
}

/** Full metadata, certificate panel and lead flags for one TLS session. */
function SessionDetail({
  analysisId,
  sessionId,
  onFilterFingerprint,
  onClose,
}: SessionDetailProps) {
  const query = useQuery<TlsSession>({
    queryKey: ['tls-detail', analysisId, sessionId],
    queryFn: () => tlsApi.get(analysisId, sessionId),
  })

  return (
    <Panel
      title="TLS session detail"
      subtitle={`${analysisId.slice(0, 12)}… · session ${sessionId}`}
      flush
      actions={
        <>
          <button
            type="button"
            className="btn px-1.5 py-1"
            onClick={() => void query.refetch()}
            disabled={query.isFetching}
            title="Re-read this session"
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
        <LoadingState label="Loading TLS session…" rows={4} />
      ) : query.error ? (
        <ErrorState
          error={query.error}
          title="Could not load the TLS session"
          onRetry={() => void query.refetch()}
        />
      ) : !query.data ? (
        <div className="px-3 py-6">
          <SectionNote>The backend returned no TLS session for this id.</SectionNote>
        </div>
      ) : (
        <SessionDetailBody
          session={query.data}
          onFilterFingerprint={onFilterFingerprint}
        />
      )}
    </Panel>
  )
}

function SessionDetailBody({
  session,
  onFilterFingerprint,
}: {
  session: TlsSession
  onFilterFingerprint: (fingerprint: string) => void
}) {
  const alpn = splitList(session.alpn)
  const fingerprintRows: { label: string; value: string | null }[] = [
    { label: 'JA3', value: session.ja3 },
    { label: 'JA3S', value: session.ja3s },
    { label: 'JA4', value: session.ja4 },
  ]

  return (
    <div className="flex flex-col divide-y divide-border">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2">
        <span className="mono text-xs text-text" title={session.sni ?? undefined}>
          {session.sni ?? 'no SNI'}
        </span>
        {session.sni ? <CopyButton value={session.sni} label="Copy the SNI" /> : null}
        <span className="chip border-border2 bg-surface2 text-muted">
          {session.version ?? 'version not available'}
        </span>
        <span className="chip border-border2 bg-surface2 text-muted">
          {session.handshake_status ?? 'handshake status not available'}
        </span>
        {session.alert ? (
          <span className="chip border-warn/40 bg-warn/10 text-warn">{alertLabel(session.alert)}</span>
        ) : null}
      </div>

      <div className="p-3">
        <DetailGrid columns={3}>
          <DetailItem label="Time" value={formatTimestamp(session.time_epoch)} />
          <DetailItem label="Client" value={session.client_ip} />
          <DetailItem label="Client port" value={session.client_port} />
          <DetailItem label="Server" value={session.server_ip} />
          <DetailItem label="Server port" value={session.server_port} />
          <DetailItem label="Stream" value={session.stream_id} />
          <DetailItem label="Client packet" value={session.client_packet} />
          <DetailItem label="Server packet" value={session.server_packet} />
          <DetailItem label="Records" value={session.record_count} />
          <DetailItem label="Version (negotiated)" value={session.version} />
          <DetailItem label="Client version" value={session.client_version} />
          <DetailItem label="Server version" value={session.server_version} />
          <DetailItem
            label="SNI"
            value={session.sni}
            unavailableReason="No SNI was present in the ClientHello of this capture, or the client concealed it (Encrypted ClientHello). The backend never invents a hostname."
          />
          <DetailItem
            label="ALPN offered"
            value={alpn.length === 0 ? null : alpn.join(', ')}
            unavailableReason="The ClientHello carried no ALPN extension in this capture."
          />
          <DetailItem
            label="ALPN selected"
            value={session.selected_alpn}
            unavailableReason="No ServerHello ALPN selection was dissected for this session."
          />
          <DetailItem
            label="Cipher suite"
            value={session.cipher_suite}
            unavailableReason="No cipher suite was negotiated in this capture."
          />
          <DetailItem
            label="Cipher (registry)"
            value={cipherLabel(session.cipher_suite)}
            unavailableReason="This code is not in the small IANA table built into this view. The hex code above is the value from the capture."
          />
          <DetailItem label="Handshake status" value={session.handshake_status} />
          <DetailItem label="Alert" value={alertLabel(session.alert)} />
          <DetailItem label="JA3" value={session.ja3} />
          <DetailItem label="JA3 (full string)" value={session.ja3_full} />
          <DetailItem label="JA3S" value={session.ja3s} />
          <DetailItem label="JA4" value={session.ja4} />
        </DetailGrid>
        <SectionNote className="mt-2">
          {HANDSHAKE_HELP[session.handshake_status ?? ''] ??
            'The handshake status was not one of the values this view documents; it is shown verbatim from the backend.'}
        </SectionNote>
      </div>

      {session.ja3 || session.ja3s || session.ja4 ? (
        <div className="flex flex-wrap items-center gap-2 p-3">
          <span className="text-2xs uppercase tracking-wider text-muted">Fingerprints</span>
          {fingerprintRows
            .filter((row): row is { label: string; value: string } => Boolean(row.value))
            .map((row) => (
              <span key={row.label} className="flex items-center gap-1">
                <span className="chip border-border2 bg-surface2 text-muted" title={`${row.label} of this ClientHello/ServerHello`}>
                  {row.label} {row.value}
                </span>
                <CopyButton value={row.value} label={`Copy ${row.label}`} />
                <button
                  type="button"
                  className="btn px-1.5 py-1"
                  onClick={() => onFilterFingerprint(row.value)}
                  title={`Show every session whose JA3, JA3S or JA4 equals this ${row.label}`}
                >
                  Sessions
                </button>
              </span>
            ))}
        </div>
      ) : null}

      <div className="p-3">
        <CertificatePanel fields={session} evaluatedAt={session.time_epoch} />
      </div>

      <div className="flex flex-col gap-2 p-3">
        <span className="text-2xs uppercase tracking-wider text-muted">Lead flags on this session</span>
        <FlagExplanations
          flags={session.flags}
          catalog={TLS_FLAG_CATALOG}
          intro="Recorded by the TLS analyser from handshake fields only. Payloads are not decrypted, so none of these come from application data."
        />
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Fingerprints                                                        */
/* ------------------------------------------------------------------ */

interface FingerprintsPanelProps {
  rows: TlsFingerprintRow[]
  loading: boolean
  error: unknown
  onRetry: () => void
  type: FingerprintType
  onType: (value: FingerprintType) => void
  search: string
  onSearch: (value: string) => void
  onShowSessions: (fingerprint: string) => void
}

/** Grouped JA3 / JA3S / JA4 values with their session counts (`/tls/fingerprints`). */
function FingerprintsPanel({
  rows,
  loading,
  error,
  onRetry,
  type,
  onType,
  search,
  onSearch,
  onShowSessions,
}: FingerprintsPanelProps) {
  const needle = search.trim().toLowerCase()
  const filtered = useMemo(() => {
    return rows
      .filter((row) => (type === '' ? true : row.type === type))
      .filter((row) => {
        if (needle === '') return true
        const haystack = [row.fingerprint, ...(row.snis ?? []), ...(row.clients ?? [])]
          .join(' ')
          .toLowerCase()
        return haystack.includes(needle)
      })
      .sort((a, b) => b.sessions - a.sessions || a.fingerprint.localeCompare(b.fingerprint))
  }, [rows, type, needle])

  const types = useMemo(() => {
    const seen = new Set(rows.map((row) => row.type))
    return (['ja3', 'ja3s', 'ja4'] as const).filter((option) => seen.has(option))
  }, [rows])

  return (
    <Panel
      title="TLS fingerprints"
      subtitle={`${formatNumber(filtered.length)} of ${formatNumber(rows.length)} grouped values${
        needle === '' ? '' : ' (filtered in the browser)'
      }`}
      flush
    >
      <FilterStrip>
        <SelectFilter
          label="Type"
          value={type}
          anyLabel="all types"
          options={types.map((option) => ({ value: option, label: option }))}
          onChange={(value) => onType(value as FingerprintType)}
          width="w-28"
          title="JA3 and JA4 describe the client's ClientHello; JA3S describes the server's ServerHello."
        />
        <TextFilter
          label="Search"
          value={search}
          placeholder="fingerprint, SNI or client"
          width="w-56"
          onChange={onSearch}
          title="Filters the grouped rows already returned for this analysis; the aggregation is not re-run."
        />
      </FilterStrip>

      {loading ? (
        <LoadingState label="Loading fingerprint groups…" rows={5} />
      ) : error ? (
        <ErrorState error={error} title="Could not load TLS fingerprints" onRetry={onRetry} />
      ) : filtered.length === 0 ? (
        <EmptyState
          variant="plain"
          icon={Fingerprint}
          title={rows.length === 0 ? 'No fingerprints in this analysis' : 'No fingerprint matches that filter'}
          description={
            rows.length === 0
              ? 'No TLS session in this capture carried a JA3, JA3S or JA4 value that could be computed. An incomplete ClientHello (no handshake to fingerprint) explains that.'
              : 'The backend returned fingerprint groups, but none of them match the type or search text you entered.'
          }
        />
      ) : (
        <div className="overflow-auto">
          <table className="dt">
            <thead>
              <tr>
                <th>Fingerprint</th>
                <th>Type</th>
                <th className="text-right">Sessions</th>
                <th>SNIs seen with it</th>
                <th>Clients</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={`${row.type}-${row.fingerprint}`}>
                  <td>
                    <MonoCell maxWidth={360}>{row.fingerprint}</MonoCell>
                  </td>
                  <td>
                    <span className="chip border-border2 bg-surface2 text-muted">{row.type}</span>
                  </td>
                  <td className="text-right">{formatNumber(row.sessions)}</td>
                  <td className="text-muted">
                    {(row.snis ?? []).length === 0 ? (
                      <span
                        className="text-faint"
                        title="No SNI was recorded for any session in this group — the ClientHello may have carried none, or it was concealed (Encrypted ClientHello)."
                      >
                        none recorded
                      </span>
                    ) : (
                      <MonoCell maxWidth={300}>{(row.snis ?? []).join(', ')}</MonoCell>
                    )}
                  </td>
                  <td className="text-muted">
                    <MonoCell maxWidth={220}>{(row.clients ?? []).join(', ')}</MonoCell>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn px-1.5 py-1"
                      onClick={() => onShowSessions(row.fingerprint)}
                      title="Open the session table filtered to this fingerprint"
                    >
                      Sessions
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex flex-col gap-2 border-t border-border px-3 py-2">
        <SectionNote>
          JA3/JA3S are hashes of the handshake parameters (versions, cipher suites, extensions,
          curves, formats); JA4 is the same idea in a readable format. The backend computes them from
          the observed handshake and groups the stored sessions by value. A shared fingerprint means
          the peers built their ClientHello/ServerHello the same way — a strong hint about the TLS
          library or tool in use, and not a statement about what the software was asked to do.
          Collisions and small variations between builds do occur, so treat a match as a lead.
        </SectionNote>
        <SectionNote>
          Certificate subject and issuer can legitimately be absent even when a certificate is
          present: TShark&apos;s subject/issuer fields are not usable for every certificate, and the
          backend stores NULL rather than a wrong value. The session table reports this as
          &ldquo;serial only&rdquo; instead of pretending the certificate is missing.
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
      {(['sessions', 'fingerprints'] as const).map((option) => (
        <button
          key={option}
          type="button"
          className={clsx('btn btn-tab', view === option && 'btn-primary')}
          onClick={() => onChange(option)}
          title={
            option === 'sessions'
              ? 'One row per TLS session, from handshake metadata'
              : 'JA3 / JA3S / JA4 values grouped with their session counts'
          }
        >
          {option}
        </button>
      ))}
    </div>
  )
}

function TlsContent() {
  const { analysisId } = useAnalysis()
  const filters = useUrlFilters(URL_KEYS, 100)

  /* `clear()` keeps non-filter state, and the fingerprint filter is a
     client-side list filter rather than a server one, so it is cleared here. */
  const resetFilters = useCallback(() => {
    filters.clear()
    filters.patch({ ftype: null, fsearch: null }, { resetPage: false })
  }, [filters])

  const view: View = filters.get('view') === 'fingerprints' ? 'fingerprints' : 'sessions'
  const page = filters.getNumber('page', 1)
  const pageSize = filters.getNumber('page_size', 100)
  const sort = filters.get('sort') || 'time_epoch'
  const order = (filters.get('order') || 'asc') as SortOrder
  const version = filters.get('version')
  const hasCert = filters.get('has_cert')
  const selectedId = filters.getNumber('sel', 0)

  const params = useMemo<TlsListParams>(
    () => ({
      page,
      page_size: pageSize,
      sort,
      order,
      sni: filters.get('sni') || undefined,
      version: version || undefined,
      ip: filters.get('ip') || undefined,
      port: filters.get('port') || undefined,
      alpn: filters.get('alpn') || undefined,
      ja3: filters.get('ja3') || undefined,
      has_cert: hasCert === '' ? undefined : hasCert === 'true',
    }),
    [filters, page, pageSize, sort, order, version, hasCert],
  )

  const query = useQuery({
    queryKey: ['tls', analysisId, params],
    queryFn: () => tlsApi.list(analysisId as string, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const fingerprintsQuery = useQuery({
    queryKey: ['tls-fingerprints', analysisId],
    queryFn: () => tlsApi.fingerprints(analysisId as string),
    enabled: Boolean(analysisId) && view === 'fingerprints',
  })

  const data = query.data
  const items = data?.items ?? []
  const snis = data?.snis ?? []
  const versions = data?.versions ?? []

  const setSort = useCallback(
    (nextSort: string, nextOrder: string) => filters.patch({ sort: nextSort, order: nextOrder }),
    [filters],
  )

  const showSessionsFor = useCallback(
    (fingerprint: string) => {
      filters.patch({ ja3: fingerprint, view: 'sessions', sel: null })
    },
    [filters],
  )

  const withCert = items.filter((session) => hasCertificate(session)).length
  const withoutSni = items.filter((session) => !session.sni).length

  return (
    <div className="flex flex-col gap-3">
      <FlagLegend
        catalog={TLS_FLAG_CATALOG}
        keys={TLS_FLAG_KEYS}
        title="How to read TLS lead flags"
        defaultOpen={false}
        note="These flags describe the handshake and the capture. None of them comes from decrypted application data, because there is none."
      />

      <div className="flex flex-wrap items-center gap-2">
        <ViewToggle view={view} onChange={(next) => filters.patch({ view: next })} />
        <span className="text-2xs text-faint">
          {view === 'sessions'
            ? 'One row per TLS session, from handshake metadata only.'
            : 'JA3 / JA3S / JA4 values grouped with their session counts.'}
        </span>
      </div>

      {view === 'sessions' ? (
        <>

          <Panel
            title="TLS sessions"
            subtitle={
              data
                ? `${formatNumber(data.total)} matching session${data.total === 1 ? '' : 's'}${
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
                label="SNI"
                value={filters.get('sni')}
                placeholder="substring"
                width="w-44"
                listId="tls-snis"
                onChange={(value) => filters.patch({ sni: value })}
                title="Substring match on the SNI. Sessions that carried no SNI cannot match this filter."
              />
              <datalist id="tls-snis">
                {snis.map((sni) => (
                  <option key={sni} value={sni} />
                ))}
              </datalist>
              <SelectFilter
                label="Version"
                value={version}
                options={versions.map((value) => ({ value, label: value }))}
                onChange={(value) => filters.patch({ version: value })}
                width="w-32"
                title="Exact negotiated version. Values are the versions actually stored in this analysis."
              />
              <TextFilter
                label="IP"
                value={filters.get('ip')}
                placeholder="client or server"
                width="w-40"
                onChange={(value) => filters.patch({ ip: value })}
                title="Exact match on either the client or the server address."
              />
              <TextFilter
                label="Port"
                value={filters.get('port')}
                placeholder="443"
                width="w-24"
                onChange={(value) => filters.patch({ port: value })}
                title="Exact match on either the client or the server port."
              />
              <TextFilter
                label="ALPN"
                value={filters.get('alpn')}
                placeholder="h2, http/1.1"
                width="w-36"
                onChange={(value) => filters.patch({ alpn: value })}
                title="Substring match on the offered ALPN list."
              />
              <TextFilter
                label="JA3/JA3S/JA4"
                value={filters.get('ja3')}
                placeholder="fingerprint"
                width="w-64"
                onChange={(value) => filters.patch({ ja3: value })}
                title="Exact match on JA3, JA3S or JA4. Pick a value from the fingerprints view to fill this in."
              />
              <SelectFilter
                label="Certificate"
                value={hasCert}
                anyLabel="any"
                options={[
                  { value: 'true', label: 'has certificate' },
                  { value: 'false', label: 'no certificate' },
                ]}
                onChange={(value) => filters.patch({ has_cert: value === '' ? null : value })}
                width="w-40"
                title="A session counts as having a certificate when any of its certificate fields was decoded — including the serial and validity window alone, since subject and issuer are not always usable."
              />
            </FilterStrip>

            {query.isLoading ? (
              <LoadingState label="Loading TLS sessions…" rows={6} />
            ) : query.error ? (
              <ErrorState
                error={query.error}
                title="Could not load TLS sessions"
                onRetry={() => void query.refetch()}
              />
            ) : items.length === 0 ? (
              <EmptyState
                variant="plain"
                icon={Lock}
                title={filters.any ? 'No sessions match these filters' : 'No TLS sessions in this analysis'}
                description={
                  filters.any ? (
                    <>
                      No stored session satisfies every filter at once. Reset the filters, or relax
                      the one you just added — the certificate filter is the usual culprit, since most
                      sessions in a modern capture carry no readable certificate.
                    </>
                  ) : (
                    <>
                      TShark dissected no TLS handshake in this capture. TLS carried over a port other
                      than the usual one, or a capture that ended before the handshake, both produce
                      this.
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
                      <th>Server</th>
                      <th className="text-right">Port</th>
                      <ColumnHeader
                        label="Version"
                        title="The negotiated TLS version as TShark dissected it. Empty when no hello pair was seen."
                      />
                      <ColumnHeader
                        label="SNI"
                        title="Server Name Indication from the ClientHello. Empty when the client sent none, when it was concealed with Encrypted ClientHello, or when the ClientHello is not in the capture."
                      />
                      <ColumnHeader
                        label="ALPN"
                        title="Application protocols offered in the ClientHello. The server's selection is shown in the detail view."
                      />
                      <ColumnHeader
                        label="Cipher"
                        title="Negotiated cipher suite, as the hex code carried in the ServerHello."
                      />
                      <ColumnHeader
                        label="JA3"
                        title="JA3 fingerprint of the ClientHello. Note that certificate subject and issuer can be absent even when a certificate is present — TShark's subject/issuer fields are not always usable and the backend stores NULL rather than a wrong value."
                      />
                      <ColumnHeader
                        label="JA3S"
                        title="JA3S fingerprint of the ServerHello. A missing value means no ServerHello was seen in this capture."
                      />
                      <ColumnHeader
                        label="JA4"
                        title="JA4 fingerprint, in the readable JA4 format. Same limits as JA3: a lead about the TLS stack, not about intent."
                      />
                      <ColumnHeader
                        label="Certificate"
                        title="Certificate metadata decoded for this session. 'serial only' means the serial and/or validity window were decoded while the subject and issuer were not usable — the backend stores NULL instead of a wrong value."
                      />
                      <ColumnHeader
                        label="Handshake"
                        title="complete, client_hello_only, server_hello_only, alert or unknown, as recorded by the analyser."
                      />
                      <th>Lead flags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((session) => {
                      const present = hasCertificate(session)
                      const subjectKnown = Boolean(session.cert_subject || session.cert_issuer)
                      return (
                        <tr
                          key={session.id}
                          className={clsx('cursor-pointer', session.id === selectedId && 'selected')}
                          tabIndex={0}
                          onClick={() => filters.patch({ sel: session.id })}
                          onKeyDown={(event) => {
                            if (event.key === 'Enter' || event.key === ' ') {
                              event.preventDefault()
                              filters.patch({ sel: session.id })
                            }
                          }}
                          title="Open the session metadata, certificate panel and lead flags"
                        >
                          <td>{formatTimestamp(session.time_epoch)}</td>
                          <td>
                            <MonoCell maxWidth={160}>
                              {session.client_ip === null
                                ? null
                                : `${session.client_ip}${
                                    session.client_port === null ? '' : `:${session.client_port}`
                                  }`}
                            </MonoCell>
                          </td>
                          <td>
                            <MonoCell maxWidth={160}>{session.server_ip}</MonoCell>
                          </td>
                          <td className="text-right">
                            {session.server_port === null ? (
                              <span className="text-faint">{EMPTY}</span>
                            ) : (
                              session.server_port
                            )}
                          </td>
                          <td className="text-muted">
                            <MonoCell>{session.version}</MonoCell>
                          </td>
                          <td className="text-text">
                            <MonoCell maxWidth={220}>{session.sni}</MonoCell>
                          </td>
                          <td className="text-muted">
                            <MonoCell maxWidth={160}>{session.alpn}</MonoCell>
                          </td>
                          <td className="text-muted">
                            <MonoCell maxWidth={110}>{session.cipher_suite}</MonoCell>
                          </td>
                          <td className="text-muted">
                            <MonoCell maxWidth={150}>{session.ja3}</MonoCell>
                          </td>
                          <td className="text-muted">
                            <MonoCell maxWidth={150}>{session.ja3s}</MonoCell>
                          </td>
                          <td className="text-muted">
                            <MonoCell maxWidth={190}>{session.ja4}</MonoCell>
                          </td>
                          <td title={certificateSummary(session)}>
                            {!present ? (
                              <span className="chip border-border2 bg-surface2 text-faint">
                                not available
                              </span>
                            ) : subjectKnown ? (
                              <span className="chip border-ok/40 bg-ok/10 text-ok">present</span>
                            ) : (
                              <span className="chip border-border2 bg-surface2 text-muted">
                                serial only
                              </span>
                            )}
                          </td>
                          <td
                            className={clsx(
                              session.handshake_status === 'complete'
                                ? 'text-ok'
                                : session.handshake_status === 'alert'
                                  ? 'text-warn'
                                  : 'text-muted',
                            )}
                            title={HANDSHAKE_HELP[session.handshake_status ?? ''] ?? undefined}
                          >
                            <MonoCell>{session.handshake_status}</MonoCell>
                          </td>
                          <td>
                            <LeadFlagList flags={session.flags} catalog={TLS_FLAG_CATALOG} />
                          </td>
                        </tr>
                      )
                    })}
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
                  On this page, {formatNumber(withCert)} of {formatNumber(items.length)} sessions carry
                  certificate metadata and {formatNumber(withoutSni)} have no SNI recorded. Both
                  numbers describe what is in the capture: TLS 1.3 encrypts the certificate, and a
                  ClientHello may carry no server name at all. Payloads are not decrypted, so the
                  paths, headers and bodies of these connections are not available anywhere in this
                  app.
                </SectionNote>
              </div>
            ) : null}
          </Panel>

          {selectedId > 0 && analysisId ? (
            <SessionDetail
              analysisId={analysisId}
              sessionId={selectedId}
              onFilterFingerprint={showSessionsFor}
              onClose={() => filters.patch({ sel: null })}
            />
          ) : null}
        </>
      ) : (
        <FingerprintsPanel
          rows={fingerprintsQuery.data?.items ?? []}
          loading={fingerprintsQuery.isLoading}
          error={fingerprintsQuery.error}
          onRetry={() => void fingerprintsQuery.refetch()}
          type={(filters.get('ftype') as FingerprintType) || ''}
          onType={(value) => filters.patch({ ftype: value || null })}
          search={filters.get('fsearch')}
          onSearch={(value) => filters.patch({ fsearch: value })}
          onShowSessions={showSessionsFor}
        />
      )}

      <div className="flex items-center gap-2 px-1 pb-1 text-2xs text-faint">
        <Lock size={12} aria-hidden />
        <span>
          Handshake metadata only — TLS payloads are not decrypted. A cell showing {EMPTY} means the
          value was not in the capture, not that it was empty.
        </span>
      </div>
    </div>
  )
}

/** TLS analysis — sessions, certificates and JA3/JA3S/JA4 fingerprints. */
export function TlsPage() {
  return (
    <Page section={SECTIONS.tls}>
      <AnalysisGuard>
        <TlsContent />
      </AnalysisGuard>
    </Page>
  )
}

export default TlsPage
