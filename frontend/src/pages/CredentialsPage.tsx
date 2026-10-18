import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeftRight,
  ArrowRight,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  RefreshCw,
  SearchX,
  Settings as SettingsIcon,
  ShieldQuestion,
  TriangleAlert,
} from 'lucide-react'
import pageBackground from '@/assets/usernamePass_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import AddressFlag from '@/components/AddressFlag'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import MonoCell from '@/components/MonoCell'
import Page from '@/components/Page'
import Pagination from '@/components/Pagination'
import Panel from '@/components/Panel'
import StatCard from '@/components/StatCard'
import { conversationUrlKey } from '@/components/findings/FollowConversationButton'
import { DetailGrid, DetailItem, ScopeNote, SectionNote } from '@/components/protocols/ProtocolDetail'
import {
  FilterStrip,
  ResetFiltersButton,
  SelectFilter,
  SortSelect,
  TextFilter,
  useUrlFilters,
} from '@/components/protocols/ProtocolFilters'
import { useAnalysis } from '@/hooks/useAnalysis'
import { credentialsApi, toApiError } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { EMPTY, formatNumber, formatTimestamp } from '@/utils/format'
import type { CredentialFinding, CredentialScanState } from '@/types'

/**
 * Credentials — the cleartext credentials this capture carried (docs/CREDENTIALS.md).
 *
 * The page is a dense evidence list over one analysis, and three of its properties come
 * straight from the contract rather than from taste:
 *
 * 1. **Nothing is shown that was not asked for.** The list redacts every value to a
 *    preview (§5); the full value is fetched for **one row at a time**, only when the
 *    analyst presses *Reveal* on it, and never for the table as a whole.
 * 2. **The scan's own state is part of the answer.** §7 makes the stage switchable, so a
 *    disabled scan is reported above the table and an empty table is never dressed up as
 *    a clean capture — and neither is a scan that has never read the protocol in question.
 * 3. **Everything is a lead.** §4's confidence is quoted, not upgraded, and §10's limits
 *    are stated in the panel above the table rather than left for the reader to infer.
 */

/** Sort columns the endpoint allows (contract §8.1). */
const SORT_COLUMNS = [
  { value: 'confidence', label: 'confidence' },
  { value: 'kind', label: 'kind' },
  { value: 'protocol', label: 'protocol' },
  { value: 'created_at', label: 'found at' },
]

/**
 * Every query-string key this page owns. The URL spells the stream filter `stream` and
 * the wire parameter `stream_id`, the same way the other pages do.
 */
const URL_KEYS = [
  'kind',
  'protocol',
  'confidence',
  'stream',
  'sort',
  'order',
  'page',
  'page_size',
]

/** Rows asked for when one row's value is revealed: enough that the row is on the page. */
const REVEAL_PAGE_SIZE = 100

/** The five protocols §2 reads, in the order the scanner lists them. */
const SCAN_PROTOCOLS = ['http', 'ftp', 'smtp', 'pop3', 'imap']

/** Every kind §6 allows, in the order the tiles and the filter read them. */
const KIND_ORDER = [
  'username',
  'password',
  'api_key',
  'bearer_token',
  'other_secret',
  'aws_access_key',
  'jwt',
  'pem_private_key',
  'github_token',
  'slack_token',
  'google_api_key',
  'stripe_key',
]

/** The five kinds that get their own tile, in the order the contract names them. */
const TILE_KINDS = [
  { key: 'username', label: 'Usernames' },
  { key: 'password', label: 'Passwords' },
  { key: 'api_key', label: 'API keys' },
  { key: 'bearer_token', label: 'Bearer tokens' },
  { key: 'other_secret', label: 'Other secrets' },
]

const KIND_LABELS: Record<string, string> = {
  username: 'username',
  password: 'password',
  api_key: 'API key',
  bearer_token: 'bearer token',
  other_secret: 'other secret',
  aws_access_key: 'AWS access key',
  jwt: 'JWT',
  pem_private_key: 'PEM private key',
  github_token: 'GitHub token',
  slack_token: 'Slack token',
  google_api_key: 'Google API key',
  stripe_key: 'Stripe key',
}

const CONFIDENCE_ORDER = ['high', 'medium', 'low']

/** §4's rule for each level, quoted where the level is shown. */
const CONFIDENCE_RULES: Record<string, string> = {
  high: 'A protocol-confirmed structured location yielded the value: an HTTP Basic, Bearer or other Authorization scheme, a form or JSON field whose name is credential-like, an FTP/SMTP/POP3/IMAP authentication command, or a §3.3 shape matched inside such a field.',
  medium:
    'A credential-like field name in a free-text body or a URL query, a credential-like cookie name, or a malformed Basic header kept as one opaque value.',
  low: 'A §3.3 shape found in a string that no field name vouched for.',
}

const CONFIDENCE_TONES: Record<string, string> = {
  high: 'border-accent/50 bg-accent/15 text-accent2',
  medium: 'border-border2 bg-surface2 text-muted',
  low: 'border-border bg-surface2 text-faint',
}

const PROTOCOL_LABELS: Record<string, string> = {
  http: 'HTTP',
  ftp: 'FTP',
  smtp: 'SMTP',
  pop3: 'POP3',
  imap: 'IMAP',
}

/** Where each protocol's own page is, so a row can hand the reader over to it. */
const PROTOCOL_PAGES: Record<string, { to: string; label: string }> = {
  http: { to: '/http', label: 'HTTP' },
  ftp: { to: '/ftp', label: 'FTP' },
  smtp: { to: '/email', label: 'Email' },
  pop3: { to: '/email', label: 'Email' },
  imap: { to: '/email', label: 'Email' },
}

/** The caps §9 fixes, quoted so the page's own numbers have their limit named. */
const VALUE_CAP_CHARS = 512
const FINDINGS_CAP = 200
const BODY_CAP_CHARS = 262144

/** `ip:port`, with the em dash when either half is missing. */
function endpoint(ip: string | null, port: number | null): string {
  if (ip === null || ip === '') return EMPTY
  return port === null ? ip : `${ip}:${port}`
}

/** A count the API actually returned, or null — which the tiles render as an em dash. */
function countFor(counts: Record<string, number>, key: string): number | null {
  const value = counts[key]
  return typeof value === 'number' ? value : null
}

/* ------------------------------------------------------------------ */
/* Summary                                                             */
/* ------------------------------------------------------------------ */

interface SummaryProps {
  total: number | null
  streams: number | null
  streamHint: string
  byKind: Record<string, number>
  byConfidence: Record<string, number>
  byProtocol: Record<string, number>
  note: string | null
  confidence: string
  onConfidence: (value: string) => void
  protocol: string
  onProtocol: (value: string) => void
}

/**
 * The headline counts, all of them from `GET /credentials/summary` (§8.2).
 *
 * A figure the response does not carry is an em dash, never a zero: "the endpoint did
 * not say" and "the scan found none" are different statements, and this page exists
 * partly because they used to be confused.
 */
function SummaryTiles({
  total,
  streams,
  streamHint,
  byKind,
  byConfidence,
  byProtocol,
  note,
  confidence,
  onConfidence,
  protocol,
  onProtocol,
}: SummaryProps) {
  /* A shape kind the endpoint counted as zero gets no chip: seven zeroes would read as a
     claim about the capture rather than as the absence of anything to say. */
  const shapeKinds = KIND_ORDER.filter((key) => {
    if (TILE_KINDS.some((tile) => tile.key === key)) return false
    const count = countFor(byKind, key)
    return count !== null && count > 0
  }).map((key) => ({ key, count: countFor(byKind, key) as number }))

  const protocolKeys = SCAN_PROTOCOLS.filter((name) => countFor(byProtocol, name) !== null)

  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
        <StatCard
          label="Findings"
          value={total}
          icon={KeyRound}
          hint="GET /credentials/summary — every credential row this analysis holds, unfiltered by the table's filters"
        />
        <StatCard
          label="Streams involved"
          value={streams}
          icon={ArrowLeftRight}
          hint={streamHint}
        />
        {TILE_KINDS.map((tile) => (
          <StatCard
            key={tile.key}
            label={tile.label}
            value={countFor(byKind, tile.key)}
            hint={`summary.by_kind.${tile.key} — findings the scanner recorded as ${tile.label.toLowerCase()}`}
          />
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-1">
        <span className="flex flex-wrap items-center gap-1.5">
          <span className="text-2xs uppercase tracking-wider text-faint">Confidence</span>
          {CONFIDENCE_ORDER.map((level) => {
            const count = countFor(byConfidence, level)
            const active = confidence === level
            return (
              <button
                key={level}
                type="button"
                className={clsx('chip cursor-pointer', CONFIDENCE_TONES[level], active && 'ring-1 ring-accent/60')}
                title={`${CONFIDENCE_RULES[level]}${active ? ' — click to clear this filter' : ' — click to filter on it'}`}
                onClick={() => onConfidence(active ? '' : level)}
              >
                {level}
                <span className="mono">{count === null ? EMPTY : formatNumber(count)}</span>
              </button>
            )
          })}
        </span>

        {protocolKeys.length > 0 ? (
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="text-2xs uppercase tracking-wider text-faint">Protocol</span>
            {protocolKeys.map((name) => {
              const count = countFor(byProtocol, name)
              const active = protocol === name
              return (
                <button
                  key={name}
                  type="button"
                  className={clsx(
                    'chip cursor-pointer border-border2 bg-surface2',
                    active ? 'text-accent2 ring-1 ring-accent/60' : 'text-muted',
                  )}
                  title={`${formatNumber(count ?? 0)} finding(s) were read from ${PROTOCOL_LABELS[name]} locations${active ? ' — click to clear this filter' : ' — click to filter on it'}.`}
                  onClick={() => onProtocol(active ? '' : name)}
                >
                  {PROTOCOL_LABELS[name]}
                  <span className="mono">{count === null ? EMPTY : formatNumber(count)}</span>
                </button>
              )
            })}
          </span>
        ) : null}

        {shapeKinds.length > 0 ? (
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs text-faint">
            <span className="uppercase tracking-wider">Secret shapes matched</span>
            {shapeKinds.map((entry) => (
              <span key={entry.key} className="chip border-warn/40 bg-warn/10 text-warn">
                {KIND_LABELS[entry.key] ?? entry.key}
                <span className="mono">{formatNumber(entry.count)}</span>
              </span>
            ))}
          </span>
        ) : null}
      </div>

      {note !== null && note !== '' ? <SectionNote>{note}</SectionNote> : null}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Scan state                                                          */
/* ------------------------------------------------------------------ */

interface ScanStateProps {
  /** The whole §7 block, or null when neither read endpoint reported one. */
  scan: CredentialScanState | null
  loading: boolean
  rescan: ReactNode
}

function protocolList(protocols: string[]): string {
  return protocols.map((name) => PROTOCOL_LABELS[name] ?? name).join(' · ')
}

/**
 * What the scan is doing, above the table it decides the contents of (§7).
 *
 * The states it separates are the reason the panel exists: the stage is off, it is on but
 * no protocol is selected, it has never run for this analysis, or it ran — and when it
 * ran, what it read and what it wrote. A capture whose list is empty for one of the first
 * three reasons has not been read, which is not the same as being free of credentials.
 */
function ScanStatePanel({ scan, loading, rescan }: ScanStateProps) {
  const enabled = scan === null ? null : scan.enabled === true
  const protocols = scan?.protocols ?? []
  const scannedAt = scan?.scanned_at ?? null
  const stageRan = scan?.stage_ran
  const rowsWrittenAt = scan?.rows_written_at ?? null

  if (enabled === false) {
    /* §7: the rows that exist stay readable, so the panel states both the setting and
       when the rows on screen were actually written. */
    const writtenAt = rowsWrittenAt ?? scannedAt
    return (
      <section className="panel">
        <header className="panel-header">
          <div className="min-w-0">
            <div className="panel-title flex items-center gap-1.5">
              <TriangleAlert size={14} className="shrink-0 text-warn" aria-hidden />
              <span>Users &amp; Passwords discovery is switched off</span>
            </div>
            <div className="panel-subtitle">
              the pipeline skipped the stage for new analyses, so nothing new was read
            </div>
          </div>
          <Link to="/settings" className="btn">
            <SettingsIcon size={13} aria-hidden />
            Settings
          </Link>
        </header>
        <div className="flex flex-col gap-2 p-3">
          <SectionNote tone="warn">
            {`The setting credential_scan_enabled is off, so this stage writes no rows. ${
              writtenAt === null
                ? 'No row and no run are recorded for this analysis at all.'
                : `The rows listed below were written ${formatTimestamp(writtenAt)}, by a run made while it was on.`
            } An empty table would therefore mean the scanner looked at nothing — it is not a statement that this capture carried no credentials.`}
          </SectionNote>
          <p className="text-2xs leading-relaxed text-muted">
            Turning the scan off does not delete what an earlier run already found: the rows that
            exist stay readable here. Turn it back on at{' '}
            <Link to="/settings" className="text-accent2 hover:underline">
              /settings
            </Link>{' '}
            to scan the protocols you select, and use <span className="mono">Scan now</span> below to
            run the stage again for this analysis.
          </p>
          <div className="flex items-center gap-2">{rescan}</div>
        </div>
      </section>
    )
  }

  if (loading && scan === null) {
    return <LoadingState label="Reading the credential scanner's state…" rows={2} />
  }

  const noProtocols = enabled === true && protocols.length === 0

  return (
    <Panel
      title="Scan state"
      subtitle="the credential stage's own settings, and what its last run on this analysis did"
    >
      {/* The house label/value grid, so this reads like every other detail block in the
          application. A figure the block does not carry is DetailItem's own em dash, with
          the reason in its tooltip — never a zero and never an invented default. */}
      <DetailGrid columns={3}>
        <DetailItem
          label="Discovery"
          mono={false}
          value={scan === null ? null : enabled === true ? 'enabled' : 'disabled'}
          tone={enabled === true ? 'ok' : 'warn'}
          unavailableReason="Neither read endpoint returned a scan block, so this page cannot say whether the stage ran."
          title={
            enabled === true
              ? 'credential_scan_enabled is on: the stage runs for analyses started from now on, over the protocols below.'
              : 'credential_scan_enabled is off: the stage writes no rows. What an earlier run found is not deleted.'
          }
        />
        <DetailItem
          label="Protocols inspected"
          value={
            enabled === null ? null : protocols.length === 0 ? 'none selected' : protocolList(protocols)
          }
          tone={noProtocols ? 'warn' : 'default'}
          unavailableReason="The scan block did not report which protocols are selected."
          title={
            noProtocols
              ? 'An empty credential_protocols list means none: with no protocol selected the scanner has no location to read.'
              : 'credential_protocols — the locations the scanner reads. Set at /settings.'
          }
        />
        <DetailItem
          label="Last scan"
          value={
            stageRan === false
              ? 'never run for this analysis'
              : scannedAt === null
                ? 'no time recorded'
                : formatTimestamp(scannedAt)
          }
          tone={stageRan === false ? 'warn' : 'default'}
          unavailableReason="Neither the scan block's marker nor the analysis's rows carry a time."
          title={
            stageRan === false
              ? 'The stage has never run for this analysis, which is a different statement from running and finding nothing.'
              : 'When the stage last wrote rows for this analysis.'
          }
        />
        {typeof scan?.findings === 'number' ? (
          <DetailItem
            label="Last run wrote"
            value={`${formatNumber(scan.findings)} row(s)`}
            title={
              scan.protocols_scanned !== undefined && scan.protocols_scanned.length > 0
                ? `The last run read ${protocolList(scan.protocols_scanned)}.`
                : "What the last run wrote, as the stage's own marker recorded it."
            }
          />
        ) : null}
        {typeof scan?.rows === 'number' ? (
          <DetailItem
            label="Rows held"
            value={formatNumber(scan.rows)}
            title="Rows the credentials table holds for this analysis now — read again on every request, so it can differ from what the last run wrote."
          />
        ) : null}
      </DetailGrid>

      {scan === null ? (
        <SectionNote tone="warn" className="mt-2">
          Neither the list nor the summary answered with a <span className="mono">scan</span> block,
          so this page cannot tell whether credential discovery ran for this analysis. The table
          below is what the endpoint returned, and an empty one is reported as empty rather than as a
          clean capture — the scanner&apos;s state is simply unknown here.
        </SectionNote>
      ) : null}

      {stageRan === false && enabled === true && protocols.length > 0 ? (
        <SectionNote tone="warn" className="mt-2">
          The stage has never run for this analysis: the rows below, if any, predate it or come from
          a different build. That is a statement about this analysis, not about the capture — use{' '}
          <span className="mono">Scan now</span> to read the protocols selected above.
        </SectionNote>
      ) : null}

      {noProtocols ? (
        <SectionNote tone="warn" className="mt-2">
          Discovery is enabled but no protocol is selected, so the scanner has no location to read:
          an empty table below is the expected result of that setting, not evidence about this
          capture. Choose the protocols to inspect at{' '}
          <Link to="/settings" className="text-accent2 hover:underline">
            /settings
          </Link>
          .
        </SectionNote>
      ) : null}
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* The value cell, and the reveal action                               */
/* ------------------------------------------------------------------ */

interface ValueCellProps {
  analysisId: string
  row: CredentialFinding
  /**
   * Start with the value already revealed. The page always leaves this at its default —
   * a value is revealed by an action, never by rendering — and only the scratch detail
   * harness sets it, to render the revealed branch without a browser.
   */
  initiallyRevealed?: boolean
}

/**
 * One row's value: the redacted preview, and a per-row reveal (§5).
 *
 * The list never asks for `reveal=1`, so no full value is in the table's own response. A
 * reveal issues **its own request for this row only** — narrowed to everything the row
 * already fixes (kind, protocol, confidence and stream), because the endpoint offers no
 * per-row parameter — and renders the item whose `id` matches. The result is cached, so
 * hiding and showing one row again costs nothing.
 */
function CredentialValueCell({ analysisId, row, initiallyRevealed = false }: ValueCellProps) {
  const [revealed, setRevealed] = useState(initiallyRevealed)

  const reveal = useQuery({
    queryKey: [
      'credential-value',
      analysisId,
      row.id,
      row.kind,
      row.protocol,
      row.confidence,
      row.stream_id,
    ],
    queryFn: () =>
      credentialsApi.list(analysisId, {
        kind: row.kind,
        protocol: row.protocol,
        confidence: row.confidence,
        stream_id: row.stream_id ?? undefined,
        reveal: 1,
        page: 1,
        page_size: REVEAL_PAGE_SIZE,
      }),
    enabled: revealed,
    staleTime: Infinity,
    retry: false,
  })

  const item = reveal.data?.items.find((candidate) => candidate.id === row.id) ?? null
  const value = typeof item?.value === 'string' && item.value !== '' ? item.value : null

  return (
    <div className="flex flex-col gap-1">
      <span
        className={clsx('cred-value', value === null && 'cred-value-preview')}
        data-credential-value={value === null ? 'redacted' : 'revealed'}
        title={
          value === null
            ? `${formatNumber(row.value_length)} characters, redacted — only the first and last few are shown. Revealing fetches the value as it crossed the wire.`
            : 'The value as it crossed the wire. It is captured content: exact, and not proof that it is current or that it works.'
        }
      >
        {value ?? row.value_preview}
      </span>
      <span className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          className="btn px-1.5 py-0.5"
          aria-expanded={revealed}
          data-credential-reveal={row.id}
          title={
            revealed
              ? 'Hide this value again; the preview is what the list response carries.'
              : `Fetch this row's full value from the wire (GET /credentials?reveal=1). The rest of the table stays redacted.`
          }
          onClick={() => setRevealed((current) => !current)}
        >
          {revealed ? <EyeOff size={11} aria-hidden /> : <Eye size={11} aria-hidden />}
          {revealed ? 'Hide' : 'Reveal'}
        </button>
        {reveal.isFetching ? <Loader2 size={11} className="animate-spin text-faint" aria-hidden /> : null}
        <span className="text-2xs text-faint">{formatNumber(row.value_length)} ch</span>
        {/* The list shows one row per distinct value, so a value the capture carried
            more than once says so here rather than appearing once and looking unique
            in a way it is not. */}
        {typeof row.occurrences === 'number' && row.occurrences > 1 ? (
          <span
            className="chip border-border2 bg-surface2 text-muted"
            title={`This value appeared ${formatNumber(row.occurrences)} times in this capture across ${
              row.stream_ids && row.stream_ids.length > 0
                ? `${formatNumber(row.stream_ids.length)} stream(s): ${row.stream_ids.join(', ')}`
                : 'the sessions beside it'
            }. It is one credential seen ${formatNumber(row.occurrences)} times, so one row stands for all of them.`}
          >
            ×{formatNumber(row.occurrences)}
          </span>
        ) : null}
        {row.value_truncated ? (
          <span
            className="chip border-warn/40 bg-warn/10 text-warn"
            title={`The stored value was longer than MAX_VALUE_CHARS = ${formatNumber(VALUE_CAP_CHARS)}, so only the first ${formatNumber(VALUE_CAP_CHARS)} characters were kept and the rest is out of reach (docs/CREDENTIALS.md §3.4, §9).`}
          >
            truncated
          </span>
        ) : null}
      </span>
      {revealed && reveal.error ? (
        <span className="text-2xs text-warn">
          {`The value could not be read: ${toApiError(reveal.error).message} The preview above is all this page has for this row.`}
        </span>
      ) : null}
      {revealed && !reveal.isFetching && reveal.data && value === null ? (
        <span className="text-2xs text-warn">
          {`The endpoint answered without a value for row ${formatNumber(row.id)}${
            reveal.data.total > reveal.data.items.length
              ? `, and the ${formatNumber(reveal.data.items.length)} rows it returned do not include it`
              : ''
          }. Nothing is substituted for it.`}
        </span>
      ) : null}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

/**
 * The value cell is exported for the scratch harness under `.tmp/ui-credentials/`, which
 * renders it directly because the revealed branch is reached by a press and the harness
 * has no browser to press it in. Nothing in the application imports it from here.
 */
export { CredentialValueCell }

function CredentialsContent() {
  const { analysisId } = useAnalysis()
  const filters = useUrlFilters(URL_KEYS, 100)
  const queryClient = useQueryClient()
  const id = analysisId as string

  const kind = filters.get('kind')
  const protocol = filters.get('protocol')
  const confidence = filters.get('confidence')
  const streamId = filters.getNumber('stream', 0)
  const sortRaw = filters.get('sort')
  const sort = SORT_COLUMNS.some((column) => column.value === sortRaw) ? sortRaw : 'confidence'
  /* The endpoint's own default direction is not fixed by §8.1, so the page always sends
     one: newest-scoring-first until the reader asks otherwise. */
  const order = filters.get('order') === 'asc' ? 'asc' : 'desc'
  const page = filters.getNumber('page', 1)
  const pageSize = filters.getNumber('page_size', 100)

  const params = useMemo(
    () => ({
      kind: kind === '' ? undefined : kind,
      protocol: protocol === '' ? undefined : protocol,
      confidence: confidence === '' ? undefined : confidence,
      stream_id: streamId > 0 ? streamId : undefined,
      sort,
      order,
      page,
      page_size: pageSize,
    }),
    [kind, protocol, confidence, streamId, sort, order, page, pageSize],
  )

  const list = useQuery({
    queryKey: ['credentials', analysisId, params],
    queryFn: () => credentialsApi.list(id, params),
    enabled: Boolean(analysisId),
    placeholderData: keepPreviousData,
  })

  const summary = useQuery({
    queryKey: ['credentials-summary', analysisId],
    queryFn: () => credentialsApi.summary(id),
    enabled: Boolean(analysisId),
  })

  const rescan = useMutation({
    mutationFn: () => credentialsApi.scan(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['credentials', analysisId] })
      void queryClient.invalidateQueries({ queryKey: ['credentials-summary', analysisId] })
    },
  })

  const setSort = useCallback(
    (nextSort: string, nextOrder: string) =>
      filters.patch({ sort: nextSort, order: nextOrder === 'asc' ? 'asc' : 'desc' }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [filters],
  )

  const rows = list.data?.items ?? []

  /* §7's state is reported by both read endpoints, so whichever answered carries it. */
  const scan = summary.data?.scan ?? list.data?.scan ?? null

  const summaryCounts = summary.data?.counts
  const byKind = summary.data?.by_kind ?? summaryCounts?.by_kind ?? {}
  const byConfidence = summary.data?.by_confidence ?? summaryCounts?.by_confidence ?? {}
  const byProtocol = summary.data?.by_protocol ?? summaryCounts?.by_protocol ?? {}

  /**
   * The summary's own total, or the sum of its per-kind counts.
   *
   * A kind partitions the findings — every row has exactly one — so the sum is the same
   * figure the endpoint would have stated, not an estimate. With neither available the
   * tile reads an em dash rather than borrowing the table's filtered total, which is a
   * different number whenever a filter is on.
   */
  const kindValues = Object.values(byKind).filter((value) => typeof value === 'number')
  const summaryTotal =
    summary.data?.total ??
    summaryCounts?.total ??
    (kindValues.length > 0 ? kindValues.reduce((sum, value) => sum + value, 0) : null)

  /* The endpoint serves the streams as one entry per distinct (protocol, stream) pair with
     a scalar beside them; a backend that serves only one of the two still gets a figure. */
  const streamGroups = Array.isArray(summary.data?.streams) ? summary.data.streams : null
  const summaryStreams =
    typeof summary.data?.stream_count === 'number'
      ? summary.data.stream_count
      : streamGroups !== null
        ? streamGroups.length
        : typeof summary.data?.streams === 'number'
          ? summary.data.streams
          : null
  const busiestStreams = (streamGroups ?? [])
    .slice(0, 3)
    .map((group) => `${group.protocol} #${String(group.stream_id ?? EMPTY)} (${formatNumber(group.findings)})`)
    .join(', ')
  const streamHint = `summary.stream_count — one per distinct (protocol, stream) pair the findings were recorded in${
    busiestStreams === '' ? '' : `. Busiest: ${busiestStreams}`
  }`

  const limits = summary.data?.limits ?? []

  const scanEnabled = scan === null ? null : scan.enabled === true
  const scannedProtocols = scan?.protocols ?? []

  /** The kinds the summary actually counted, so the filter offers real values only. */
  const kindOptions = useMemo(() => {
    const present = Object.keys(byKind)
    const ordered = present.length === 0 ? KIND_ORDER : KIND_ORDER.filter((key) => present.includes(key))
    const extra = present.filter((key) => !KIND_ORDER.includes(key))
    return [...ordered, ...extra].map((key) => ({ value: key, label: KIND_LABELS[key] ?? key }))
  }, [byKind])

  const rescanButton = (
    <button
      type="button"
      className="btn"
      disabled={rescan.isPending || scanEnabled === false || analysisId === null}
      title={
        scanEnabled === false
          ? 'Credential discovery is switched off in Settings, so the backend refuses this with 409 credential_scan_disabled. Switch it on at /settings first.'
          : 'Re-run the credential stage for this capture (POST /credentials/scan). It re-reads the rows the other analysers stored and rewrites only the credentials table.'
      }
      onClick={() => rescan.mutate()}
    >
      {rescan.isPending ? (
        <Loader2 size={13} className="animate-spin" aria-hidden />
      ) : (
        <RefreshCw size={13} aria-hidden />
      )}
      {rescan.isPending ? 'Scanning…' : 'Scan now'}
    </button>
  )

  const emptyState = () => {
    if (filters.any) {
      return (
        <EmptyState
          icon={ShieldQuestion}
          title="No credential matches these filters"
          description="The scanner ran; these filters excluded everything it recorded. Clearing them shows the whole table."
          action={<ResetFiltersButton onClick={filters.clear} />}
        />
      )
    }
    if (scanEnabled === false) {
      return (
        <EmptyState
          icon={TriangleAlert}
          title="Nothing was looked for: the scan is switched off"
          description={
            <>
              Credential discovery is disabled, so the stage wrote no rows for this analysis. This
              table is empty because nothing was read, not because the capture is clean. Enable it at{' '}
              <Link to="/settings" className="text-accent2 hover:underline">
                /settings
              </Link>{' '}
              and scan again.
            </>
          }
        />
      )
    }
    if (scanEnabled === true && scannedProtocols.length === 0) {
      return (
        <EmptyState
          icon={TriangleAlert}
          title="No protocol is selected, so no location was read"
          description={
            <>
              Discovery is on, but the protocol selection is empty, which §7 reads as “none”. Nothing
              was inspected. Choose HTTP, FTP, SMTP, POP3 or IMAP at{' '}
              <Link to="/settings" className="text-accent2 hover:underline">
                /settings
              </Link>{' '}
              and scan again.
            </>
          }
        />
      )
    }
    /* The stage has never run for this analysis: an analysis indexed before this feature
       existed, or one whose stage was skipped. A different statement from "ran, found
       nothing", and the one a reader would otherwise mistake for a clean capture. */
    if (scanEnabled === true && scan?.stage_ran === false) {
      return (
        <EmptyState
          icon={SearchX}
          title="The credential scan has never run for this analysis"
          description={
            <>
              Nothing has been read yet, so this table is empty because no scan has written to it —
              not because the capture carries no credentials.
              {scannedProtocols.length > 0
                ? ` A run now would read ${protocolList(scannedProtocols)}.`
                : ' No protocol is selected either, so a run would have nothing to read.'}{' '}
              The protocols to read are set at{' '}
              <Link to="/settings" className="text-accent2 hover:underline">
                /settings
              </Link>
              , and <span className="mono">Scan now</span> runs the stage over the rows this analysis
              already holds.
            </>
          }
        />
      )
    }
    return (
      <EmptyState
        icon={KeyRound}
        title="No visible credential was found in the locations the scanner reads"
        description={
          <>
            The scanner reads HTTP request headers (Authorization, Cookie and API-key fields), URL
            queries and form or JSON bodies, and the FTP, SMTP, POP3 and IMAP authentication
            commands
            {scanEnabled === true && scannedProtocols.length > 0
              ? ` for ${protocolList(scannedProtocols)}, then only in the protocols selected`
              : ''}
            . That is a statement about those locations and nothing else: nothing encrypted is
            examined at all (TLS, SSH, SMB signing, STARTTLS and anything on 443, 465, 993, 995 or
            22 — this build never decrypts), and bodies are read from the stored previews, so
            anything the earlier analyser truncated is out of reach here. A capture can carry
            credentials this page cannot see.
          </>
        }
      />
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <SummaryTiles
        total={summaryTotal}
        streams={summaryStreams}
        streamHint={streamHint}
        byKind={byKind}
        byConfidence={byConfidence}
        byProtocol={byProtocol}
        note={summary.data?.note ?? null}
        confidence={confidence}
        onConfidence={(value) => filters.patch({ confidence: value })}
        protocol={protocol}
        onProtocol={(value) => filters.patch({ protocol: value })}
      />

      <ScanStatePanel
        scan={scan}
        loading={summary.isLoading && list.isLoading}
        rescan={rescanButton}
      />

      <ScopeNote
        title="What this page reads, and what it cannot"
        collapsible
        defaultOpen={false}
        items={[
          {
            can: true,
            text: (
              <>
                Cleartext credentials in HTTP (Authorization, Cookie, URL query, form and JSON
                bodies), FTP <span className="mono">USER</span>/
                <span className="mono">PASS</span>, SMTP, POP3 and IMAP authentication commands, and
                the Base64-decoded fields a protocol says are Base64.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>Anything encrypted.</strong> TLS, HTTPS, SSH, SMB signing,{' '}
                <span className="mono">AUTH TLS</span>/STARTTLS/STLS sessions, and anything on ports
                443, 465, 993, 995 or 22. This build never decrypts, so a credential inside those
                sessions is unreachable — which is not the same as absent.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>Anything the earlier stage truncated.</strong> Bodies are read from the
                stored previews (<span className="mono">MAX_BODY_CHARS</span> ={' '}
                {formatNumber(BODY_CAP_CHARS)} characters) and commands from the stored command
                lists, so a credential the analyser did not record cannot be found here. A value
                longer than <span className="mono">MAX_VALUE_CHARS</span> ={' '}
                {formatNumber(VALUE_CAP_CHARS)} is stored truncated, and the row says so.
              </>
            ),
          },
          {
            can: true,
            text: (
              <>
                <strong>Base64 is encoding, not encryption</strong> — which is exactly why{' '}
                <span className="mono">Basic</span> and <span className="mono">AUTH LOGIN</span> are
                readable here. It is decoded only where a protocol says the field is Base64: a
                Base64-looking string with no context is reported as nothing.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>A shape is not proof the credential works.</strong> An{' '}
                <span className="mono">AKIA…</span>-shaped string is reported as an AWS access-key
                identifier; the matching secret is not in it, and the identifier alone does not open
                anything. Patterns only fire on values a field name already selected, so a secret
                pasted into an unlabelled body is scored <span className="mono">low</span> — or not
                reported at all.
              </>
            ),
          },
          {
            can: false,
            text: (
              <>
                <strong>A finding is a lead, not a verdict.</strong> A value in a field called{' '}
                <span className="mono">password</span> is a credential the capture carried; it is not
                proof that it worked, that it is current, or that it is not a test value. Treat a
                revealed value as sensitive captured content.
              </>
            ),
          },
        ]}
        caveat={
          <>
            The scan is switchable (§7) and the page reports the switch above the table, so an empty
            list is never presented as a clean capture. At most{' '}
            {formatNumber(FINDINGS_CAP)} findings are stored per analysis, highest confidence first,
            so a capture with more than that is stored partially as well as read partially.
          </>
        }
      />

      <Panel
        title="Credential findings"
        subtitle={
          list.data
            ? `${formatNumber(list.data.total)} matching row${list.data.total === 1 ? '' : 's'}${
                filters.any ? ' (filters active)' : ''
              }${list.data.reveal ? ' — this response carried full values' : ' — values redacted'}`
            : 'loading…'
        }
        flush
        actions={rescanButton}
      >
        <FilterStrip
          actions={
            <>
              <SortSelect columns={SORT_COLUMNS} sort={sort} order={order} onChange={setSort} />
              <ResetFiltersButton onClick={filters.clear} disabled={!filters.any} />
            </>
          }
        >
          <SelectFilter
            label="kind"
            value={kind}
            anyLabel="all kinds"
            options={kindOptions}
            onChange={(value) => filters.patch({ kind: value })}
            width="w-36"
            title="The kind the scanner recorded: what a protocol-confirmed location said the value was, or the shape a pattern recognised in it (docs/CREDENTIALS.md §3, §6)."
          />
          <SelectFilter
            label="protocol"
            value={protocol}
            anyLabel="all"
            options={SCAN_PROTOCOLS.map((name) => ({ value: name, label: PROTOCOL_LABELS[name] }))}
            onChange={(value) => filters.patch({ protocol: value })}
            width="w-24"
          />
          <SelectFilter
            label="confidence"
            value={confidence}
            anyLabel="any"
            options={CONFIDENCE_ORDER.map((level) => ({
              value: level,
              label: level,
              title: CONFIDENCE_RULES[level],
            }))}
            onChange={(value) => filters.patch({ confidence: value })}
            width="w-28"
          />
          <TextFilter
            label="stream"
            value={streamId > 0 ? String(streamId) : ''}
            placeholder="any"
            width="w-24"
            onChange={(value) => filters.patch({ stream: value.trim() === '' ? null : value.trim() })}
            title="Exact stream id (stream_id on the wire). Only rows the conversation reassembly could tie to a stream carry one."
          />
        </FilterStrip>

        {rescan.data ? (
          <div className="flex items-start gap-2 border-b border-border px-3 py-2 text-2xs text-accent2">
            <Loader2 size={13} className="mt-0.5 shrink-0" aria-hidden />
            <span className="flex-1">
              {`Credential scan started as job ${rescan.data.job_id} (${rescan.data.status}). The stage re-reads the stored rows in the background and rewrites only the credentials table; the list here refreshes when it finishes.`}
            </span>
          </div>
        ) : null}
        {rescan.error ? (
          <ErrorState
            error={rescan.error}
            variant="plain"
            title="Could not start the credential scan"
            className="py-3"
          />
        ) : null}

        {list.isLoading && !list.data ? (
          <LoadingState label="Reading the credential findings…" rows={6} />
        ) : list.error ? (
          <ErrorState
            error={list.error}
            title="Could not load the credential findings"
            onRetry={() => void list.refetch()}
          />
        ) : rows.length === 0 ? (
          emptyState()
        ) : (
          <div className="overflow-x-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th>kind</th>
                  <th>value</th>
                  <th>protocol</th>
                  <th>confidence</th>
                  <th>location / field</th>
                  <th>stream</th>
                  <th>client → server</th>
                  <th>packet</th>
                  <th>evidence</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  /* The conversation's own key form (`transport:stream_id`) comes from the
                     module that owns it, and the destination is the application's existing
                     conversation deep link — the same one the Findings page's Follow
                     conversation button and the Dashboard's destination panel use, so the
                     three cannot drift apart. */
                  const streamKey =
                    row.transport === null || row.stream_id === null
                      ? null
                      : conversationUrlKey({ transport: row.transport, stream_id: row.stream_id })
                  const streamPage =
                    streamKey === null
                      ? null
                      : `/conversations?stream=${encodeURIComponent(streamKey)}&tab=timeline`
                  const packetPage = row.packet_first === null ? null : `/packets?sel=${String(row.packet_first)}`
                  const protocolPage = PROTOCOL_PAGES[row.protocol] ?? null
                  const endpoints =
                    row.direction === 'server_to_client'
                      ? 'the server sent this value'
                      : row.direction === 'client_to_server'
                        ? 'the client sent this value'
                        : 'the direction was not recorded'
                  return (
                    <tr key={row.id} data-credential-id={row.id}>
                      <td>
                        <span
                          className="chip border-border2 bg-surface2 text-text"
                          title={`${KIND_LABELS[row.kind] ?? row.kind} · derived by ${row.method}${
                            typeof row.created_at === 'number'
                              ? ` · written ${formatTimestamp(row.created_at)} — the time of the scan, not of the traffic`
                              : ''
                          }${row.note ? ` — ${row.note}` : ''}`}
                        >
                          {KIND_LABELS[row.kind] ?? row.kind}
                        </span>
                      </td>
                      <td className="whitespace-normal align-top">
                        <CredentialValueCell analysisId={id} row={row} />
                      </td>
                      <td>
                        {protocolPage ? (
                          <Link
                            to={protocolPage.to}
                            className="chip border-border2 bg-surface2 text-accent2"
                            title={`Open the ${protocolPage.label} page for this capture — this row was read from a ${PROTOCOL_LABELS[row.protocol] ?? row.protocol} location.`}
                          >
                            {PROTOCOL_LABELS[row.protocol] ?? row.protocol}
                          </Link>
                        ) : (
                          <span className="text-faint">{row.protocol}</span>
                        )}
                      </td>
                      <td>
                        <span
                          className={clsx('chip', CONFIDENCE_TONES[row.confidence] ?? 'border-border2 bg-surface2 text-muted')}
                          title={`${CONFIDENCE_RULES[row.confidence] ?? 'A level this page does not have a rule quoted for.'}${
                            row.note ? ` — ${row.note}` : ''
                          }`}
                        >
                          {row.confidence}
                        </span>
                      </td>
                      <td>
                        <MonoCell
                          maxWidth={220}
                          title={`${row.location}${
                            row.source_field ? ` · field ${row.source_field}` : ' · no field name selected it'
                          } · ${row.method}${row.note ? ` — ${row.note}` : ''}`}
                        >
                          {row.location}
                        </MonoCell>
                        <span className="block truncate text-2xs text-faint" style={{ maxWidth: 220 }}>
                          {row.source_field === null ? '—' : `field: ${row.source_field}`}
                        </span>
                      </td>
                      <td>
                        {streamPage === null ? (
                          <span
                            className="text-faint"
                            title="No transport and stream id were recorded for this row, so there is no conversation to open — the key below is only a row number, not a stream. The endpoints beside it are still the ones the analyser stored."
                          >
                            {EMPTY}
                          </span>
                        ) : (
                          <Link
                            to={streamPage}
                            className="text-accent2 hover:underline"
                            title={`Open ${row.transport?.toUpperCase() ?? ''} stream ${String(
                              row.stream_id,
                            )} on the Conversations page's Timeline tab. ${endpoints}.${
                              row.stream_ids && row.stream_ids.length > 1
                                ? ` This value was also seen in stream(s) ${row.stream_ids
                                    .filter((idValue) => idValue !== row.stream_id)
                                    .join(', ')} — the first one is linked.`
                                : ''
                            }`}
                          >
                            {`${row.transport ?? 'tcp'} #${String(row.stream_id)}`}
                          </Link>
                        )}
                      </td>
                      <td>
                        <span className="flex items-center gap-1">
                          <span
                            className="flex items-center gap-1"
                            data-ip={row.client_ip ?? undefined}
                            data-ip-transport={row.transport ?? undefined}
                            data-ip-stream={row.stream_id ?? undefined}
                            data-ip-port={row.client_port ?? undefined}
                          >
                            {row.client_ip === null ? null : <AddressFlag ip={row.client_ip} />}
                            <MonoCell maxWidth={170}>{endpoint(row.client_ip, row.client_port)}</MonoCell>
                          </span>
                          <ArrowRight size={11} className="shrink-0 text-faint" aria-hidden />
                          <span
                            className="flex items-center gap-1"
                            data-ip={row.server_ip ?? undefined}
                            data-ip-transport={row.transport ?? undefined}
                            data-ip-stream={row.stream_id ?? undefined}
                            data-ip-port={row.server_port ?? undefined}
                          >
                            {row.server_ip === null ? null : <AddressFlag ip={row.server_ip} />}
                            <MonoCell maxWidth={170}>{endpoint(row.server_ip, row.server_port)}</MonoCell>
                          </span>
                        </span>
                      </td>
                      <td>
                        {packetPage === null ? (
                          <span className="text-faint" title="The source row recorded no frame number for this credential.">
                            {EMPTY}
                          </span>
                        ) : (
                          <Link
                            to={packetPage}
                            className="text-accent2 hover:underline"
                            title={`Open frame ${formatNumber(row.packet_first)} in the packet browser${
                              row.packet_last !== null && row.packet_last !== row.packet_first
                                ? ` (the source row also recorded frame ${formatNumber(row.packet_last)})`
                                : ''
                            }.`}
                          >
                            {`#${formatNumber(row.packet_first)}`}
                          </Link>
                        )}
                      </td>
                      <td className="whitespace-normal align-top">
                        {row.evidence === null || row.evidence === '' ? (
                          <span className="text-faint" title="No evidence line was recorded for this row.">
                            {EMPTY}
                          </span>
                        ) : (
                          <MonoCell
                            maxWidth={320}
                            title={`${row.evidence}${row.note ? `\n${row.note}` : ''}`}
                            className="text-2xs"
                          >
                            {row.evidence}
                          </MonoCell>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {list.data && rows.length > 0 ? (
          <Pagination
            page={list.data.page}
            pageSize={list.data.page_size}
            total={list.data.total}
            disabled={list.isFetching}
            onPageChange={(next) => filters.patch({ page: next }, { resetPage: false })}
            onPageSizeChange={(next) => filters.patch({ page_size: next })}
          />
        ) : null}

        {rows.length > 0 ? (
          <SectionNote className="m-3">
            {`Every number above is read from this analysis' credentials table — the capture is not dissected again to draw this page. Values are redacted to a preview; `}
            <span className="mono">Reveal</span>
            {` fetches one row's value as it crossed the wire and nothing else, and the confidence shown is the one the scanner stored, never a re-scored guess. A row is a lead: the value's shape or its field name is not proof that it works, and nothing encrypted was examined.`}
          </SectionNote>
        ) : null}

        {/* The scanner states, in its own words, what it had to interpret in the contract.
            Nothing on this page paraphrases them, so a reader comparing the two sees the
            build's reading rather than this component's. */}
        {limits.length > 0 ? (
          <SectionNote className="m-3">
            {`The scanner states its own reading of the contract in ${formatNumber(limits.length)} note(s) — `}
            <span className="mono">GET /credentials/summary → limits</span>
            {`: ${limits.join(' ')}`}
          </SectionNote>
        ) : null}
      </Panel>
    </div>
  )
}

/** Credentials: the cleartext credentials this capture carried (docs/CREDENTIALS.md). */
export function CredentialsPage() {
  return (
    <Page section={SECTIONS.credentials} headerImage={pageBackground}>
      <AnalysisGuard
        emptyDescription="Upload a PCAP/PCAPNG capture or select an existing analysis in the top bar to read its cleartext credentials. The scanner reads only tables that already exist, so it needs a finished analysis."
      >
        <CredentialsContent />
      </AnalysisGuard>
    </Page>
  )
}

export default CredentialsPage
