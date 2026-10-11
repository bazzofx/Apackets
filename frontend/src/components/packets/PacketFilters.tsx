import { type ReactNode } from 'react'
import clsx from 'clsx'
import { Braces, SlidersHorizontal, X } from 'lucide-react'
import {
  FilterField,
  FilterStrip,
  ResetFiltersButton,
  TextFilter,
} from '@/components/protocols/ProtocolFilters'
import type { PacketListParams, Transport } from '@/types'

/**
 * Packet-filter state, its URL serialisation, the query parameters it turns into
 * and the Wireshark display filter the neighbour navigation steps through.
 *
 * Two mutually exclusive modes (contract §5, and the UI requirement that they
 * must never be conflated):
 *
 * * **basic** — structured fields, sent as the list endpoint's typed query
 *   parameters (`ip`, `port`, `transport`, …). These become indexed SQL
 *   predicates and the backend reports an invalid *display* filter only when
 *   `filter` is used, so a basic-mode view can never be "invalid".
 * * **advanced** — one raw Wireshark display filter sent as `filter`. The list
 *   endpoint answers `422 invalid_filter` with `details.reason` when TShark
 *   rejects it; that is a *syntax* failure, which is a different state from
 *   "valid filter, zero matching packets".
 *
 * Only the active mode is ever sent to the API, so the two can never be
 * silently combined behind the analyst's back.
 */

export type PacketFilterMode = 'basic' | 'advanced'

export interface PacketFilterState {
  mode: PacketFilterMode
  /** Free text over info / protocol / IP columns. */
  search: string
  ip: string
  srcIp: string
  dstIp: string
  port: string
  srcPort: string
  dstPort: string
  protocol: string
  /** `''` | `tcp` | `udp`. */
  transport: string
  /** Substring of TShark's TCP flag string. */
  tcpFlags: string
  minLength: string
  maxLength: string
  /** Epoch seconds (strings so the URL round-trips exactly). */
  startTime: string
  endTime: string
  /** Raw display filter, advanced mode only. */
  displayFilter: string
  /** Set by the Conversations page link; not editable in the filter bar. */
  streamId: string
}

export const EMPTY_PACKET_FILTERS: PacketFilterState = {
  mode: 'basic',
  search: '',
  ip: '',
  srcIp: '',
  dstIp: '',
  port: '',
  srcPort: '',
  dstPort: '',
  protocol: '',
  transport: '',
  tcpFlags: '',
  minLength: '',
  maxLength: '',
  startTime: '',
  endTime: '',
  displayFilter: '',
  streamId: '',
}

/** Every query-string key this page owns. */
export const PACKET_FILTER_URL_KEYS = [
  'mode',
  'search',
  'ip',
  'src_ip',
  'dst_ip',
  'port',
  'src_port',
  'dst_port',
  'protocol',
  'transport',
  'tcp_flags',
  'min_length',
  'max_length',
  'start_time',
  'end_time',
  'filter',
  'stream_id',
  'sort',
  'order',
  'page',
  'page_size',
  'sel',
]

/** Sort columns the packets endpoint allows (contract §5). */
export const PACKET_SORT_COLUMNS: { value: string; label: string }[] = [
  { value: 'number', label: 'packet number' },
  { value: 'time_epoch', label: 'time' },
  { value: 'src_ip', label: 'source IP' },
  { value: 'dst_ip', label: 'destination IP' },
  { value: 'src_port', label: 'source port' },
  { value: 'dst_port', label: 'destination port' },
  { value: 'protocol', label: 'protocol' },
  { value: 'frame_len', label: 'length' },
]

/** The display protocols a packet list most often shows, offered as hints only. */
export const PROTOCOL_HINTS = [
  'TCP',
  'UDP',
  'HTTP',
  'DNS',
  'TLS',
  'ICMP',
  'ARP',
  'SMB2',
  'SSH',
  'DHCP',
]

/**
 * TShark renders `tcp.flags.str` as a 12-character string of the letters
 * `F S R P A U E C` (and `·` elsewhere). The backend matches `tcp_flags` as a
 * substring of exactly that string, so these are the useful inputs — `SYN` is
 * *not* one of them, which surprises analysts coming from Wireshark's filter
 * syntax.
 */
export const TCP_FLAG_HINTS = ['S', 'SA', 'A', 'PA', 'FA', 'RA', 'R', 'AS', 'AP']

/* ------------------------------------------------------------------ */
/* URL <-> state                                                       */
/* ------------------------------------------------------------------ */

/** Read the filter state out of the URL. `get` returns `''` for absent keys. */
export function readPacketFilters(get: (key: string) => string): PacketFilterState {
  return {
    mode: get('mode') === 'advanced' ? 'advanced' : 'basic',
    search: get('search'),
    ip: get('ip'),
    srcIp: get('src_ip'),
    dstIp: get('dst_ip'),
    port: get('port'),
    srcPort: get('src_port'),
    dstPort: get('dst_port'),
    protocol: get('protocol'),
    transport: get('transport'),
    tcpFlags: get('tcp_flags'),
    minLength: get('min_length'),
    maxLength: get('max_length'),
    startTime: get('start_time'),
    endTime: get('end_time'),
    displayFilter: get('filter'),
    streamId: get('stream_id'),
  }
}

/**
 * Turn the state into URL keys. Only non-empty values are emitted so a cleared
 * filter leaves a clean, shareable URL; `mode` is always written because it is
 * the switch that decides which half of the filter is applied.
 */
export function packetFilterUrlPatch(
  state: PacketFilterState,
): Record<string, string | null> {
  const text = (value: string): string | null => (value.trim() === '' ? null : value)
  return {
    mode: state.mode === 'advanced' ? 'advanced' : null,
    search: text(state.search),
    ip: text(state.ip),
    src_ip: text(state.srcIp),
    dst_ip: text(state.dstIp),
    port: text(state.port),
    src_port: text(state.srcPort),
    dst_port: text(state.dstPort),
    protocol: text(state.protocol),
    transport: text(state.transport),
    tcp_flags: text(state.tcpFlags),
    min_length: text(state.minLength),
    max_length: text(state.maxLength),
    start_time: text(state.startTime),
    end_time: text(state.endTime),
    filter: text(state.displayFilter),
    stream_id: text(state.streamId),
  }
}

/** Digits only, so a malformed port/length can never reach the API as `422`. */
export function digitsOnly(value: string, max = 10): string {
  return value.replace(/[^0-9]/g, '').slice(0, max)
}

/** Number of active filters in the *active* mode. */
export function activeFilterCount(state: PacketFilterState): number {
  if (state.mode === 'advanced') return state.displayFilter.trim() === '' ? 0 : 1
  const patch = packetFilterUrlPatch(state)
  return Object.entries(patch).filter(([key, value]) => key !== 'mode' && value !== null).length
}

/* ------------------------------------------------------------------ */
/* API parameters                                                      */
/* ------------------------------------------------------------------ */

/**
 * The list/export parameters for the current filter. Local extension: the
 * packets endpoint accepts `stream_id` (used by the Conversations page) but
 * `PacketListParams` in `src/types/index.ts` does not model it, and that file is
 * owned by another agent.
 */
export type PacketListParamsWithStream = PacketListParams & { stream_id?: number }

function numeric(value: string): string | undefined {
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

function portValue(value: string): number | undefined {
  const trimmed = value.trim()
  if (trimmed === '') return undefined
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}

/** Query parameters for the active filter mode (no paging/sorting). */
export function packetFilterParams(state: PacketFilterState): PacketListParamsWithStream {
  if (state.mode === 'advanced') {
    return { filter: state.displayFilter.trim() || undefined }
  }
  const transport = state.transport.trim()
  const params: PacketListParamsWithStream = {
    search: state.search.trim() || undefined,
    ip: state.ip.trim() || undefined,
    src_ip: state.srcIp.trim() || undefined,
    dst_ip: state.dstIp.trim() || undefined,
    port: portValue(state.port),
    src_port: portValue(state.srcPort),
    dst_port: portValue(state.dstPort),
    protocol: state.protocol.trim() || undefined,
    transport: transport === 'tcp' || transport === 'udp' ? (transport as Transport) : undefined,
    tcp_flags: state.tcpFlags.trim() || undefined,
    min_length: numeric(state.minLength),
    max_length: numeric(state.maxLength),
    start_time: numeric(state.startTime),
    end_time: numeric(state.endTime),
  }
  const streamId = state.streamId.trim()
  if (streamId !== '') {
    const stream = Number(streamId)
    if (Number.isFinite(stream)) params.stream_id = stream
  }
  return params
}

/** True when the current filter would restrict the result set at all. */
export function hasActiveFilter(state: PacketFilterState): boolean {
  const params = packetFilterParams(state)
  return Object.values(params).some((value) => value !== undefined)
}

/* ------------------------------------------------------------------ */
/* Display-filter derivation (neighbour navigation)                    */
/* ------------------------------------------------------------------ */

export interface DerivedNeighborFilter {
  /** Always a syntactically complete display filter. */
  expression: string
  /** False when at least one active field had to be approximated. */
  exact: boolean
  /** Human-readable reasons for every approximation. */
  notes: string[]
}

/**
 * Escape a term so it can sit inside a `"…"` literal in a display filter.
 * TShark's filter lexer accepts `\\`, `\"`, `\n`, `\r`, `\t` and rejects every
 * other escape (verified: `\.` and `\^` are rejected as
 * "is not a valid character escape sequence"), so nothing else is escaped here.
 */
function quoteFilterString(text: string): string {
  return text
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
}

const REGEX_CLASS_ESCAPES: Record<string, string> = {
  '.': '[.]',
  '*': '[*]',
  '+': '[+]',
  '?': '[?]',
  '(': '[(]',
  ')': '[)]',
  '[': '[[]',
  ']': '[]]',
  '{': '[{]',
  '}': '[}]',
  '|': '[|]',
}

/**
 * Escape a term for a PCRE `matches` argument using character classes only —
 * never backslash escapes (see {@link quoteFilterString}). Returns `null` for
 * terms containing `\`, `^` or `$`, which cannot be expressed safely as a
 * literal without a backslash escape; the caller then falls back to `contains`.
 */
function pcreLiteral(term: string): string | null {
  let out = ''
  for (const char of term) {
    if (char === '\\' || char === '^' || char === '$') return null
    const escaped = REGEX_CLASS_ESCAPES[char]
    out += escaped ?? char
  }
  return out
}

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/
const IPV6_RE = /^[0-9a-fA-F:.]*:[0-9a-fA-F:.]+$/

/**
 * Build the display filter the *next match* / *previous match* buttons step
 * through.
 *
 * Every mapping below was verified against the live backend on the generated
 * HTTP capture, by comparing `GET /packets` totals (structured/SQL) with
 * `POST /filter` totals (display filter) for the same input:
 *
 * | field                  | display filter                          | equal |
 * |------------------------|-----------------------------------------|-------|
 * | `ip`                   | `(ip.addr == A)`                        | yes   |
 * | `src_ip` / `dst_ip`    | `(ip.src == A)` / `(ip.dst == A)`       | yes   |
 * | `port`                 | `(tcp.port == P \|\| udp.port == P)`     | yes   |
 * | `src_port`/`dst_port`  | `(tcp.srcport == P \|\| udp.srcport…)`  | yes   |
 * | `protocol`             | `_ws.col.protocol matches "(?i)^X$"`    | yes   |
 * | `transport`            | `tcp` / `udp`                           | yes   |
 * | `tcp_flags`            | `tcp.flags.str contains "X"`            | yes   |
 * | `min_length`/`max_length` | `frame.len >= N` / `<= N`            | yes   |
 * | `start_time`/`end_time`| `frame.time_epoch >= S` / `<= S`        | yes   |
 * | `stream_id`            | `(tcp.stream == N \|\| udp.stream == N)`| yes   |
 * | `search`               | `_ws.col.info`/`_ws.col.protocol` + IP  | see note |
 *
 * `_ws.col.protocol` is the field behind the stored `protocol` column
 * (`_ws.col.Protocol` is *not* a valid field name — TShark rejects it).
 * Case-insensitive equality uses `matches "(?i)^…$"` because the SQL side
 * compares with `UPPER()`; the display filter is otherwise case-sensitive.
 *
 * The one approximation is `search`: the SQL predicate is a `LIKE` over
 * `info`, `protocol`, `src_ip` and `dst_ip`, while a display filter can only
 * match those columns case-insensitively for the two string columns (`matches`)
 * and exactly for the IP columns (`==`), because Wireshark's `matches` does not
 * apply to IP address fields (verified: `ip.src matches …` is rejected). That
 * difference, and case-sensitivity for terms containing `\`, `^` or `$`, is
 * reported through `notes` and surfaced in the UI.
 */
export function buildNeighborFilter(state: PacketFilterState): DerivedNeighborFilter {
  const notes: string[] = []

  if (state.mode === 'advanced') {
    const expression = state.displayFilter.trim()
    if (expression === '') {
      // No filter at all: step through every packet. `frame.number >= 1` is
      // always true for a capture whose frame numbers start at 1 (verified:
      // it matches every frame of the test capture) and is a complete, valid
      // expression, which the neighbours endpoint requires.
      return { expression: 'frame.number >= 1', exact: true, notes }
    }
    return { expression, exact: true, notes }
  }

  const predicates: string[] = []
  const push = (value: string | undefined, build: (text: string) => string) => {
    const trimmed = (value ?? '').trim()
    if (trimmed !== '') predicates.push(build(trimmed))
  }

  push(state.ip, (value) => `(ip.addr == ${quoteFilterString(value)})`)
  push(state.srcIp, (value) => `(ip.src == ${quoteFilterString(value)})`)
  push(state.dstIp, (value) => `(ip.dst == ${quoteFilterString(value)})`)
  push(state.port, (value) => `(tcp.port == ${value} || udp.port == ${value})`)
  push(state.srcPort, (value) => `(tcp.srcport == ${value} || udp.srcport == ${value})`)
  push(state.dstPort, (value) => `(tcp.dstport == ${value} || udp.dstport == ${value})`)
  push(state.protocol, (value) => {
    // The value is escaped as a PCRE literal so a crafted protocol name cannot
    // change the expression; when it cannot be escaped safely the case-sensitive
    // equality operator is used instead.
    const literal = pcreLiteral(value)
    return literal === null
      ? `_ws.col.protocol == "${quoteFilterString(value)}"`
      : `_ws.col.protocol matches "(?i)^${literal}$"`
  })
  push(state.transport, (value) => (value === 'tcp' || value === 'udp' ? value : ''))
  push(state.tcpFlags, (value) => `tcp.flags.str contains "${quoteFilterString(value)}"`)
  push(state.minLength, (value) => `frame.len >= ${value}`)
  push(state.maxLength, (value) => `frame.len <= ${value}`)
  push(state.startTime, (value) => `frame.time_epoch >= ${value}`)
  push(state.endTime, (value) => `frame.time_epoch <= ${value}`)
  push(state.streamId, (value) => `(tcp.stream == ${value} || udp.stream == ${value})`)

  const search = state.search.trim()
  if (search !== '') {
    const literal = pcreLiteral(search)
    const parts: string[] = []
    if (literal !== null) {
      const quoted = quoteFilterString(literal)
      parts.push(`_ws.col.info matches "(?i)${quoted}"`)
      parts.push(`_ws.col.protocol matches "(?i)${quoted}"`)
    } else {
      // Fall back to the case-sensitive substring operator: TShark's lexer
      // rejects the backslash escapes a PCRE literal would need here.
      const quoted = quoteFilterString(search)
      parts.push(`_ws.col.info contains "${quoted}"`)
      parts.push(`_ws.col.protocol contains "${quoted}"`)
      notes.push(
        'the text search is matched case-sensitively by the display filter because it contains a character (\\ ^ or $) that the filter syntax cannot escape in a regular expression',
      )
    }
    if (IPV4_RE.test(search) || IPV6_RE.test(search)) {
      parts.push(`ip.src == ${quoteFilterString(search)}`)
      parts.push(`ip.dst == ${quoteFilterString(search)}`)
      notes.push(
        'the text search also matches packets whose source or destination address equals the search term (an exact match, not a substring)',
      )
    }
    predicates.push(`(${parts.join(' || ')})`)
  }

  if (predicates.length === 0) {
    return { expression: 'frame.number >= 1', exact: true, notes }
  }
  return { expression: predicates.join(' && '), exact: notes.length === 0, notes }
}

/* ------------------------------------------------------------------ */
/* Time inputs                                                         */
/* ------------------------------------------------------------------ */

function pad(value: number, width = 2): string {
  return String(value).padStart(width, '0')
}

/** Epoch seconds (string) -> `YYYY-MM-DDTHH:MM:SS` in local time, or `''`. */
export function epochToLocalInput(value: string): string {
  if (value.trim() === '') return ''
  const numericValue = Number(value)
  if (!Number.isFinite(numericValue)) return ''
  const date = new Date(numericValue * 1000)
  if (Number.isNaN(date.getTime())) return ''
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  )
}

/** `YYYY-MM-DDTHH:MM:SS` (local) -> epoch seconds as a string, or `''`. */
export function localInputToEpoch(value: string): string {
  if (value.trim() === '') return ''
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return ''
  return String(ms / 1000)
}

/** Digits-only numeric input used for ports and frame lengths. */
function NumberFilter({
  label,
  value,
  onChange,
  placeholder,
  title,
  width = 'w-24',
}: {
  label: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  title?: string
  width?: string
}) {
  return (
    <FilterField label={label} width={width} title={title}>
      <input
        className="input py-1"
        value={value}
        inputMode="numeric"
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        onChange={(event) => onChange(digitsOnly(event.target.value))}
      />
    </FilterField>
  )
}

/* ------------------------------------------------------------------ */
/* The filter bar                                                      */
/* ------------------------------------------------------------------ */

export interface PacketFilterBarProps {
  filters: PacketFilterState
  /** Patch the state; filters also reset the page unless told otherwise. */
  onChange: (patch: Partial<PacketFilterState>) => void
  onReset: () => void
  /** Result count of the current request, or null while unknown. */
  total: number | null
  /** Right-aligned controls (navigation, export). */
  actions?: ReactNode
  /** Currently focused packet number, shown in the strip. */
  selectedNumber?: number | null
  disabled?: boolean
}

/**
 * Basic/advanced packet filter strip.
 *
 * The mode is visible at all times and the inactive half is explicitly labelled
 * as ignored, because silently combining a display filter with the structured
 * fields is exactly the confusion this page must avoid.
 */
export function PacketFilterBar({
  filters,
  onChange,
  onReset,
  total,
  actions,
  selectedNumber = null,
  disabled = false,
}: PacketFilterBarProps) {
  const advanced = filters.mode === 'advanced'
  const activeCount = activeFilterCount(filters)
  const streamId = filters.streamId.trim()

  return (
    <div className="flex flex-col divide-y divide-border">
      <FilterStrip
        actions={
          <>
            {total !== null ? (
              <span className="mono text-2xs text-faint">
                {total.toLocaleString('en-US')} rows
              </span>
            ) : null}
            {actions}
            <ResetFiltersButton onClick={onReset} disabled={activeCount === 0 && selectedNumber === null} />
          </>
        }
      >
        <span className="flex items-center gap-1" role="group" aria-label="Filter mode">
          <button
            type="button"
            className={clsx('btn px-2 py-1', !advanced && 'btn-primary')}
            onClick={() => onChange({ mode: 'basic' })}
            title="Filter with the typed fields (indexed SQL predicates)"
            aria-pressed={!advanced}
          >
            <SlidersHorizontal size={12} aria-hidden />
            Basic
          </button>
          <button
            type="button"
            className={clsx('btn px-2 py-1', advanced && 'btn-primary')}
            onClick={() => onChange({ mode: 'advanced' })}
            title="Filter with raw Wireshark display-filter syntax"
            aria-pressed={advanced}
          >
            <Braces size={12} aria-hidden />
            Advanced
          </button>
        </span>

        {advanced ? (
          <span className="text-2xs text-faint">
            the typed basic fields above are ignored while advanced mode is on
          </span>
        ) : (
          <>
            <TextFilter
              label="search"
              value={filters.search}
              onChange={(value) => onChange({ search: value })}
              placeholder="GET /index.html"
              width="w-44"
              title="Substring match over info, protocol, source IP and destination IP"
            />
            <TextFilter
              label="ip"
              value={filters.ip}
              onChange={(value) => onChange({ ip: value })}
              placeholder="10.0.0.10"
              width="w-32"
              title="Either endpoint matches this address exactly"
            />
            <TextFilter
              label="src ip"
              value={filters.srcIp}
              onChange={(value) => onChange({ srcIp: value })}
              placeholder="10.0.0.10"
              width="w-32"
            />
            <TextFilter
              label="dst ip"
              value={filters.dstIp}
              onChange={(value) => onChange({ dstIp: value })}
              placeholder="10.0.0.20"
              width="w-32"
            />
            <NumberFilter
              label="port"
              value={filters.port}
              onChange={(value) => onChange({ port: value })}
              placeholder="80"
              title="Either port equals this value"
            />
            <NumberFilter
              label="src port"
              value={filters.srcPort}
              onChange={(value) => onChange({ srcPort: value })}
              placeholder="51000"
            />
            <NumberFilter
              label="dst port"
              value={filters.dstPort}
              onChange={(value) => onChange({ dstPort: value })}
              placeholder="80"
            />
            <FilterField label="protocol" width="w-28" title="Exact display protocol, e.g. HTTP (case-insensitive)">
              <input
                className="input py-1"
                value={filters.protocol}
                list="apackets-protocol-hints"
                spellCheck={false}
                autoComplete="off"
                placeholder="HTTP"
                onChange={(event) => onChange({ protocol: event.target.value })}
              />
            </FilterField>
            <FilterField label="transport" width="w-24">
              <select
                className="select w-full py-1"
                value={filters.transport}
                onChange={(event) => onChange({ transport: event.target.value })}
              >
                <option value="">any</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </select>
            </FilterField>
            <FilterField
              label="tcp flags"
              width="w-24"
              title="Substring of TShark's flag string (letters F S R P A U E C), e.g. S for SYN, PA for PSH+ACK. The literal word SYN is not part of that string."
            >
              <input
                className="input py-1"
                value={filters.tcpFlags}
                list="apackets-tcp-flag-hints"
                spellCheck={false}
                autoComplete="off"
                placeholder="S"
                onChange={(event) => onChange({ tcpFlags: event.target.value })}
              />
            </FilterField>
            <NumberFilter
              label="min len"
              value={filters.minLength}
              onChange={(value) => onChange({ minLength: value })}
              placeholder="60"
            />
            <NumberFilter
              label="max len"
              value={filters.maxLength}
              onChange={(value) => onChange({ maxLength: value })}
              placeholder="1500"
            />
            <FilterField
              label="from"
              width="w-52"
              title="Frames at or after this time. Stored as epoch seconds so the URL is unambiguous."
            >
              <input
                type="datetime-local"
                step={1}
                className="input py-[3px] [color-scheme:dark]"
                value={epochToLocalInput(filters.startTime)}
                onChange={(event) => onChange({ startTime: localInputToEpoch(event.target.value) })}
              />
            </FilterField>
            <FilterField label="to" width="w-52" title="Frames at or before this time.">
              <input
                type="datetime-local"
                step={1}
                className="input py-[3px] [color-scheme:dark]"
                value={epochToLocalInput(filters.endTime)}
                onChange={(event) => onChange({ endTime: localInputToEpoch(event.target.value) })}
              />
            </FilterField>
          </>
        )}

        {streamId !== '' ? (
          <span
            className="chip border-accent/50 bg-accent/15 text-accent2"
            title="Set by the Conversations page: only frames of this TCP/UDP stream"
          >
            stream {streamId}
            <button
              type="button"
              className="ml-0.5 text-accent2 hover:text-text"
              onClick={() => onChange({ streamId: '' })}
              title="Remove the stream filter"
              aria-label="Remove the stream filter"
            >
              <X size={11} aria-hidden />
            </button>
          </span>
        ) : null}
      </FilterStrip>

      {advanced ? (
        <div className="flex flex-col gap-1.5 px-3 py-2">
          <label className="flex items-start gap-2">
            <span className="mt-1 shrink-0 text-2xs uppercase tracking-wider text-faint">
              display filter
            </span>
            <textarea
              className={clsx('input mono min-h-[3.25rem] flex-1 py-1', disabled && 'opacity-60')}
              value={filters.displayFilter}
              spellCheck={false}
              autoComplete="off"
              placeholder={'ip.addr == 192.168.1.10 && tcp.port == 443'}
              onChange={(event) => onChange({ displayFilter: event.target.value })}
            />
          </label>
          <div className="flex flex-wrap items-center gap-1.5 text-2xs text-faint">
            <span>examples:</span>
            {[
              'ip.addr == 192.168.1.10',
              'tcp.port == 443',
              'dns',
              'http',
              'tls.handshake.type == 1',
              'tcp.flags.syn == 1 && tcp.flags.ack == 0',
            ].map((example) => (
              <button
                key={example}
                type="button"
                className="chip border-border2 bg-surface2 text-muted hover:border-border2 hover:text-text"
                onClick={() => onChange({ displayFilter: example })}
                title="Use this expression"
              >
                {example}
              </button>
            ))}
          </div>
          <span className="text-2xs leading-relaxed text-faint">
            Passed to TShark verbatim. A syntax error is reported by the backend as an invalid
            filter with TShark&apos;s own reason — that is not the same as a valid filter that
            matches nothing.
          </span>
        </div>
      ) : null}

      {/* Shared hint lists, referenced by the protocol and tcp-flags inputs. */}
      <datalist id="apackets-protocol-hints">
        {PROTOCOL_HINTS.map((hint) => (
          <option key={hint} value={hint} />
        ))}
      </datalist>
      <datalist id="apackets-tcp-flag-hints">
        {TCP_FLAG_HINTS.map((hint) => (
          <option key={hint} value={hint} />
        ))}
      </datalist>
    </div>
  )
}
