/**
 * Compact chip primitives and tolerant parsers for the `hosts` table columns.
 *
 * `ports`, `protocols`, `dns_names`, `tls_sni` and `peers` are JSON columns
 * (contract §3). `src/types/index.ts` models them as parsed arrays/objects, but
 * the live backend serialises them as JSON **strings**
 * (`"ports": "[{\"port\":80,...}]"` — verified against
 * `GET /api/analyses/{id}/hosts`). Both spellings are accepted here, so the view
 * is correct today and stays correct if the backend starts parsing them.
 *
 * Nothing in this module ever stringifies an object: a value that is not a
 * primitive is dropped rather than rendered, so `[object Object]` cannot appear.
 */

import clsx from 'clsx'
import type { ReactNode } from 'react'

/* ------------------------------------------------------------------ */
/* tolerant parsing                                                    */
/* ------------------------------------------------------------------ */

/** A primitive rendered as text, or `null` for anything else. */
export function asText(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed === '' ? null : trimmed
  }
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return String(value)
  return null
}

/** Parse a JSON column; already-parsed values pass through unchanged. */
export function parseJsonColumn(raw: unknown): unknown {
  if (typeof raw !== 'string') return raw ?? null
  const text = raw.trim()
  if (text === '') return null
  try {
    return JSON.parse(text) as unknown
  } catch {
    return null
  }
}

export interface PortUsage {
  port: number
  /** `null` when the backend did not report a count. */
  count: number | null
  directions: string[]
}

/** `[{"port":80,"count":3,"direction":"dst"}]` → one entry per port, counts summed. */
export function parsePorts(raw: unknown): PortUsage[] {
  const parsed = parseJsonColumn(raw)
  if (!Array.isArray(parsed)) return []

  const byPort = new Map<number, PortUsage>()
  for (const entry of parsed) {
    let port: number | null = null
    let count: number | null = null
    let direction: string | null = null

    if (typeof entry === 'number' && Number.isFinite(entry)) {
      port = entry
    } else if (entry !== null && typeof entry === 'object') {
      const record = entry as Record<string, unknown>
      const rawPort = record['port']
      const rawCount = record['count']
      port = typeof rawPort === 'number' && Number.isFinite(rawPort) ? rawPort : null
      count = typeof rawCount === 'number' && Number.isFinite(rawCount) ? rawCount : null
      direction = asText(record['direction'])
    }
    if (port === null) continue

    const existing = byPort.get(port) ?? { port, count: null, directions: [] }
    if (count !== null) existing.count = (existing.count ?? 0) + count
    if (direction !== null && !existing.directions.includes(direction)) {
      existing.directions.push(direction)
    }
    byPort.set(port, existing)
  }

  return [...byPort.values()].sort(
    (a, b) => (b.count ?? 0) - (a.count ?? 0) || a.port - b.port,
  )
}

export interface ProtocolUsage {
  name: string
  /** `null` when the backend reported a bare list instead of a count map. */
  count: number | null
}

/** `{"HTTP":12}` (or `["HTTP"]`) → a sorted list of protocol names. */
export function parseProtocols(raw: unknown): ProtocolUsage[] {
  const parsed = parseJsonColumn(raw)
  if (Array.isArray(parsed)) {
    return parsed
      .map((entry) => asText(entry))
      .filter((name): name is string => name !== null)
      .map((name) => ({ name, count: null }))
  }
  if (parsed !== null && typeof parsed === 'object') {
    return Object.entries(parsed as Record<string, unknown>)
      .map(([name, value]) => ({
        name,
        count: typeof value === 'number' && Number.isFinite(value) ? value : null,
      }))
      .filter((entry) => entry.name !== '')
      .sort((a, b) => (b.count ?? 0) - (a.count ?? 0) || a.name.localeCompare(b.name))
  }
  return []
}

/** `["a.example"]`, a bare string, or a comma-separated list → string list. */
export function parseStringList(raw: unknown): string[] {
  const parsed = parseJsonColumn(raw)
  if (Array.isArray(parsed)) {
    return parsed.map((entry) => asText(entry)).filter((value): value is string => value !== null)
  }
  const single = asText(parsed) ?? (typeof raw === 'string' ? asText(raw) : null)
  if (single === null) return []
  return single
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

/* ------------------------------------------------------------------ */
/* chips                                                              */
/* ------------------------------------------------------------------ */

export type ChipTone = 'default' | 'accent' | 'ok' | 'warn' | 'danger' | 'sni'

const TONE_CLASS: Record<ChipTone, string> = {
  default: 'border-border2 bg-surface2 text-muted',
  accent: 'border-accent/40 bg-accent/10 text-accent2',
  ok: 'border-ok/40 bg-ok/10 text-ok',
  warn: 'border-warn/40 bg-warn/10 text-amber-300',
  danger: 'border-danger/40 bg-danger/10 text-red-300',
  sni: 'border-accent2/40 bg-accent2/10 text-accent2',
}

export interface ChipItem {
  key: string
  label: ReactNode
  /** Tooltip; also used for the "+N more" summary. */
  title?: string
  tone?: ChipTone
}

export interface ChipListProps {
  chips: ChipItem[]
  /** How many chips to show before collapsing the rest into "+N more". */
  max?: number
  emptyLabel?: string
  className?: string
}

/**
 * Compact wrapping chip row with a "+N more" affordance. The collapsed chips stay
 * reachable through the tooltip on the counter — nothing is silently dropped.
 */
export function ChipList({ chips, max = 4, emptyLabel = '—', className }: ChipListProps) {
  if (chips.length === 0) {
    return <span className={clsx('text-2xs text-faint', className)}>{emptyLabel}</span>
  }
  const shown = max > 0 ? chips.slice(0, max) : chips
  const hidden = chips.slice(shown.length)

  return (
    <span className={clsx('flex flex-wrap items-center gap-1', className)}>
      {shown.map((chip) => (
        <span key={chip.key} className={clsx('chip', TONE_CLASS[chip.tone ?? 'default'])} title={chip.title}>
          {chip.label}
        </span>
      ))}
      {hidden.length > 0 ? (
        <span
          className={clsx('chip', TONE_CLASS.default)}
          title={hidden.map((chip) => chip.title ?? String(chip.label)).join('\n')}
        >
          +{hidden.length} more
        </span>
      ) : null}
    </span>
  )
}

function plural(count: number, one: string, many: string): string {
  return count === 1 ? one : many
}

/** Most-used ports, one chip per port (src/dst counts summed). */
export function PortChips({ ports, max = 4 }: { ports: PortUsage[]; max?: number }) {
  const chips: ChipItem[] = ports.map((entry) => {
    const directions = entry.directions.length > 0 ? entry.directions.join('/') : null
    const parts = [
      `Port ${entry.port}`,
      entry.count !== null ? `${entry.count} ${plural(entry.count, 'packet', 'packets')}` : null,
      directions !== null ? `direction ${directions}` : null,
    ].filter((part): part is string => part !== null)
    return {
      key: String(entry.port),
      label: entry.count !== null ? `${entry.port} · ${entry.count}` : String(entry.port),
      title: parts.join(' · '),
      tone: 'default',
    }
  })
  return <ChipList chips={chips} max={max} emptyLabel="no ports" />
}

/** Display protocols observed for the host, most frequent first. */
export function ProtocolChips({ protocols, max = 3 }: { protocols: ProtocolUsage[]; max?: number }) {
  const chips: ChipItem[] = protocols.map((entry) => ({
    key: entry.name,
    label: entry.count !== null ? `${entry.name} · ${entry.count}` : entry.name,
    title:
      entry.count !== null
        ? `${entry.name}: ${entry.count} ${plural(entry.count, 'packet', 'packets')} to or from this host`
        : `${entry.name} (packet count not reported by the API)`,
    tone: 'accent',
  }))
  return <ChipList chips={chips} max={max} emptyLabel="no protocols" />
}

/**
 * DNS names (grey) and TLS SNI values (blue) attributed to the host. The two
 * sources are kept visually distinct because they mean different things.
 */
export function NameChips({
  dnsNames,
  tlsSni,
  max = 3,
}: {
  dnsNames: string[]
  tlsSni: string[]
  max?: number
}) {
  const chips: ChipItem[] = [
    ...dnsNames.map((name) => ({
      key: `dns:${name}`,
      label: name,
      title: `DNS name resolved for or by this host: ${name}`,
      tone: 'default' as ChipTone,
    })),
    ...tlsSni.map((name) => ({
      key: `sni:${name}`,
      label: name,
      title: `TLS SNI value offered by this host: ${name}`,
      tone: 'sni' as ChipTone,
    })),
  ]
  return <ChipList chips={chips} max={max} emptyLabel="no names" />
}

/** Private/public classification, with "unknown" kept distinct from "public". */
export function ScopeChip({ isPrivate }: { isPrivate: number | null | undefined }) {
  if (isPrivate === null || isPrivate === undefined) {
    return (
      <span
        className={clsx('chip', TONE_CLASS.default)}
        title="The address could not be classified (not parseable as IPv4/IPv6)."
      >
        unknown
      </span>
    )
  }
  if (isPrivate === 1) {
    return (
      <span
        className={clsx('chip', TONE_CLASS.accent)}
        title="RFC1918 / RFC4193 / loopback / link-local address"
      >
        private
      </span>
    )
  }
  return (
    <span
      className={clsx('chip', TONE_CLASS.warn)}
      title="Routable address outside the private, loopback and link-local ranges"
    >
      public
    </span>
  )
}

/** `N peers` chip that reveals the peer list on hover. */
export function PeerChip({ peers, peerCount }: { peers: string[]; peerCount: number | null }) {
  const count = peers.length > 0 ? peers.length : (peerCount ?? 0)
  if (count === 0) {
    return <span className="text-2xs text-faint">no peers</span>
  }
  const label = `${count} ${plural(count, 'peer', 'peers')}`
  if (peers.length === 0) {
    return (
      <span
        className={clsx('chip', TONE_CLASS.default)}
        title="The API reported a peer count but not the peer list."
      >
        {label}
      </span>
    )
  }
  return (
    <span className={clsx('chip', TONE_CLASS.default)} title={peers.join('\n')}>
      {label}
    </span>
  )
}
