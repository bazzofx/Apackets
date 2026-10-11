/** Display formatting helpers. Every helper tolerates `null`/`undefined` and
 *  returns the em-dash placeholder — the contract forbids inventing values. */

export const EMPTY = '—'

const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'] as const

/** Human readable byte size, e.g. `1.5 MiB`. */
export function formatBytes(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  const n = value
  if (n === 0) return '0 B'
  const sign = n < 0 ? '-' : ''
  let abs = Math.abs(n)
  let unit = 0
  while (abs >= 1024 && unit < BYTE_UNITS.length - 1) {
    abs /= 1024
    unit += 1
  }
  const precision = unit === 0 ? 0 : abs < 10 ? digits : abs < 100 ? 1 : 0
  return `${sign}${abs.toFixed(precision)} ${BYTE_UNITS[unit]}`
}

/** Thousands separators; passes strings through untouched. */
export function formatNumber(value: number | string | null | undefined): string {
  if (value === null || value === undefined) return EMPTY
  if (typeof value === 'string') return value
  if (!Number.isFinite(value)) return EMPTY
  if (Number.isInteger(value)) return value.toLocaleString('en-US')
  return value.toLocaleString('en-US', { maximumFractionDigits: 3 })
}

/**
 * Seconds -> `1.234 s` | `12.3 s` | `3 m 4 s` | `1 h 2 m`.
 * Sub-10 s durations keep millisecond precision, sub-minute durations keep one
 * decimal, longer durations drop to whole seconds.
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return EMPTY
  const s = seconds
  if (s < 0) return EMPTY
  if (s < 10) return `${s.toFixed(3)} s`
  if (s < 60) return `${s.toFixed(1)} s`
  const total = Math.floor(s)
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const secs = total % 60
  if (hours > 0) return `${hours} h ${minutes} m`
  return `${minutes} m ${secs} s`
}

const pad = (n: number, width = 2): string => String(n).padStart(width, '0')

/** Epoch seconds -> `YYYY-MM-DD HH:MM:SS.mmm` (local time). */
export function formatTimestamp(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  const ms = Math.round(value * 1000)
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return EMPTY
  const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  return `${date} ${time}.${pad(d.getMilliseconds(), 3)}`
}

/** Epoch seconds -> `HH:MM:SS` (local time), for dense tables and chart axes. */
export function formatClockTime(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  const d = new Date(Math.round(value * 1000))
  if (Number.isNaN(d.getTime())) return EMPTY
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** Epoch seconds -> `just now` | `12 s ago` | `3 min ago` | `2 h ago` | `4 d ago`. */
export function formatRelativeTime(value: number | null | undefined, now = Date.now()): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  const seconds = now / 1000 - value
  if (!Number.isFinite(seconds)) return EMPTY
  if (seconds < 0) return 'in the future'
  if (seconds < 5) return 'just now'
  if (seconds < 60) return `${Math.floor(seconds)} s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days} d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months} mo ago`
  return `${Math.floor(months / 12)} y ago`
}

/** Clamp a string to `max` characters, appending an ellipsis when cut. */
export function truncate(value: string | null | undefined, max = 64): string {
  if (value === null || value === undefined) return EMPTY
  if (value.length <= max) return value
  return `${value.slice(0, Math.max(0, max - 1))}…`
}

/** Percentage 0..1 or 0..100 -> `42%`. Used by progress displays. */
export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY
  const pct = value <= 1 ? value * 100 : value
  return `${pct.toFixed(pct < 10 ? 1 : 0)}%`
}
