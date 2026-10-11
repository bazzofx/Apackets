import type { ReactNode } from 'react'
import clsx from 'clsx'
import { Check, MinusCircle, TriangleAlert } from 'lucide-react'
import { EMPTY } from '@/utils/format'

/**
 * Shared presentation primitives for the protocol detail panes.
 *
 * Everything here renders capture-derived strings as text (never HTML) and shows
 * the em dash plus a reason when a value genuinely is not available.
 */

export interface DetailGridProps {
  children: ReactNode
  /** Column count at wider breakpoints. */
  columns?: 1 | 2 | 3
  className?: string
}

const GRID_COLUMNS: Record<1 | 2 | 3, string> = {
  1: 'grid-cols-1',
  2: 'grid-cols-1 md:grid-cols-2',
  3: 'grid-cols-1 md:grid-cols-2 xl:grid-cols-3',
}

/** Definition list laid out as dense label/value rows. */
export function DetailGrid({ children, columns = 2, className }: DetailGridProps) {
  return (
    <dl className={clsx('grid gap-x-5 gap-y-0.5', GRID_COLUMNS[columns], className)}>{children}</dl>
  )
}

export interface DetailItemProps {
  label: string
  value: ReactNode
  /** Tooltip; defaults to a string value. */
  title?: string
  /** Render the value in the monospace font (default: yes). */
  mono?: boolean
  /** Accent the value (used for status codes and negotiated settings). */
  tone?: 'default' | 'warn' | 'ok' | 'danger'
  /** Explanation shown when the value is unavailable. */
  unavailableReason?: string
}

const TONES: Record<'default' | 'warn' | 'ok' | 'danger', string> = {
  default: 'text-text',
  warn: 'text-warn',
  ok: 'text-ok',
  danger: 'text-red-300',
}

/** One label/value row inside a `DetailGrid`. */
export function DetailItem({
  label,
  value,
  title,
  mono = true,
  tone = 'default',
  unavailableReason,
}: DetailItemProps) {
  const missing = value === null || value === undefined || value === '' || value === EMPTY
  const tooltip =
    title ??
    (typeof value === 'string' || typeof value === 'number' ? String(value) : undefined) ??
    (missing ? unavailableReason : undefined)
  return (
    <div className="flex min-w-0 items-baseline gap-2 border-b border-border/40 py-0.5">
      <dt className="w-40 shrink-0 text-2xs uppercase tracking-wide text-faint">{label}</dt>
      <dd
        className={clsx('min-w-0 flex-1 break-words', mono && 'mono', missing ? 'text-faint' : TONES[tone])}
        title={tooltip}
      >
        {missing ? EMPTY : value}
      </dd>
    </div>
  )
}

export interface SectionNoteProps {
  children: ReactNode
  tone?: 'info' | 'warn'
  className?: string
}

/** Short factual paragraph attached to a detail section. */
export function SectionNote({ children, tone = 'info', className }: SectionNoteProps) {
  return (
    <p
      className={clsx(
        'rounded border px-2 py-1.5 text-2xs leading-relaxed',
        tone === 'warn'
          ? 'border-warn/40 bg-warn/10 text-warn'
          : 'border-border bg-surface2/40 text-muted',
        className,
      )}
    >
      {children}
    </p>
  )
}

export interface ScopeNoteItem {
  /** `can` = true, `cannot` = false. */
  can: boolean
  text: ReactNode
}

export interface ScopeNoteProps {
  title: string
  items: ScopeNoteItem[]
  /** Extra caveat rendered below the list. */
  caveat?: ReactNode
  className?: string
}

/**
 * Honest statement of what a page can and cannot show. Used by all three
 * protocol pages so the limits of the analysis are visible above the data.
 */
export function ScopeNote({ title, items, caveat, className }: ScopeNoteProps) {
  return (
    <section className={clsx('panel', className)}>
      <header className="panel-header">
        <div className="panel-title">{title}</div>
      </header>
      <ul className="grid grid-cols-1 gap-x-5 gap-y-1 p-3 md:grid-cols-2">
        {items.map((item, index) => (
          <li key={index} className="flex items-start gap-2 text-2xs leading-relaxed">
            {item.can ? (
              <Check size={12} className="mt-0.5 shrink-0 text-ok" aria-hidden />
            ) : (
              <MinusCircle size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            )}
            <span className={item.can ? 'text-muted' : 'text-muted'}>{item.text}</span>
          </li>
        ))}
      </ul>
      {caveat ? (
        <div className="flex items-start gap-2 border-t border-border px-3 py-2">
          <TriangleAlert size={13} className="mt-0.5 shrink-0 text-warn" aria-hidden />
          <p className="text-2xs leading-relaxed text-muted">{caveat}</p>
        </div>
      ) : null}
    </section>
  )
}

export interface ColumnHeaderProps {
  label: string
  title: string
  className?: string
}

/**
 * Table header cell with an explanatory tooltip. Used where a column is easy to
 * misread (fingerprints, certificate fields, decrypted-payload questions).
 */
export function ColumnHeader({ label, title, className }: ColumnHeaderProps) {
  return (
    <th className={className} title={title}>
      <span className="cursor-help border-b border-dotted border-border2">{label}</span>
    </th>
  )
}
