import type { ReactNode } from 'react'
import clsx from 'clsx'
import { EMPTY } from '@/utils/format'

export interface MonoCellProps {
  children?: ReactNode
  /** Tooltip; falls back to the raw string child. */
  title?: string
  className?: string
  /** Truncate with a CSS ellipsis at this max width (px). */
  maxWidth?: number
}

/** Monospace cell for packet/IP/hex data, safe for untrusted capture strings. */
export function MonoCell({ children, title, className, maxWidth }: MonoCellProps) {
  const text =
    title ??
    (typeof children === 'string' || typeof children === 'number' ? String(children) : undefined)
  const empty =
    children === null ||
    children === undefined ||
    children === '' ||
    (typeof children === 'string' && children === EMPTY)
  return (
    <span
      className={clsx(
        'block truncate mono',
        empty && 'text-faint',
        className,
      )}
      style={maxWidth ? { maxWidth } : undefined}
      title={text}
    >
      {empty ? EMPTY : children}
    </span>
  )
}

export default MonoCell
