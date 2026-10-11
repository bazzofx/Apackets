import clsx from 'clsx'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { formatNumber } from '@/utils/format'

export interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
  pageSizeOptions?: number[]
  className?: string
  /** Disable while a request is in flight. */
  disabled?: boolean
}

/** Dense pagination footer: range, prev/next and a page-size select. */
export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [50, 100, 250, 500, 1000],
  className,
  disabled = false,
}: PaginationProps) {
  const safePageSize = pageSize > 0 ? pageSize : 100
  const pageCount = Math.max(1, Math.ceil(total / safePageSize))
  const current = Math.min(Math.max(1, page), pageCount)
  const from = total === 0 ? 0 : (current - 1) * safePageSize + 1
  const to = Math.min(total, current * safePageSize)

  return (
    <div
      className={clsx(
        'flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-2xs text-muted',
        className,
      )}
    >
      <div className="font-mono">
        {total === 0
          ? 'no rows'
          : `${formatNumber(from)}–${formatNumber(to)} of ${formatNumber(total)}`}
        <span className="ml-2 text-faint">
          page {formatNumber(current)} / {formatNumber(pageCount)}
        </span>
      </div>
      <div className="flex items-center gap-2">
        {onPageSizeChange ? (
          <label className="flex items-center gap-1">
            <span className="text-faint">rows</span>
            <select
              className="select py-0.5 text-2xs"
              value={safePageSize}
              disabled={disabled}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
            >
              {pageSizeOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <div className="flex items-center gap-1">
          <button
            type="button"
            className="btn px-1.5 py-1"
            disabled={disabled || current <= 1}
            onClick={() => onPageChange(current - 1)}
            title="Previous page"
          >
            <ChevronLeft size={13} aria-hidden />
          </button>
          <button
            type="button"
            className="btn px-1.5 py-1"
            disabled={disabled || current >= pageCount}
            onClick={() => onPageChange(current + 1)}
            title="Next page"
          >
            <ChevronRight size={13} aria-hidden />
          </button>
        </div>
      </div>
    </div>
  )
}

export default Pagination
