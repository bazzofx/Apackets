import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import { X } from 'lucide-react'

/**
 * URL-backed filter controls shared by the HTTP / DNS / TLS pages.
 *
 * Every filter lives in the query string so a view can be copied, bookmarked and
 * shared. Booleans are written as the API's own `true`/`false` spelling; an
 * absent key means "no filter at all", which is deliberately different from
 * `false` (the API treats `has_cert=false` as a real filter).
 */

export type FilterValue = string | number | boolean | null | undefined

export interface UrlFilterApi {
  /** Raw value, or `''` when absent. */
  get: (key: string) => string
  /** `true` only when the stored value is exactly `true`. */
  getBool: (key: string) => boolean
  /** Parsed number, or `fallback` when absent/unparseable. */
  getNumber: (key: string, fallback: number) => number
  /** Merge values in; `null`/`undefined`/`''`/`false` removes the key. */
  patch: (next: Record<string, FilterValue>, options?: { resetPage?: boolean }) => void
  /** Drop every key this page owns. */
  clear: () => void
  /** True when at least one owned key is present. */
  any: boolean
}

/**
 * Keys that are paging/sorting state, or that only filter a list already
 * returned (the per-domain and fingerprint views), rather than narrowing the
 * API request. They are kept out of `any` so an empty table is only reported as
 * "filtered" when a server-side filter is really responsible.
 */
const NON_FILTER_KEYS = new Set([
  'page',
  'page_size',
  'sort',
  'order',
  'view',
  'tx',
  'sel',
  'dsearch',
  'dsort',
  'ftype',
  'fsearch',
])

/**
 * Read and write the page's own query-string keys.
 *
 * `keys` is the full set the page owns; anything else in the URL is preserved.
 * Changing any filter resets `page` to 1 unless the caller says otherwise.
 */
export function useUrlFilters(keys: string[], defaultPageSize = 100): UrlFilterApi {
  const [searchParams, setSearchParams] = useSearchParams()
  const owned = useMemo(() => keys.join('\u0000'), [keys])

  const get = useCallback(
    (key: string) => searchParams.get(key) ?? '',
    [searchParams],
  )

  const getBool = useCallback((key: string) => searchParams.get(key) === 'true', [searchParams])

  const getNumber = useCallback(
    (key: string, fallback: number) => {
      const raw = searchParams.get(key)
      if (raw === null || raw.trim() === '') return fallback
      const value = Number(raw)
      return Number.isFinite(value) ? value : fallback
    },
    [searchParams],
  )

  const patch = useCallback(
    (next: Record<string, FilterValue>, options?: { resetPage?: boolean }) => {
      const touchesFilter = Object.keys(next).some(
        (key) => !NON_FILTER_KEYS.has(key) && next[key] !== undefined,
      )
      setSearchParams(
        (previous) => {
          const params = new URLSearchParams(previous)
          for (const [key, value] of Object.entries(next)) {
            if (value === null || value === undefined || value === '' || value === false) {
              params.delete(key)
            } else {
              params.set(key, String(value))
            }
          }
          if (touchesFilter && options?.resetPage !== false) params.delete('page')
          return params
        },
        { replace: true },
      )
    },
    [setSearchParams],
  )

  const clear = useCallback(() => {
    setSearchParams(
      (previous) => {
        const params = new URLSearchParams(previous)
        for (const key of owned.split('\u0000')) params.delete(key)
        return params
      },
      { replace: true },
    )
  }, [setSearchParams, owned])

  const any = useMemo(
    () =>
      owned
        .split('\u0000')
        .some((key) => !NON_FILTER_KEYS.has(key) && (searchParams.get(key) ?? '') !== ''),
    [owned, searchParams],
  )

  // Keep the page size valid even when the URL carries something odd.
  const pageSize = getNumber('page_size', defaultPageSize)
  useEffect(() => {
    if (pageSize <= 0) patch({ page_size: defaultPageSize })
  }, [pageSize, defaultPageSize, patch])

  return { get, getBool, getNumber, patch, clear, any }
}

/* ------------------------------------------------------------------ */
/* Controls                                                            */
/* ------------------------------------------------------------------ */

export interface FilterFieldProps {
  label: string
  children: ReactNode
  /** Tailwind width class; defaults to a compact fixed width. */
  width?: string
  title?: string
}

function Label({ text, title }: { text: string; title?: string }) {
  return (
    <span className="shrink-0 text-2xs uppercase tracking-wider text-faint" title={title}>
      {text}
    </span>
  )
}

/** Label + control pair used across the filter strips. */
export function FilterField({ label, children, width = 'w-40', title }: FilterFieldProps) {
  return (
    <label className="flex items-center gap-1.5">
      <Label text={label} title={title} />
      <span className={clsx('min-w-0', width)}>{children}</span>
    </label>
  )
}

export interface TextFilterProps {
  label: string
  value: string
  placeholder?: string
  onChange: (value: string) => void
  width?: string
  title?: string
  /** `id` of a `<datalist>` rendered elsewhere on the page. */
  listId?: string
}

/**
 * Text filter with a short debounce so a request is not sent per keystroke.
 * Enter commits immediately.
 */
export function TextFilter({
  label,
  value,
  placeholder,
  onChange,
  width,
  title,
  listId,
}: TextFilterProps) {
  const [draft, setDraft] = useState(value)
  // Held in a ref so a re-render (a settling request, for instance) cannot keep
  // postponing the debounced commit by changing the callback identity.
  const commit = useRef(onChange)

  useEffect(() => {
    commit.current = onChange
  }, [onChange])

  useEffect(() => {
    setDraft(value)
  }, [value])

  useEffect(() => {
    if (draft === value) return
    const timer = window.setTimeout(() => commit.current(draft), 300)
    return () => window.clearTimeout(timer)
  }, [draft, value])

  return (
    <FilterField label={label} width={width} title={title}>
      <input
        className="input py-1"
        value={draft}
        list={listId}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            event.preventDefault()
            onChange(draft)
          }
          if (event.key === 'Escape') {
            setDraft('')
            onChange('')
          }
        }}
      />
    </FilterField>
  )
}

export interface SelectOption {
  value: string
  label: string
  title?: string
}

export interface SelectFilterProps {
  label: string
  value: string
  options: SelectOption[]
  onChange: (value: string) => void
  /** Rendered as the empty-valued option. */
  anyLabel?: string
  width?: string
  title?: string
  disabled?: boolean
}

/** Dropdown filter; the empty option always means "no filter". */
export function SelectFilter({
  label,
  value,
  options,
  onChange,
  anyLabel = 'any',
  width,
  title,
  disabled = false,
}: SelectFilterProps) {
  const known = options.some((option) => option.value === value)
  return (
    <FilterField label={label} width={width} title={title}>
      <select
        className="select w-full py-1"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">{anyLabel}</option>
        {!known && value !== '' ? <option value={value}>{value}</option> : null}
        {options.map((option) => (
          <option key={option.value} value={option.value} title={option.title}>
            {option.label}
          </option>
        ))}
      </select>
    </FilterField>
  )
}

export interface CheckFilterProps {
  label: string
  checked: boolean
  onChange: (checked: boolean) => void
  title?: string
}

/** Boolean filter rendered as an "only …" checkbox. */
export function CheckFilter({ label, checked, onChange, title }: CheckFilterProps) {
  return (
    <label
      className={clsx(
        'flex cursor-pointer items-center gap-1.5 rounded border px-1.5 py-1 text-2xs',
        checked ? 'border-accent/60 bg-accent/15 text-accent2' : 'border-border bg-surface2 text-muted',
      )}
      title={title}
    >
      <input
        type="checkbox"
        className="h-3 w-3 accent-accent"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
      {label}
    </label>
  )
}

export interface FilterStripProps {
  children: ReactNode
  /** Right-aligned actions (reset, refresh, row count…). */
  actions?: ReactNode
  className?: string
}

/** Wrapping filter strip that sits above a dense table. */
export function FilterStrip({ children, actions, className }: FilterStripProps) {
  return (
    <div
      className={clsx(
        'flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border px-3 py-2',
        className,
      )}
    >
      {children}
      {actions ? <div className="ml-auto flex items-center gap-1.5">{actions}</div> : null}
    </div>
  )
}

export interface ResetFiltersButtonProps {
  onClick: () => void
  disabled?: boolean
}

export function ResetFiltersButton({ onClick, disabled = false }: ResetFiltersButtonProps) {
  return (
    <button
      type="button"
      className="btn px-1.5 py-1"
      onClick={onClick}
      disabled={disabled}
      title="Clear every filter in the URL"
    >
      <X size={12} aria-hidden />
      Reset filters
    </button>
  )
}

export interface SortSelectProps {
  /** Allow-listed column keys. */
  columns: { value: string; label: string }[]
  sort: string
  order: string
  onChange: (sort: string, order: string) => void
}

/** Sort column + direction pair, restricted to the endpoint's allow-list. */
export function SortSelect({ columns, sort, order, onChange }: SortSelectProps) {
  const descending = order === 'desc'
  return (
    <span className="flex items-center gap-1.5">
      <Label text="Sort" title="Only the columns the backend allows are listed." />
      <select
        className="select py-1"
        value={sort}
        onChange={(event) => onChange(event.target.value, order || 'asc')}
      >
        {columns.map((column) => (
          <option key={column.value} value={column.value}>
            {column.label}
          </option>
        ))}
      </select>
      <button
        type="button"
        className="btn px-1.5 py-1"
        title={descending ? 'Descending — click for ascending' : 'Ascending — click for descending'}
        onClick={() => onChange(sort, descending ? 'asc' : 'desc')}
      >
        {descending ? 'desc' : 'asc'}
      </button>
    </span>
  )
}
