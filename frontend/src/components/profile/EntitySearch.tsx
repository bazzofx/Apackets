import { useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CornerDownLeft, Globe, Link2, Network, Search, X } from 'lucide-react'
import { profileApi } from '@/services/api'
import { formatNumber } from '@/utils/format'
import type { ProfileKind, ProfileMatch } from '@/types'

/**
 * The Investigate lookup box: one field, in the middle of the page, that takes an
 * IP address, a domain name or a URL.
 *
 * The reader does not choose a kind — the field works it out from what was typed and
 * says so — because knowing whether `10.0.0.5` is an address or a hostname is the
 * application's job, not the reader's. Suggestions come from this capture's own
 * tables, so a name that never appears here is never offered.
 *
 * A query that matches nothing is still offered verbatim, with the kind it was read
 * as: the entity endpoint answers an unknown entity with every question marked "not
 * applicable", which is a truthful "this capture never recorded it" rather than a
 * dead end. Nothing is resolved or looked up online.
 */

/** One hue per kind, from the theme's chart palette, so the kinds differ by colour. */
const KIND_HUE: Record<ProfileKind, string> = {
  ip: '--c-chart-2',
  domain: '--c-chart-3',
  url: '--c-chart-6',
}

const KIND_LABEL: Record<ProfileKind, string> = {
  ip: 'IP',
  domain: 'domain',
  url: 'URL',
}

const KIND_WORD: Record<ProfileKind, string> = {
  ip: 'an IP address',
  domain: 'a domain name',
  url: 'a URL',
}

function KindIcon({ kind, size = 11 }: { kind: ProfileKind; size?: number }) {
  if (kind === 'ip') return <Network size={size} aria-hidden />
  if (kind === 'url') return <Link2 size={size} aria-hidden />
  return <Globe size={size} aria-hidden />
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/
const IPV6ISH = /^[0-9a-fA-F:.]+$/

/**
 * Which kind a typed value is, as far as its shape can say.
 *
 * Shape is all this reads: `10.0.0.5` is treated as an address, anything with a
 * scheme or a path as a URL, and anything else as a domain name. A wrong guess costs
 * nothing — the entity endpoint answers an unknown entity honestly — and the guess is
 * always shown next to the value before it is used.
 */
export function guessKind(value: string): ProfileKind {
  const text = value.trim()
  if (IPV4.test(text)) return 'ip'
  if (text.includes(':') && IPV6ISH.test(text)) return 'ip'
  if (text.includes('://') || text.includes('/')) return 'url'
  return 'domain'
}

export interface EntitySearchProps {
  analysisId: string
  /** The entity currently open, if any, so the field can show it. */
  current: { kind: ProfileKind; entity: string } | null
  onPick: (kind: ProfileKind, entity: string) => void
  onClear: () => void
}

export function EntitySearch({ analysisId, current, onPick, onClear }: EntitySearchProps) {
  const [text, setText] = useState(current?.entity ?? '')
  const [debounced, setDebounced] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(-1)
  const boxRef = useRef<HTMLDivElement | null>(null)

  /* The field follows the URL: opening a deep link has to show the entity it
     names, and clearing it has to empty the box. */
  const currentKey = current === null ? '' : `${current.kind}:${current.entity}`
  useEffect(() => {
    setText(current?.entity ?? '')
    setDebounced('')
    setOpen(false)
    setActive(-1)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentKey])

  /* One request per pause, not one per keystroke. */
  useEffect(() => {
    const trimmed = text.trim()
    if (trimmed.length < 2) {
      setDebounced('')
      return
    }
    const timer = window.setTimeout(() => setDebounced(trimmed), 250)
    return () => window.clearTimeout(timer)
  }, [text])

  /* A click anywhere else closes the list. */
  useEffect(() => {
    if (!open) return
    const onDown = (event: MouseEvent) => {
      if (boxRef.current !== null && !boxRef.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const search = useQuery({
    queryKey: ['profile-search', analysisId, debounced],
    queryFn: () => profileApi.search(analysisId, debounced),
    enabled: analysisId !== '' && debounced.length >= 2,
    staleTime: 30_000,
  })

  const matches: ProfileMatch[] = useMemo(() => search.data?.matches ?? [], [search.data])
  const typed = text.trim()
  const guess = typed.length > 0 ? guessKind(typed) : null
  const exact = matches.some((match) => match.entity.toLowerCase() === typed.toLowerCase())
  const offerTyped = typed.length > 0 && guess !== null && !exact
  const rowCount = matches.length + (offerTyped ? 1 : 0)

  const pick = (kind: ProfileKind, entity: string) => {
    setText(entity)
    setOpen(false)
    setActive(-1)
    onPick(kind, entity)
  }

  const submit = () => {
    if (active >= 0 && active < matches.length) {
      const match = matches[active]
      if (match !== undefined) pick(match.kind, match.entity)
      return
    }
    if (offerTyped && guess !== null) {
      pick(guess, typed)
      return
    }
    const only = matches[0]
    if (matches.length === 1 && only !== undefined) pick(only.kind, only.entity)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setOpen(true)
      setActive((index) => (rowCount === 0 ? -1 : (index + 1) % rowCount))
      return
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault()
      setOpen(true)
      setActive((index) => (rowCount === 0 ? -1 : (index - 1 + rowCount) % rowCount))
      return
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      submit()
      return
    }
    if (event.key === 'Escape') {
      event.preventDefault()
      if (open) setOpen(false)
      else if (current !== null) onClear()
    }
  }

  return (
    <div className="signal-search" ref={boxRef}>
      <div className="relative flex items-center">
        <Search size={14} className="pointer-events-none absolute left-3 text-faint" aria-hidden />
        <input
          type="search"
          value={text}
          onChange={(event) => {
            setText(event.target.value)
            setOpen(true)
            setActive(-1)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          placeholder="Search an IP address, a domain name or a URL from this capture…"
          aria-label="Search this capture by IP address, domain name or URL"
          role="combobox"
          aria-expanded={open && rowCount > 0}
          aria-controls="signal-search-results"
          aria-autocomplete="list"
          autoComplete="off"
          spellCheck={false}
          data-profile-search-input
          className="input w-full py-2 pl-9 pr-9 text-sm"
        />
        {text !== '' ? (
          <button
            type="button"
            className="absolute right-2.5 text-faint hover:text-text"
            aria-label="Clear the search"
            title="Clear the search"
            onClick={() => {
              setText('')
              setDebounced('')
              setOpen(false)
              setActive(-1)
              onClear()
            }}
          >
            <X size={14} aria-hidden />
          </button>
        ) : null}
      </div>

      {open && rowCount > 0 ? (
        <div className="signal-search-results" id="signal-search-results" role="listbox">
          {matches.map((match, index) => (
            <button
              key={`${match.kind}:${match.entity}`}
              type="button"
              role="option"
              aria-selected={active === index}
              data-active={active === index}
              data-profile-match={match.entity}
              className="signal-match"
              onMouseEnter={() => setActive(index)}
              onClick={() => pick(match.kind, match.entity)}
            >
              <span
                className="chip signal-kind"
                style={{ '--kind-hue': `var(${KIND_HUE[match.kind]})` } as CSSProperties}
              >
                <KindIcon kind={match.kind} />
                {KIND_LABEL[match.kind]}
              </span>
              <span className="min-w-0 flex-1">
                {/* The label is what to read (a URL carries its host); the value is
                    what the profile endpoint takes, and it stays in the tooltip. */}
                <span className="mono block truncate text-xs text-text" title={match.entity}>
                  {match.label !== '' ? match.label : match.entity}
                </span>
                <span className="block truncate text-2xs text-faint">{match.hint}</span>
              </span>
              <span
                className="shrink-0 font-mono text-2xs text-muted"
                title={`${formatNumber(match.count)} row(s) in this capture mention it`}
              >
                {formatNumber(match.count)}
              </span>
            </button>
          ))}

          {offerTyped && guess !== null ? (
            <button
              type="button"
              role="option"
              aria-selected={active === matches.length}
              data-active={active === matches.length}
              data-profile-open-typed={typed}
              className="signal-match"
              onMouseEnter={() => setActive(matches.length)}
              onClick={() => pick(guess, typed)}
            >
              <span
                className="chip signal-kind"
                style={{ '--kind-hue': `var(${KIND_HUE[guess]})` } as CSSProperties}
              >
                <KindIcon kind={guess} />
                {KIND_LABEL[guess]}
              </span>
              <span className="min-w-0 flex-1">
                <span className="mono block truncate text-xs text-text">{typed}</span>
                <span className="block truncate text-2xs text-faint">
                  Nothing in this capture matches it exactly — read it as {KIND_WORD[guess]} and open it
                  anyway; an entity this capture never recorded answers every question with why.
                </span>
              </span>
              <CornerDownLeft size={12} className="shrink-0 text-faint" aria-hidden />
            </button>
          ) : null}
        </div>
      ) : null}

      <p className="mt-1.5 text-2xs text-faint" data-profile-search-hint>
        {search.isFetching
          ? 'Searching this capture…'
          : debounced.length >= 2 && search.error
            ? 'The search request failed. Pressing Enter still opens what you typed, read by its shape.'
            : debounced.length >= 2
              ? search.data?.truncated === true
                ? 'More entities match than are listed. Keep typing to narrow it down.'
                : `${formatNumber(matches.length)} ${matches.length === 1 ? 'match' : 'matches'} in this capture’s own tables.`
              : current !== null
                ? `Showing “${current.entity}” (${KIND_LABEL[current.kind]}). Search again, or press Esc to clear.`
                : 'Everything is read from this analysis’ indexed tables — nothing is resolved over the network.'}
      </p>
    </div>
  )
}

export { KIND_HUE, KIND_LABEL, KindIcon }
export default EntitySearch
