import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight, Loader2, Search, TriangleAlert } from 'lucide-react'
import { toApiError } from '@/services/api'
import type { StreamFollow, StreamMode } from '@/types'
import { EMPTY, formatNumber } from '@/utils/format'
import { clientNodeIndex, searchStream, type StreamSearchMatch } from './streamClient'

/**
 * Search inside the reassembled stream payload.
 *
 * `GET …/streams/{id}/search` is case-insensitive over the reassembled bytes and
 * reports each hit as a direction plus a byte offset inside that direction's
 * payload, with surrounding context rendered in the requested mode. Jumping to a
 * hit is delegated to the viewer, which owns the chunk rows and can map an offset
 * onto the chunk that carried it.
 */

export interface StreamSearchPanelProps {
  analysisId: string
  streamId: number
  mode: StreamMode
  /** Directions in this stream, for labelling hits. */
  follow: StreamFollow
  /** Move the viewer to the chunk that contains this match. */
  onJump: (match: StreamSearchMatch) => void
  /** True when the stream has no reassembled bytes to search. */
  disabled?: boolean
}

/** Context strings can be long; show a readable window of each hit. */
const CONTEXT_CHARS = 240

export function StreamSearchPanel({
  analysisId,
  streamId,
  mode,
  follow,
  onJump,
  disabled = false,
}: StreamSearchPanelProps) {
  const [query, setQuery] = useState('')
  const [request, setRequest] = useState<{ term: string; nonce: number } | null>(null)
  const [matches, setMatches] = useState<StreamSearchMatch[]>([])
  const [truncated, setTruncated] = useState(false)
  const [active, setActive] = useState(-1)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Keeping the callback in a ref means a new `onJump` identity cannot restart
  // the search effect and re-fire the same request.
  const onJumpRef = useRef(onJump)
  useEffect(() => {
    onJumpRef.current = onJump
  }, [onJump])

  useEffect(() => {
    if (request === null || request.term.trim() === '') return
    let cancelled = false
    setBusy(true)
    setError(null)
    void (async () => {
      try {
        const result = await searchStream(analysisId, streamId, request.term, mode)
        if (cancelled) return
        setMatches(result.items)
        setTruncated(result.truncated)
        setActive(result.items.length > 0 ? 0 : -1)
        if (result.items.length > 0) onJumpRef.current(result.items[0])
      } catch (cause) {
        if (cancelled) return
        setMatches([])
        setTruncated(false)
        setActive(-1)
        setError(toApiError(cause).message)
      } finally {
        if (!cancelled) setBusy(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [analysisId, streamId, mode, request])

  const submit = useCallback(
    (event: FormEvent) => {
      event.preventDefault()
      const term = query.trim()
      if (term === '') return
      setRequest({ term, nonce: Date.now() })
    },
    [query],
  )

  const step = useCallback(
    (delta: number) => {
      if (matches.length === 0) return
      const next = active + delta
      if (next < 0 || next >= matches.length) return
      setActive(next)
      onJumpRef.current(matches[next])
    },
    [active, matches],
  )

  const directionOf = (direction: number): string => {
    if (follow.client_to_server?.direction === direction) return 'client → server'
    if (follow.server_to_client?.direction === direction) return 'server → client'
    const clientNode = clientNodeIndex(follow)
    if (clientNode !== null) {
      return (direction === 0) === (clientNode === 0) ? 'client → server' : 'server → client'
    }
    return direction === 0 ? 'node0 → node1' : 'node1 → node0'
  }

  return (
    <div className="flex flex-col gap-2 p-3">
      <form className="flex flex-wrap items-center gap-2" onSubmit={submit}>
        <label className="flex min-w-[16rem] flex-1 items-center gap-2">
          <span className="shrink-0 text-2xs uppercase tracking-wider text-faint">find</span>
          <input
            className="input py-1"
            value={query}
            spellCheck={false}
            autoComplete="off"
            disabled={disabled}
            placeholder="GET /index.html, password, Host:"
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <button type="submit" className="btn btn-primary px-2 py-1" disabled={disabled || busy}>
          {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Search size={12} aria-hidden />}
          Search
        </button>
        <span className="flex items-center gap-1">
          <button
            type="button"
            className="btn px-1.5 py-1"
            disabled={busy || active <= 0}
            onClick={() => step(-1)}
            title="Previous match"
          >
            <ChevronLeft size={12} aria-hidden />
          </button>
          <button
            type="button"
            className="btn px-1.5 py-1"
            disabled={busy || active < 0 || active >= matches.length - 1}
            onClick={() => step(1)}
            title="Next match"
          >
            <ChevronRight size={12} aria-hidden />
          </button>
          <span className="mono text-2xs text-faint">
            {matches.length === 0
              ? 'no matches'
              : `${formatNumber(active + 1)} / ${formatNumber(matches.length)}`}
          </span>
        </span>
      </form>

      <p className="text-2xs leading-relaxed text-faint">
        Searching the reassembled bytes, not the packet list. Hits show the direction and the byte
        offset inside that direction&apos;s payload, and jumping highlights the chunk that carried
        them.{' '}
        {follow.chunks_truncated || (follow.chunk_count ?? 0) > follow.chunks.length
          ? 'Only the chunks the backend returned inline can be highlighted.'
          : ''}
      </p>

      {disabled ? (
        <p className="text-2xs leading-relaxed text-muted">
          This stream has no reassembled payload to search.
        </p>
      ) : null}

      {error ? (
        <div className="flex items-start gap-2 rounded border border-danger/40 bg-danger/10 px-2 py-1.5 text-2xs text-red-200" role="alert">
          <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>{error}</span>
        </div>
      ) : null}

      {truncated ? (
        <div className="flex items-start gap-2 rounded border border-warn/40 bg-warn/10 px-2 py-1.5 text-2xs text-warn">
          <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>
            The backend stopped at its match cap, so this is not the complete set of hits. Narrow the
            search term.
          </span>
        </div>
      ) : null}

      {matches.length === 0 ? (
        <p className="text-2xs text-faint">
          {request === null
            ? 'Enter a substring to search the reconstructed payload.'
            : busy
              ? 'Searching…'
              : `No occurrence of ${request.term} in the reassembled bytes of this stream.`}
        </p>
      ) : (
        <ul className="divide-y divide-border/60 rounded border border-border">
          {matches.map((match, index) => {
            const context = match.context ?? ''
            return (
              <li key={`${match.direction}-${match.offset}-${index}`}>
                <button
                  type="button"
                  className={clsx(
                    'flex w-full flex-col gap-1 px-2 py-1.5 text-left',
                    index === active ? 'bg-accent/15' : 'hover:bg-surface2/60',
                  )}
                  onClick={() => {
                    setActive(index)
                    onJumpRef.current(match)
                  }}
                  title="Jump to the chunk that carried these bytes"
                >
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="mono text-2xs text-faint">#{formatNumber(index + 1)}</span>
                    <span
                      className={clsx(
                        'chip',
                        directionOf(match.direction) === 'client → server'
                          ? 'border-accent/50 bg-accent/15 text-accent2'
                          : 'border-ok/50 bg-ok/15 text-ok',
                      )}
                    >
                      {directionOf(match.direction)}
                    </span>
                    <span className="mono text-2xs text-muted">
                      byte offset {formatNumber(match.offset)}
                    </span>
                  </span>
                  <span className="mono break-all whitespace-pre-wrap text-2xs text-text">
                    {context === '' ? EMPTY : context.slice(0, CONTEXT_CHARS)}
                    {context.length > CONTEXT_CHARS ? ' …' : ''}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export default StreamSearchPanel
