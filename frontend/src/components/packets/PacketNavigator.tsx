import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight, Loader2, TriangleAlert } from 'lucide-react'
import { packetsApi, toApiError } from '@/services/api'
import type { NeighborsResponse } from '@/types'
import { truncate } from '@/utils/format'
import { buildNeighborFilter, type PacketFilterState } from './PacketFilters'

/**
 * "Jump to the next/previous matching packet" navigation.
 *
 * The neighbours endpoint only understands a Wireshark display filter, so the
 * current structured filter is first translated into an equivalent display
 * filter (see `buildNeighborFilter`). That translation is verified against the
 * API before it is used: `POST /filter` reports `valid`/`reason` without ever
 * raising, so a translation the TShark parser rejects disables the buttons with
 * an explanation instead of failing a click.
 *
 * The response's `boundary` flag is what turns a button off: `packet_number:
 * null` means "no further match in this direction", which is a real answer and
 * must not be shown as an error.
 *
 * `NeighborsResponse` in `src/types/index.ts` models only `packet_number`; the
 * live API also returns `direction`, `filter` and `boundary`, so they are
 * modelled locally here instead of editing a file owned by another agent.
 */

type NeighborsResult = NeighborsResponse & {
  boundary?: boolean
  direction?: string
  filter?: string
}

export interface PacketNavigatorProps {
  analysisId: string
  filters: PacketFilterState
  /** Currently focused frame number; navigation needs a starting point. */
  current: number | null
  /** Rows the filtered list request returned, for the equivalence note. */
  filteredTotal: number | null
  onSelect: (packetNumber: number) => void
  /** True while the list itself is loading. */
  listBusy?: boolean
}

export function PacketNavigator({
  analysisId,
  filters,
  current,
  filteredTotal,
  onSelect,
  listBusy = false,
}: PacketNavigatorProps) {
  const derived = useMemo(() => buildNeighborFilter(filters), [filters])
  const [boundary, setBoundary] = useState<{ next: boolean; prev: boolean }>({
    next: false,
    prev: false,
  })
  const [pending, setPending] = useState<'next' | 'prev' | null>(null)
  const [error, setError] = useState<string | null>(null)

  // A fresh expression is a fresh traversal: the recorded boundaries no longer
  // describe it, and neither does any pending error.
  useEffect(() => {
    setBoundary({ next: false, prev: false })
    setError(null)
    setPending(null)
  }, [derived.expression])

  const check = useQuery({
    queryKey: ['packet-neighbor-filter', analysisId, derived.expression],
    queryFn: () => packetsApi.filter(analysisId, { filter: derived.expression, page_size: 1 }),
    // Validated only once a packet is selected: the check runs TShark over the
    // capture through POST /filter, and the buttons are unusable before there is
    // a starting point to step from.
    enabled: Boolean(analysisId) && current !== null,
    staleTime: 5 * 60 * 1000,
    retry: false,
  })

  const valid = check.data?.valid ?? null
  const reason = check.data?.reason ?? null
  const traversalTotal = check.data?.total ?? null

  const go = useCallback(
    (direction: 'next' | 'prev') => {
      if (current === null || pending !== null) return
      setPending(direction)
      setError(null)
      void (async () => {
        try {
          const result: NeighborsResult = await packetsApi.neighbors(analysisId, current, {
            filter: derived.expression,
            direction,
          })
          if (result.packet_number === null || result.boundary === true) {
            setBoundary((previous) => ({ ...previous, [direction]: true }))
          } else {
            setBoundary((previous) => ({ ...previous, [direction]: false }))
            onSelect(result.packet_number)
          }
        } catch (cause) {
          const apiError = toApiError(cause)
          const detail = apiError.details?.reason
          setError(
            `${apiError.message}${typeof detail === 'string' && detail !== '' ? ` — ${detail}` : ''}`,
          )
        } finally {
          setPending(null)
        }
      })()
    },
    [analysisId, current, derived.expression, onSelect, pending],
  )

  const noSelection = current === null
  const blocked = valid === false
  const mismatched =
    valid === true &&
    traversalTotal !== null &&
    filteredTotal !== null &&
    traversalTotal !== filteredTotal

  const title = [
    `Steps through: ${derived.expression}`,
    ...derived.notes.map((note) => `Note: ${note}`),
    noSelection ? 'Select a packet first.' : '',
    blocked ? `The display-filter form of this filter is not valid: ${reason ?? 'reason unknown'}` : '',
  ]
    .filter((part) => part !== '')
    .join('\n')

  return (
    <span className="flex items-center gap-1.5">
      <button
        type="button"
        className="btn px-1.5 py-1"
        disabled={noSelection || blocked || pending !== null || boundary.prev || listBusy}
        onClick={() => go('prev')}
        title={`${boundary.prev ? 'No earlier matching packet. ' : ''}${title}`}
      >
        {pending === 'prev' ? (
          <Loader2 size={12} className="animate-spin" aria-hidden />
        ) : (
          <ChevronLeft size={12} aria-hidden />
        )}
        Prev match
      </button>
      <button
        type="button"
        className="btn px-1.5 py-1"
        disabled={noSelection || blocked || pending !== null || boundary.next || listBusy}
        onClick={() => go('next')}
        title={`${boundary.next ? 'No later matching packet. ' : ''}${title}`}
      >
        {pending === 'next' ? (
          <Loader2 size={12} className="animate-spin" aria-hidden />
        ) : (
          <ChevronRight size={12} aria-hidden />
        )}
        Next match
      </button>
      <span
        className={clsx(
          'mono max-w-[16rem] truncate text-2xs',
          blocked ? 'text-danger' : 'text-faint',
        )}
        title={title}
      >
        {blocked ? (
          <span className="flex items-center gap-1">
            <TriangleAlert size={11} aria-hidden />
            not traversable
          </span>
        ) : (
          truncate(derived.expression, 42)
        )}
      </span>
      {error ? (
        <span className="max-w-[18rem] truncate text-2xs text-danger" title={error} role="alert">
          {error}
        </span>
      ) : null}
      {mismatched ? (
        <span
          className="max-w-[18rem] truncate text-2xs text-warn"
          title={`The display-filter form of the current filter matches ${traversalTotal} frame(s) while the filtered list holds ${filteredTotal} row(s). Next/previous steps through the display-filter set.`}
        >
          traversal set differs ({traversalTotal} vs {filteredTotal})
        </span>
      ) : null}
    </span>
  )
}

export default PacketNavigator
