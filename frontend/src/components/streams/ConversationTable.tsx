import clsx from 'clsx'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import MonoCell from '@/components/MonoCell'
import type { Conversation, ConversationState, SortOrder } from '@/types'
import { formatBytes, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'

/**
 * Dense conversation table.
 *
 * Every number comes from the `conversations` table: `packets_a_to_b`,
 * `bytes_a_to_b`, `packets_b_to_a`, `bytes_b_to_a` and their totals, plus the
 * TCP `state` the backend derived from the flags it actually saw. Nothing here
 * re-derives or estimates a value, and a missing one stays an em dash.
 */

/** Stable identity of a conversation: transport plus stream id. */
export function conversationKey(conversation: Conversation): string {
  return `${conversation.transport}:${conversation.stream_id}`
}

/** Parse the `transport:id` form stored in the URL. */
export function parseConversationKey(key: string): { transport: 'tcp' | 'udp'; streamId: number } | null {
  const [transport, rawId] = key.split(':')
  if (transport !== 'tcp' && transport !== 'udp') return null
  const streamId = Number(rawId)
  if (!Number.isFinite(streamId)) return null
  return { transport, streamId }
}

const STATE_STYLES: Record<ConversationState, string> = {
  established: 'border-ok/50 bg-ok/15 text-ok',
  reset: 'border-danger/50 bg-danger/15 text-red-300',
  half_open: 'border-warn/50 bg-warn/15 text-warn',
  closed: 'border-border2 bg-surface2 text-muted',
  unknown: 'border-border2 bg-surface2 text-faint',
}

/** TCP connection state as reported by the backend. */
export function StateChip({ state }: { state: ConversationState }) {
  const style = STATE_STYLES[state] ?? STATE_STYLES.unknown
  return (
    <span className={clsx('chip', style)} title={`conversation state: ${state}`}>
      {state}
    </span>
  )
}

interface SortHeaderProps {
  label: string
  sortKey: string | null
  sort: string
  order: SortOrder
  onSort: (key: string) => void
  numeric?: boolean
  title: string
}

function SortHeader({ label, sortKey, sort, order, onSort, numeric = false, title }: SortHeaderProps) {
  const align = numeric ? 'text-right' : 'text-left'
  if (sortKey === null) {
    return (
      <th className={align} title={title}>
        {label}
      </th>
    )
  }
  const active = sort === sortKey
  const Icon = !active ? ChevronsUpDown : order === 'asc' ? ArrowUp : ArrowDown
  return (
    <th className={align} title={title}>
      <button
        type="button"
        className={clsx(
          'inline-flex items-center gap-1 rounded px-0.5 hover:text-text',
          active ? 'text-accent2' : 'text-muted',
        )}
        onClick={() => onSort(sortKey)}
        title={`Sort by ${title}${active ? ` (currently ${order})` : ''}`}
      >
        {label}
        <Icon size={11} aria-hidden className={active ? undefined : 'opacity-50'} />
      </button>
    </th>
  )
}

function CellCopy({ value, label }: { value: string | number | null; label: string }) {
  if (value === null || value === '') return null
  return (
    <span
      className="ml-1 inline-flex opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100"
      onClick={(event) => event.stopPropagation()}
    >
      <CopyButton
        value={String(value)}
        label={label}
        className="border-transparent bg-transparent px-0.5 py-0 text-faint hover:text-text"
      />
    </span>
  )
}

export interface ConversationTableProps {
  items: Conversation[]
  /** `transport:id` of the expanded conversation. */
  selectedKey: string | null
  onSelect: (conversation: Conversation) => void
  sort: string
  order: SortOrder
  onSort: (key: string) => void
  busy?: boolean
}

export function ConversationTable({
  items,
  selectedKey,
  onSelect,
  sort,
  order,
  onSort,
  busy = false,
}: ConversationTableProps) {
  const header = (
    <tr>
      <SortHeader
        label="endpoint A"
        sortKey="endpoint_a"
        sort={sort}
        order={order}
        onSort={onSort}
        title="endpoint_a (the side whose SYN / first datagram was seen first)"
      />
      <th title="Endpoint B">endpoint B</th>
      <th title="transport protocol">transport</th>
      <th className="text-right" title="The TCP/UDP stream id this conversation belongs to">
        stream
      </th>
      <SortHeader
        label="pkts A->B"
        sortKey={null}
        sort={sort}
        order={order}
        onSort={onSort}
        numeric
        title="packets_a_to_b"
      />
      <SortHeader
        label="pkts B->A"
        sortKey={null}
        sort={sort}
        order={order}
        onSort={onSort}
        numeric
        title="packets_b_to_a"
      />
      <SortHeader
        label="pkts"
        sortKey="packets_total"
        sort={sort}
        order={order}
        onSort={onSort}
        numeric
        title="packets_total"
      />
      <th className="text-right" title="bytes_a_to_b">
        bytes A-&gt;B
      </th>
      <th className="text-right" title="bytes_b_to_a">
        bytes B-&gt;A
      </th>
      <SortHeader
        label="bytes"
        sortKey="bytes_total"
        sort={sort}
        order={order}
        onSort={onSort}
        numeric
        title="bytes_total"
      />
      <SortHeader
        label="start"
        sortKey="start_time"
        sort={sort}
        order={order}
        onSort={onSort}
        title="start_time"
      />
      <th title="end_time">end</th>
      <SortHeader
        label="duration"
        sortKey="duration"
        sort={sort}
        order={order}
        onSort={onSort}
        numeric
        title="duration"
      />
      <th title="TCP connection state derived from the observed flags">state</th>
      <th title="Application protocols observed inside the stream (comma separated)">protocols</th>
    </tr>
  )

  return (
    <div className={clsx('max-h-[56vh] overflow-auto', busy && 'opacity-60')}>
      <table className="dt">
        <thead>{header}</thead>
        <tbody>
          {items.map((conversation) => {
            const key = conversationKey(conversation)
            const isSelected = selectedKey === key
            return (
              <tr
                key={key}
                className={clsx('group cursor-pointer', isSelected && 'selected')}
                aria-selected={isSelected}
                tabIndex={0}
                onClick={() => onSelect(conversation)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(conversation)
                  }
                }}
                title={conversation.conv_id}
              >
                <td>
                  <span className="flex items-center">
                    <MonoCell maxWidth={210}>{conversation.endpoint_a}</MonoCell>
                    <CellCopy value={conversation.endpoint_a} label="Copy endpoint A" />
                  </span>
                </td>
                <td>
                  <span className="flex items-center">
                    <MonoCell maxWidth={210}>{conversation.endpoint_b}</MonoCell>
                    <CellCopy value={conversation.endpoint_b} label="Copy endpoint B" />
                  </span>
                </td>
                <td>
                  <span className="chip border-border2 bg-surface2 text-muted">
                    {conversation.transport}
                  </span>
                </td>
                <td className="text-right tabular-nums">{formatNumber(conversation.stream_id)}</td>
                <td className="text-right tabular-nums">
                  {formatNumber(conversation.packets_a_to_b)}
                </td>
                <td className="text-right tabular-nums">
                  {formatNumber(conversation.packets_b_to_a)}
                </td>
                <td className="text-right tabular-nums">{formatNumber(conversation.packets_total)}</td>
                <td className="text-right tabular-nums">{formatBytes(conversation.bytes_a_to_b)}</td>
                <td className="text-right tabular-nums">{formatBytes(conversation.bytes_b_to_a)}</td>
                <td className="text-right tabular-nums">{formatBytes(conversation.bytes_total)}</td>
                <td title={conversation.start_time === null ? undefined : String(conversation.start_time)}>
                  {formatTimestamp(conversation.start_time)}
                </td>
                <td title={conversation.end_time === null ? undefined : String(conversation.end_time)}>
                  {formatTimestamp(conversation.end_time)}
                </td>
                <td className="text-right tabular-nums">{formatDuration(conversation.duration)}</td>
                <td>
                  <StateChip state={conversation.state} />
                </td>
                <td>
                  <MonoCell maxWidth={140} title={conversation.protocols ?? undefined}>
                    {conversation.protocols}
                  </MonoCell>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default ConversationTable