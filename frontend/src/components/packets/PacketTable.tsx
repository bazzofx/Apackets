import clsx from 'clsx'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import MonoCell from '@/components/MonoCell'
import type { PacketSummary, SortOrder } from '@/types'
import { EMPTY, formatNumber, formatTimestamp } from '@/utils/format'

/**
 * Dense packet list.
 *
 * Columns are exactly the ones the packet browser is specified with: packet
 * number, time, source IP, source port, destination IP, destination port,
 * protocol, length, TCP flags and info. Frame length is read from `frame_len`
 * (with the contract §7 `length` spelling accepted as a fallback) and the MAC
 * addresses from `eth_src`/`eth_dst` — those are the names the live API sends.
 */

/** Frame length under either spelling the API has used. */
export function packetLength(packet: PacketSummary): number | null {
  return packet.frame_len ?? packet.length ?? null
}

export interface SortableColumn {
  /** Allow-listed `sort` value, or null when the column cannot be sorted. */
  key: string | null
  label: string
  title: string
  numeric?: boolean
}

export const PACKET_COLUMNS: SortableColumn[] = [
  { key: 'number', label: '#', title: 'frame.number — sortable', numeric: true },
  { key: 'time_epoch', label: 'time', title: 'frame.time_epoch — sortable' },
  { key: 'src_ip', label: 'source', title: 'ip.src / ipv6.src — sortable' },
  { key: 'src_port', label: 'sport', title: 'tcp.srcport / udp.srcport — sortable', numeric: true },
  { key: 'dst_ip', label: 'destination', title: 'ip.dst / ipv6.dst — sortable' },
  { key: 'dst_port', label: 'dport', title: 'tcp.dstport / udp.dstport — sortable', numeric: true },
  { key: 'protocol', label: 'protocol', title: '_ws.col.Protocol — sortable' },
  { key: 'frame_len', label: 'len', title: 'frame.len — sortable', numeric: true },
  { key: null, label: 'tcp flags', title: 'tcp.flags.str — not in the sort allow-list' },
  { key: null, label: 'info', title: '_ws.col.Info — not in the sort allow-list' },
]

interface SortHeaderProps {
  column: SortableColumn
  sort: string
  order: SortOrder
  onSort: (key: string) => void
}

function SortHeader({ column, sort, order, onSort }: SortHeaderProps) {
  const align = column.numeric ? 'text-right' : 'text-left'
  if (column.key === null) {
    return (
      <th className={align} title={column.title}>
        {column.label}
      </th>
    )
  }
  const active = sort === column.key
  const Icon = !active ? ChevronsUpDown : order === 'asc' ? ArrowUp : ArrowDown
  return (
    <th className={align} title={column.title} aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        className={clsx(
          'inline-flex items-center gap-1 rounded px-0.5 hover:text-text',
          active ? 'text-accent2' : 'text-muted',
        )}
        onClick={() => onSort(column.key as string)}
        title={`Sort by ${column.label}${active ? ` (currently ${order})` : ''}`}
      >
        {column.label}
        <Icon size={11} aria-hidden className={active ? undefined : 'opacity-50'} />
      </button>
    </th>
  )
}

/** Copy affordance that only appears on the hovered (or focused) row. */
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

export interface PacketTableProps {
  items: PacketSummary[]
  /** Currently selected frame number. */
  selected: number | null
  onSelect: (packetNumber: number) => void
  sort: string
  order: SortOrder
  onSort: (key: string) => void
  /** Dim the body while a request is in flight. */
  busy?: boolean
  /** Tailwind max-height for the scroll container. */
  maxHeightClass?: string
}

export function PacketTable({
  items,
  selected,
  onSelect,
  sort,
  order,
  onSort,
  busy = false,
  maxHeightClass = 'max-h-[58vh]',
}: PacketTableProps) {
  return (
    <div className={clsx('overflow-auto', maxHeightClass, busy && 'opacity-60')}>
      <table className="dt">
        <thead>
          <tr>
            {PACKET_COLUMNS.map((column) => (
              <SortHeader
                key={column.label}
                column={column}
                sort={sort}
                order={order}
                onSort={onSort}
              />
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((packet) => {
            const isSelected = selected === packet.number
            const length = packetLength(packet)
            return (
              <tr
                key={packet.number}
                className={clsx('group cursor-pointer', isSelected && 'selected')}
                aria-selected={isSelected}
                tabIndex={0}
                onClick={() => onSelect(packet.number)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(packet.number)
                  }
                }}
                title={packet.protocols ? `protocols: ${packet.protocols}` : undefined}
              >
                <td className="text-right tabular-nums">{formatNumber(packet.number)}</td>
                <td title={packet.time_epoch === null ? undefined : String(packet.time_epoch)}>
                  {formatTimestamp(packet.time_epoch)}
                </td>
                <td>
                  <span className="flex items-center">
                    <MonoCell maxWidth={190}>{packet.src_ip}</MonoCell>
                    <CellCopy value={packet.src_ip} label="Copy the source IP" />
                  </span>
                </td>
                <td className="text-right tabular-nums">
                  <span className="flex items-center justify-end">
                    {packet.src_port === null ? (
                      <span className="text-faint">{EMPTY}</span>
                    ) : (
                      formatNumber(packet.src_port)
                    )}
                    <CellCopy value={packet.src_port} label="Copy the source port" />
                  </span>
                </td>
                <td>
                  <span className="flex items-center">
                    <MonoCell maxWidth={190}>{packet.dst_ip}</MonoCell>
                    <CellCopy value={packet.dst_ip} label="Copy the destination IP" />
                  </span>
                </td>
                <td className="text-right tabular-nums">
                  <span className="flex items-center justify-end">
                    {packet.dst_port === null ? (
                      <span className="text-faint">{EMPTY}</span>
                    ) : (
                      formatNumber(packet.dst_port)
                    )}
                    <CellCopy value={packet.dst_port} label="Copy the destination port" />
                  </span>
                </td>
                <td>
                  <MonoCell maxWidth={140} title={packet.protocol ?? undefined}>
                    {packet.protocol}
                  </MonoCell>
                </td>
                <td className="text-right tabular-nums">{formatNumber(length)}</td>
                <td>
                  <MonoCell maxWidth={130} title={packet.tcp_flags ?? undefined}>
                    {packet.tcp_flags === null ? null : packet.tcp_flags.replace(/\u00b7/g, '.')}
                  </MonoCell>
                </td>
                <td className="w-full">
                  <span className="flex items-center">
                    <MonoCell maxWidth={900} title={packet.info ?? undefined}>
                      {packet.info}
                    </MonoCell>
                    <CellCopy value={packet.info} label="Copy the info text" />
                  </span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default PacketTable
