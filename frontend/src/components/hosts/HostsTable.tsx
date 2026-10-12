/**
 * Dense host inventory table.
 *
 * Every cell renders either a primitive from the API or the em-dash placeholder —
 * nothing is derived that the backend did not report.
 */

import clsx from 'clsx'
import { ArrowDown, ArrowUp } from 'lucide-react'
import MonoCell from '@/components/MonoCell'
import {
  NameChips,
  PeerChip,
  PortChips,
  ProtocolChips,
  ScopeChip,
  parsePorts,
  parseProtocols,
  parseStringList,
} from '@/components/hosts/chips'
import type { Host, SortOrder } from '@/types'
import { formatBytes, formatNumber, formatTimestamp } from '@/utils/format'

/** Sort allow-list — mirrors `routes_hosts.SORTABLE` exactly. */
export const HOST_SORT_KEYS = [
  'ip',
  'packets_sent',
  'bytes_sent',
  'bytes_received',
  'first_seen',
  'last_seen',
  'peer_count',
] as const

export type HostSortKey = (typeof HOST_SORT_KEYS)[number]

export function isHostSortKey(value: string | null | undefined): value is HostSortKey {
  return value !== null && value !== undefined && (HOST_SORT_KEYS as readonly string[]).includes(value)
}

export const HOST_SORT_LABELS: Record<HostSortKey, string> = {
  ip: 'IP address',
  packets_sent: 'Packets sent',
  bytes_sent: 'Bytes sent',
  bytes_received: 'Bytes received',
  first_seen: 'First seen',
  last_seen: 'Last seen',
  peer_count: 'Peers',
}

interface SortHeaderProps {
  label: string
  sortKey: HostSortKey
  activeKey: HostSortKey
  order: SortOrder
  onSort: (key: HostSortKey) => void
  align?: 'left' | 'right'
}

function SortHeader({ label, sortKey, activeKey, order, onSort, align = 'left' }: SortHeaderProps) {
  const active = activeKey === sortKey
  return (
    <th
      aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}
      className={align === 'right' ? 'text-right' : undefined}
    >
      <button
        type="button"
        className={clsx(
          'inline-flex items-center gap-1 uppercase tracking-wider hover:text-text',
          active ? 'text-text' : 'text-muted',
          align === 'right' && 'flex-row-reverse',
        )}
        onClick={() => onSort(sortKey)}
        title={`Sort by ${label.toLowerCase()} (${active && order === 'asc' ? 'descending' : 'ascending'})`}
      >
        {active ? (
          order === 'asc' ? (
            <ArrowUp size={11} aria-hidden />
          ) : (
            <ArrowDown size={11} aria-hidden />
          )
        ) : null}
        {label}
      </button>
    </th>
  )
}

export interface HostsTableProps {
  hosts: Host[]
  selectedIp: string | null
  onSelect: (ip: string) => void
  sort: HostSortKey
  order: SortOrder
  onSort: (key: HostSortKey) => void
}

/**
 * One row per observed IP address. `ports`, `protocols`, `dns_names`, `tls_sni`
 * and `peers` arrive as JSON columns and are rendered as capped chip lists.
 */
export function HostsTable({ hosts, selectedIp, onSelect, sort, order, onSort }: HostsTableProps) {
  return (
    <div className="max-h-[34rem] overflow-auto">
      <table className="dt">
        <thead>
          <tr>
            <SortHeader label="IP" sortKey="ip" activeKey={sort} order={order} onSort={onSort} />
            <th>MAC</th>
            <th>Scope</th>
            <SortHeader
              label="First seen"
              sortKey="first_seen"
              activeKey={sort}
              order={order}
              onSort={onSort}
            />
            <SortHeader
              label="Last seen"
              sortKey="last_seen"
              activeKey={sort}
              order={order}
              onSort={onSort}
            />
            <SortHeader
              label="Pkts sent"
              sortKey="packets_sent"
              activeKey={sort}
              order={order}
              onSort={onSort}
              align="right"
            />
            <th className="text-right">Pkts recv</th>
            <SortHeader
              label="Bytes sent"
              sortKey="bytes_sent"
              activeKey={sort}
              order={order}
              onSort={onSort}
              align="right"
            />
            <SortHeader
              label="Bytes recv"
              sortKey="bytes_received"
              activeKey={sort}
              order={order}
              onSort={onSort}
              align="right"
            />
            <th>Top ports</th>
            <th>Protocols</th>
            <th>Names</th>
            <SortHeader
              label="Peers"
              sortKey="peer_count"
              activeKey={sort}
              order={order}
              onSort={onSort}
            />
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => {
            const selected = host.ip === selectedIp
            const dnsNames = parseStringList(host.dns_names)
            const tlsSni = parseStringList(host.tls_sni)
            const peers = parseStringList(host.peers)
            return (
              <tr
                key={host.ip}
                className={selected ? 'selected' : undefined}
                /* Anywhere on the row, so the whole row is a right-click target
                   for this host (see components/context/IpContextMenu.tsx). */
                data-ip={host.ip}
              >
                <td>
                  <button
                    type="button"
                    className={clsx(
                      'mono text-left hover:underline',
                      selected ? 'text-accent2' : 'text-text',
                    )}
                    onClick={() => onSelect(host.ip)}
                    title={`Show detail for ${host.ip}`}
                  >
                    {host.ip}
                  </button>
                </td>
                <td>
                  <MonoCell maxWidth={150}>{host.mac}</MonoCell>
                </td>
                <td>
                  <ScopeChip isPrivate={host.is_private} />
                </td>
                <td className="text-muted">{formatTimestamp(host.first_seen)}</td>
                <td className="text-muted">{formatTimestamp(host.last_seen)}</td>
                <td className="text-right">{formatNumber(host.packets_sent)}</td>
                <td className="text-right">{formatNumber(host.packets_received)}</td>
                <td className="text-right">{formatBytes(host.bytes_sent)}</td>
                <td className="text-right">{formatBytes(host.bytes_received)}</td>
                <td className="whitespace-normal">
                  <PortChips ports={parsePorts(host.ports)} max={3} />
                </td>
                <td className="whitespace-normal">
                  <ProtocolChips protocols={parseProtocols(host.protocols)} max={3} />
                </td>
                <td className="whitespace-normal">
                  <NameChips dnsNames={dnsNames} tlsSni={tlsSni} max={2} />
                </td>
                <td>
                  <PeerChip peers={peers} peerCount={host.peer_count} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export default HostsTable
