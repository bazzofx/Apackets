import { RefreshCw, X } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Panel from '@/components/Panel'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import type { PacketDetail } from '@/types'
import { EMPTY, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import { HexDumpView } from './HexDumpView'
import { LayerTree } from './LayerTree'
import { packetLength } from './PacketTable'

/**
 * Packet detail pane: the summary row the list already knows, the decoded
 * protocol layer tree and the byte dump.
 *
 * Every absent field renders the em dash with a reason in its tooltip — the pane
 * never prints `undefined`/`null` and never invents a value.
 */

/** A value plus its copy affordance, for the identity fields worth reusing. */
function CopyableValue({ value, label }: { value: string | null; label: string }) {
  if (value === null || value === '') return <span className="text-faint">{EMPTY}</span>
  return (
    <span className="inline-flex items-center gap-1">
      <span className="mono break-all">{value}</span>
      <CopyButton value={value} label={label} className="border-transparent bg-transparent px-0.5 py-0 text-faint" />
    </span>
  )
}

function SummaryBody({ detail }: { detail: PacketDetail }) {
  const flags = detail.tcp_flags === null ? null : detail.tcp_flags.replace(/\u00b7/g, '.')
  const length = packetLength(detail)

  return (
    <DetailGrid columns={3}>
      <DetailItem
        label="Time"
        value={formatTimestamp(detail.time_epoch)}
        title={detail.time_epoch === null ? undefined : `frame.time_epoch = ${detail.time_epoch}`}
        unavailableReason="The frame timestamp was not indexed for this packet."
      />
      <DetailItem
        label="Since first frame"
        value={detail.time_relative === null ? null : formatDuration(detail.time_relative)}
        unavailableReason="frame.time_relative was not recorded for this packet."
      />
      <DetailItem
        label="Frame length"
        value={length === null ? null : `${formatNumber(length)} bytes`}
        unavailableReason="frame.len was not indexed for this packet."
      />
      <DetailItem
        label="Source"
        value={<CopyableValue value={detail.src_ip} label="Copy the source IP" />}
        title={detail.src_ip ?? undefined}
        mono={false}
        unavailableReason="No IP (or IPv6) source address was dissected."
      />
      <DetailItem
        label="Source port"
        value={
          detail.src_port === null ? null : <CopyableValue value={String(detail.src_port)} label="Copy the source port" />
        }
        mono={false}
        unavailableReason="Non-TCP/UDP frames have no ports."
      />
      <DetailItem
        label="Destination"
        value={<CopyableValue value={detail.dst_ip} label="Copy the destination IP" />}
        title={detail.dst_ip ?? undefined}
        mono={false}
        unavailableReason="No IP (or IPv6) destination address was dissected."
      />
      <DetailItem
        label="Destination port"
        value={
          detail.dst_port === null ? null : <CopyableValue value={String(detail.dst_port)} label="Copy the destination port" />
        }
        mono={false}
        unavailableReason="Non-TCP/UDP frames have no ports."
      />
      <DetailItem label="Protocol" value={detail.protocol} unavailableReason="No display protocol was recorded." />
      <DetailItem label="Transport" value={detail.transport} unavailableReason="No transport protocol was dissected." />
      <DetailItem
        label="TCP flags"
        value={flags === null ? null : <CopyableValue value={flags} label="Copy the TCP flags" />}
        mono={false}
        title={detail.tcp_flags ?? undefined}
        unavailableReason="tcp.flags.str is present only for TCP frames."
      />
      <DetailItem
        label="Dissection chain"
        value={detail.protocols}
        title={detail.protocols ?? undefined}
        unavailableReason="frame.protocols was not recorded."
      />
      <DetailItem
        label="TCP stream"
        value={detail.tcp_stream === null || detail.tcp_stream === undefined ? null : detail.tcp_stream}
        unavailableReason="tcp.stream is present only for TCP frames."
      />
      <DetailItem
        label="TTL / hop limit"
        value={detail.ttl}
        unavailableReason="ip.ttl / ipv6.hlim is present only for IP frames."
      />
      <DetailItem
        label="VLAN id"
        value={detail.vlan_id}
        unavailableReason="vlan.id is present only for 802.1Q frames."
      />
      <DetailItem label="IP version" value={detail.ip_version} unavailableReason="No IP layer was dissected." />
      <DetailItem
        label="Source MAC"
        value={detail.eth_src}
        title={detail.eth_src ?? undefined}
        unavailableReason="eth.src is present only for Ethernet frames."
      />
      <DetailItem
        label="Destination MAC"
        value={detail.eth_dst}
        title={detail.eth_dst ?? undefined}
        unavailableReason="eth.dst is present only for Ethernet frames."
      />
      <DetailItem
        label="HTTP"
        value={
          detail.http_method === null && detail.http_uri === null
            ? null
            : `${detail.http_method ?? '?'} ${detail.http_uri ?? ''}`.trim()
        }
        unavailableReason="No HTTP request field belongs to this packet."
      />
      <DetailItem
        label="HTTP host"
        value={detail.http_host}
        title={detail.http_host ?? undefined}
        unavailableReason="No Host header was dissected for this packet."
      />
      <DetailItem
        label="HTTP status"
        value={detail.http_status}
        unavailableReason="No HTTP response code belongs to this packet."
      />
      <DetailItem
        label="DNS query"
        value={detail.dns_query}
        title={detail.dns_query ?? undefined}
        unavailableReason="No DNS question name was dissected for this packet."
      />
      <DetailItem
        label="TLS SNI"
        value={detail.tls_sni}
        title={detail.tls_sni ?? undefined}
        unavailableReason="No TLS server_name extension was dissected for this packet."
      />
      <DetailItem
        label="TLS version"
        value={detail.tls_version}
        unavailableReason="No TLS handshake version was dissected for this packet."
      />
    </DetailGrid>
  )
}

export interface PacketDetailPanelProps {
  /** Frame number being inspected. */
  packetNumber: number
  detail: PacketDetail | undefined
  isLoading: boolean
  error: unknown
  onRetry: () => void
  onClose: () => void
  /** Shown in the header so the pane can explain a packet outside the page. */
  pageNote?: string
}

export function PacketDetailPanel({
  packetNumber,
  detail,
  isLoading,
  error,
  onRetry,
  onClose,
  pageNote,
}: PacketDetailPanelProps) {
  return (
    <div className="flex flex-col gap-3">
      <Panel
        title={`Packet ${formatNumber(packetNumber)}`}
        subtitle={
          detail
            ? [
                detail.protocols ?? 'no dissection chain',
                `frame.len ${formatNumber(packetLength(detail))}`,
                detail.info ?? '',
              ]
                .filter((part) => part !== '')
                .join(' · ')
            : pageNote ?? 'loading from the retained capture'
        }
        flush
        actions={
          <>
            <button
              type="button"
              className="btn px-1.5 py-1"
              onClick={onRetry}
              disabled={isLoading}
              title="Re-read this packet from the capture"
            >
              <RefreshCw size={12} aria-hidden />
              Reload
            </button>
            <button type="button" className="btn px-1.5 py-1" onClick={onClose} title="Clear the selection">
              <X size={12} aria-hidden />
              Close
            </button>
          </>
        }
      >
        {isLoading ? (
          <LoadingState label={`Loading packet ${packetNumber}…`} rows={5} />
        ) : error ? (
          <ErrorState error={error} title="Could not load the packet" onRetry={onRetry} />
        ) : !detail ? (
          <div className="p-3">
            <SectionNote>
              The backend returned no detail for packet {formatNumber(packetNumber)}.
            </SectionNote>
          </div>
        ) : (
          <div className="p-3">
            <SummaryBody detail={detail} />
          </div>
        )}
      </Panel>

      {detail ? (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          <Panel
            title="Protocol layers"
            subtitle={`${(detail.layer_order ?? []).length} layers in the dissection chain`}
            flush
          >
            <div className="max-h-[52vh] overflow-auto">
              <LayerTree layers={detail.layers} layerOrder={detail.layer_order ?? []} />
            </div>
          </Panel>
          <Panel title="Bytes" subtitle="tshark -x dump plus the ASCII rendering" flush>
            <HexDumpView detail={detail} />
          </Panel>
        </div>
      ) : null}
    </div>
  )
}

export default PacketDetailPanel
