import { useEffect, useState } from 'react'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import MonoCell from '@/components/MonoCell'
import PacketDetailView from '@/components/findings/PacketDetailView'
import { formatBytes, formatClockTime, formatNumber } from '@/utils/format'
import type { FindingContextPacket } from '@/types'

export interface FindingPacketsProps {
  analysisId: string
  packets: FindingContextPacket[]
  truncated: boolean
  limit: number
  alertingCount: number
}

/** The packets that triggered the alert, with the dissection of the selected one. */
export function FindingPackets({
  analysisId,
  packets,
  truncated,
  limit,
  alertingCount,
}: FindingPacketsProps) {
  const [selected, setSelected] = useState<number | null>(packets[0]?.number ?? null)

  useEffect(() => {
    setSelected(packets[0]?.number ?? null)
  }, [packets])

  if (packets.length === 0) {
    return (
      <div className="px-3 py-8 text-center text-2xs text-muted">
        This finding recorded no packet numbers, so there is nothing to dissect. That happens for
        rules that describe a host or a summary rather than a single frame.
      </div>
    )
  }

  const index = packets.findIndex((packet) => packet.number === selected)
  const step = (delta: number) => {
    const next = packets[index + delta]
    if (next) setSelected(next.number)
  }

  return (
    <div className="flex flex-col gap-3 p-3">
      <div className="panel overflow-hidden">
        <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
          <span className="text-2xs text-faint">
            {formatNumber(packets.length)} packet(s) shown
            {truncated ? ` of a cap of ${formatNumber(limit)} — the rule matched more` : ''} ·{' '}
            {formatNumber(alertingCount)} alerting packet(s) in the finding
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              className="btn px-1.5 py-1"
              disabled={index <= 0}
              onClick={() => step(-1)}
              title="Previous packet of this finding"
            >
              <ChevronLeft size={13} aria-hidden />
            </button>
            <button
              type="button"
              className="btn px-1.5 py-1"
              disabled={index < 0 || index >= packets.length - 1}
              onClick={() => step(1)}
              title="Next packet of this finding"
            >
              <ChevronRight size={13} aria-hidden />
            </button>
          </div>
        </div>
        <div className="max-h-72 overflow-auto">
          <table className="dt">
            <thead>
              <tr>
                <th className="text-right">#</th>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Proto</th>
                <th className="text-right">Length</th>
                <th>Flags</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((packet) => (
                <tr
                  key={packet.number}
                  className={clsx('cursor-pointer', selected === packet.number && 'selected')}
                  onClick={() => setSelected(packet.number)}
                >
                  <td className="text-right">{packet.number}</td>
                  <td>{formatClockTime(packet.time_epoch)}</td>
                  <td>
                    <MonoCell maxWidth={220}>{`${packet.src_ip ?? '-'}${
                      packet.src_port !== null && packet.src_port !== undefined
                        ? `:${packet.src_port}`
                        : ''
                    }`}</MonoCell>
                  </td>
                  <td>
                    <MonoCell maxWidth={220}>{`${packet.dst_ip ?? '-'}${
                      packet.dst_port !== null && packet.dst_port !== undefined
                        ? `:${packet.dst_port}`
                        : ''
                    }`}</MonoCell>
                  </td>
                  <td className="text-muted">{packet.protocol ?? '-'}</td>
                  <td className="text-right">
                    {formatBytes(packet.frame_len ?? packet.length ?? null)}
                  </td>
                  <td>
                    <MonoCell maxWidth={120}>{packet.tcp_flags}</MonoCell>
                  </td>
                  <td>
                    <MonoCell maxWidth={360} title={packet.info ?? undefined}>
                      {packet.info}
                    </MonoCell>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected !== null ? (
        <PacketDetailView analysisId={analysisId} number={selected} />
      ) : null}
    </div>
  )
}

export default FindingPackets