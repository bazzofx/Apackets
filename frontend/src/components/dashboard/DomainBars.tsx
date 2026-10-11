import { Globe } from 'lucide-react'
import EmptyState from '@/components/EmptyState'
import { useThemeTokens } from '@/theme/ThemeProvider'
import MonoCell from '@/components/MonoCell'
import { formatBytes, formatNumber } from '@/utils/format'
import type { SummaryTopDomain } from '@/types'

export interface DomainBarsProps {
  domains: SummaryTopDomain[]
  onSelect?: (ip: string) => void
}

/** Ranked domains with a direction-split bar: sent vs received on one scale. */
export function DomainBars({ domains, onSelect }: DomainBarsProps) {
  const tokens = useThemeTokens()
  const sentColour = tokens.accent
  const receivedColour = tokens.accent2
  if (domains.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={Globe}
        title="No traffic could be attributed to a domain"
        description="Attribution needs two things: a name seen in a captured DNS answer, and traffic to that address in the same capture. A capture that only resolves names, or one whose traffic never touches a resolved address, legitimately produces an empty list."
        className="py-8"
      />
    )
  }

  const max = Math.max(1, ...domains.map((domain) => domain.bytes_total || 0))

  return (
    <div className="flex flex-col">
      {domains.map((domain, index) => {
        const sent = domain.bytes_sent || 0
        const received = domain.bytes_received || 0
        const sentWidth = (sent / max) * 100
        const receivedWidth = (received / max) * 100
        return (
          <div
            key={domain.domain}
            className="flex flex-col gap-1 border-b border-border/60 px-3 py-2 last:border-0"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono w-4 shrink-0 text-right text-2xs text-faint">{index + 1}</span>
              <MonoCell className="text-xs text-text" maxWidth={320} title={domain.domain}>
                {domain.domain}
              </MonoCell>
              <span className="ml-auto shrink-0 text-2xs text-muted">
                {formatNumber(domain.packets)} pkts · {formatNumber(domain.client_count)} client
                {domain.client_count === 1 ? '' : 's'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <div
                className="flex h-3 min-w-0 flex-1 items-stretch overflow-hidden rounded-sm bg-surface2"
                title={`sent ${formatBytes(sent)} · received ${formatBytes(received)}`}
              >
                <div style={{ width: `${sentWidth}%`, background: sentColour }} />
                <div style={{ width: `${receivedWidth}%`, background: receivedColour }} />
              </div>
              <span className="mono shrink-0 text-2xs text-text" title="Total bytes for this domain">
                {formatBytes(domain.bytes_total)}
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-muted">
              <span className="mono" style={{ color: sentColour }}>
                sent {formatBytes(sent)}
              </span>
              <span className="mono" style={{ color: receivedColour }}>
                received {formatBytes(received)}
              </span>
              {domain.ips.slice(0, 3).map((ip) => (
                <button
                  key={ip}
                  type="button"
                  className="mono text-faint hover:text-accent2"
                  onClick={() => onSelect?.(ip)}
                  title={`Open ${ip} on the Hosts page`}
                >
                  {ip}
                </button>
              ))}
              {domain.ips.length > 3 ? (
                <span className="text-faint" title={domain.ips.slice(3).join(', ')}>
                  +{domain.ips.length - 3} more
                </span>
              ) : null}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default DomainBars