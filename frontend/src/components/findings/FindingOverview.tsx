import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { ArrowDownRight, ArrowUpRight, Ban, Clock, Info, Lightbulb, ListTree, Scale } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EntityChips from '@/components/findings/EntityChips'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import { formatClockTime, formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import type { FindingContext } from '@/types'

export interface FindingOverviewProps {
  context: FindingContext
  onSelectRelated: (id: string) => void
}

function EndpointCard({
  endpoint,
  onPivot,
}: {
  endpoint: FindingContext['endpoints'][number]
  onPivot: (path: string) => void
}) {
  const isSource = endpoint.direction === 'source'
  return (
    <div className="panel flex flex-col gap-1 p-2.5">
      <div className="flex items-center gap-1.5">
        {isSource ? (
          <ArrowUpRight size={13} className="text-accent2" aria-hidden />
        ) : (
          <ArrowDownRight size={13} className="text-accent2" aria-hidden />
        )}
        <span className="text-2xs uppercase tracking-wider text-faint">{endpoint.direction}</span>
        {endpoint.is_private === 1 ? (
          <span className="chip border-border2 bg-surface2 text-faint">private</span>
        ) : null}
      </div>
      <button
        type="button"
        className="mono text-left text-sm text-text hover:text-accent2"
        onClick={() => onPivot(`/packets?ip=${encodeURIComponent(endpoint.ip)}`)}
        title="Show this host's packets"
      >
        {endpoint.ip}
      </button>
      <div className="flex flex-wrap items-center gap-1">
        {endpoint.ports.map((port) => (
          <button
            key={`${port.port}-${port.transport}`}
            type="button"
            className="chip border-border2 bg-surface2 text-text hover:border-accent hover:text-accent2"
            onClick={() => onPivot(`/packets?ip=${encodeURIComponent(endpoint.ip)}&port=${port.port}`)}
            title={`${formatNumber(port.packets)} packet(s) of this alert — show this port`}
          >
            {(port.transport ?? 'ip').toUpperCase()}/{port.port}
            {port.service ? ` ${port.service}` : ''}
          </button>
        ))}
      </div>
      {endpoint.mac ? (
        <div className="mono text-2xs text-faint">
          {endpoint.mac}
          {endpoint.hostnames.length > 0 ? ` · ${endpoint.hostnames.slice(0, 2).join(', ')}` : ''}
        </div>
      ) : null}
      <div className="text-2xs text-muted">
        {formatNumber(endpoint.packets_in_alert)} packet(s) in this alert · host totals{' '}
        {formatNumber(endpoint.packets_sent ?? null)} sent / {formatNumber(endpoint.packets_received ?? null)} received
      </div>
    </div>
  )
}

/** Why the rule fired, who was involved, and the evidence the backend recorded. */
export function FindingOverview({ context, onSelectRelated }: FindingOverviewProps) {
  const navigate = useNavigate()
  const [showRule, setShowRule] = useState(false)
  const { finding, rule, analysis, endpoints, related, timeline, counts, truncated } = context

  const evidence = (finding.evidence ?? {}) as Record<string, unknown>
  const matches = Array.isArray(evidence.matches)
    ? (evidence.matches as Record<string, unknown>[])
    : []
  const basis = typeof evidence.match_basis === 'string' ? evidence.match_basis : null
  const buffers = Array.isArray(evidence.buffers) ? (evidence.buffers as unknown[]).map(String) : []

  return (
    <div className="flex flex-col gap-3 p-3">
      <Panel flush title="Endpoints involved" subtitle="source and destination with the ports this alert used">
        <div className="grid grid-cols-1 gap-2 p-3 md:grid-cols-2 xl:grid-cols-3">
          {endpoints.length === 0 ? (
            <div className="text-2xs text-faint">No endpoints could be derived from this finding.</div>
          ) : (
            endpoints.map((endpoint) => (
              <EndpointCard
                key={`${endpoint.ip}-${endpoint.direction}`}
                endpoint={endpoint}
                onPivot={(path) => navigate(path)}
              />
            ))
          )}
        </div>
        {truncated.endpoints ? (
          <div className="px-3 pb-2 text-2xs text-faint">More endpoints were involved than are shown.</div>
        ) : null}
      </Panel>

      <Panel
        flush
        title="Why this fired"
        subtitle={`${finding.rule_id} · ${finding.severity}`}
        actions={
          <div className="flex items-center gap-1">
            <SeverityBadge severity={finding.severity} showLabel />
            <CopyButton value={finding.id} label="Copy finding id" />
          </div>
        }
      >
        <div className="flex flex-col gap-2 p-3">
          <div className="text-sm text-text">{finding.title}</div>
          {finding.description ? (
            <div className="text-2xs text-muted">{finding.description}</div>
          ) : null}
          <div className="whitespace-pre-wrap rounded border border-border bg-[#0d1526] p-2 text-2xs leading-relaxed text-text">
            {finding.reason}
          </div>
          {finding.recommendation ? (
            <div className="flex items-start gap-2 text-2xs text-muted">
              <Lightbulb size={13} className="mt-0.5 shrink-0 text-warn" aria-hidden />
              <span>{finding.recommendation}</span>
            </div>
          ) : null}
          {basis ? (
            <div className="flex items-start gap-2 text-2xs text-faint">
              <Scale size={13} className="mt-0.5 shrink-0" aria-hidden />
              <span>
                Match basis: {basis}
                {buffers.length > 0 ? ` · buffers: ${buffers.join(', ')}` : ''}
              </span>
            </div>
          ) : null}
        </div>
      </Panel>

      {matches.length > 0 ? (
        <Panel flush title="Matched evidence" subtitle={`${matches.length} recorded match(es)`}>
          <div className="overflow-auto">
            <table className="dt">
              <thead>
                <tr>
                  <th className="text-right">Packet</th>
                  <th>Where</th>
                  <th>Buffers</th>
                  <th>Excerpt</th>
                </tr>
              </thead>
              <tbody>
                {matches.map((match, index) => (
                  <tr key={index}>
                    <td className="text-right">
                      {typeof match.packet === 'number' ? (
                        <button
                          type="button"
                          className="text-accent2 hover:underline"
                          onClick={() => navigate(`/packets?number=${match.packet}`)}
                        >
                          {match.packet}
                        </button>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      <MonoCell maxWidth={280} title={String(match.where ?? '')}>
                        {match.where ? String(match.where) : null}
                      </MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={220}>
                        {Array.isArray(match.fields) ? match.fields.map(String).join(', ') : null}
                      </MonoCell>
                    </td>
                    <td>
                      <MonoCell maxWidth={420} title={String(match.excerpt ?? '')}>
                        {match.excerpt ? String(match.excerpt) : null}
                      </MonoCell>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}

      {rule ? (
        <Panel
          flush
          title="Suricata rule behind this alert"
          subtitle={`sid ${rule.sid} rev ${rule.rev} · ${rule.source}${rule.category ? ` · ${rule.category}` : ''}`}
          actions={
            <div className="flex items-center gap-1">
              <button type="button" className="btn px-1.5 py-0.5" onClick={() => setShowRule((value) => !value)}>
                <ListTree size={12} aria-hidden />
                {showRule ? 'hide rule text' : 'show rule text'}
              </button>
              <button
                type="button"
                className="btn px-1.5 py-0.5"
                onClick={() => navigate(`/settings?sid=${rule.sid}`)}
                title="Open the rule editor in Settings"
              >
                edit in settings
              </button>
            </div>
          }
        >
          <dl className="grid grid-cols-1 gap-x-4 gap-y-1 p-3 text-2xs md:grid-cols-[9rem_1fr]">
            <dt className="text-faint">Action / protocol</dt>
            <dd className="mono text-text">
              {rule.action} {rule.protocol}
            </dd>
            <dt className="text-faint">Classtype</dt>
            <dd className="mono text-text">{rule.classtype ?? '—'}</dd>
            <dt className="text-faint">Header</dt>
            <dd className="mono text-text">
              {rule.src_net} {rule.src_port} {rule.direction} {rule.dst_net} {rule.dst_port}
            </dd>
            <dt className="text-faint">State</dt>
            <dd className="flex items-center gap-1">
              <span className={clsx('chip', rule.enabled ? 'border-ok/50 bg-ok/15 text-ok' : 'border-border2 bg-surface2 text-faint')}>
                {rule.enabled ? 'enabled' : 'disabled'}
              </span>
              {!rule.supported ? (
                <span className="chip border-warn/50 bg-warn/15 text-warn" title={rule.unsupported.join(', ')}>
                  <Ban size={10} aria-hidden />
                  not evaluable by the matcher
                </span>
              ) : null}
            </dd>
            {rule.reference ? (
              <>
                <dt className="text-faint">Reference</dt>
                <dd className="mono break-all text-text">{rule.reference}</dd>
              </>
            ) : null}
          </dl>
          {showRule ? (
            <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-all border-t border-border bg-[#0d1526] p-2 text-2xs text-text">
              {rule.raw}
            </pre>
          ) : null}
        </Panel>
      ) : null}

      <Panel flush title="Artefacts" subtitle="everything this finding mentions">
        <div className="flex flex-col gap-1.5 p-3">
          <EntityChips
            label="addresses"
            values={finding.entities?.ips ?? []}
            onSelect={(value) => navigate(`/packets?ip=${encodeURIComponent(value)}`)}
          />
          <EntityChips
            label="names"
            values={finding.entities?.hostnames ?? []}
            onSelect={(value) => navigate(`/packets?search=${encodeURIComponent(value)}`)}
          />
          <EntityChips
            label="ports"
            values={finding.entities?.ports ?? []}
            onSelect={(value) => navigate(`/packets?port=${encodeURIComponent(value)}`)}
          />
          <EntityChips
            label="URIs"
            values={finding.entities?.uris ?? []}
            onSelect={(value) => navigate(`/packets?search=${encodeURIComponent(value)}`)}
          />
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Panel flush title="Timeline" subtitle="first and last activity of this alert">
          {timeline.length === 0 ? (
            <div className="px-3 py-6 text-center text-2xs text-faint">No timestamps recorded.</div>
          ) : (
            <ul className="flex flex-col">
              {timeline.map((entry, index) => (
                <li key={index} className="flex items-center gap-2 border-b border-border/50 px-3 py-1.5 last:border-0 text-2xs">
                  <Clock size={11} className="shrink-0 text-faint" aria-hidden />
                  <span className="mono text-muted">{formatClockTime(entry.t)}</span>
                  <span className="chip border-border2 bg-surface2 text-faint">{entry.kind}</span>
                  <span className="min-w-0 flex-1 truncate text-text" title={entry.label}>
                    {entry.label}
                  </span>
                  {entry.packet !== null && entry.packet !== undefined ? (
                    <button
                      type="button"
                      className="mono text-accent2 hover:underline"
                      onClick={() => navigate(`/packets?number=${entry.packet}`)}
                    >
                      #{entry.packet}
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel flush title="Scope of this alert" subtitle="what the context contains">
          <dl className="grid grid-cols-2 gap-x-3 gap-y-1 p-3 text-2xs">
            <dt className="text-faint">Alerting packets</dt>
            <dd className="mono text-text">{formatNumber(counts.alerting_packets)}</dd>
            <dt className="text-faint">Conversations</dt>
            <dd className="mono text-text">{formatNumber(counts.conversations)}</dd>
            <dt className="text-faint">Streams with content</dt>
            <dd className="mono text-text">{formatNumber(counts.streams)}</dd>
            <dt className="text-faint">HTTP / DNS / TLS rows</dt>
            <dd className="mono text-text">
              {formatNumber(counts.http)} / {formatNumber(counts.dns)} / {formatNumber(counts.tls)}
            </dd>
            <dt className="text-faint">Files</dt>
            <dd className="mono text-text">{formatNumber(counts.objects)}</dd>
            <dt className="text-faint">Related findings</dt>
            <dd className="mono text-text">{formatNumber(counts.related)}</dd>
            <dt className="text-faint">Capture</dt>
            <dd className="mono text-text">{analysis.original_filename}</dd>
            <dt className="text-faint">Capture length</dt>
            <dd className="mono text-text">{formatDuration(analysis.duration)}</dd>
            <dt className="text-faint">First packet</dt>
            <dd className="mono text-text">{formatTimestamp(analysis.capture_start)}</dd>
          </dl>
          <div className="flex items-start gap-2 border-t border-border px-3 py-2 text-2xs text-faint">
            <Info size={12} className="mt-0.5 shrink-0" aria-hidden />
            <span>
              A signature match is a lead, not a verdict. Confirm the activity against the host's
              expected behaviour before acting.
            </span>
          </div>
        </Panel>
      </div>

      {related.length > 0 ? (
        <Panel flush title="Related findings" subtitle={`${related.length} share artefacts with this one`}>
          <ul className="flex flex-col">
            {related.map((item) => (
              <li key={item.id} className="border-b border-border/50 last:border-0">
                <button
                  type="button"
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-surface2/70"
                  onClick={() => onSelectRelated(item.id)}
                >
                  <SeverityBadge severity={item.severity} showLabel />
                  <span className="min-w-0 flex-1 truncate text-xs text-text" title={item.title}>
                    {item.title}
                  </span>
                  <span className="flex shrink-0 items-center gap-1">
                    {item.shared.slice(0, 3).map((value) => (
                      <span key={value} className="chip border-border2 bg-surface2 text-faint">
                        {value}
                      </span>
                    ))}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  )
}

export default FindingOverview