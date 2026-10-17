import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Ban,
  Info,
  Lightbulb,
  ListTree,
  Scale,
  Target,
} from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EntityChips from '@/components/findings/EntityChips'
import { FollowConversationButton } from '@/components/findings/FollowConversationButton'
import MonoCell from '@/components/MonoCell'
import Panel from '@/components/Panel'
import SeverityBadge from '@/components/SeverityBadge'
import { formatDuration, formatNumber, formatTimestamp } from '@/utils/format'
import type { FindingContext } from '@/types'

export interface FindingOverviewProps {
  context: FindingContext
}

/**
 * What the match evidence cell shows, and where it came from.
 *
 * The backend records one evidence record per satisfied condition, naming the
 * buffer the rule inspected (`http.request_body`, `http.uri`, …), the byte offset
 * of the match in that buffer, and the matched bytes themselves. The excerpt drawn
 * beside it is the same buffer around that offset, so the tooltip spells the link
 * out instead of leaving it implicit.
 */
function evidenceTooltip(match: Record<string, unknown>): string {
  const parts: string[] = []
  if (match.buffer) parts.push(`matched in ${String(match.buffer)}`)
  if (typeof match.offset === 'number') parts.push(`at byte ${String(match.offset)}`)
  if (match.matched) parts.push(`bytes: ${String(match.matched)}`)
  if (match.matched_hex) parts.push(`hex: ${String(match.matched_hex)}`)
  if (match.evidence_error) parts.push(`evidence error: ${String(match.evidence_error)}`)
  const note = parts.length > 0 ? `${parts.join(', ')}. The excerpt is drawn from that buffer.` : ''
  const excerpt = match.excerpt ? String(match.excerpt) : ''
  return [note, excerpt].filter(Boolean).join(' ')
}

/** One end of the alert: its address, the ports it used, and what it is. */
function EndpointCard({
  endpoint,
  onPivot,
}: {
  endpoint: FindingContext['endpoints'][number]
  onPivot: (path: string) => void
}) {
  const isSource = endpoint.direction === 'source'
  return (
    <div className="panel flex min-w-0 flex-col gap-1 p-2.5">
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
        className="mono truncate text-left text-sm text-text hover:text-accent2"
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
        <div className="mono truncate text-2xs text-faint">
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

/** A labelled rule between the sections inside a card. */
function SectionLabel({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 px-3 pt-2">
      <span className="text-2xs font-semibold uppercase tracking-wider text-muted">{label}</span>
      <span className="h-px flex-1 bg-border" aria-hidden />
    </div>
  )
}

/**
 * The Overview tab: the alert itself, who and what it involves, the evidence, the
 * rule behind it, and the scope of the context.
 *
 * The alert's own text leads, minimised, so the first thing on the page is what
 * fired rather than a wall of prose. Endpoints and artefacts share one card
 * because they answer the same question - who and what was involved - and the
 * timeline and related findings are tabs of their own rather than cards here.
 */
export function FindingOverview({ context }: FindingOverviewProps) {
  const navigate = useNavigate()
  const [showRule, setShowRule] = useState(false)
  /* The alert's own text is the longest block on this page, so it starts
     minimised and opens on demand. */
  const [alertOpen, setAlertOpen] = useState(false)
  const { finding, rule, detection_rule: detectionRule, analysis, endpoints, counts, truncated } =
    context

  const evidence = (finding.evidence ?? {}) as Record<string, unknown>
  const matches = Array.isArray(evidence.matches)
    ? (evidence.matches as Record<string, unknown>[])
    : []
  const basis = typeof evidence.match_basis === 'string' ? evidence.match_basis : null
  const buffers = Array.isArray(evidence.buffers) ? (evidence.buffers as unknown[]).map(String) : []

  /* One line of the reason, so a minimised Alert panel still says what fired
     rather than only naming the rule. Panel truncates it and shows the whole
     text on hover. The reason is nullable, so an absent one yields no subtitle
     rather than the string "null". */
  const reasonPreview = (finding.reason ?? '').replace(/\s+/g, ' ').trim() || undefined

  const sources = endpoints.filter((endpoint) => endpoint.direction === 'source')
  const destinations = endpoints.filter((endpoint) => endpoint.direction === 'destination')

  return (
    <div className="flex flex-col gap-3 p-3">
      <Panel
        flush
        title="Alert"
        /* Minimised it shows one line of the reason, so the panel says what
           fired without being opened; expanded it shows the rule and severity. */
        subtitle={alertOpen ? `${finding.rule_id} · ${finding.severity}` : reasonPreview}
        onHeaderToggle={() => setAlertOpen((value) => !value)}
        headerExpanded={alertOpen}
        actions={
          <div className="flex items-center gap-1">
            <SeverityBadge severity={finding.severity} showLabel />
            <CopyButton value={finding.id} label="Copy finding id" />
          </div>
        }
      >
        {alertOpen ? (
          <div className="flex flex-col gap-2 p-3">
            <div className="text-sm text-text">{finding.title}</div>
            {finding.description ? (
              <div className="text-2xs text-muted">{finding.description}</div>
            ) : null}
            <div className="whitespace-pre-wrap rounded border border-border bg-bg p-2 text-2xs leading-relaxed text-text">
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
        ) : null}
      </Panel>

      <Panel
        flush
        title="Endpoints and artefacts"
        subtitle="who was involved, and every address, name, port and URI this finding mentions"
      >
        <SectionLabel label="Endpoints" />
        {endpoints.length === 0 ? (
          <div className="px-3 py-2 text-2xs text-faint">
            No endpoints could be derived from this finding.
          </div>
        ) : sources.length === 1 && destinations.length === 1 ? (
          /* One source and one destination: draw the direction of the traffic
             rather than leaving the reader to infer it from the card order. */
          <div className="grid grid-cols-1 items-center gap-2 p-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
            <EndpointCard endpoint={sources[0]} onPivot={(path) => navigate(path)} />
            <ArrowRight size={18} className="mx-auto shrink-0 text-accent2" aria-hidden />
            <EndpointCard endpoint={destinations[0]} onPivot={(path) => navigate(path)} />
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-2 p-3 md:grid-cols-2 xl:grid-cols-3">
            {endpoints.map((endpoint) => (
              <EndpointCard
                key={`${endpoint.ip}-${endpoint.direction}`}
                endpoint={endpoint}
                onPivot={(path) => navigate(path)}
              />
            ))}
          </div>
        )}
        {truncated.endpoints ? (
          <div className="px-3 pb-2 text-2xs text-faint">More endpoints were involved than are shown.</div>
        ) : null}

        <SectionLabel label="Artefacts" />
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

      {matches.length > 0 ? (
        <Panel
          flush
          className="border-accent/70 bg-accent/[0.05]"
          title={
            <span className="flex items-center gap-1.5">
              <Target size={12} className="text-accent" aria-hidden />
              Matched evidence
            </span>
          }
          subtitle={`${matches.length} recorded match(es)`}
          actions={<FollowConversationButton context={context} />}
        >
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
                          onClick={() => navigate(`/packets?sel=${match.packet}`)}
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
                      <div className="flex items-baseline gap-1">
                        <MonoCell maxWidth={420} title={evidenceTooltip(match)}>
                          {match.excerpt ? String(match.excerpt) : null}
                        </MonoCell>
                        {/* The offset is the match's position in the buffer named
                            in the previous column — the same buffer the excerpt
                            above was taken from. */}
                        {typeof match.offset === 'number' ? (
                          <span className="text-2xs text-faint" title="Byte offset of the match in that buffer">
                            @{String(match.offset)}
                          </span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}

      <div className="mt-1 flex items-center gap-2">
        <span className="text-2xs font-semibold uppercase tracking-wider text-muted">Rules</span>
        <span className="h-px flex-1 bg-border" aria-hidden />
      </div>

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
                onClick={() => navigate(`/alert-settings?sid=${rule.sid}`)}
                title="Open the rule editor in Alert Settings"
              >
                edit in Alert Settings
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
            <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-all border-t border-border bg-bg p-2 text-2xs text-text">
              {rule.raw}
            </pre>
          ) : null}
        </Panel>
      ) : detectionRule ? (
        <Panel
          flush
          title="Detection rule behind this alert"
          subtitle={
            'built-in rule ' +
            detectionRule.rule_id +
            ' · ' +
            detectionRule.severity +
            (detectionRule.enabled ? '' : ' · disabled')
          }
          actions={
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="btn px-1.5 py-0.5"
                onClick={() =>
                  navigate('/alert-settings?rule=' + encodeURIComponent(detectionRule.rule_id))
                }
                title="Open this rule in Alert Settings to enable it or change its thresholds"
              >
                edit in Alert Settings
              </button>
            </div>
          }
        >
          <dl className="grid grid-cols-1 gap-x-4 gap-y-1 p-3 text-2xs md:grid-cols-[9rem_1fr]">
            <dt className="text-faint">Rule</dt>
            <dd className="text-text">{detectionRule.title}</dd>
            <dt className="text-faint">Fires when</dt>
            <dd className="mono text-text">{detectionRule.threshold}</dd>
            <dt className="text-faint">State</dt>
            <dd>
              <span
                className={clsx(
                  'chip',
                  detectionRule.enabled
                    ? 'border-ok/50 bg-ok/15 text-ok'
                    : 'border-border2 bg-surface2 text-faint',
                )}
              >
                {detectionRule.enabled ? 'enabled' : 'disabled - stored findings remain'}
              </span>
            </dd>
            <dt className="text-faint">What it counts</dt>
            <dd className="text-muted">{detectionRule.description}</dd>
            {detectionRule.notes ? (
              <>
                <dt className="text-faint">Note</dt>
                <dd className="text-muted">{detectionRule.notes}</dd>
              </>
            ) : null}
          </dl>
          <div className="flex items-start gap-2 border-t border-border px-3 py-2 text-2xs text-faint">
            <Info size={12} className="mt-0.5 shrink-0" aria-hidden />
            <span>
              The matching logic is part of the detection engine and is not editable; the
              thresholds it compares against are, in Settings, and the sentence above is
              regenerated from whatever they are set to.
            </span>
          </div>
        </Panel>
      ) : null}

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
  )
}

export default FindingOverview
