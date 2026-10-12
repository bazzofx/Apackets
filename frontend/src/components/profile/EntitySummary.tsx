import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { Clock, Database, Fingerprint, Globe, Info, Network, ShieldAlert } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import { formatBytes, formatNumber, formatTimestamp } from '@/utils/format'
import type { EntityProfile, ProfileKind } from '@/types'
import { KIND_HUE, KIND_LABEL, KindIcon } from './EntitySearch'

/**
 * What the capture knows about the entity itself, above its widgets.
 *
 * These are the entity's own header facts — who it is, what it was called, how much
 * it moved and over what span — because they are the same whichever question is
 * asked, and repeating them inside each of the sixteen tiles would be noise. The
 * hostnames and the scope come from the analysis' own tables; a fact this capture
 * cannot supply shows an em dash rather than a plausible value.
 */

interface FactProps {
  icon: typeof Clock
  label: string
  value: string
  title?: string
}

function Fact({ icon: Icon, label, value, title }: FactProps) {
  return (
    <span className="flex items-baseline gap-1.5" title={title ?? label}>
      <Icon size={12} className="shrink-0 translate-y-0.5 text-faint" aria-hidden />
      <span className="text-2xs uppercase tracking-wider text-faint">{label}</span>
      <span className="mono text-xs text-text">{value}</span>
    </span>
  )
}

export interface EntitySummaryProps {
  profile: EntityProfile
  /** Where "all hosts" should point for this kind, or null when there is no page. */
  onClear: () => void
}

export function EntitySummary({ profile, onClear }: EntitySummaryProps) {
  const summary = profile.summary
  const kind: ProfileKind = profile.kind
  const hostnames = summary.hostnames ?? []
  /* The backend's note about this entity is an explanation, so it belongs on the
     strip's tooltip with every other one rather than in the row: the strip prints the
     facts and the note says what they do and do not mean. */
  const note = typeof summary.note === 'string' && summary.note.trim() !== '' ? summary.note : null

  return (
    <section className="profile-strip" data-profile-summary={profile.entity} title={note ?? undefined}>
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1.5">
        <span
          className="chip signal-kind"
          style={{ '--kind-hue': `var(${KIND_HUE[kind]})` } as CSSProperties}
          title={`Looked up as ${KIND_LABEL[kind]}`}
        >
          <KindIcon kind={kind} size={12} />
          {KIND_LABEL[kind]}
        </span>
        <span className="mono min-w-0 break-all text-lg font-semibold text-text" data-profile-entity>
          {summary.label !== '' ? summary.label : profile.entity}
        </span>
        <CopyButton value={profile.entity} label="Copy the entity" />
        {summary.label !== '' && summary.label !== profile.entity ? (
          <span className="mono break-all text-2xs text-faint" title="The value this profile was looked up by">
            {profile.entity}
          </span>
        ) : null}
      </div>

      <div className="flex w-full flex-wrap items-center gap-x-4 gap-y-1.5">
        <Fact icon={Network} label="Scope" value={summary.scope ?? '—'} />
        <Fact icon={Fingerprint} label="MAC" value={summary.mac ?? '—'} />
        <Fact
          icon={Database}
          label="Packets"
          value={formatNumber(summary.packets)}
          title="Frames of this capture the entity is an endpoint of"
        />
        <Fact
          icon={Database}
          label="Bytes"
          value={formatBytes(summary.bytes)}
          title="Frame bytes summed over those frames"
        />
        <Fact
          icon={Clock}
          label="First seen"
          value={formatTimestamp(summary.first_seen)}
          title="First frame of this capture the entity appears in"
        />
        <Fact
          icon={Clock}
          label="Last seen"
          value={formatTimestamp(summary.last_seen)}
          title="Last frame of this capture the entity appears in"
        />
        <span className="flex items-center gap-1.5">
          <Globe size={12} className="shrink-0 text-faint" aria-hidden />
          <span className="text-2xs uppercase tracking-wider text-faint">Names</span>
          {hostnames.length === 0 ? (
            <span className="mono text-xs text-muted" title="No name was associated with it in this capture">
              none recorded
            </span>
          ) : (
            <span className="flex flex-wrap items-center gap-1">
              {hostnames.slice(0, 8).map((name) => (
                <span key={name} className="chip border-border2 bg-surface2 text-muted">
                  {name}
                </span>
              ))}
              {hostnames.length > 8 ? (
                <span className="text-2xs text-faint">+{formatNumber(hostnames.length - 8)} more</span>
              ) : null}
            </span>
          )}
        </span>
      </div>

      <div className="flex w-full flex-wrap items-center gap-1.5">
        <Link
          to={kind === 'ip' ? '/hosts' : kind === 'domain' ? '/dns' : '/http'}
          className="chip border-border2 bg-surface2 text-muted hover:bg-surface2/60 hover:text-text"
          title="Open the page that lists every row of this kind"
        >
          {kind === 'ip' ? 'All hosts' : kind === 'domain' ? 'All DNS queries' : 'All HTTP requests'}
        </Link>
        {kind === 'ip' ? (
          <Link
            to="/findings"
            className="chip border-border2 bg-surface2 text-muted hover:bg-surface2/60 hover:text-text"
            title="Findings that name this entity"
          >
            <ShieldAlert size={11} aria-hidden />
            Findings
          </Link>
        ) : null}
        <span className="ml-auto flex items-center gap-1.5 text-2xs text-faint" title={note ?? undefined}>
          <Info size={11} aria-hidden data-profile-summary-info />
          hover for what these mean
        </span>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={onClear}
          title="Clear the lookup and return to the search"
        >
          Close
        </button>
      </div>
    </section>
  )
}

export default EntitySummary
