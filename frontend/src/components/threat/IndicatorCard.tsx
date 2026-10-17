import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { ArrowUpRight, TriangleAlert, Wrench } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import Panel from '@/components/Panel'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntIndicator, ThreatHuntVisual } from '@/types'
import BarsVisual from './BarsVisual'
import HeatmapVisual from './HeatmapVisual'
import HistogramVisual from './HistogramVisual'
import ScatterVisual from './ScatterVisual'
import TableVisual from './TableVisual'
import TimelineVisual from './TimelineVisual'
import { AVAILABILITY_TONE, TONE_CHIP, TONE_TEXT, availabilityChipLabel } from './visualKit'

/**
 * One Threat Map indicator (contract §3.1), drawn entirely from the object it is
 * given.
 *
 * This component fetches nothing: the page owns the single query, so a card can be
 * rendered from a fixture and every visual kind can be checked in isolation. It
 * shows the title, the question the detection answers, the headline measure, each
 * visual, what the pattern may indicate, what it does *not* establish (kept
 * visibly secondary — that is what stops a lead reading as a verdict) and the
 * links into the rest of the app as real router links.
 *
 * When `availability` is not `"ok"` the reason is always shown, and a visual is
 * drawn whenever it actually carries data. "Empty" means nothing crossed the
 * threshold, not that nothing was measured, so the distribution that stayed under it
 * is still worth showing. An empty chart frame is never drawn, because that would
 * read as "nothing found" - a different claim from "this could not be computed".
 */

/** The leading sentence of the notice that replaces the visuals. */
function availabilityLead(availability: string): string {
  if (availability === 'empty') return 'Nothing matched.'
  if (availability === 'not_applicable') return 'This capture cannot answer this question.'
  return `The backend marked this indicator “${availability}”.`
}

/** Where the reason comes from, stated so the tone of the card stays honest. */
function reasonSource(availability: string): string {
  if (availability === 'empty') return 'threshold that was applied'
  if (availability === 'not_applicable') return 'why the capture cannot answer it'
  return 'reason'
}

/**
 * Whether a visual actually carries data.
 *
 * Contract §4 lets an indicator that is not `"ok"` send empty arrays, and the
 * backend also sends real measurements for a threshold that simply was not crossed.
 * Drawing only what has data keeps both honest: no empty frame is ever rendered, and
 * no measurement is thrown away either.
 */
function hasData(visual: ThreatHuntVisual): boolean {
  switch (visual.kind) {
    case 'bars':
      return visual.items.length > 0
    case 'timeline':
      return visual.points.length > 0
    case 'histogram':
      return visual.buckets.length > 0
    case 'scatter':
      return visual.points.length > 0
    case 'heatmap':
      return visual.columns.length > 0 && visual.rows.length > 0
    case 'table':
      return visual.rows.length > 0
    default:
      // An unknown kind is reported rather than dropped, so keep it on screen.
      return true
  }
}

/** Dispatches on the §4 `kind` tag. */
function IndicatorVisual({ visual }: { visual: ThreatHuntVisual }) {
  switch (visual.kind) {
    case 'bars':
      return <BarsVisual visual={visual} />
    case 'timeline':
      return <TimelineVisual visual={visual} />
    case 'histogram':
      return <HistogramVisual visual={visual} />
    case 'scatter':
      return <ScatterVisual visual={visual} />
    case 'heatmap':
      return <HeatmapVisual visual={visual} />
    case 'table':
      return <TableVisual visual={visual} />
    default: {
      // A kind this build does not know is reported, never silently dropped.
      const unknown = visual as { kind?: unknown }
      return (
        <p className="text-2xs leading-relaxed text-warn" data-threat-visual-unknown={String(unknown.kind)}>
          The backend returned a visual of kind “{String(unknown.kind)}”, which this build of ShinboShark does
          not know how to draw.
        </p>
      )
    }
  }
}

export interface IndicatorCardProps {
  indicator: ThreatHuntIndicator
}

export function IndicatorCard({ indicator }: IndicatorCardProps) {
  const availability = indicator.availability
  const available = availability === 'ok'
  const headline = indicator.headline
  const visuals = indicator.visuals ?? []
  const drawable = visuals.filter(hasData)
  const links = indicator.links ?? []
  const reason =
    typeof indicator.availability_reason === 'string' && indicator.availability_reason.trim() !== ''
      ? indicator.availability_reason
      : null
  const caveat =
    typeof indicator.caveat === 'string' && indicator.caveat.trim() !== '' ? indicator.caveat : null

  return (
    <Panel
      title={indicator.title}
      actions={
        <span
          className={clsx('chip', AVAILABILITY_TONE[availability] ?? AVAILABILITY_TONE.empty)}
          title={
            available
              ? 'Computed from this analysis’ indexed tables, with something to show.'
              : `Not drawn: ${reasonSource(availability)} below.`
          }
          data-threat-availability-chip={availability}
        >
          {availabilityChipLabel(availability)}
        </span>
      }
      flush
    >
      <div data-threat-card={indicator.id} className="flex flex-col gap-3 p-3">
        <div className="flex flex-wrap items-start gap-2">
          <p className="min-w-0 flex-1 text-xs leading-relaxed text-muted">{indicator.question}</p>
          <span className="flex shrink-0 items-center gap-1">
            <span
              className="chip border-border2 bg-surface2 text-faint"
              title="Stable indicator id (docs/THREAT_HUNT.md §1)"
            >
              {indicator.id}
            </span>
            <CopyButton value={indicator.id} label="Copy the indicator id" />
          </span>
        </div>

        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5" data-threat-headline>
          <span
            className={clsx(
              'mono text-2xl font-semibold leading-none',
              TONE_TEXT[headline.tone] ?? 'text-text',
            )}
          >
            {formatNumber(headline.value)}
          </span>
          <span className="text-xs text-text">{headline.label}</span>
        </div>

        {!available ? (
          <div
            data-threat-availability={availability}
            className="flex items-start gap-2 rounded border border-border bg-surface2/40 px-2 py-2"
          >
            <Wrench size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
            <p className="text-2xs leading-relaxed text-muted">
              <span className="text-text">{availabilityLead(availability)}</span>{' '}
              {reason ??
                `The backend did not state the ${reasonSource(availability)}, so read this card as “not answered” rather than as a negative result.`}
            </p>
          </div>
        ) : null}

        {drawable.length > 0 ? (
          <div className="flex flex-col gap-2">
            {available ? null : (
              <p className="text-2xs leading-relaxed text-faint" data-threat-below-threshold={indicator.id}>
                Below the threshold, but measured: these are the real numbers that stayed under it, which is
                what the count above reflects.
              </p>
            )}
            {drawable.map((visual, index) => (
              <IndicatorVisual key={`${visual.kind}-${index}`} visual={visual} />
            ))}
          </div>
        ) : available ? (
          <p className="text-2xs leading-relaxed text-warn" data-threat-visuals-missing={indicator.id}>
            The backend marked this indicator computed but sent no visuals, so nothing is drawn. §4 requires
            at least one visual when the availability is “ok”.
          </p>
        ) : null}

        <div className="flex flex-col gap-1 border-l-2 border-accent/40 pl-2">
          <span className="text-2xs uppercase tracking-wider text-faint">What it may indicate</span>
          <p className="text-xs leading-relaxed text-text">{indicator.interpretation}</p>
        </div>

        <div
          className="flex items-start gap-1.5 border-t border-border pt-2"
          data-threat-caveat={indicator.id}
        >
          <TriangleAlert size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
          <p className="text-2xs italic leading-relaxed text-faint">
            {caveat ??
              'The backend sent no caveat for this indicator. Treat it as a lead to verify against the packets, not as a conclusion.'}
          </p>
        </div>

        {links.length > 0 ? (
          <div className="flex flex-wrap items-center gap-1.5" data-threat-links={indicator.id}>
            <span className="text-2xs uppercase tracking-wider text-faint">
              {links.length === 1 ? 'Check' : 'Check these'}
            </span>
            {links.map((link, index) => (
              <Link
                key={`${link.to}-${index}`}
                to={link.to}
                className={clsx('chip hover:bg-accent/10', TONE_CHIP.info)}
                title={`Open ${link.to}`}
              >
                <ArrowUpRight size={11} aria-hidden />
                {link.label}
              </Link>
            ))}
          </div>
        ) : null}
      </div>
    </Panel>
  )
}

export default IndicatorCard
