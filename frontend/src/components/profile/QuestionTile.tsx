import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { ArrowUpRight, TriangleAlert } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import { AVAILABILITY_TONE, TONE_TEXT, availabilityChipLabel } from '@/components/threat/visualKit'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntIndicator } from '@/types'
import { EntityVisual, hasVisualData } from './EntityVisual'

/**
 * One Investigate widget: one question, the charts that answer it, and the links
 * that open the rows behind them.
 *
 * The card contract is the Threat Map's (docs/ENTITY_PROFILE.md §3, docs/THREAT_HUNT.md
 * §3.1), so an indicator is drawn here exactly as it is drawn there — same fields,
 * same renderers, same honesty rules. What differs is the treatment: on this page
 * each widget is a tile in a grid and carries its own hue from the theme's chart
 * palette, because the whole point of the section is to answer sixteen questions at
 * a glance and a field of identical grey cards answers none of them.
 *
 * Nothing here fetches: the page owns the single query, so a tile renders from a
 * fixture.
 */

/** How many hues the theme publishes; the tiles cycle through them. */
const HUE_COUNT = 8

/**
 * The tile's hue, as a reference to one of the theme's chart custom properties.
 *
 * Those properties hold space-separated `r g b` triples, which is what lets the
 * stylesheet tint the rail, the wash and the number with `rgb(var(--tile-hue) / x)`.
 * Returning the variable rather than a colour keeps every literal in `theme/themes.ts`.
 */
export function profileHueVar(index: number): string {
  const wrapped = ((index % HUE_COUNT) + HUE_COUNT) % HUE_COUNT
  return `--c-chart-${String(wrapped + 1)}`
}

/** The inline style that publishes one tile's hue to `.profile-tile`. */
export function profileHueStyle(index: number): CSSProperties {
  return { '--tile-hue': `var(${profileHueVar(index)})` } as CSSProperties
}

/** The leading sentence of the notice that replaces the visuals. */
function availabilityLead(availability: string): string {
  if (availability === 'empty') return 'Nothing matched.'
  if (availability === 'not_applicable') return 'This capture cannot answer this question.'
  return `The backend marked this question “${availability}”.`
}

export interface QuestionTileProps {
  question: ThreatHuntIndicator
  /**
   * Position in the contract's question list, 0-based. The tile shows it as a
   * number and takes its hue from it, so a question keeps the same colour on every
   * entity it is opened for.
   */
  index: number
  /**
   * Whether the response reported this question's visual as cut to a contract cap.
   * The headline counts everything; only the chart is shortened, and the tile says
   * so rather than letting a truncated drawing read as the whole picture.
   */
  capped?: boolean
}

export function QuestionTile({ question, index, capped = false }: QuestionTileProps) {
  const availability = question.availability
  const available = availability === 'ok'
  const visuals = question.visuals ?? []
  const drawable = visuals.filter(hasVisualData)
  const links = question.links ?? []
  const number = String(index + 1).padStart(2, '0')
  const reason =
    typeof question.availability_reason === 'string' && question.availability_reason.trim() !== ''
      ? question.availability_reason
      : null
  const caveat =
    typeof question.caveat === 'string' && question.caveat.trim() !== '' ? question.caveat : null

  return (
    <article
      className="profile-tile"
      style={profileHueStyle(index)}
      data-profile-tile={question.id}
      data-profile-tile-availability={availability}
    >
      <header className="flex items-baseline gap-2">
        <span className="profile-tile-index shrink-0" aria-hidden>
          {number}
        </span>
        <h3 className="min-w-0 flex-1 text-sm font-semibold leading-snug text-text">{question.title}</h3>
        <span
          className={clsx('chip shrink-0', AVAILABILITY_TONE[availability] ?? AVAILABILITY_TONE.empty)}
          title={
            available
              ? 'Answered from this analysis’ indexed tables, with something to show.'
              : 'Not answered by this capture — the reason is stated below.'
          }
        >
          {availabilityChipLabel(availability)}
        </span>
      </header>

      {capped ? (
        <span
          className="chip w-fit border-warn/40 bg-warn/10 text-warn"
          data-profile-tile-capped={question.id}
          title="The chart below was cut to this question’s contract cap. The number above counts every row the capture holds."
        >
          chart capped
        </span>
      ) : null}

      <p className="text-2xs leading-relaxed text-muted">{question.question}</p>

      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5" data-profile-tile-headline>
        <span className={clsx('mono profile-tile-headline text-xl leading-none', !available && 'opacity-70')}>
          {formatNumber(question.headline.value)}
        </span>
        <span className={clsx('text-xs', TONE_TEXT[question.headline.tone] ?? 'text-text')}>
          {question.headline.label}
        </span>
      </div>

      {!available ? (
        <p className="text-2xs leading-relaxed text-faint" data-profile-tile-reason={question.id}>
          <span className="text-muted">{availabilityLead(availability)}</span>{' '}
          {reason ??
            'The backend did not state why, so read this widget as “not answered” rather than as a negative result.'}
        </p>
      ) : null}

      {drawable.length > 0 ? (
        <div className="flex flex-col gap-2">
          {drawable.map((visual, visualIndex) => (
            <EntityVisual key={`${visual.kind}-${String(visualIndex)}`} visual={visual} />
          ))}
        </div>
      ) : available ? (
        <p className="text-2xs leading-relaxed text-warn" data-profile-visuals-missing={question.id}>
          This question is marked answered but carries no visuals, so nothing is drawn here.
        </p>
      ) : null}

      <div className="profile-tile-rule flex flex-col gap-0.5">
        <span className="text-2xs uppercase tracking-wider text-faint">What it may indicate</span>
        <p className="text-xs leading-relaxed text-text">{question.interpretation}</p>
      </div>

      <div className="flex items-start gap-1.5 border-t border-border pt-2">
        <TriangleAlert size={12} className="mt-0.5 shrink-0 text-faint" aria-hidden />
        <p className="text-2xs italic leading-relaxed text-faint">
          {caveat ??
            'The backend sent no caveat for this question. Treat it as a lead to verify against the packets, not as a conclusion.'}
        </p>
      </div>

      <footer className="mt-auto flex flex-wrap items-center gap-1.5 pt-1">
        <span className="chip border-border2 bg-surface2 text-faint" title="Stable question id">
          {question.id}
        </span>
        <CopyButton value={question.id} label="Copy the question id" />
        {links.map((link, linkIndex) => (
          <Link
            key={`${link.to}-${String(linkIndex)}`}
            to={link.to}
            className="chip border-border2 bg-surface2 text-muted hover:bg-surface2/60 hover:text-text"
            title={`Open ${link.to}`}
          >
            <ArrowUpRight size={11} aria-hidden />
            {link.label}
          </Link>
        ))}
      </footer>
    </article>
  )
}

export default QuestionTile
