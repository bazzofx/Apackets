import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import { ArrowUpRight, Info, type LucideIcon } from 'lucide-react'
import { AVAILABILITY_TONE, TONE_TEXT, availabilityChipLabel } from '@/components/threat/visualKit'
import { SECTION_BY_ROUTE } from '@/theme/sections'
import { formatNumber } from '@/utils/format'
import type { ThreatHuntIndicator } from '@/types'
import { EntityVisual, hasVisualData } from './EntityVisual'

/**
 * One Investigate widget: one question, its charts, its own hue.
 *
 * The card contract is the Threat Map's (docs/ENTITY_PROFILE.md §3, docs/THREAT_HUNT.md
 * §3.1), so an indicator is drawn here exactly as it is drawn there. What differs is the
 * treatment, because this page is a grid of sixteen answers rather than a stack of
 * sixteen dossiers:
 *
 * * the tile prints only what the reader came for — the question's title, the sentence
 *   it answers, its headline number and its data labels. Everything explanatory (what
 *   the pattern may indicate, what it does not prove, why a question could not be
 *   answered, each chart's own note, the question id) is on the tile's tooltip, one
 *   hover away and never in the way;
 * * a question the capture could not answer is greyed out rather than hidden, so the
 *   grid keeps its shape and a missing answer reads as a missing answer;
 * * the chart inside is drawn larger than the Threat Map draws it (the `signal pages`
 *   block of index.css) because on a tile it is the thing worth reading;
 * * a link is named after the section it opens instead of describing it, since that
 *   sentence belongs to the tooltip too.
 *
 * Nothing here fetches: the page owns the single query, so a tile renders from a fixture.
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

/**
 * Where a link goes, as an icon.
 *
 * The endpoint's label is what distinguishes one link from the next — a peer address, a
 * domain, a port, a finding id — so the label stays and is truncated by the stylesheet
 * rather than replaced. What the label does not say is *which page* it opens, and five
 * links to five pages all read alike without it, so the destination's own icon from
 * `sections.ts` (the sidebar's icon) is drawn beside it and the section's name goes in
 * the tooltip.
 */
function destination(to: string): { label: string; icon: LucideIcon } | null {
  const first = to.split('?')[0]?.split('/').filter(Boolean)[0]
  if (first === undefined) return null
  const section = SECTION_BY_ROUTE['/' + first]
  if (section === undefined) return null
  return { label: section.label, icon: section.icon }
}

export interface QuestionTileProps {
  question: ThreatHuntIndicator
  /**
   * Position in the contract's question list, 0-based. The tile shows it as a number
   * and takes its hue from it, so a question keeps the same colour on every entity it
   * is opened for.
   */
  index: number
  /**
   * Whether the response reported this question's visual as cut to a contract cap. The
   * headline counts everything; only the chart is shortened, and the tile says so rather
   * than letting a truncated drawing read as the whole picture.
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
    typeof question.caveat === 'string' && question.caveat.trim() !== ''
      ? question.caveat
      : 'The backend sent no caveat for this question, so treat it as a lead to verify against the packets rather than as a conclusion.'

  /* Everything the tile refuses to print. It is one hover away, on the tile itself and
     on the mark in its header, so no explanation is lost — only moved out of the way. */
  const hover = [
    `What it may indicate: ${question.interpretation}`,
    `What it does not prove: ${caveat}`,
    available ? null : `${availabilityLead(availability)} ${reason ?? 'The backend did not state why.'}`,
    ...visuals
      .map((visual) => (typeof visual.note === 'string' && visual.note.trim() !== '' ? visual.note : null))
      .filter((note): note is string => note !== null),
    capped ? 'The chart on this tile was cut to its contract cap; the number counts every row.' : null,
    `Question id: ${question.id}`,
  ]
    .filter((line): line is string => line !== null)
    .join('\n\n')

  return (
    <article
      className="profile-tile"
      style={profileHueStyle(index)}
      data-profile-tile={question.id}
      data-profile-tile-state={availability}
      title={hover}
    >
      <header className="flex items-baseline gap-1.5">
        <span className="profile-tile-index shrink-0" aria-hidden>
          {number}
        </span>
        <h3 className="profile-tile-title min-w-0 flex-1">{question.title}</h3>
        {available ? null : (
          <span
            className={clsx('chip shrink-0', AVAILABILITY_TONE[availability] ?? AVAILABILITY_TONE.empty)}
            data-profile-tile-chip={availability}
          >
            {availabilityChipLabel(availability)}
          </span>
        )}
        {capped ? (
          <span
            className="chip shrink-0 border-warn/40 bg-warn/10 text-warn"
            data-profile-tile-capped={question.id}
          >
            capped
          </span>
        ) : null}
        {/* The hover affordance: everything this tile is not printing is in here. */}
        <Info size={11} className="shrink-0 text-faint" aria-hidden data-profile-tile-info />
      </header>

      <p className="profile-tile-question">{question.question}</p>

      <div className="flex flex-wrap items-baseline gap-x-2" data-profile-tile-headline>
        <span className={clsx('mono profile-tile-headline text-2xl leading-none', !available && 'opacity-80')}>
          {formatNumber(question.headline.value)}
        </span>
        <span className={clsx('text-xs', TONE_TEXT[question.headline.tone] ?? 'text-text')}>
          {question.headline.label}
        </span>
      </div>

      {drawable.length > 0 ? (
        <div className="flex flex-col gap-1.5">
          {drawable.map((visual, visualIndex) => (
            <EntityVisual key={`${visual.kind}-${String(visualIndex)}`} visual={visual} />
          ))}
        </div>
      ) : available ? (
        <p className="text-2xs leading-relaxed text-warn" data-profile-visuals-missing={question.id}>
          This question is marked answered but carries no visuals, so nothing is drawn here.
        </p>
      ) : null}

      {links.length > 0 ? (
        <footer className="mt-auto flex flex-wrap items-center gap-1 pt-0.5">
          {links.map((link, linkIndex) => {
            const target = destination(link.to)
            const Icon = target?.icon
            return (
              <Link
                key={`${link.to}-${String(linkIndex)}`}
                to={link.to}
                className="chip max-w-[11rem] border-border2 bg-surface2 text-muted hover:bg-surface2/60 hover:text-text"
                title={`${link.label} — opens ${target?.label ?? link.to}${target === null ? '' : ` (${link.to})`}`}
              >
                {Icon === undefined ? <ArrowUpRight size={10} aria-hidden /> : <Icon size={10} aria-hidden />}
                <span className="truncate">{link.label}</span>
              </Link>
            )
          })}
        </footer>
      ) : null}
    </article>
  )
}

export default QuestionTile
