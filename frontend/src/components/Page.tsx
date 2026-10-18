import type { CSSProperties, ReactNode } from 'react'
import clsx from 'clsx'
import type { SectionIdentity } from '@/theme/sections'

export interface PageProps {
  /** The section this page belongs to; see `theme/sections.ts`. */
  section: SectionIdentity
  /**
   * Compact facts for the right edge of the headline - a count, a status, a
   * primary action. It must only use data the page has already fetched.
   */
  aside?: ReactNode
  /** Chips or small notes rendered under the purpose line. */
  meta?: ReactNode
  children: ReactNode
  className?: string
  /** Override the body's own layout when a page needs something else. */
  bodyClassName?: string
  /**
   * An image painted behind the headline - the page's own hero, as a URL. The
   * caller imports the asset so Vite resolves and fingerprints it; this
   * component only publishes it as `--page-head-image`, and the stylesheet
   * decides how it is fitted and how far it is washed back for legibility.
   */
  headerImage?: string
}

/**
 * The shell every page renders inside: a section headline, an optional aside,
 * and the page body.
 *
 * Two things make pages distinguishable:
 *
 * 1. `--s-accent` is published here from the section's `hueVar`, which is an
 *    existing themed custom property (`--c-chart-4`, `--c-sev-high`, ...). The
 *    stylesheet tints the headline, its rule, its bloom and a hairline on every
 *    card from that one variable, so a section reads differently without any
 *    component knowing a colour.
 * 2. The `variant` changes the headline's weight and the body's density, so a
 *    landing page, a ledger and a settings form are not laid out identically.
 *
 * The headline sits outside `AnalysisGuard` on purpose: it is the page's
 * identity, so it should be there while data loads and while the guard is
 * showing an empty or failed state.
 */
export function Page({
  section,
  aside,
  meta,
  children,
  className,
  bodyClassName,
  headerImage,
}: PageProps) {
  const Icon = section.icon
  /* A custom property is not part of React's CSSProperties type, so the object
     is built as one and cast. The value is a `var()` reference, never a colour. */
  const style = { '--s-accent': `var(${section.hueVar})` } as CSSProperties
  /* The image is published as a custom property, not as a `background-image`
     here: the wash that keeps the headline readable is a decision about the
     stylesheet, and it must stay in one place with the rest of the type rules. */
  const headStyle = headerImage
    ? ({ '--page-head-image': `url(${headerImage})` } as CSSProperties)
    : undefined

  return (
    <div
      className={clsx('page', 'page-' + section.variant, className)}
      style={style}
      data-section={section.id}
    >
      <header className="page-head" style={headStyle} data-header-image={headerImage ? 'true' : undefined}>
        <div className="page-head-text">
          {/* The eyebrow says which group of the sidebar the page belongs to. Three
              pages are their group's own name - Dashboard under Dashboard, Investigate
              under Investigate, Settings under Settings - and repeating a word directly
              above itself is noise, so it is dropped only for those. */}
          {section.group === section.label ? null : (
            <div className="page-eyebrow">
              <Icon size={13} aria-hidden />
              <span>{section.group}</span>
            </div>
          )}
          <h1 className="page-title">{section.label}</h1>
          <p className="page-purpose">{section.purpose}</p>
          {meta ? <div className="page-meta">{meta}</div> : null}
        </div>
        {aside ? <div className="page-aside">{aside}</div> : null}
      </header>
      <div className={clsx('page-body', bodyClassName)}>{children}</div>
    </div>
  )
}

export default Page
