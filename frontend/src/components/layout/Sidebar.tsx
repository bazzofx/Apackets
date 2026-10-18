import { Fragment } from 'react'
import { NavLink } from 'react-router-dom'
import clsx from 'clsx'
import type { LucideIcon } from 'lucide-react'

export interface SidebarItem {
  to: string
  label: string
  icon: LucideIcon
  badge?: string
  badgeTone?: 'default' | 'danger' | 'warn'
  title?: string
  /** The heading drawn immediately above this item, when it starts a group. */
  section?: string
}

export interface SidebarProps {
  items: SidebarItem[]
  /** The tshark/backend line, so this component stays presentational. */
  status?: React.ReactNode
  /**
   * The shell's own controls - baseline mode, Refresh, Upload - drawn under the
   * navigation rather than in the banner. Passed in rather than built here for the
   * same reason as `items`: this component owns layout, not queries.
   */
  actions?: React.ReactNode
}

/**
 * The left navigation: five groups, one line icon per destination, badges where a
 * number or a state matters.
 *
 * The grouping is the analyst's work order - the capture at a glance, what it
 * connected to, what can be asked of it, what the protocols said, and the plumbing -
 * and the same order the routes already have. Nothing here changes what a route does.
 *
 * Under the groups, and above the standing note, sit the shell's three controls
 * (baseline mode, Refresh, Upload). They were a second row of the banner until that
 * row was removed: three buttons do not need their own strip of the shell.
 */
export function Sidebar({ items, status, actions }: SidebarProps) {
  return (
    <aside className="flex w-14 shrink-0 flex-col border-r border-border bg-surface lg:w-56">
      {status !== undefined ? (
        <>
          <div className="hidden border-b border-border px-3 py-2 lg:block">{status}</div>
          <div className="flex justify-center border-b border-border px-1 py-2 lg:hidden">
            {status}
          </div>
        </>
      ) : null}

      <nav className="flex-1 overflow-y-auto pb-2">
        {items.map((item) => (
          <Fragment key={item.to}>
            {item.section !== undefined ? (
              <div className="nav-group">
                <span className="nav-group-label hidden lg:inline">{item.section}</span>
              </div>
            ) : null}
            <NavLink
              to={item.to}
              end={item.to === '/'}
              title={item.title ?? item.label}
              className={({ isActive }) =>
                clsx('nav-link', isActive ? 'nav-link-active' : 'nav-link-idle')
              }
            >
              <item.icon size={15} className="shrink-0" aria-hidden />
              <span className="hidden flex-1 truncate lg:inline">{item.label}</span>
              {item.badge !== undefined ? (
                <span
                  className={clsx(
                    'chip hidden shrink-0 lg:inline-flex',
                    item.badgeTone === 'danger'
                      ? 'border-danger/50 bg-danger/15 text-red-300'
                      : item.badgeTone === 'warn'
                        ? 'border-warn/50 bg-warn/15 text-warn'
                        : 'border-border2 bg-surface2 text-muted',
                  )}
                  title={item.title}
                >
                  {item.badge}
                </span>
              ) : null}
            </NavLink>
          </Fragment>
        ))}
      </nav>

      {/* The shell actions sit under the navigation, flush with it: the stylesheet
          gives them the nav link's own left inset, so their icons line up with the
          nav icons instead of starting where a padded box happened to start. */}
      {actions !== undefined ? <div className="nav-actions">{actions}</div> : null}

      <div className="hidden border-t border-border px-3 py-2 text-2xs text-faint lg:block">
        Local-only tool · no telemetry
      </div>
    </aside>
  )
}

export default Sidebar
