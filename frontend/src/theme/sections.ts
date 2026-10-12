/**
 * Section identity: what makes each page look like itself.
 *
 * Every page used to render the same stack of `.panel` cards under the same
 * single accent hue, so the only thing distinguishing the Dashboard from the
 * TLS browser was the sidebar highlight. This module gives each section its own
 * hue, icon, eyebrow and structural variant, which `Page` (components/Page.tsx)
 * turns into CSS custom properties and a headline.
 *
 * The hues deliberately point at CSS custom properties that already exist -
 * `--c-chart-1..8`, the theme's own `--c-accent`, and the two loudest severity
 * tokens - so a section follows the active theme automatically and this file
 * still contains no colour literal. `themes.ts` remains the only place allowed
 * to name a colour.
 *
 * The assignment is chosen so no two neighbours in the sidebar share a hue, and
 * so the two utility pages (PCAP Files, Settings) stay deliberately quiet: they
 * are forms, not analysis, and reading as neutral is itself the signal.
 */

import {
  ArrowLeftRight,
  FolderOpen,
  Globe,
  Info,
  LayoutDashboard,
  List,
  Lock,
  Package,
  Radar,
  Search,
  Server,
  ScanSearch,
  Settings as SettingsIcon,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'

/**
 * How a page is laid out beneath its headline. These are structural, not
 * decorative: they decide the width of the headline block and how much air the
 * body gets, which is what stops a table page and a form page reading alike.
 *
 * * `hero`    - widest headline, bloom behind it. The landing page.
 * * `console` - compact headline, maximum density above the fold.
 * * `ledger`  - full-bleed body for a dense table or diagram.
 * * `split`   - narrow headline, wide left gutter, for forms and card grids.
 * * `signal`  - centred headline with a spectrum rule, for the Hunt page:
 *               it is one search box and a field of coloured widgets, so it is
 *               laid out and coloured unlike every other page on purpose.
 */
export type PageVariant = 'hero' | 'console' | 'ledger' | 'split' | 'signal'

/**
 * The sidebar grouping a page belongs to.
 *
 * It is both the heading the sidebar draws above the group's items and the eyebrow over
 * each of those pages' titles, so the two can never disagree about where a page lives.
 * The names are the working groups of an investigation: the capture at a glance, what it
 * connected to, what it can be asked, what the protocols said, and the plumbing.
 */
export type SectionGroup = 'Dashboard' | 'Connections' | 'Investigate' | 'Protocols' | 'Settings'

export interface SectionIdentity {
  /** Stable key, e.g. `dns`. */
  id: string
  /** The section's own route, for cross-referencing with the router. */
  route: string
  group: SectionGroup
  /** The headline itself. Kept identical to the sidebar label. */
  label: string
  /** One line under the headline saying what the page is for. */
  purpose: string
  icon: LucideIcon
  /**
   * Which existing CSS custom property carries this section's hue. It must hold
   * a space-separated `r g b` triple so `rgb(var(--s-accent) / 0.15)` works.
   */
  hueVar: string
  variant: PageVariant
}

export const SECTIONS = {
  dashboard: {
    id: 'dashboard',
    route: '/',
    group: 'Dashboard',
    label: 'Dashboard',
    purpose:
      'The capture at a glance: the headline counts, who talked to whom, and how the traffic splits across protocols.',
    icon: LayoutDashboard,
    hueVar: '--c-accent',
    variant: 'hero',
  },
  info: {
    id: 'info',
    route: '/info',
    group: 'Dashboard',
    label: 'Info',
    purpose:
      'The full reference view: every counter, series and ranking the backend computes for this capture, in one page.',
    icon: Info,
    hueVar: '--c-chart-8',
    variant: 'console',
  },
  conversations: {
    id: 'conversations',
    route: '/conversations',
    group: 'Connections',
    label: 'Conversations',
    purpose:
      'Every distinct flow in the capture, with the five-stage diagram of who talked to whom and how much they moved.',
    icon: ArrowLeftRight,
    hueVar: '--c-chart-2',
    variant: 'ledger',
  },
  hosts: {
    id: 'hosts',
    route: '/hosts',
    group: 'Dashboard',
    label: 'Hosts',
    purpose:
      'An inventory of the addresses observed in this capture: their roles, their peers, and the services they offered.',
    icon: Server,
    hueVar: '--c-chart-4',
    variant: 'split',
  },
  findings: {
    id: 'findings',
    route: '/findings',
    group: 'Connections',
    label: 'Findings',
    purpose:
      'Everything the built-in detection engine and the imported Suricata rules flagged, with the evidence behind each hit.',
    icon: ShieldAlert,
    /* The one page whose hue is the severity vocabulary itself: findings are
       graded in these colours, so the page should be read in them too. */
    hueVar: '--c-sev-high',
    variant: 'split',
  },
  threatHunt: {
    id: 'threat-hunt',
    route: '/threat-hunt',
    group: 'Investigate',
    label: 'Threat Map',
    purpose:
      'The hunt hypotheses, detection by detection, each with the measured evidence that fired it or the reason it stayed quiet.',
    icon: Radar,
    hueVar: '--c-sev-medium',
    variant: 'console',
  },
  investigate: {
    id: 'investigate',
    route: '/investigate',
    group: 'Investigate',
    label: 'Hunt',
    purpose:
      'Look up one address, domain or URL and see everything this capture recorded about it, one question per widget.',
    icon: ScanSearch,
    /* Emerald: the only legible hue no other section already uses. */
    hueVar: '--c-map-local',
    variant: 'signal',
  },
  objects: {
    id: 'objects',
    route: '/objects',
    group: 'Investigate',
    label: 'Files and Objects',
    purpose:
      'Files carved out of the capture, with their hashes, their sizes and the HTTP transactions they were correlated against.',
    icon: Package,
    hueVar: '--c-chart-6',
    variant: 'ledger',
  },
  packets: {
    id: 'packets',
    route: '/packets',
    group: 'Connections',
    label: 'Packets',
    purpose:
      'The frame-level ledger over the indexed packets, with layer trees, hex dumps and display-filter support.',
    icon: List,
    hueVar: '--c-chart-7',
    variant: 'ledger',
  },
  http: {
    id: 'http',
    route: '/http',
    group: 'Protocols',
    label: 'HTTP',
    purpose:
      'Every request and response: methods, hosts, paths, user agents, and the credentials that crossed the wire in clear text.',
    icon: Globe,
    hueVar: '--c-chart-5',
    variant: 'ledger',
  },
  dns: {
    id: 'dns',
    route: '/dns',
    group: 'Protocols',
    label: 'DNS',
    purpose:
      'Queries and their answers, with the name shapes that look generated rather than resolved.',
    icon: Search,
    hueVar: '--c-chart-3',
    variant: 'ledger',
  },
  tls: {
    id: 'tls',
    route: '/tls',
    group: 'Protocols',
    label: 'TLS',
    purpose:
      'Handshakes, versions, cipher suites, JA3 fingerprints and the certificates this capture actually observed.',
    icon: Lock,
    hueVar: '--c-chart-1',
    variant: 'ledger',
  },
  files: {
    id: 'files',
    route: '/files',
    group: 'Settings',
    label: 'PCAP Files',
    purpose:
      'Upload, track and manage the captures this installation holds, and see what each one is doing.',
    icon: FolderOpen,
    /* The library is the one page that is neither analysis nor configuration, so
       it takes the neutral slate: quiet, but still legible as an accent. */
    hueVar: '--c-sev-informational',
    variant: 'split',
  },
  settings: {
    id: 'settings',
    route: '/settings',
    group: 'Settings',
    label: 'Settings',
    purpose:
      'The configuration in force, the limits you can change at runtime, indicators, Suricata rules and themes.',
    icon: SettingsIcon,
    hueVar: '--c-accent2',
    variant: 'split',
  },
} as const satisfies Record<string, SectionIdentity>

export type SectionKey = keyof typeof SECTIONS

/** Every identity, in sidebar order. */
export const SECTION_LIST: SectionIdentity[] = [
  SECTIONS.dashboard,
  SECTIONS.info,
  SECTIONS.hosts,
  SECTIONS.conversations,
  SECTIONS.packets,
  SECTIONS.findings,
  SECTIONS.threatHunt,
  SECTIONS.investigate,
  SECTIONS.objects,
  SECTIONS.http,
  SECTIONS.dns,
  SECTIONS.tls,
  SECTIONS.files,
  SECTIONS.settings,
]

/** Look a section up by its route, e.g. `/dns`. */
export const SECTION_BY_ROUTE: Record<string, SectionIdentity> = Object.fromEntries(
  SECTION_LIST.map((section) => [section.route, section]),
)

/**
 * Resolve the section for a concrete pathname.
 *
 * `useLocation()` reports the full path, so `/findings/<id>` has to fall back to
 * its first segment. An unknown path (the catch-all route) reports the
 * Dashboard, which keeps the shell styled rather than unstyled.
 */
export function sectionForRoute(pathname: string): SectionIdentity {
  const exact = SECTION_BY_ROUTE[pathname]
  if (exact) return exact
  const first = pathname.split('/').filter(Boolean)[0]
  if (first !== undefined) {
    const parent = SECTION_BY_ROUTE['/' + first]
    if (parent) return parent
  }
  return SECTIONS.dashboard
}

export default SECTIONS
