/**
 * Single source of truth for every colour in the application.
 *
 * Both consumers read from here:
 *
 * * `ThemeProvider` publishes each token as a CSS custom property on `<html>`
 *   (`--c-bg`, `--c-accent`, ...), which is what `tailwind.config.js` and
 *   `index.css` point at. Components therefore get themed automatically through
 *   ordinary Tailwind classes (`bg-surface`, `border-danger/50`).
 * * Charts and inline SVG cannot use CSS classes for a concrete colour, so they
 *   read `useThemeTokens()` and get the same values as plain strings.
 *
 * Channels are stored as hex for readability and converted to the `r g b` triple
 * that Tailwind's `<alpha-value>` syntax needs by `themeCssVariables()`. This
 * file is the only place in `src/**` allowed to contain a colour literal.
 */

export type ThemeId = 'shinobi' | 'steel-blue' | 'cyber-punk' | 'cyber-samurai' | 'soc'

export interface ThemeTokens {
  /* surfaces */
  bg: string
  surface: string
  surface2: string
  border: string
  border2: string
  /* brand */
  accent: string
  accent2: string
  /* type */
  text: string
  muted: string
  faint: string
  /** Soft accent bloom used behind the KPI row and the map centre. */
  glow: string
  /* severity (fixed vocabulary: informational, low, medium, high) */
  sevInformational: string
  sevLow: string
  sevMedium: string
  sevHigh: string
  /* status */
  ok: string
  warn: string
  danger: string
  /** Exactly eight distinguishable series hues, free of the amber/red severity hues. */
  chart: readonly string[]
  /* network map classification */
  mapPrivate: string
  mapPublic: string
  mapMulticast: string
  mapLocal: string
  mapUnclassified: string
}

export interface ThemeDefinition {
  id: ThemeId
  label: string
  description: string
  /** Representative colours for the Settings preview chips. */
  swatch: string[]
  tokens: ThemeTokens
}

/*
 * Shinobi is the default: jet black, grey and one neon ascent blue. The four
 * palettes that shipped before it remain, and a browser that has already chosen one
 * keeps it - the default only decides what a first visit looks like.
 */
export const DEFAULT_THEME_ID: ThemeId = 'shinobi'

/** Per-browser preference. A theme is not analysis data, so it stays local. */
export const THEME_STORAGE_KEY = 'apackets.theme'

const SHINOBI: ThemeTokens = {
  bg: '#050607',
  surface: '#0b0d10',
  surface2: '#12161a',
  border: '#1d2429',
  border2: '#2b343b',
  accent: '#35a7ff',
  accent2: '#7fd2ff',
  text: '#e7edf2',
  muted: '#9aa7b2',
  faint: '#65717c',
  glow: 'rgba(53,167,255,0.38)',
  sevInformational: '#6b7783',
  sevLow: '#4cc9ff',
  sevMedium: '#f5a524',
  sevHigh: '#ff4d5e',
  ok: '#35d391',
  warn: '#f5a524',
  danger: '#ff4d5e',
  chart: ['#35a7ff', '#4cc9ff', '#8b9dff', '#35d391', '#f5a524', '#ff8a3d', '#b07cff', '#3ad6c5'],
  mapPrivate: '#35a7ff',
  mapPublic: '#f5a524',
  mapMulticast: '#b07cff',
  mapLocal: '#35d391',
  mapUnclassified: '#6b7783',
}
const STEEL_BLUE: ThemeTokens = {
  bg: '#0b1120',
  surface: '#111a2e',
  surface2: '#16203a',
  border: '#22304d',
  border2: '#2c3c5e',
  accent: '#3b82f6',
  accent2: '#60a5fa',
  text: '#e2e8f0',
  muted: '#8296b4',
  faint: '#5a6b88',
  glow: 'rgba(59,130,246,0.35)',
  sevInformational: '#64748b',
  sevLow: '#38bdf8',
  sevMedium: '#f59e0b',
  sevHigh: '#ef4444',
  ok: '#22c55e',
  warn: '#f59e0b',
  danger: '#ef4444',
  chart: ['#3b82f6', '#38bdf8', '#a78bfa', '#14b8a6', '#22c55e', '#e879f9', '#818cf8', '#0ea5e9'],
  mapPrivate: '#60a5fa',
  mapPublic: '#f59e0b',
  mapMulticast: '#a78bfa',
  mapLocal: '#34d399',
  mapUnclassified: '#64748b',
}

const CYBER_PUNK: ThemeTokens = {
  bg: '#08060f',
  surface: '#120b1f',
  surface2: '#1a1030',
  border: '#3b1d5e',
  border2: '#56268a',
  accent: '#ff2d95',
  accent2: '#22d3ee',
  text: '#f0e7ff',
  muted: '#a78bd6',
  faint: '#6f5a9c',
  glow: 'rgba(255,45,149,0.45)',
  sevInformational: '#7c6ba8',
  sevLow: '#22d3ee',
  sevMedium: '#fbbf24',
  sevHigh: '#ff3b5c',
  ok: '#39ff88',
  warn: '#fbbf24',
  danger: '#ff3b5c',
  chart: ['#e02df0', '#22d3ee', '#c084fc', '#39ff88', '#a78bfa', '#67e8f9', '#f0abfc', '#5eead4'],
  mapPrivate: '#c084fc',
  mapPublic: '#ff2d95',
  mapMulticast: '#22d3ee',
  mapLocal: '#39ff88',
  mapUnclassified: '#6f5a9c',
}

const CYBER_SAMURAI: ThemeTokens = {
  bg: '#0c0a09',
  surface: '#171310',
  surface2: '#201a15',
  border: '#3a2f26',
  border2: '#55402f',
  accent: '#d7263d',
  accent2: '#e8b04b',
  text: '#f2e9dd',
  muted: '#b3a08c',
  faint: '#7d6b58',
  glow: 'rgba(215,38,61,0.40)',
  sevInformational: '#8a7c6d',
  sevLow: '#6ea8c8',
  sevMedium: '#e8b04b',
  sevHigh: '#d7263d',
  ok: '#7fa650',
  warn: '#e8b04b',
  danger: '#d7263d',
  chart: ['#6ea8c8', '#9b8ec4', '#7fa650', '#5f8d8a', '#4a6fa5', '#a05fb0', '#a8a29a', '#4f9d7a'],
  mapPrivate: '#6ea8c8',
  mapPublic: '#e8b04b',
  mapMulticast: '#b07cc6',
  mapLocal: '#7fa650',
  mapUnclassified: '#7d6b58',
}

const SOC: ThemeTokens = {
  bg: '#060b12',
  surface: '#0d1620',
  surface2: '#13202c',
  border: '#1e3242',
  border2: '#2a4759',
  accent: '#06b6d4',
  accent2: '#22d3ee',
  text: '#dbe7ee',
  muted: '#7f9aab',
  faint: '#55707f',
  glow: 'rgba(6,182,212,0.35)',
  sevInformational: '#6b8298',
  sevLow: '#38bdf8',
  sevMedium: '#f59e0b',
  sevHigh: '#ef4444',
  ok: '#22c55e',
  warn: '#f59e0b',
  danger: '#ef4444',
  chart: ['#06b6d4', '#22d3ee', '#38bdf8', '#2dd4bf', '#14b8a6', '#a78bfa', '#6366f1', '#0ea5e9'],
  mapPrivate: '#22d3ee',
  mapPublic: '#f59e0b',
  mapMulticast: '#a78bfa',
  mapLocal: '#22c55e',
  mapUnclassified: '#6b8298',
}

export const THEMES: Record<ThemeId, ThemeDefinition> = {
  shinobi: {
    id: 'shinobi',
    label: 'Shinobi',
    description:
      'Jet black, quiet grey and one neon ascent blue. The stealth palette: edges are hairlines, hue is reserved for what matters.',
    swatch: ['#050607', '#12161a', '#35a7ff', '#7fd2ff', '#e7edf2'],
    tokens: SHINOBI,
  },
  'steel-blue': {
    id: 'steel-blue',
    label: 'Steel Blue',
    description: 'The original restrained analyst palette: deep navy, a single blue accent, quiet greys.',
    swatch: ['#0b1120', '#16203a', '#3b82f6', '#60a5fa', '#e2e8f0'],
    tokens: STEEL_BLUE,
  },
  'cyber-punk': {
    id: 'cyber-punk',
    label: 'Cyber Punk',
    description: 'Neon magenta and cyan on purple-black. The boldest and highest-contrast of the four.',
    swatch: ['#08060f', '#1a1030', '#ff2d95', '#22d3ee', '#f0e7ff'],
    tokens: CYBER_PUNK,
  },
  'cyber-samurai': {
    id: 'cyber-samurai',
    label: 'Cyber Samurai',
    description: 'Crimson and gold on ink-black with warm paper text. Muted, print-like series colours.',
    swatch: ['#0c0a09', '#201a15', '#d7263d', '#e8b04b', '#f2e9dd'],
    tokens: CYBER_SAMURAI,
  },
  soc: {
    id: 'soc',
    label: 'SOC',
    description: 'Security-operations cyan on navy-black, with green reserved for healthy status.',
    swatch: ['#060b12', '#13202c', '#06b6d4', '#22d3ee', '#dbe7ee'],
    tokens: SOC,
  },
}

export const THEME_LIST: ThemeDefinition[] = [
  THEMES.shinobi,
  THEMES['steel-blue'],
  THEMES['cyber-punk'],
  THEMES['cyber-samurai'],
  THEMES.soc,
]

export function isThemeId(value: unknown): value is ThemeId {
  return typeof value === 'string' && value in THEMES
}

export function themeById(id: string | null | undefined): ThemeDefinition {
  return isThemeId(id) ? THEMES[id] : THEMES[DEFAULT_THEME_ID]
}
/** Token key -> CSS custom property name. */
export const TOKEN_VARS = {
  bg: '--c-bg',
  surface: '--c-surface',
  surface2: '--c-surface2',
  border: '--c-border',
  border2: '--c-border2',
  accent: '--c-accent',
  accent2: '--c-accent2',
  text: '--c-text',
  muted: '--c-muted',
  faint: '--c-faint',
  glow: '--c-glow',
  sevInformational: '--c-sev-informational',
  sevLow: '--c-sev-low',
  sevMedium: '--c-sev-medium',
  sevHigh: '--c-sev-high',
  ok: '--c-ok',
  warn: '--c-warn',
  danger: '--c-danger',
  mapPrivate: '--c-map-private',
  mapPublic: '--c-map-public',
  mapMulticast: '--c-map-multicast',
  mapLocal: '--c-map-local',
  mapUnclassified: '--c-map-unclassified',
} as const

/** Keys of `TOKEN_VARS` that hold a single colour and are published on every change. */
export type ChannelToken = keyof typeof TOKEN_VARS

/** `#0b1120` -> `11 17 32`, the form `rgb(var(--x) / <alpha-value>)` needs. */
export function hexToChannels(hex: string): string {
  const value = hex.trim().replace(/^#/, '')
  const full =
    value.length === 3
      ? value
          .split('')
          .map((char) => char + char)
          .join('')
      : value
  if (!/^[0-9a-fA-F]{6}$/.test(full)) return '0 0 0'
  const red = Number.parseInt(full.slice(0, 2), 16)
  const green = Number.parseInt(full.slice(2, 4), 16)
  const blue = Number.parseInt(full.slice(4, 6), 16)
  return red + ' ' + green + ' ' + blue
}

/**
 * Every CSS custom property for one theme: all channel tokens (as `r g b`), the
 * glow (kept whole because it always carries alpha) and the eight chart hues so
 * CSS can reach them too.
 */
export function themeCssVariables(theme: ThemeDefinition): Record<string, string> {
  const variables: Record<string, string> = {}
  for (const key of Object.keys(TOKEN_VARS) as ChannelToken[]) {
    variables[TOKEN_VARS[key]] = hexToChannels(theme.tokens[key] as string)
  }
  variables['--c-glow'] = theme.tokens.glow
  theme.tokens.chart.forEach((colour, index) => {
    variables['--c-chart-' + String(index + 1)] = hexToChannels(colour)
  })
  return variables
}

/**
 * Severity colour as a CSS value that follows the active theme. Useful for SVG
 * and inline styles where a class is not an option.
 */
export function severityVar(severity: string): string {
  switch (severity) {
    case 'high':
      return 'rgb(var(--c-sev-high))'
    case 'medium':
      return 'rgb(var(--c-sev-medium))'
    case 'low':
      return 'rgb(var(--c-sev-low))'
    default:
      return 'rgb(var(--c-sev-informational))'
  }
}