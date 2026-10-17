/** @type {import('tailwindcss').Config} */
// Every colour is a CSS custom property published by src/theme/ThemeProvider.tsx
// from the palettes in src/theme/themes.ts. The variables hold space separated
// RGB channels so Tailwind's opacity modifiers (bg-accent/15, divide-border/60)
// keep working. index.css carries the Steel Blue defaults in :root so the app is
// styled before React runs.
const token = (name) => `rgb(var(${name}) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg: token('--c-bg'),
        surface: token('--c-surface'),
        surface2: token('--c-surface2'),
        border: token('--c-border'),
        border2: token('--c-border2'),
        accent: token('--c-accent'),
        accent2: token('--c-accent2'),
        text: token('--c-text'),
        muted: token('--c-muted'),
        faint: token('--c-faint'),
        sev: {
          informational: token('--c-sev-informational'),
          low: token('--c-sev-low'),
          medium: token('--c-sev-medium'),
          high: token('--c-sev-high'),
        },
        ok: token('--c-ok'),
        warn: token('--c-warn'),
        danger: token('--c-danger'),
      },
      fontFamily: {
        /* Body, table and UI text. Gurajada's Latin is drawn to Telugu
           proportions, so its @font-face in src/index.css carries a
           size-adjust that brings it back to a normal footprint; the fallbacks
           also supply the eight punctuation glyphs it does not contain. */
        sans: ['Gurajada', 'Segoe UI', 'system-ui', 'sans-serif'],
        /* Headings only: the page headline and every card title. Metal Mania
           ships a single weight, so nothing may set font-weight on it. */
        display: ['Metal Mania', 'Gurajada', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Cascadia Mono', 'Consolas', 'monospace'],
      },
      fontSize: {
        /* The smallest label in the interface: chips, panel subtitles, table
           captions, eyebrow text. 13px, and a line-height that keeps the same
           ratio the 11px value had (1.45), so multi-line captions still breathe
           without every panel growing a row. */
        '2xs': ['0.8125rem', { lineHeight: '1.1875rem' }],
      },
      boxShadow: {
        panel: '0 1px 2px 0 rgb(var(--c-bg) / 0.6)',
        bloom: '0 0 0 1px rgb(var(--c-border) / 0.8), 0 12px 40px -12px var(--c-glow)',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
      },
      animation: {
        'fade-in': 'fade-in 120ms ease-out',
      },
    },
  },
  plugins: [],
}