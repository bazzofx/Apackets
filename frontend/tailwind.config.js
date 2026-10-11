/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
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
        sev: {
          informational: '#64748b',
          low: '#38bdf8',
          medium: '#f59e0b',
          high: '#ef4444',
        },
        ok: '#22c55e',
        warn: '#f59e0b',
        danger: '#ef4444',
      },
      fontFamily: {
        sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Cascadia Mono', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
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
