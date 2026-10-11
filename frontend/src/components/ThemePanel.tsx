import clsx from 'clsx'
import { Check, Palette } from 'lucide-react'
import Panel from '@/components/Panel'
import { useTheme } from '@/theme/ThemeProvider'

/**
 * Theme chooser: four palettes, applied instantly and remembered per browser.
 * The swatches come from the theme definitions, so this panel can never drift
 * from the palettes themselves.
 */
export function ThemePanel() {
  const { themeId, setTheme, themes } = useTheme()

  return (
    <Panel
      title="Theme"
      subtitle="applies immediately across the app and is remembered in this browser"
      actions={
        <span className="flex items-center gap-1 text-2xs text-faint">
          <Palette size={13} aria-hidden />
          {themes.length} palettes
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {themes.map((theme) => {
          const active = theme.id === themeId
          return (
            <button
              key={theme.id}
              type="button"
              onClick={() => setTheme(theme.id)}
              aria-pressed={active}
              title={theme.description}
              className={clsx(
                'panel flex flex-col gap-2 p-3 text-left transition-colors',
                active ? 'border-accent shadow-bloom' : 'hover:border-border2',
              )}
            >
              <div className="flex items-center gap-2">
                <span className="truncate text-sm font-medium text-text">{theme.label}</span>
                {active ? (
                  <span className="chip ml-auto border-accent/50 bg-accent/15 text-accent2">
                    <Check size={10} aria-hidden />
                    active
                  </span>
                ) : (
                  <span className="ml-auto text-2xs text-faint">select</span>
                )}
              </div>

              <div className="flex items-center gap-1" aria-hidden>
                {theme.swatch.map((colour) => (
                  <span
                    key={colour}
                    className="h-5 w-6 rounded-sm border border-black/30"
                    style={{ background: colour }}
                  />
                ))}
              </div>

              <p className="text-2xs leading-relaxed text-muted">{theme.description}</p>

              <div className="flex flex-wrap items-center gap-1 text-2xs">
                <span
                  className="chip border-border2 bg-surface2"
                  style={{ color: theme.tokens.accent2 }}
                >
                  accent
                </span>
                <span
                  className="chip border-border2 bg-surface2"
                  style={{ color: theme.tokens.accent }}
                >
                  accent 2
                </span>
                <span className="chip border-border2 bg-surface2 text-muted">
                  {theme.tokens.chart.length} series
                </span>
              </div>
            </button>
          )
        })}
      </div>
      <p className="mt-2 text-2xs text-faint">
        The palette drives interface colours, charts and the network map. Severity colours keep the
        same meaning in every theme, and every combination is checked for text contrast.
      </p>
    </Panel>
  )
}

export default ThemePanel