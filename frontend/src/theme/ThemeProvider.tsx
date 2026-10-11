import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import {
  DEFAULT_THEME_ID,
  THEMES,
  THEME_LIST,
  THEME_STORAGE_KEY,
  isThemeId,
  themeById,
  themeCssVariables,
  type ThemeDefinition,
  type ThemeId,
  type ThemeTokens,
} from '@/theme/themes'

export interface ThemeContextValue {
  themeId: ThemeId
  /** Switch theme: applies immediately and persists for this browser. */
  setTheme: (id: ThemeId) => void
  /** Active palette as plain strings, for charts and inline SVG. */
  tokens: ThemeTokens
  theme: ThemeDefinition
  themes: ThemeDefinition[]
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

/** `localStorage` can throw (private mode, disabled storage), so read defensively. */
function readStoredTheme(): ThemeId {
  if (typeof window === 'undefined') return DEFAULT_THEME_ID
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isThemeId(stored) ? stored : DEFAULT_THEME_ID
  } catch {
    return DEFAULT_THEME_ID
  }
}

/**
 * Publish one palette as CSS custom properties on `<html>`.
 *
 * This is the single write path for theming: Tailwind colours and every
 * component class resolve `rgb(var(--c-…))`, so one call re-themes the whole
 * application. `data-theme` is set as well, for debugging and for any future
 * attribute-scoped CSS.
 */
export function applyTheme(id: ThemeId): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  const theme = themeById(id)
  for (const [name, value] of Object.entries(themeCssVariables(theme))) {
    root.style.setProperty(name, value)
  }
  root.dataset.theme = theme.id
  root.dataset.themeReady = 'true'
  root.style.colorScheme = 'dark'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [themeId, setThemeId] = useState<ThemeId>(() => readStoredTheme())

  // Layout effect: the variables are in place before the browser paints the
  // first frame, so switching themes never shows an intermediate palette.
  useLayoutEffect(() => {
    applyTheme(themeId)
  }, [themeId])

  const setTheme = useCallback((id: ThemeId) => {
    setThemeId(id)
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, id)
    } catch {
      // Storage unavailable: the choice still applies for this page view.
    }
  }, [])

  const value = useMemo<ThemeContextValue>(
    () => ({
      themeId,
      setTheme,
      tokens: THEMES[themeId].tokens,
      theme: THEMES[themeId],
      themes: THEME_LIST,
    }),
    [themeId, setTheme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext)
  if (context) return context
  // Defensive: a component rendered outside the provider still gets colours.
  return {
    themeId: DEFAULT_THEME_ID,
    setTheme: () => undefined,
    tokens: THEMES[DEFAULT_THEME_ID].tokens,
    theme: THEMES[DEFAULT_THEME_ID],
    themes: THEME_LIST,
  }
}

/** Active palette only - the common case for charts and inline SVG. */
export function useThemeTokens(): ThemeTokens {
  return useTheme().tokens
}