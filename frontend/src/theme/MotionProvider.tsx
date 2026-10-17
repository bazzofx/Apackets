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
  DEFAULT_MOTION,
  MOTION_STORAGE_KEY,
  applyMotionAttribute,
  motionIsStill,
  readStoredMotion,
  type MotionPreference,
} from '@/theme/motion'

export interface MotionContextValue {
  motion: MotionPreference
  /** Switch the preference: applies immediately and persists for this browser. */
  setMotion: (next: MotionPreference) => void
  /**
   * True when nothing should move: the setting is `off`, or the operating system asked
   * for reduced motion. Components that animate beyond CSS ask this.
   */
  still: boolean
}

const MotionContext = createContext<MotionContextValue | null>(null)

export function MotionProvider({ children }: { children: ReactNode }) {
  const [motion, setMotionState] = useState<MotionPreference>(() => readStoredMotion())

  /* Before paint, so the first frame is already the right one - the same reason the
     palette is set in an inline script in index.html. */
  useLayoutEffect(() => {
    applyMotionAttribute(motion)
  }, [motion])

  const setMotion = useCallback((next: MotionPreference) => {
    setMotionState(next)
    try {
      window.localStorage.setItem(MOTION_STORAGE_KEY, next)
    } catch {
      /* storage unavailable (private mode): the choice holds for this page only */
    }
  }, [])

  const value = useMemo<MotionContextValue>(
    () => ({ motion, setMotion, still: motion === 'off' || motionIsStill() }),
    [motion, setMotion],
  )

  return <MotionContext.Provider value={value}>{children}</MotionContext.Provider>
}

export function useMotion(): MotionContextValue {
  const ctx = useContext(MotionContext)
  if (!ctx) throw new Error('useMotion must be used inside <MotionProvider>')
  return ctx
}

export type { MotionPreference }
export { DEFAULT_MOTION, MOTION_STORAGE_KEY }
