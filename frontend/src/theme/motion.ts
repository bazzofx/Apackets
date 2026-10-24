/**
 * Motion: how much the interface is allowed to move.
 *
 * The application animates entrance, presence and the world map's ambience, never a
 * number a reader is comparing. That is a design rule, but it is also a preference: a
 * reader who wants stillness should get stillness, not a slower firework. There are two
 * values and no more, because a slider on "how much motion" is a slider nobody can set
 * consistently:
 *
 * * `calm` - the default. Slow entrances, the map's slow travel, 260-1400 ms transitions.
 * * `off`   - stillness. `[data-motion='off']` in index.css removes every animation and
 *             every transition, and the world map stops drawing its travelling dash.
 *
 * The operating system's `prefers-reduced-motion` is honoured as well, and it wins: a
 * reader who has asked their OS for less motion is not asked again here. The choice is
 * per browser and stored locally - it is a preference, not analysis data.
 */

export type MotionPreference = 'calm' | 'off'

/** Per-browser preference. Kept on the application's existing storage prefix. */
export const MOTION_STORAGE_KEY = 'shadowpackets.motion'

/** The key this preference used before the rename; read once, when the new one is empty. */
const LEGACY_MOTION_STORAGE_KEY = 'apackets.motion'

export const DEFAULT_MOTION: MotionPreference = 'calm'

export function isMotionPreference(value: unknown): value is MotionPreference {
  return value === 'calm' || value === 'off'
}

/** Publish the preference on `<html>`, which is what the stylesheet reads. */
export function applyMotionAttribute(preference: MotionPreference): void {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-motion', preference)
}

/** The stored preference, or the default when storage is unavailable or empty. */
export function readStoredMotion(): MotionPreference {
  if (typeof window === 'undefined') return DEFAULT_MOTION
  try {
    const stored = window.localStorage.getItem(MOTION_STORAGE_KEY)
    if (isMotionPreference(stored)) return stored
    const legacy = window.localStorage.getItem(LEGACY_MOTION_STORAGE_KEY)
    if (!isMotionPreference(legacy)) return DEFAULT_MOTION
    try {
      window.localStorage.setItem(MOTION_STORAGE_KEY, legacy)
    } catch {
      // Storage is read-only here; the migrated value still applies for this view.
    }
    return legacy
  } catch {
    return DEFAULT_MOTION
  }
}

/**
 * Whether the interface is currently still.
 *
 * Components that animate something CSS cannot reach (the world map's dash offset, a
 * chart's draw-in) ask this instead of testing the media query themselves, so the
 * setting and the OS preference can never disagree about who is in charge.
 */
export function motionIsStill(): boolean {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false
  if (document.documentElement.getAttribute('data-motion') === 'off') return true
  try {
    return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true
  } catch {
    return false
  }
}
