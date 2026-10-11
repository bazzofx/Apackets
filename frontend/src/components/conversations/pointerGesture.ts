import type { FlowView } from './flowLayout'

/**
 * Pointer bookkeeping for pan-on-drag.
 *
 * The rule this module exists to protect: **pointer capture is taken only when a
 * press has become a drag**, never on pointerdown. Capturing up front makes the
 * browser deliver the following `click` to the capture target - the SVG root -
 * instead of the node or band that was actually hit, so every click on the chart
 * silently stops working. A pan still captures, so it keeps tracking the pointer
 * after it leaves the element.
 *
 * Everything here is pure, so the ordering is testable without a DOM.
 */

export interface PointerGesture {
  pointerId: number
  /** Where the press started, in the parent viewBox. */
  startX: number
  startY: number
  /** The view as it was when the press began, so a pan never accumulates drift. */
  view: FlowView
  /** True once the press has become a drag. */
  moved: boolean
}

/** How far a press may move before it counts as a drag, in screen pixels. */
export const DRAG_THRESHOLD_PX = 3

export interface DragStep {
  /** True on the one step where the drag begins: this is when to capture. */
  capture: boolean
  /** True while the gesture is a drag (this step and every later one). */
  dragging: boolean
  /** How far to pan, in plot units. */
  dx: number
  dy: number
}

/** Record a press. Nothing is captured here, on purpose. */
export function beginGesture(pointerId: number, x: number, y: number, view: FlowView): PointerGesture {
  return { pointerId, startX: x, startY: y, view, moved: false }
}

/**
 * Advance a gesture with a new pointer position.
 *
 * `capture` is true exactly once per gesture: on the step where the threshold is
 * crossed, which is the only moment pointer capture may be taken.
 */
export function dragStep(
  gesture: PointerGesture,
  x: number,
  y: number,
  scale: number,
  threshold: number = DRAG_THRESHOLD_PX,
): DragStep {
  const dxView = x - gesture.startX
  const dyView = y - gesture.startY
  const justStarted = !gesture.moved && Math.hypot(dxView, dyView) * scale >= threshold
  if (!gesture.moved && !justStarted) return { capture: false, dragging: false, dx: 0, dy: 0 }
  const safeScale = scale > 0 ? scale : 1
  return { capture: justStarted, dragging: true, dx: dxView / safeScale, dy: dyView / safeScale }
}

/** A drag, and only a drag, consumes the click that follows it. */
export function endGesture(gesture: PointerGesture | null | undefined): boolean {
  return gesture !== null && gesture !== undefined && gesture.moved
}

/**
 * Decide whether a click may run, consuming the suppression exactly once.
 *
 * One click after a drag is swallowed; every later click runs normally, so a
 * drag can never cost the user their next selection.
 */
export function takeClick(suppressed: boolean): { allow: boolean; suppressed: boolean } {
  return { allow: !suppressed, suppressed: false }
}

interface CaptureTarget {
  setPointerCapture?: (pointerId: number) => void
}

interface ReleaseTarget {
  hasPointerCapture?: (pointerId: number) => boolean
  releasePointerCapture?: (pointerId: number) => void
}

/**
 * Take pointer capture, tolerating every failure.
 *
 * The pointer can already be gone by the time a drag starts, and a throw here
 * would abort the rest of the move handler and leave the pan stuck.
 */
export function capturePointer(target: CaptureTarget | null, pointerId: number): boolean {
  if (target === null || typeof target.setPointerCapture !== 'function') return false
  try {
    target.setPointerCapture(pointerId)
    return true
  } catch {
    return false
  }
}

/** Release pointer capture, tolerating every failure, including not having it. */
export function releasePointer(target: ReleaseTarget | null, pointerId: number): void {
  if (target === null || typeof target.releasePointerCapture !== 'function') return
  try {
    if (typeof target.hasPointerCapture === 'function' && !target.hasPointerCapture(pointerId)) return
    target.releasePointerCapture(pointerId)
  } catch {
    /* The pointer is gone; there is nothing left to release. */
  }
}