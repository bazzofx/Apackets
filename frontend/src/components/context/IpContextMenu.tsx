/**
 * The right-click menu for an IP address: one menu, for every address on screen.
 *
 * Addresses are drawn in a dozen different components — a table cell, a map
 * node, a card, a chip — and threading a provider through all of them would
 * mean touching each one's props and breaking the ones that render a bare
 * string. So the menu **delegates**: it listens once on ``document`` for a
 * ``contextmenu`` event, walks up from whatever was clicked to the nearest
 * element carrying a ``data-ip`` attribute, and opens there. Adding the menu to
 * a new surface is therefore one attribute, and no component has to know the
 * menu exists.
 *
 * What an element can say about itself, all optional except the address:
 *
 * | Attribute | Meaning |
 * |---|---|
 * | `data-ip` | the address, required — this is what makes an element menu-able |
 * | `data-ip-transport` | `tcp`, `udp`, … when the element is one conversation |
 * | `data-ip-stream` | that conversation's stream id |
 * | `data-ip-port` | the port to fall back on when no stream applies |
 *
 * The stream matters to two of the three actions: it is what makes the
 * Conversations link open *that exchange*, and the Wireshark pivot open *that
 * conversation* rather than every frame the address appears in.
 *
 * Three actions, and no fourth that quietly does something else:
 *
 * * **Pivot <ip> to Hunt** — the one-entity profile for this address.
 * * **Show Conversations with <ip>** — the conversations list, filtered to it.
 * * **Pivot to Wireshark** — asks the backend to open this capture in the
 *   Wireshark GUI, filtered. The item is only offered when the backend reports a
 *   GUI to open; when it does not, the reason is shown instead of a control that
 *   would fail.
 *
 * The menu is a portal on ``document.body``, positioned at the pointer and
 * clamped into the viewport, so it is never clipped by the scroll container or
 * the `overflow: hidden` panel the address happens to sit in.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MutableRefObject,
} from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, CheckCircle2, Crosshair, Loader2, MonitorPlay, TriangleAlert } from 'lucide-react'
import { useAnalysis } from '@/hooks/useAnalysis'
import { wiresharkApi } from '@/services/api'

/** How close to the viewport edge the menu may come. */
const MARGIN = 8
/** Used only when the menu cannot be measured (a jsdom-free render). */
const MENU_WIDTH = 288

/** The address, and the conversation it was found in when that is known. */
export interface IpTargetFacts {
  ip: string
  transport: string | null
  streamId: number | null
  port: number | null
}

/** Where "Pivot <ip> to Hunt" goes: the profile page's documented parameters. */
export function huntUrl(ip: string): string {
  return `/investigate?kind=ip&entity=${encodeURIComponent(ip)}`
}

/**
 * Where "Show Conversations with <ip>" goes.
 *
 * The stream is added when the element knew it, so the page can open that
 * conversation rather than only filtering the list to the address. The value is
 * the same `transport:stream_id` key the Conversations page already reads.
 */
export function conversationsUrl(
  ip: string,
  transport: string | null,
  streamId: number | null,
): string {
  const base = `/conversations?ip=${encodeURIComponent(ip)}`
  if (streamId === null || streamId === undefined || !transport) return base
  return `${base}&stream=${encodeURIComponent(`${transport}:${streamId}`)}`
}

/**
 * Read the address — and, when it declares one, the conversation — off an element.
 *
 * The nearest `data-ip` ancestor wins, so a conversation row can carry its own
 * stream and address while a cell inside it names a different one.
 */
export function ipFactsFrom(element: Element | null): IpTargetFacts | null {
  const holder = (element as Element | null)?.closest?.('[data-ip]') ?? null
  if (!holder) return null
  const ip = holder.getAttribute('data-ip')
  if (ip === null || ip.trim() === '') return null
  const stream = holder.getAttribute('data-ip-stream')
  const port = holder.getAttribute('data-ip-port')
  const parsedStream = stream === null ? null : Number.parseInt(stream, 10)
  const parsedPort = port === null ? null : Number.parseInt(port, 10)
  return {
    ip: ip.trim(),
    transport: holder.getAttribute('data-ip-transport'),
    streamId: parsedStream !== null && Number.isFinite(parsedStream) ? parsedStream : null,
    port: parsedPort !== null && Number.isFinite(parsedPort) ? parsedPort : null,
  }
}

/** Typing targets keep their own context menu; nothing else is exempt. */
export function isTypingTarget(element: Element | null): boolean {
  if (!element) return false
  const tag = element.tagName.toLowerCase()
  return (
    tag === 'input' ||
    tag === 'textarea' ||
    tag === 'select' ||
    element.getAttribute('contenteditable') === 'true'
  )
}

/* ------------------------------------------------------------------ */
/* the body, separated so it can be rendered and read without a DOM     */
/* ------------------------------------------------------------------ */

export interface IpMenuBodyProps {
  facts: IpTargetFacts
  /** Whether the backend reports a Wireshark GUI to open. */
  available: boolean
  /** True while that answer is still being fetched. */
  checking: boolean
  version: string | null
  unavailableReason: string | null
  pending: boolean
  error: string | null
  /** The filter the backend composed, once a launch has succeeded. */
  result: string | null
  onHunt: () => void
  onConversations: () => void
  onWireshark: () => void
  onKeyDown?: (event: ReactKeyboardEvent<HTMLDivElement>) => void
  menuRef?: MutableRefObject<HTMLDivElement | null>
  firstItemRef?: MutableRefObject<HTMLButtonElement | null>
  style?: { left: number; top: number }
}

/** The menu itself: a heading, three actions, and the outcome of the last one. */
export function IpMenuBody({
  facts,
  available,
  checking,
  version,
  unavailableReason,
  pending,
  error,
  result,
  onHunt,
  onConversations,
  onWireshark,
  onKeyDown,
  menuRef,
  firstItemRef,
  style,
}: IpMenuBodyProps) {
  const scope =
    facts.streamId !== null && facts.transport
      ? `${facts.transport.toUpperCase()} stream ${facts.streamId}`
      : null

  return (
    <div
      ref={menuRef}
      className="ip-menu"
      style={style}
      role="menu"
      aria-label={`Actions for ${facts.ip}`}
      onKeyDown={onKeyDown}
      onContextMenu={(event) => event.preventDefault()}
    >
      <div className="ip-menu-head">
        <span className="mono">{facts.ip}</span>
        {scope ? <span className="ip-menu-scope">{scope}</span> : null}
      </div>

      <button ref={firstItemRef} type="button" role="menuitem" className="ip-menu-item" onClick={onHunt}>
        <Crosshair size={13} aria-hidden />
        <span>Pivot {facts.ip} to Hunt</span>
      </button>

      <button type="button" role="menuitem" className="ip-menu-item" onClick={onConversations}>
        <ArrowLeftRight size={13} aria-hidden />
        <span>Show Conversations with {facts.ip}</span>
      </button>

      <button
        type="button"
        role="menuitem"
        className="ip-menu-item"
        disabled={!available || pending}
        title={
          available
            ? `Open this capture in Wireshark, filtered to ${scope ?? facts.ip}`
            : (unavailableReason ?? 'Checking whether Wireshark is installed…')
        }
        onClick={onWireshark}
      >
        {pending ? (
          <Loader2 size={13} className="animate-spin" aria-hidden />
        ) : (
          <MonitorPlay size={13} aria-hidden />
        )}
        <span>Pivot to Wireshark</span>
        {version ? <span className="ip-menu-hint">v{version}</span> : null}
      </button>

      {!available && !checking ? (
        <p className="ip-menu-note">
          {unavailableReason ?? 'No Wireshark GUI was found on this machine.'} Install Wireshark, or
          set <span className="mono">APACKETS_WIRESHARK_PATH</span> to the executable.
        </p>
      ) : null}

      {error ? (
        <p className="ip-menu-error">
          <TriangleAlert size={11} aria-hidden />
          <span>{error}</span>
        </p>
      ) : null}

      {result ? (
        <p className="ip-menu-ok">
          <CheckCircle2 size={11} aria-hidden />
          <span>
            Opened in Wireshark — filter <span className="mono">{result}</span>
          </span>
        </p>
      ) : null}

      <div className={result ? 'ip-menu-foot ip-menu-foot-ok' : 'ip-menu-foot'}>
        {scope
          ? `The filter follows this conversation, not every frame with ${facts.ip}.`
          : `Opens every frame ${facts.ip} appears in.`}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* the live menu: listening, positioning, and the three actions        */
/* ------------------------------------------------------------------ */

interface OpenTarget extends IpTargetFacts {
  x: number
  y: number
  /** Where focus goes back to when the menu closes. */
  opener: HTMLElement | null
}

export function IpContextMenu() {
  const { analysisId } = useAnalysis()
  const navigate = useNavigate()
  const [target, setTarget] = useState<OpenTarget | null>(null)
  const [position, setPosition] = useState({ left: 0, top: 0 })
  const menuRef = useRef<HTMLDivElement | null>(null)
  const firstItemRef = useRef<HTMLButtonElement | null>(null)

  const close = useCallback((refocus = false) => {
    setTarget((current) => {
      if (refocus && current?.opener?.isConnected) current.opener.focus()
      return null
    })
  }, [])

  /* ---------------------------------------------------------------- */
  /* opening: pointer, and the keyboard equivalent                     */
  /* ---------------------------------------------------------------- */

  useEffect(() => {
    const onContextMenu = (event: MouseEvent) => {
      const facts = ipFactsFrom(event.target as Element | null)
      if (!facts) return // not an address: leave the browser's own menu alone
      event.preventDefault()
      setTarget({
        ...facts,
        x: event.clientX,
        y: event.clientY,
        opener: (event.target as HTMLElement) ?? null,
      })
    }

    /* Shift+F10 and the dedicated context-menu key are what a keyboard user has
       instead of a right click, and they only ever mean this menu. */
    const onKeyDown = (event: KeyboardEvent) => {
      const isMenuKey = event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')
      if (!isMenuKey) return
      const active = document.activeElement
      if (isTypingTarget(active)) return
      const facts = ipFactsFrom(active)
      if (!facts) return
      event.preventDefault()
      const rect = (active as HTMLElement).getBoundingClientRect()
      setTarget({ ...facts, x: rect.left + 12, y: rect.top + rect.height, opener: active as HTMLElement })
    }

    document.addEventListener('contextmenu', onContextMenu)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('contextmenu', onContextMenu)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [])

  /* Dismissal: Escape, a press anywhere else, scrolling, or a resize. */
  useEffect(() => {
    if (!target) return
    const onDown = (event: PointerEvent) => {
      if (menuRef.current?.contains(event.target as Node)) return
      close()
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        close(true)
      }
    }
    const onScrollOrResize = () => close()
    document.addEventListener('pointerdown', onDown, true)
    document.addEventListener('keydown', onKey, true)
    window.addEventListener('scroll', onScrollOrResize, true)
    window.addEventListener('resize', onScrollOrResize)
    return () => {
      document.removeEventListener('pointerdown', onDown, true)
      document.removeEventListener('keydown', onKey, true)
      window.removeEventListener('scroll', onScrollOrResize, true)
      window.removeEventListener('resize', onScrollOrResize)
    }
  }, [target, close])

  /* Position: at the pointer, then pulled back inside the frame. */
  useLayoutEffect(() => {
    if (!target) return
    const box = menuRef.current?.getBoundingClientRect()
    const width = box?.width ?? MENU_WIDTH
    const height = box?.height ?? 0
    const maxLeft = Math.max(MARGIN, window.innerWidth - width - MARGIN)
    const maxTop = Math.max(MARGIN, window.innerHeight - height - MARGIN)
    setPosition({
      left: Math.min(Math.max(MARGIN, target.x), maxLeft),
      top: Math.min(Math.max(MARGIN, target.y), maxTop),
    })
  }, [target])

  /* Focus the first item when the menu opens, so the keyboard can walk it. */
  useEffect(() => {
    if (target) firstItemRef.current?.focus()
  }, [target])

  const onMenuKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    event.preventDefault()
    const items = Array.from(
      menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([disabled])') ?? [],
    )
    if (items.length === 0) return
    const index = items.indexOf(document.activeElement as HTMLButtonElement)
    const next = event.key === 'ArrowDown' ? index + 1 : index - 1
    items[(next + items.length) % items.length]?.focus()
  }

  /* ---------------------------------------------------------------- */
  /* the actions                                                       */
  /* ---------------------------------------------------------------- */

  const status = useQuery({
    queryKey: ['wireshark-status', analysisId],
    queryFn: () => wiresharkApi.status(analysisId as string),
    enabled: Boolean(analysisId && target),
    retry: false,
    staleTime: 60_000,
  })

  const launch = useMutation({
    mutationFn: (facts: OpenTarget) =>
      wiresharkApi.launch(analysisId as string, {
        ip: facts.ip,
        transport: facts.transport,
        stream_id: facts.streamId,
        port: facts.port,
      }),
  })

  if (!target) return null

  return createPortal(
    <IpMenuBody
      facts={target}
      available={status.data?.available === true}
      checking={status.isLoading || status.isFetching}
      version={status.data?.version ?? null}
      unavailableReason={
        status.data?.reason ??
        (status.isError ? 'The backend could not be asked whether Wireshark is installed.' : null)
      }
      pending={launch.isPending}
      error={
        launch.isError
          ? launch.error instanceof Error && launch.error.message
            ? launch.error.message
            : 'Wireshark could not be started.'
          : null
      }
      result={launch.isSuccess ? launch.data.filter : null}
      menuRef={menuRef}
      firstItemRef={firstItemRef}
      style={position}
      onKeyDown={onMenuKeyDown}
      onHunt={() => {
        close()
        navigate(huntUrl(target.ip))
      }}
      onConversations={() => {
        close()
        navigate(conversationsUrl(target.ip, target.transport, target.streamId))
      }}
      onWireshark={() => launch.mutate(target)}
    />,
    document.body,
  )
}

export default IpContextMenu
