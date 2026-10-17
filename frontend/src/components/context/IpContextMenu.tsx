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
import {
  ArrowLeftRight,
  CheckCircle2,
  Crosshair,
  Hash,
  Loader2,
  MonitorPlay,
  TriangleAlert,
  Waypoints,
} from 'lucide-react'
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
  /** The frame number, when the click landed inside a packet row. */
  frame: number | null
  /**
   * The other end of the conversation, when the element knows both.
   *
   * With a peer the Wireshark pivot composes `ip.src == <ip> && ip.dst == <peer>` —
   * a direction rather than every frame the address touches, which is what an
   * analyst looking at one side of an exchange actually means.
   */
  peer: string | null
}

/** Where "Pivot <ip> to Hunt" goes: the profile page's documented parameters. */
export function huntUrl(ip: string): string {
  return `/investigate?kind=ip&entity=${encodeURIComponent(ip)}`
}

/**
 * Where "Show Conversations with <ip>" goes: the address filter, plus the stream
 * when the element knew it so the page can preselect that conversation. The value
 * is the same `transport:stream_id` key the Conversations page already reads, and
 * no `tab` is set, so the page opens on its primary tab (the flow diagram) - this
 * item answers "what does this address talk to", not "show me this exchange".
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
 * Where "Follow this conversation" goes: that exchange, on its own timeline.
 *
 * `tab=timeline` is the point of following one - the frames in order with the
 * stream's reassembled bodies - rather than the flow diagram, which is where a
 * reader arriving without a target should land. Every other follow link in the
 * application (the Findings button, a Dashboard destination, a credential row)
 * builds the same `?stream=<transport>:<id>&tab=timeline` form, so following a
 * conversation always looks the same; the address is added here because the menu
 * was opened on a specific row and the list behind it should agree.
 */
export function conversationTimelineUrl(
  ip: string | null,
  transport: string | null,
  streamId: number | null,
): string {
  const query = new URLSearchParams()
  if (ip !== null && ip !== '') query.set('ip', ip)
  query.set('tab', 'timeline')
  if (streamId !== null && streamId !== undefined && transport) {
    query.set('stream', `${transport}:${streamId}`)
  }
  return `/conversations?${query.toString()}`
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
  /* The frame is read from an ancestor rather than the holder: a cell carries the
     address and the conversation, the row carries the frame it is a row of. */
  const frameHolder = (element as Element | null)?.closest?.('[data-frame]') ?? null
  const parsedFrame =
    frameHolder === null ? null : Number.parseInt(frameHolder.getAttribute('data-frame') ?? '', 10)
  /* The peer is read from the same holder as the address: an element that knows
     both ends of a conversation declares both, so the filter can name a direction. */
  const peer = holder.getAttribute('data-ip-peer')
  return {
    ip: ip.trim(),
    transport: holder.getAttribute('data-ip-transport'),
    streamId: parsedStream !== null && Number.isFinite(parsedStream) ? parsedStream : null,
    port: parsedPort !== null && Number.isFinite(parsedPort) ? parsedPort : null,
    frame: parsedFrame !== null && Number.isFinite(parsedFrame) ? parsedFrame : null,
    peer: peer === null || peer.trim() === '' ? null : peer.trim(),
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
/* finding an address in text                                          */
/* ------------------------------------------------------------------ */

/**
 * Every address is right-clickable, including the ones drawn by components that
 * know nothing about this menu.
 *
 * The explicit `data-ip` attributes are the precise route — they can also carry
 * a conversation — but they only cover the surfaces somebody remembered to
 * annotate. So the menu also reads the text under the pointer: an address is an
 * address wherever it is printed, and an analyst should not have to learn which
 * tables are "menu-able". Both routes end in the same three actions.
 */

const IPV4_CANDIDATE = /(?:\d{1,3}\.){3}\d{1,3}/g
const IPV6_CANDIDATE = /(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/g

/** Four dotted decimal groups, each 0–255. */
export function isIpv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

/**
 * A hex-colon address. Deliberately stricter than "contains a colon": a
 * `transport:stream` label like `tcp:30` is not an address, and neither is
 * `12:34:56`, so a candidate has to survive the group count and the `::` rule.
 */
export function isIpv6(value: string): boolean {
  if (!value.includes(':') || !/^[0-9a-fA-F:.]+$/.test(value)) return false
  const doubleColons = value.split('::').length - 1
  if (doubleColons > 1) return false
  const groups = value.split(':').filter((group) => group !== '')
  if (groups.length === 0 || groups.length > 8) return false
  if (groups.some((group) => group.length > 4)) return false
  if (doubleColons === 0 && groups.length !== 8) return false
  const tail = groups[groups.length - 1]
  return /^[0-9a-fA-F]{1,4}$/.test(tail) || isIpv4(tail)
}

export interface IpToken {
  ip: string
  /** Trailing `:port`, when the text carried one (an `ip:port` endpoint). */
  port: number | null
  start: number
  end: number
}

/** Every address in a string, with where it sits in it. */
export function ipTokens(text: string): IpToken[] {
  const found: IpToken[] = []

  const collect = (pattern: RegExp, valid: (value: string) => boolean, ipv4: boolean) => {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      const value = match[0]
      if (!valid(value)) continue
      const start = match.index ?? 0
      const end = start + value.length
      if (found.some((token) => start < token.end && end > token.start)) continue
      let port: number | null = null
      if (ipv4) {
        /* `192.168.8.229:443` is one endpoint: the port is read as part of it but
           kept separate, because the filter wants the address and the menu wants
           the port only when no stream applies. */
        const tail = text.slice(end).match(/^:(\d{1,5})\b/)
        if (tail) {
          const parsed = Number(tail[1])
          if (parsed <= 65535) port = parsed
        }
      }
      found.push({ ip: value, port, start, end })
    }
  }

  collect(IPV4_CANDIDATE, isIpv4, true)
  collect(IPV6_CANDIDATE, isIpv6, false)
  return found.sort((left, right) => left.start - right.start)
}

/** The address the caret is inside, if any. */
export function ipAtOffset(text: string, offset: number): IpToken | null {
  for (const token of ipTokens(text)) {
    if (offset >= token.start && offset <= token.end) return token
  }
  return null
}

/** The text node under a point, when the browser can say which one it is. */
function textNodeAt(x: number, y: number): { node: Text; offset: number } | null {
  const doc = document as Document & {
    caretRangeFromPoint?: (x: number, y: number) => Range | null
    caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node; offset: number } | null
  }
  const range = doc.caretRangeFromPoint?.(x, y) ?? null
  if (range?.startContainer?.nodeType === Node.TEXT_NODE) {
    return { node: range.startContainer as Text, offset: range.startOffset }
  }
  const position = doc.caretPositionFromPoint?.(x, y) ?? null
  if (position?.offsetNode?.nodeType === Node.TEXT_NODE) {
    return { node: position.offsetNode as Text, offset: position.offset }
  }
  return null
}

/**
 * The address under the pointer, when the element under it declares none.
 *
 * First the caret's own text node — so in a cell holding
 * `192.168.8.229:51000 <-> 150.171.109.217:443` the address actually under the
 * cursor wins rather than the first one in the row. Then, for elements whose
 * text is one short value (a chip, a label, a mono cell), that text. A container
 * holding a paragraph is ignored rather than mined for addresses nobody aimed
 * at.
 */
export function factsFromPoint(x: number, y: number): IpTargetFacts | null {
  const caret = textNodeAt(x, y)
  if (caret) {
    const token = ipAtOffset(caret.node.data, caret.offset)
    if (token) {
      return { ip: token.ip, transport: null, streamId: null, port: token.port, frame: null, peer: null }
    }
  }

  let element = document.elementFromPoint?.(x, y) ?? null
  for (let depth = 0; element && depth < 4; depth += 1) {
    const text = (element.textContent ?? '').trim()
    if (text !== '' && text.length <= 64) {
      const tokens = ipTokens(text)
      if (tokens.length === 1) {
        return {
          ip: tokens[0].ip,
          transport: null,
          streamId: null,
          port: tokens[0].port,
          frame: null,
          peer: null,
        }
      }
    }
    element = element.parentElement
  }
  return null
}

/* ------------------------------------------------------------------ */
/* the body, separated so it can be rendered and read without a DOM     */
/* ------------------------------------------------------------------ */

export interface IpMenuBodyProps {
  /** `null` when the right click landed on something that names no address. */
  facts: IpTargetFacts | null
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
  /** A one-line confirmation for an action with no other outcome (a copy). */
  notice?: string | null
  onHunt: () => void
  onConversations: () => void
  onWireshark: () => void
  /** Open this conversation on the Conversations page. */
  onFollow?: () => void
  /** Copy the frame number the click landed on. */
  onCopyFrame?: () => void
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
  onFollow,
  onCopyFrame,
  notice = null,
  onKeyDown,
  menuRef,
  firstItemRef,
  style,
}: IpMenuBodyProps) {
  const ip = facts?.ip ?? null
  const scope =
    facts && facts.streamId !== null && facts.transport
      ? `${facts.transport.toUpperCase()} stream ${facts.streamId}`
      : null
  /* With no address every action is shown and none of them can do anything:
     greyed out, with the reason in one line, rather than a menu that vanishes or
     one that lies about being able to act. */
  const inert = ip === null
  const inertTitle = 'Right-click an address to use this'

  return (
    <div
      ref={menuRef}
      className="ip-menu"
      style={style}
      role="menu"
      aria-label={ip === null ? 'Address actions' : `Actions for ${ip}`}
      onKeyDown={onKeyDown}
      onContextMenu={(event) => event.preventDefault()}
    >
      <div className="ip-menu-head">
        {ip === null ? (
          <span className="text-faint">No address selected</span>
        ) : (
          <>
            <span className="mono">{ip}</span>
            {scope ? <span className="ip-menu-scope">{scope}</span> : null}
          </>
        )}
      </div>

      <button
        ref={firstItemRef}
        type="button"
        role="menuitem"
        className="ip-menu-item"
        disabled={inert}
        title={inert ? inertTitle : `Open the profile of ${ip}`}
        onClick={onHunt}
      >
        <Crosshair size={13} aria-hidden />
        <span>{ip === null ? 'Pivot to Hunt' : `Pivot ${ip} to Hunt`}</span>
      </button>

      <button
        type="button"
        role="menuitem"
        className="ip-menu-item"
        disabled={inert}
        title={inert ? inertTitle : `Every conversation involving ${ip}`}
        onClick={onConversations}
      >
        <ArrowLeftRight size={13} aria-hidden />
        <span>{ip === null ? 'Show Conversations' : `Show Conversations with ${ip}`}</span>
      </button>

      {scope !== null && onFollow !== undefined ? (
        <button
          type="button"
          role="menuitem"
          className="ip-menu-item"
          title={`Open ${scope} on the Conversations timeline`}
          onClick={onFollow}
        >
          <Waypoints size={13} aria-hidden />
          <span>Follow this conversation</span>
          <span className="ip-menu-hint">{scope}</span>
        </button>
      ) : null}

      <button
        type="button"
        role="menuitem"
        className="ip-menu-item"
        disabled={inert || !available || pending}
        title={
          inert
            ? inertTitle
            : available
              ? facts !== null && facts.peer !== null
                ? `Open this capture in Wireshark, filtered to ${ip} → ${facts.peer}${scope ? ' (' + scope + ')' : ''}`
                : `Open this capture in Wireshark, filtered to ${scope ?? ip}`
              : (unavailableReason ?? 'Checking whether Wireshark is installed…')
        }
        onClick={onWireshark}
      >
        {pending ? (
          <Loader2 size={13} className="animate-spin" aria-hidden />
        ) : (
          <MonitorPlay size={13} aria-hidden />
        )}
        <span>{scope !== null ? 'Open conversation in Wireshark' : 'Pivot to Wireshark'}</span>
        {version ? <span className="ip-menu-hint">v{version}</span> : null}
      </button>

      {facts !== null && facts.frame !== null && onCopyFrame !== undefined ? (
        <button
          type="button"
          role="menuitem"
          className="ip-menu-item"
          title={`Copy frame ${facts.frame} to the clipboard`}
          onClick={onCopyFrame}
        >
          <Hash size={13} aria-hidden />
          <span>Copy frame number</span>
          <span className="ip-menu-hint">#{facts.frame}</span>
        </button>
      ) : null}

      {inert ? (
        <p className="ip-menu-note">
          This menu works on any address in the application — a host row, a conversation endpoint, a
          packet's source or destination. Right-click one of those.
        </p>
      ) : null}

      {!inert && !available && !checking ? (
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

      {notice ? (
        <p className="ip-menu-ok">
          <CheckCircle2 size={11} aria-hidden />
          <span>{notice}</span>
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
        {inert
          ? 'Nothing here names an address, so there is nothing to pivot to.'
          : scope
            ? `The filter follows this conversation, not every frame with ${ip}.`
            : `Opens every frame ${ip} appears in, with the first selected.`}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* the live menu: listening, positioning, and the three actions        */
/* ------------------------------------------------------------------ */

interface OpenTarget {
  /** `null` when the right click landed on something that names no address. */
  facts: IpTargetFacts | null
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
  /* The last copy's confirmation, cleared with the menu: the menu closes on scroll
     and on the next right click, so a notice never outlives the action. */
  const [notice, setNotice] = useState<string | null>(null)
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
      /* A right click inside the menu itself keeps it where it is. */
      if (menuRef.current?.contains(event.target as Node)) {
        event.preventDefault()
        return
      }
      /* Text fields keep the browser's own menu: paste, spell-check and the rest
         of it belong to the field, and an address is never editable there. */
      if (isTypingTarget(event.target as Element | null)) return

      /* Everywhere else the menu opens — the application's own menu instead of
         the browser's — with the actions greyed out when the click named no
         address. */
      event.preventDefault()
      const facts =
        ipFactsFrom(event.target as Element | null) ??
        factsFromPoint(event.clientX, event.clientY)
      setNotice(null)
      setTarget({
        facts,
        x: event.clientX,
        y: event.clientY,
        opener: (event.target as HTMLElement) ?? null,
      })
    }

    /* Shift+F10 and the dedicated context-menu key are what a keyboard user has
       instead of a right click, and they only ever mean this menu. As with the
       pointer, the menu opens even when the focused element names no address. */
    const onKeyDown = (event: KeyboardEvent) => {
      const isMenuKey = event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')
      if (!isMenuKey) return
      const active = document.activeElement
      if (isTypingTarget(active)) return
      event.preventDefault()
      const facts =
        ipFactsFrom(active) ??
        (() => {
          const rect = (active as HTMLElement | null)?.getBoundingClientRect()
          return rect ? factsFromPoint(rect.left + 4, rect.top + rect.height / 2) : null
        })()
      const rect = (active as HTMLElement | null)?.getBoundingClientRect()
      setTarget({
        facts,
        x: rect ? rect.left + 12 : 24,
        y: rect ? rect.top + rect.height : 24,
        opener: (active as HTMLElement) ?? null,
      })
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
    mutationFn: (facts: IpTargetFacts) =>
      wiresharkApi.launch(analysisId as string, {
        ip: facts.ip,
        peer_ip: facts.peer,
        transport: facts.transport,
        stream_id: facts.streamId,
        port: facts.port,
      }),
  })

  if (!target) return null

  const facts = target.facts

  return createPortal(
    <IpMenuBody
      facts={facts}
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
      notice={notice}
      onFollow={() => {
        if (!facts) return
        close()
        navigate(conversationTimelineUrl(facts.ip, facts.transport, facts.streamId))
      }}
      onCopyFrame={() => {
        if (!facts || facts.frame === null) return
        const value = String(facts.frame)
        void (async () => {
          try {
            await navigator.clipboard.writeText(value)
            setNotice('Frame ' + value + ' copied to the clipboard.')
          } catch {
            setNotice('The clipboard is not available in this context.')
          }
        })()
      }}
      menuRef={menuRef}
      firstItemRef={firstItemRef}
      style={position}
      onKeyDown={onMenuKeyDown}
      onHunt={() => {
        if (!facts) return
        close()
        navigate(huntUrl(facts.ip))
      }}
      onConversations={() => {
        if (!facts) return
        close()
        navigate(conversationsUrl(facts.ip, facts.transport, facts.streamId))
      }}
      onWireshark={() => {
        if (!facts) return
        launch.mutate(facts)
      }}
    />,
    document.body,
  )
}

export default IpContextMenu
