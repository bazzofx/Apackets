import { useMemo, useState } from 'react'
import clsx from 'clsx'
import { ChevronDown, ChevronRight, Layers, TriangleAlert } from 'lucide-react'
import { EMPTY } from '@/utils/format'

/**
 * Protocol layer tree for one packet.
 *
 * The tree is rendered directly from the API's `layers` object (`tshark -T json`
 * with every `*_tree` child flattened into its parent, contract §7) and ordered
 * by `layer_order`. In practice `layer_order` is derived from
 * `frame.protocols`, which does *not* list `frame` itself, while `layers` does
 * contain a `frame` key — so `frame` is pinned to the top and every key present
 * in `layers` but absent from `layer_order` is appended in name order. Nothing
 * is invented and nothing is dropped.
 *
 * All values are capture-derived and therefore untrusted: they are rendered as
 * text nodes only, never as markup.
 */

/** Values longer than this are collapsed behind a "show all" toggle. */
const LONG_VALUE_CHARS = 400

/** Sanity cap so a pathological dissection cannot build an unbounded tree. */
const MAX_DEPTH = 8

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function primitiveText(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value)
  }
  return ''
}

/** One field value: monospace, wrapped, with a toggle for very long payloads. */
function ValueText({ text, tone = 'text-text' }: { text: string; tone?: string }) {
  const [expanded, setExpanded] = useState(false)
  if (text === '') return <span className="text-faint">{EMPTY}</span>
  const long = text.length > LONG_VALUE_CHARS
  const shown = long && !expanded ? `${text.slice(0, LONG_VALUE_CHARS)}…` : text
  return (
    <span className={clsx('mono min-w-0 break-all whitespace-pre-wrap', tone)}>
      {shown}
      {long ? (
        <button
          type="button"
          className="ml-1 shrink-0 rounded border border-border2 bg-surface2 px-1 text-2xs text-muted hover:text-text"
          onClick={() => setExpanded((value) => !value)}
          title={expanded ? 'Collapse this value' : `Show all ${text.length} characters`}
        >
          {expanded ? 'less' : `${text.length} chars`}
        </button>
      ) : null}
    </span>
  )
}

function FieldNode({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  const [open, setOpen] = useState(depth < 1)

  if (Array.isArray(value)) {
    // Arrays of objects (rare in a dissection) get their own sub-tree; arrays of
    // primitives are shown inline so simple repeats stay readable.
    const scalars = value.every((item) => !isPlainObject(item) && !Array.isArray(item))
    if (scalars) {
      const text = value.map((item) => primitiveText(item)).filter((item) => item !== '').join(', ')
      return (
        <div className="flex items-start gap-2 py-0.5 pl-1">
          <span className="w-56 shrink-0 truncate text-2xs text-faint" title={name}>
            {name}
          </span>
          <span className="min-w-0 flex-1">
            <ValueText text={text} />
            <span className="ml-1 text-2xs text-faint">({value.length} value(s))</span>
          </span>
        </div>
      )
    }
    return (
      <div className="py-0.5 pl-1">
        <button
          type="button"
          className="flex w-full items-center gap-1 text-left"
          onClick={() => setOpen((current) => !current)}
          aria-expanded={open}
        >
          {open ? <ChevronDown size={11} aria-hidden /> : <ChevronRight size={11} aria-hidden />}
          <span className="truncate text-2xs text-faint" title={name}>
            {name}
          </span>
          <span className="text-2xs text-faint">{value.length} entries</span>
        </button>
        {open ? (
          <div className="ml-3 border-l border-border/60 pl-2">
            {value.map((item, index) => (
              <FieldNode key={index} name={`[${index}]`} value={item} depth={depth + 1} />
            ))}
          </div>
        ) : null}
      </div>
    )
  }

  if (isPlainObject(value)) {
    if (depth >= MAX_DEPTH) {
      return (
        <div className="flex items-start gap-2 py-0.5 pl-1">
          <span className="w-56 shrink-0 truncate text-2xs text-faint" title={name}>
            {name}
          </span>
          <span className="text-2xs text-warn">
            nested deeper than {MAX_DEPTH} levels — not expanded
          </span>
        </div>
      )
    }
    const entries = Object.entries(value)
    return (
      <div className="py-0.5 pl-1">
        <button
          type="button"
          className="flex w-full items-center gap-1 text-left"
          onClick={() => setOpen((current) => !current)}
          aria-expanded={open}
        >
          {open ? <ChevronDown size={11} aria-hidden /> : <ChevronRight size={11} aria-hidden />}
          <span className="truncate text-2xs text-faint" title={name}>
            {name}
          </span>
          <span className="text-2xs text-faint">{entries.length} fields</span>
        </button>
        {open ? (
          <div className="ml-3 border-l border-border/60 pl-2">
            {entries.map(([key, child]) => (
              <FieldNode key={key} name={key} value={child} depth={depth + 1} />
            ))}
          </div>
        ) : null}
      </div>
    )
  }

  return (
    <div className="flex items-start gap-2 py-0.5 pl-1">
      <span className="w-56 shrink-0 truncate text-2xs text-faint" title={name}>
        {name}
      </span>
      <span className="min-w-0 flex-1">
        <ValueText text={primitiveText(value)} />
      </span>
    </div>
  )
}

function LayerBlock({
  name,
  value,
  startOpen,
}: {
  name: string
  value: unknown
  startOpen: boolean
}) {
  const [open, setOpen] = useState(startOpen)
  const entries = useMemo(() => (isPlainObject(value) ? Object.entries(value) : []), [value])
  const malformed = !isPlainObject(value)

  return (
    <section className="border-b border-border/60 last:border-b-0">
      <button
        type="button"
        className="flex w-full items-center gap-1.5 px-2 py-1 text-left hover:bg-surface2/60"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        {open ? <ChevronDown size={12} aria-hidden /> : <ChevronRight size={12} aria-hidden />}
        <Layers size={11} className="text-faint" aria-hidden />
        <span className="mono text-xs text-text">{name}</span>
        <span className="ml-auto text-2xs text-faint">
          {malformed ? 'unexpected shape' : `${entries.length} fields`}
        </span>
      </button>
      {open ? (
        malformed ? (
          <div className="flex items-start gap-2 px-3 pb-2 text-2xs text-warn">
            <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
            <span>
              This layer did not come back as an object and cannot be expanded. The raw value is
              shown as text below.
            </span>
          </div>
        ) : null
      ) : null}
      {open ? (
        <div className="pb-1.5 pl-3 pr-2">
          {malformed ? <ValueText text={primitiveText(value)} /> : null}
          {entries.map(([key, child]) => (
            <FieldNode key={key} name={key} value={child} depth={0} />
          ))}
        </div>
      ) : null}
    </section>
  )
}

export interface LayerTreeProps {
  layers: Record<string, unknown>
  layerOrder: string[]
  /** Layers expanded on first render (the first N of the resolved order). */
  initiallyExpanded?: number
  className?: string
}

/** Ordered, collapsible protocol layer tree. */
export function LayerTree({
  layers,
  layerOrder,
  initiallyExpanded = 3,
  className,
}: LayerTreeProps) {
  const { order, missing, extra } = useMemo(() => {
    const keys = Object.keys(layers ?? {})
    const known = new Set(keys)
    // `frame` is always the outermost layer but is absent from `layer_order`.
    const head = known.has('frame') ? ['frame'] : []
    const ordered = layerOrder.filter((name) => known.has(name) && name !== 'frame')
    const rest = keys.filter((name) => !head.includes(name) && !ordered.includes(name)).sort()
    return {
      order: [...head, ...ordered, ...rest],
      // `ethertype` is a pseudo-layer: TShark lists it in `frame.protocols` for
      // every Ethernet frame but folds its value into the `eth` layer, so it is
      // never a key of the JSON `layers` object. Reporting it as "missing" on
      // every single packet would be noise, not information.
      missing: layerOrder.filter((name) => name !== 'ethertype' && !known.has(name)),
      extra: rest,
    }
  }, [layers, layerOrder])

  if (order.length === 0) {
    return (
      <div className={clsx('px-3 py-4 text-2xs leading-relaxed text-muted', className)}>
        The backend returned no decoded layers for this packet. TShark&apos;s JSON dissection can
        fail for a malformed frame; the byte dump below comes from a separate read and may still
        be intact.
      </div>
    )
  }

  return (
    <div className={className}>
      {missing.length > 0 ? (
        <div className="flex items-start gap-2 border-b border-border/60 px-3 py-1.5 text-2xs text-warn">
          <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden />
          <span>
            <span className="mono">{missing.join(', ')}</span>{' '}
            {missing.length === 1 ? 'is' : 'are'} named in this packet&apos;s dissection chain but
            absent from the decoded layers.
          </span>
        </div>
      ) : null}
      {order.map((name, index) => (
        <LayerBlock
          key={name}
          name={name}
          value={(layers ?? {})[name]}
          startOpen={index < initiallyExpanded}
        />
      ))}
      {extra.length > 0 ? (
        <div className="px-3 py-1.5 text-2xs text-faint">
          {extra.length} layer(s) were present in the dissection but not in <span className="mono">
            frame.protocols</span>; they are listed last.
        </div>
      ) : null}
    </div>
  )
}

export default LayerTree
