import clsx from 'clsx'
import { CopyButton } from '@/components/CopyButton'
import { SectionNote } from '@/components/protocols/ProtocolDetail'
import { EMPTY, formatBytes, formatNumber } from '@/utils/format'

/** Parsed HTTP header objects (`request_headers` / `response_headers`). */
export type HeaderMap = Record<string, string>

export interface HeadersTableProps {
  headers: HeaderMap | null | undefined
  /** Heading used by the copy button label and the empty state. */
  label: string
  /** Text shown when the analyser stored no headers at all. */
  emptyText: string
  className?: string
}

function headerText(headers: HeaderMap): string {
  return Object.entries(headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n')
}

/**
 * HTTP header block as a dense name/value table. Header values are untrusted
 * capture strings and are rendered as text only.
 */
export function HeadersTable({ headers, label, emptyText, className }: HeadersTableProps) {
  const map: HeaderMap = headers ?? {}
  const entries = Object.entries(map)
  if (entries.length === 0) {
    return <SectionNote className={className}>{emptyText}</SectionNote>
  }
  return (
    <div className={clsx('overflow-hidden rounded border border-border', className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border bg-surface2/60 px-2 py-1">
        <span className="text-2xs uppercase tracking-wider text-muted">
          {label} · {formatNumber(entries.length)}
        </span>
        <CopyButton value={headerText(map)} label={`Copy ${label.toLowerCase()}`} />
      </div>
      <table className="dt">
        <tbody>
          {entries.map(([name, value], index) => (
            <tr key={`${name}-${index}`}>
              <td className="w-56 align-top text-accent2" title={name}>
                {name}
              </td>
              <td className="whitespace-pre-wrap break-all text-text" title={value}>
                {value === '' ? EMPTY : value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Content types that are not text, so the preview is a printable rendering. */
const BINARY_TYPES = [
  'application/pdf',
  'application/octet-stream',
  'application/zip',
  'application/gzip',
  'application/x-gzip',
  'application/x-tar',
  'image/',
  'audio/',
  'video/',
  'font/',
]

function looksBinary(contentType: string | null | undefined): boolean {
  if (!contentType) return false
  const kind = contentType.split(';')[0].trim().toLowerCase()
  return BINARY_TYPES.some((prefix) => kind.startsWith(prefix))
}

export interface BodyPreviewProps {
  /** e.g. `Request body` / `Response body`. */
  label: string
  /** Decoded preview string, or `null` when nothing is stored. */
  body: string | null | undefined
  /** Body size in bytes as measured from the reassembled stream. */
  size: number | null | undefined
  /** Explicit truncation flag from the API (`response_body_truncated`), 0/1/null. */
  truncated?: boolean | number | null
  /** Message Content-Type, used for the binary-rendering notice. */
  contentType?: string | null
  /** Sentence used when the message carried no body at all. */
  emptyText: string
}

/**
 * Body preview with an explicit notice for the three real cases: full preview,
 * preview cut at the configured limit, and no preview stored while a size was
 * still measured. Nothing is inferred about the content itself.
 */
export function BodyPreview({
  label,
  body,
  size,
  truncated,
  contentType,
  emptyText,
}: BodyPreviewProps) {
  const text = typeof body === 'string' && body !== '' ? body : null
  const previewChars = text === null ? 0 : text.length
  const reported = typeof size === 'number' && Number.isFinite(size) ? size : null
  const isTruncated = truncated === true || truncated === 1

  const notices: { tone: 'info' | 'warn'; text: string }[] = []

  if (text === null) {
    if (reported !== null && reported > 0) {
      notices.push({
        tone: 'warn',
        text: `No body preview is stored for this message, although the reassembled stream shows ${formatBytes(
          reported,
        )} (${formatNumber(reported)} bytes). The body could not be aligned with this message, or the preview was suppressed.`,
      })
    } else if (reported === 0) {
      notices.push({ tone: 'info', text: `${emptyText} The reported body length is 0 bytes.` })
    } else {
      notices.push({
        tone: 'info',
        text: `${emptyText} No body length was reported either, so the analyser could not measure it.`,
      })
    }
  } else if (isTruncated) {
    notices.push({
      tone: 'warn',
      text: `Truncated preview: only the first ${formatNumber(previewChars)} characters of ${formatNumber(
        reported,
      )} bytes are shown. The limit is the backend setting body_preview_bytes; raise it and re-run the analysis for the full body.`,
    })
  } else {
    notices.push({
      tone: 'info',
      text:
        reported === null
          ? `${formatNumber(previewChars)} characters of preview are stored; the analyser reported no body length.`
          : `Preview stored in full: ${formatNumber(previewChars)} characters against a reported body length of ${formatNumber(
              reported,
            )} bytes.`,
    })
  }

  if (
    text !== null &&
    !isTruncated &&
    reported !== null &&
    previewChars > 0 &&
    previewChars < reported
  ) {
    notices.push({
      tone: 'info',
      text: `The stored preview is shorter than the reported body length. A multi-byte character encoding explains part of that; a preview cut at the limit or an incomplete reassembly explains the rest — compare with the stream view if it matters.`,
    })
  }

  if (text !== null && looksBinary(contentType)) {
    notices.push({
      tone: 'info',
      text: `Content-Type "${contentType}" is not text, so the stored preview is a printable rendering of the captured bytes (non-printable bytes appear as dots). The real bytes are available from stream reassembly or object export.`,
    })
  }

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs uppercase tracking-wider text-muted">
          {label}
          {text !== null ? ` · ${formatNumber(previewChars)} chars` : ''}
        </span>
        {text !== null ? <CopyButton value={text} label={`Copy ${label.toLowerCase()}`} /> : null}
      </div>
      {text !== null ? (
        <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-[#0d1526] p-2 mono text-2xs text-text">
          {text}
        </pre>
      ) : null}
      {notices.map((notice, index) => (
        <SectionNote key={index} tone={notice.tone}>
          {notice.text}
        </SectionNote>
      ))}
    </div>
  )
}

export default HeadersTable
