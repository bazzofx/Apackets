import { useCallback, useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Download, Loader2 } from 'lucide-react'
import { apiUrl, buildQuery } from '@/services/api'

/**
 * Download helpers for the byte-level exports of the two forensic pages.
 *
 * Both the packets CSV and the stream export are plain `GET` endpoints that
 * answer with `Content-Disposition` and — for the CSV — `X-Total-Rows`,
 * `X-Exported-Rows` and (when the cap bites) `X-Truncated`. Fetching the body
 * ourselves lets the UI report those numbers honestly instead of silently
 * handing over a truncated file. If the response is cross-origin and the headers
 * are not exposed, the report degrades to "unknown" rather than guessing.
 */

export interface DownloadReport {
  /** Filename the backend chose, from `Content-Disposition`. */
  filename: string | null
  /** Rows the filter matched (`X-Total-Rows`), when the endpoint reports it. */
  total: number | null
  /** Rows actually written (`X-Exported-Rows`), when the endpoint reports it. */
  rows: number | null
  /** True when the backend flagged the export as capped. */
  truncated: boolean
  bytes: number
}

function numericHeader(headers: Headers, name: string): number | null {
  const raw = headers.get(name)
  if (raw === null || raw.trim() === '') return null
  const value = Number(raw)
  return Number.isFinite(value) ? value : null
}

function filenameFromDisposition(value: string | null): string | null {
  if (!value) return null
  const quoted = /filename="([^"]+)"/i.exec(value)
  if (quoted) return quoted[1]
  const bare = /filename=([^;]+)/i.exec(value)
  return bare ? bare[1].trim() : null
}

/** Error message from the API error envelope, or a transport-level message. */
async function exportError(response: Response): Promise<string> {
  let text = ''
  try {
    text = await response.text()
  } catch {
    text = ''
  }
  if (text) {
    try {
      const parsed = JSON.parse(text) as { error?: { message?: string } }
      const message = parsed.error?.message
      if (typeof message === 'string' && message !== '') return message
    } catch {
      /* not JSON: fall through to a status-based message */
    }
  }
  return `The export failed with HTTP ${response.status}.`
}

/** Fetch an export URL and hand the file to the browser as a download. */
export async function downloadFromUrl(url: string): Promise<DownloadReport> {
  let response: Response
  try {
    response = await fetch(url, { headers: { Accept: '*/*' } })
  } catch (cause) {
    throw new Error(
      `Could not reach the backend for this export: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    )
  }
  if (!response.ok) throw new Error(await exportError(response))

  const blob = await response.blob()
  const filename = filenameFromDisposition(response.headers.get('content-disposition'))
  const total = numericHeader(response.headers, 'x-total-rows')
  const rows = numericHeader(response.headers, 'x-exported-rows')
  const truncated = (response.headers.get('x-truncated') ?? '').toLowerCase() === 'true'

  const objectUrl = window.URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = objectUrl
    if (filename) anchor.download = filename
    anchor.rel = 'noopener'
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
  } finally {
    // Give the browser a moment to start the download before revoking.
    window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 10_000)
  }

  return { filename, total, rows, truncated, bytes: blob.size }
}

/** Build a URL for an endpoint `api.ts` does not wrap. */
export function exportUrl(path: string, params?: Record<string, unknown>): string {
  return `${apiUrl(path)}${buildQuery(params)}`
}

export interface DownloadButtonProps {
  url: string
  label: string
  title?: string
  className?: string
  disabled?: boolean
  onReport?: (report: DownloadReport) => void
  onError?: (message: string) => void
}

/** Button that fetches an export endpoint and reports what was downloaded. */
export function DownloadButton({
  url,
  label,
  title,
  className,
  disabled = false,
  onReport,
  onError,
}: DownloadButtonProps) {
  const [busy, setBusy] = useState(false)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const run = useCallback(() => {
    if (busy) return
    setBusy(true)
    void (async () => {
      try {
        const report = await downloadFromUrl(url)
        if (mounted.current) onReport?.(report)
      } catch (error) {
        if (mounted.current) {
          onError?.(error instanceof Error ? error.message : String(error))
        }
      } finally {
        if (mounted.current) setBusy(false)
      }
    })()
  }, [busy, url, onReport, onError])

  return (
    <button
      type="button"
      className={clsx('btn px-1.5 py-1', className)}
      onClick={run}
      disabled={disabled || busy}
      title={title ?? `Download ${label}`}
    >
      {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Download size={12} aria-hidden />}
      {label}
    </button>
  )
}

export default DownloadButton
