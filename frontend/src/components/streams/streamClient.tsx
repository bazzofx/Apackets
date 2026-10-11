import { ApiError, apiUrl, buildQuery } from '@/services/api'
import type { Stream, StreamFollow, StreamMode } from '@/types'

/**
 * Local client for the two stream endpoints that `src/services/api.ts` does not
 * wrap yet (`GET …/streams/{id}/search` and `GET …/streams/{id}/export`), plus
 * the URL builders the download buttons need.
 *
 * This file holds no JSX; it lives here because the whole `components/streams/`
 * directory belongs to the conversations work. **API gap to report:** these two
 * endpoints should eventually get typed helpers in `services/api.ts` alongside
 * `conversationsApi.stream`.
 */

/** One hit inside the reassembled payload. */
export interface StreamSearchMatch {
  /** 0 = node0 → node1, 1 = node1 → node0. */
  direction: number
  /** Byte offset inside that direction's reassembled payload. */
  offset: number
  /** Surrounding bytes, rendered in the requested mode. */
  context: string
}

export interface StreamSearchResponse {
  stream: Stream
  query: string
  mode: StreamMode
  count: number
  /** True when the backend stopped at its match cap. */
  truncated: boolean
  items: StreamSearchMatch[]
}

/**
 * Normalised index of the TShark node the backend identified as the client.
 *
 * `StreamFollow.client_node` is `string | null` (`'node0'`/`'node1'`), which is
 * what the live API sends. The numeric spellings are still accepted so a change
 * on either side cannot silently mislabel a direction.
 */
export function clientNodeIndex(follow: StreamFollow): 0 | 1 | null {
  const raw: unknown = follow.client_node
  if (raw === 'node0' || raw === 0) return 0
  if (raw === 'node1' || raw === 1) return 1
  return null
}

/** Export formats the endpoint accepts (`stream_analyzer.EXPORT_FORMATS`). */
export const STREAM_EXPORT_FORMATS = ['txt', 'hex', 'csv', 'raw'] as const
export type StreamExportFormat = (typeof STREAM_EXPORT_FORMATS)[number]

/** URL of `GET /api/analyses/{id}/streams/{streamId}/search`. */
export function streamSearchUrl(
  analysisId: string,
  streamId: number,
  query: string,
  mode: StreamMode,
): string {
  return `${apiUrl(`/analyses/${analysisId}/streams/${streamId}/search`)}${buildQuery({
    q: query,
    mode,
  })}`
}

/** URL of `GET /api/analyses/{id}/streams/{streamId}/export`. */
export function streamExportUrl(
  analysisId: string,
  streamId: number,
  mode: StreamMode,
  format: StreamExportFormat,
): string {
  return `${apiUrl(`/analyses/${analysisId}/streams/${streamId}/export`)}${buildQuery({
    mode,
    format,
  })}`
}

/** Unwrap the API error envelope into an `ApiError`, like `services/api.ts`. */
async function toApiErrorFromResponse(response: Response): Promise<ApiError> {
  let body: unknown
  let text = ''
  try {
    text = await response.text()
    body = text ? JSON.parse(text) : undefined
  } catch {
    body = undefined
  }
  const envelope = (body ?? {}) as {
    error?: { code?: unknown; message?: unknown; details?: unknown }
  }
  const code = typeof envelope.error?.code === 'string' ? envelope.error.code : 'http_error'
  const message =
    typeof envelope.error?.message === 'string'
      ? envelope.error.message
      : `The stream search failed with HTTP ${response.status}.`
  const details =
    envelope.error?.details && typeof envelope.error.details === 'object'
      ? (envelope.error.details as Record<string, unknown>)
      : {}
  return new ApiError(response.status, code, message, details)
}

/**
 * Search the reassembled payload. The endpoint answers
 * `{stream, query, mode, count, truncated, items:[{direction, offset, context}]}`
 * with `items` ordered by direction and then by offset.
 */
export async function searchStream(
  analysisId: string,
  streamId: number,
  query: string,
  mode: StreamMode,
): Promise<StreamSearchResponse> {
  const url = streamSearchUrl(analysisId, streamId, query, mode)
  let response: Response
  try {
    response = await fetch(url, { headers: { Accept: 'application/json' } })
  } catch (cause) {
    throw ApiError.network('Could not reach the backend for the stream search.', {
      url,
      cause: cause instanceof Error ? cause.message : String(cause),
    })
  }
  if (!response.ok) throw await toApiErrorFromResponse(response)
  return (await response.json()) as StreamSearchResponse
}
