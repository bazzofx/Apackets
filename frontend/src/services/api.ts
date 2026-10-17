/**
 * Typed fetch wrapper for the APackets API (docs/CONTRACT.md §2, §5).
 *
 * - Base path `/api`; the origin is taken from `VITE_API_BASE` so a built
 *   bundle can be served directly by the FastAPI backend, and falls back to a
 *   same-origin relative path (the Vite dev proxy handles `/api`).
 * - Non-2xx responses are unwrapped from `{ "error": { code, message, details } }`
 *   into `ApiError`.
 * - Network failures (backend down) become `ApiError` with code `network_error`.
 */

import type {
  ActionOk,
  AnalysesListResponse,
  Analysis,
  AnalysisDetail,
  AnalysisSummary,
  ConversationAlertsResponse,
  ConversationsListResponse,
  CredentialListParams,
  CredentialScanResult,
  CredentialsListResponse,
  CredentialsSummaryResponse,
  DeleteAnalysisResult,
  DetectionRule,
  DetectionRulesResponse,
  DetectionRuleUpdate,
  DnsDomainsResponse,
  DnsListResponse,
  DnsQuery,
  EntityProfile,
  ExtractObjectsResponse,
  Finding,
  FindingContext,
  FindingRescanResult,
  FindingRulesResponse,
  FindingsListResponse,
  GeographyCountryDetail,
  GeographyResponse,
  GeoipStatus,
  HealthResponse,
  HostDetail,
  HostGraph,
  HostsListResponse,
  HttpListResponse,
  HttpTransaction,
  Indicator,
  IndicatorCreate,
  IndicatorsResponse,
  IpLookupResponse,
  JobsResponse,  NeighborsResponse,
  ObjectsResponse,
  PacketDetail,
  PacketFilterRequest,
  PacketFilterResponse,
  PacketListParams,
  PacketListResponse,
  Paginated,
  ProfileKind,
  ProfileSearch,
  ProtocolListParams,
  ProtocolSessionDetail,
  ProtocolSessionsResponse,
  ProtocolSummaryResponse,
  Settings,
  SettingsUpdate,
  SettingsUpdateResponse,
  Severity,
  SortOrder,
  StreamDetail,
  StreamMode,
  SuricataAlertsResponse,
  SuricataConfig,
  SuricataImportResult,
  SuricataRule,
  SuricataRuleStats,
  SuricataRuleUpdate,
  SuricataRulesResponse,
  SuricataRunResult,
  ThreatHuntResponse,
  TlsFingerprintsResponse,
  TlsListResponse,
  TlsSession,
  Transport,
  BaselineStatus,
  BaselineSummary,
  WiresharkAvailability,
  WiresharkLaunchResult,
} from '@/types'

/* ------------------------------------------------------------------ */
/* Base URL + query building                                           */
/* ------------------------------------------------------------------ */

/** Empty string => same origin (dev server proxy or backend-served bundle). */
export const API_BASE = String(import.meta.env.VITE_API_BASE ?? '').replace(/\/+$/, '')

export const API_PREFIX = '/api'

/** Absolute-or-relative URL for an `/api/...` path. */
export function apiUrl(path: string): string {
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${API_BASE}${API_PREFIX}${suffix}`
}

/**
 * Serialise query params, dropping `undefined`, `null` and empty strings.
 * Booleans become `true`/`false`; arrays repeat the key.
 */
export function buildQuery(params?: unknown): string {
  if (!params || typeof params !== 'object') return ''
  const search = new URLSearchParams()
  for (const [key, raw] of Object.entries(params as Record<string, unknown>)) {
    if (raw === undefined || raw === null) continue
    if (typeof raw === 'string') {
      if (raw.trim() === '') continue
      search.append(key, raw)
      continue
    }
    if (typeof raw === 'number') {
      if (!Number.isFinite(raw)) continue
      search.append(key, String(raw))
      continue
    }
    if (typeof raw === 'boolean') {
      search.append(key, raw ? 'true' : 'false')
      continue
    }
    if (Array.isArray(raw)) {
      for (const item of raw) {
        if (item === undefined || item === null || item === '') continue
        search.append(key, String(item))
      }
    }
  }
  const qs = search.toString()
  return qs ? `?${qs}` : ''
}

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

export interface ApiErrorInit {
  status?: number
  code?: string
  message?: string
  details?: Record<string, unknown>
}

/** Normalised API failure. `status` is 0 for transport-level failures. */
export class ApiError extends Error {
  status: number
  code: string
  details: Record<string, unknown>

  constructor(
    status: number,
    code: string,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
    Object.setPrototypeOf(this, ApiError.prototype)
  }

  static network(message = NETWORK_ERROR_MESSAGE, details: Record<string, unknown> = {}): ApiError {
    return new ApiError(0, 'network_error', message, details)
  }

  get isNetworkError(): boolean {
    return this.status === 0 || this.code === 'network_error'
  }

  get isNotFound(): boolean {
    return this.status === 404
  }

  get isConflict(): boolean {
    return this.status === 409
  }
}

export const NETWORK_ERROR_MESSAGE =
  'Could not reach the APackets backend. Start it with `python -m uvicorn app.main:app --port 8000` and check that it is listening on 127.0.0.1:8000.'

/** Coerce any thrown value into an `ApiError` for uniform display. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (error instanceof Error) {
    return new ApiError(0, 'network_error', error.message || NETWORK_ERROR_MESSAGE, {})
  }
  return new ApiError(0, 'unknown_error', String(error), {})
}

interface ErrorEnvelope {
  error?: { code?: unknown; message?: unknown; details?: unknown }
  detail?: unknown
}

function parseErrorEnvelope(body: unknown): ApiErrorInit {
  if (!body || typeof body !== 'object') return {}
  const envelope = body as ErrorEnvelope
  const err = envelope.error
  if (err && typeof err === 'object') {
    return {
      code: typeof err.code === 'string' ? err.code : undefined,
      message: typeof err.message === 'string' ? err.message : undefined,
      details:
        err.details && typeof err.details === 'object'
          ? (err.details as Record<string, unknown>)
          : {},
    }
  }
  // Fallback for a bare FastAPI `detail` (the backend normalises these, but be safe).
  if (typeof envelope.detail === 'string') return { message: envelope.detail, code: 'http_error' }
  return {}
}

const STATUS_FALLBACK: Record<number, string> = {
  400: 'Bad request',
  403: 'Forbidden',
  404: 'Not found',
  409: 'Conflicts with the current state',
  413: 'Payload too large',
  415: 'Unsupported file type',
  422: 'Request rejected',
  500: 'Unexpected server error',
  504: 'TShark timed out',
}

async function toApiErrorFromResponse(res: Response): Promise<ApiError> {
  let body: unknown = undefined
  let text = ''
  try {
    text = await res.text()
    body = text ? JSON.parse(text) : undefined
  } catch {
    body = undefined
  }
  const parsed = parseErrorEnvelope(body)
  const message =
    parsed.message ??
    (text && text.length < 300 ? text : undefined) ??
    STATUS_FALLBACK[res.status] ??
    `Request failed with status ${res.status}`
  return new ApiError(res.status, parsed.code ?? 'http_error', message, parsed.details ?? {})
}

/* ------------------------------------------------------------------ */
/* Request core                                                        */
/* ------------------------------------------------------------------ */

type RequestInitLite = Omit<RequestInit, 'body'> & { body?: unknown; json?: unknown }

const JSON_HEADERS: Record<string, string> = { Accept: 'application/json' }

async function request<T>(path: string, init: RequestInitLite = {}): Promise<T> {
  const { json, body, headers, ...rest } = init
  const url = apiUrl(path)
  const finalHeaders: Record<string, string> = { ...JSON_HEADERS, ...(headers as Record<string, string>) }
  let payload = body as BodyInit | undefined
  if (json !== undefined) {
    payload = JSON.stringify(json)
    finalHeaders['Content-Type'] = 'application/json'
  }

  let res: Response
  try {
    res = await fetch(url, { ...rest, headers: finalHeaders, body: payload })
  } catch (cause) {
    throw ApiError.network(NETWORK_ERROR_MESSAGE, {
      url,
      cause: cause instanceof Error ? cause.message : String(cause),
    })
  }

  if (!res.ok) throw await toApiErrorFromResponse(res)
  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (!text) return undefined as T
  try {
    return JSON.parse(text) as T
  } catch {
    throw new ApiError(res.status, 'invalid_json', `Response from ${url} was not valid JSON`, { url })
  }
}

/* ------------------------------------------------------------------ */
/* Pagination helpers                                                  */
/* ------------------------------------------------------------------ */

export interface PageParams {
  page?: number
  page_size?: number
  sort?: string
  order?: SortOrder
}

function pageQuery(params?: PageParams): string {
  return buildQuery(params)
}

/* ------------------------------------------------------------------ */
/* /api/health                                                         */
/* ------------------------------------------------------------------ */

export const healthApi = {
  get: () => request<HealthResponse>('/health'),
}

/* ------------------------------------------------------------------ */
/* Analyses                                                            */
/* ------------------------------------------------------------------ */

export interface UploadProgress {
  loaded: number
  total: number
  /** 0..100; 0 when the browser cannot determine the total size. */
  percent: number
}

export interface UploadOptions {
  onProgress?: (progress: UploadProgress) => void
  signal?: AbortSignal
}

const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'] as const

/** True when the filename carries a capture extension accepted by the backend. */
export function isAllowedCaptureFile(filename: string): boolean {
  const lower = filename.trim().toLowerCase()
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))
}

export const ALLOWED_CAPTURE_EXTENSIONS = ALLOWED_EXTENSIONS

/**
 * `POST /api/analyses` — multipart upload via XMLHttpRequest so upload progress
 * can be reported. Resolves with the created analysis (202).
 */
export function uploadAnalysis(file: File, options: UploadOptions = {}): Promise<Analysis> {
  const { onProgress, signal } = options
  return new Promise<Analysis>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const url = apiUrl('/analyses')

    const onAbort = () => xhr.abort()
    const cleanup = () => {
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    xhr.open('POST', url, true)
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.responseType = 'text'

    xhr.upload.onprogress = (event: ProgressEvent) => {
      if (!onProgress) return
      const total = event.lengthComputable ? event.total : 0
      const loaded = event.loaded
      onProgress({
        loaded,
        total,
        percent: total > 0 ? Math.min(100, (loaded / total) * 100) : 0,
      })
    }

    xhr.onload = () => {
      cleanup()
      const text = typeof xhr.response === 'string' ? xhr.response : xhr.responseText
      let body: unknown = undefined
      if (text) {
        try {
          body = JSON.parse(text)
        } catch {
          body = undefined
        }
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as Analysis)
        return
      }
      const parsed = parseErrorEnvelope(body)
      reject(
        new ApiError(
          xhr.status,
          parsed.code ?? 'http_error',
          parsed.message ?? STATUS_FALLBACK[xhr.status] ?? `Upload failed with status ${xhr.status}`,
          parsed.details ?? {},
        ),
      )
    }

    xhr.onerror = () => {
      cleanup()
      reject(ApiError.network(NETWORK_ERROR_MESSAGE, { url }))
    }

    xhr.ontimeout = () => {
      cleanup()
      reject(new ApiError(0, 'timeout', 'The upload timed out before the backend answered', { url }))
    }

    xhr.onabort = () => {
      cleanup()
      reject(new ApiError(0, 'aborted', 'Upload cancelled', { url }))
    }

    if (signal) {
      if (signal.aborted) {
        reject(new ApiError(0, 'aborted', 'Upload cancelled', { url }))
        return
      }
      signal.addEventListener('abort', onAbort)
    }

    const form = new FormData()
    form.append('file', file, file.name)
    xhr.send(form)
  })
}

export const analysesApi = {
  list: (params?: PageParams) =>
    request<AnalysesListResponse>(`/analyses${pageQuery(params)}`),

  get: (analysisId: string) => request<AnalysisDetail>(`/analyses/${analysisId}`),

  summary: (analysisId: string) =>
    request<AnalysisSummary>(`/analyses/${analysisId}/summary`),

  upload: uploadAnalysis,

  /** `DELETE /api/analyses/{id}?confirm=true` */
  remove: (analysisId: string) =>
    request<DeleteAnalysisResult>(`/analyses/${analysisId}${buildQuery({ confirm: true })}`, {
      method: 'DELETE',
    }),

  cancel: (analysisId: string) =>
    request<ActionOk>(`/analyses/${analysisId}/cancel`, { method: 'POST' }),

  jobs: (analysisId: string) => request<JobsResponse>(`/analyses/${analysisId}/jobs`),
}

/* ------------------------------------------------------------------ */
/* Packets                                                             */
/* ------------------------------------------------------------------ */

export interface NeighborParams {
  /** Required: the backend returns 422 validation_error without it. */
  filter: string
  direction: 'next' | 'prev'
}

export const packetsApi = {
  list: (analysisId: string, params?: PacketListParams) =>
    request<PacketListResponse>(
      `/analyses/${analysisId}/packets${buildQuery(params as Record<string, unknown>)}`,
    ),

  detail: (analysisId: string, number: number) =>
    request<PacketDetail>(`/analyses/${analysisId}/packets/${number}`),

  neighbors: (analysisId: string, number: number, params: NeighborParams) =>
    request<NeighborsResponse>(
      `/analyses/${analysisId}/packets/${number}/neighbors${buildQuery({
        filter: params.filter,
        direction: params.direction,
      })}`,
    ),

  /** `POST /api/analyses/{id}/filter` — never 422s for an invalid filter. */
  filter: (analysisId: string, body: PacketFilterRequest) =>
    request<PacketFilterResponse>(`/analyses/${analysisId}/filter`, {
      method: 'POST',
      json: body,
    }),

  exportCsvUrl: (analysisId: string, params?: PacketListParams) =>
    `${apiUrl(`/analyses/${analysisId}/packets/export.csv`)}${buildQuery(
      params as Record<string, unknown>,
    )}`,
}

/** Standalone CSV export URL builder (same params as the packet list). */
export const exportPacketsCsvUrl = packetsApi.exportCsvUrl

/* ------------------------------------------------------------------ */
/* Conversations + streams                                             */
/* ------------------------------------------------------------------ */

export interface ConversationListParams extends PageParams {
  transport?: Transport
  ip?: string
  port?: number | string
  search?: string
}

export const conversationsApi = {
  list: (analysisId: string, params?: ConversationListParams) =>
    request<ConversationsListResponse>(
      `/analyses/${analysisId}/conversations${buildQuery(params as Record<string, unknown>)}`,
    ),

  stream: (analysisId: string, streamId: number, mode: StreamMode = 'ascii') =>
    request<StreamDetail>(
      `/analyses/${analysisId}/streams/${streamId}${buildQuery({ mode })}`,
    ),
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

export interface HttpListParams extends PageParams {
  method?: string
  host?: string
  uri?: string
  status?: string
  client_ip?: string
  server_ip?: string
  user_agent?: string
  search?: string
  interesting?: boolean
}

export const httpApi = {
  list: (analysisId: string, params?: HttpListParams) =>
    request<HttpListResponse>(
      `/analyses/${analysisId}/http${buildQuery(params as Record<string, unknown>)}`,
    ),

  get: (analysisId: string, transactionId: number) =>
    request<HttpTransaction>(`/analyses/${analysisId}/http/${transactionId}`),
}

/* ------------------------------------------------------------------ */
/* DNS                                                                 */
/* ------------------------------------------------------------------ */

export interface DnsListParams extends PageParams {
  domain?: string
  client_ip?: string
  server_ip?: string
  qtype?: string
  rcode?: string
  unanswered?: boolean
  nxdomain?: boolean
  suspicious?: boolean
  search?: string
}

export const dnsApi = {
  list: (analysisId: string, params?: DnsListParams) =>
    request<DnsListResponse>(
      `/analyses/${analysisId}/dns${buildQuery(params as Record<string, unknown>)}`,
    ),

  get: (analysisId: string, rowId: number) =>
    request<DnsQuery>(`/analyses/${analysisId}/dns/${rowId}`),

  domains: (analysisId: string) =>
    request<DnsDomainsResponse>(`/analyses/${analysisId}/dns/domains`),
}

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

export interface TlsListParams extends PageParams {
  sni?: string
  version?: string
  ip?: string
  port?: number | string
  alpn?: string
  ja3?: string
  has_cert?: boolean
}

export const tlsApi = {
  list: (analysisId: string, params?: TlsListParams) =>
    request<TlsListResponse>(
      `/analyses/${analysisId}/tls${buildQuery(params as Record<string, unknown>)}`,
    ),

  get: (analysisId: string, sessionId: number) =>
    request<TlsSession>(`/analyses/${analysisId}/tls/${sessionId}`),

  fingerprints: (analysisId: string) =>
    request<TlsFingerprintsResponse>(`/analyses/${analysisId}/tls/fingerprints`),
}

/* ------------------------------------------------------------------ */
/* Hosts                                                               */
/* ------------------------------------------------------------------ */

export interface HostListParams extends PageParams {
  ip?: string
  search?: string
  is_private?: boolean
  protocol?: string
}

export const hostsApi = {
  list: (analysisId: string, params?: HostListParams) =>
    request<HostsListResponse>(
      `/analyses/${analysisId}/hosts${buildQuery(params as Record<string, unknown>)}`,
    ),

  get: (analysisId: string, ip: string) =>
    request<HostDetail>(`/analyses/${analysisId}/hosts/${encodeURIComponent(ip)}`),

  /**
   * Registration data for one address. The plain call only reads the server's
   * cache; `fetchLookup` performs the lookup now and caches it (docs/IP_LOOKUP.md
   * §5). Neither is ever called automatically — sending an address to a registry
   * is the operator's decision, one address at a time.
   */
  lookup: (analysisId: string, ip: string) =>
    request<IpLookupResponse>(`/analyses/${analysisId}/hosts/${encodeURIComponent(ip)}/lookup`),

  fetchLookup: (analysisId: string, ip: string) =>
    request<IpLookupResponse>(`/analyses/${analysisId}/hosts/${encodeURIComponent(ip)}/lookup`, {
      method: 'POST',
    }),

  graph: (analysisId: string) => request<HostGraph>(`/analyses/${analysisId}/hosts/graph`),
}

/* ------------------------------------------------------------------ */
/* Findings                                                            */
/* ------------------------------------------------------------------ */

export interface FindingListParams extends PageParams {
  severity?: string
  rule_id?: string
  search?: string
}

export const findingsApi = {
  list: (analysisId: string, params?: FindingListParams) =>
    request<FindingsListResponse>(
      `/analyses/${analysisId}/findings${buildQuery(params as Record<string, unknown>)}`,
    ),

  get: (analysisId: string, findingId: string) =>
    request<Finding>(`/analyses/${analysisId}/findings/${encodeURIComponent(findingId)}`),

  rules: (analysisId: string) =>
    request<FindingRulesResponse>(`/analyses/${analysisId}/findings/rules`),

  /**
   * Everything the Findings workbench needs for one alert: the finding, its
   * packets, the conversations and streams they belong to, the application
   * layer, transferred files, related findings and a timeline.
   */
  context: (analysisId: string, findingId: string, params?: FindingContextParams) =>
    request<FindingContext>(
      `/analyses/${analysisId}/findings/${encodeURIComponent(findingId)}/context${buildQuery(
        params as Record<string, unknown>,
      )}`,
    ),

  /**
   * Re-runs the built-in detection engine. Note: that engine rewrites every
   * finding row for the analysis, so Suricata matches must be re-run after it
   * (see `suricataApi.run`) - the Findings page does both.
   */
  rescan: (analysisId: string) =>
    request<FindingRescanResult>(`/analyses/${analysisId}/findings/rescan`, { method: 'POST' }),
}

export interface FindingContextParams {
  packets_limit?: number
  streams_limit?: number
  http_limit?: number
  dns_limit?: number
  tls_limit?: number
  objects_limit?: number
  related_limit?: number
  include_follow?: boolean
  follow_mode?: StreamMode
}

/* ------------------------------------------------------------------ */
/* Objects                                                             */
/* ------------------------------------------------------------------ */

export interface ObjectListParams extends PageParams {
  protocol?: string
  search?: string
}

export const objectsApi = {
  list: (analysisId: string, params?: ObjectListParams) =>
    request<ObjectsResponse>(
      `/analyses/${analysisId}/objects${buildQuery(params as Record<string, unknown>)}`,
    ),

  exportUrl: (analysisId: string, objectId: string) =>
    apiUrl(`/analyses/${analysisId}/objects/${encodeURIComponent(objectId)}/export`),

  extract: (analysisId: string) =>
    request<ExtractObjectsResponse>(`/analyses/${analysisId}/objects/extract`, {
      method: 'POST',
    }),
}

/* ------------------------------------------------------------------ */
/* Settings + indicators                                               */
/* ------------------------------------------------------------------ */

export const settingsApi = {
  get: () => request<Settings>('/settings'),

  /** `PUT /api/settings` — returns `{ ok, changed, settings }`. */
  update: (payload: SettingsUpdate) =>
    request<SettingsUpdateResponse>('/settings', { method: 'PUT', json: payload }),

  indicators: {
    list: () => request<IndicatorsResponse>('/indicators'),

    create: (payload: IndicatorCreate) =>
      request<Indicator>('/indicators', { method: 'POST', json: payload }),

    remove: (id: number) => request<ActionOk>(`/indicators/${id}`, { method: 'DELETE' }),
  },
}

/* ------------------------------------------------------------------ */
/* Credential discovery (docs/CREDENTIALS.md §8)                       */
/* ------------------------------------------------------------------ */

/**
 * The three calls the Credentials page makes.
 *
 * Nothing here is revealed by default: the list redacts every value to its
 * preview (§5) and only a request that asks for `reveal=1` — which the page
 * issues for one row at a time, on an explicit action — carries the full value.
 * `scan` re-runs the stage in the background and answers `202` with the job it
 * started; it is refused with `409 credential_scan_disabled` while the setting
 * at `/settings` is off.
 */
export const credentialsApi = {
  list: (analysisId: string, params?: CredentialListParams) =>
    request<CredentialsListResponse>(
      `/analyses/${analysisId}/credentials${buildQuery(params as Record<string, unknown>)}`,
    ),

  summary: (analysisId: string) =>
    request<CredentialsSummaryResponse>(`/analyses/${analysisId}/credentials/summary`),

  scan: (analysisId: string) =>
    request<CredentialScanResult>(`/analyses/${analysisId}/credentials/scan`, { method: 'POST' }),
}

/* ------------------------------------------------------------------ */
/* Convenience re-exports                                              */
/* ------------------------------------------------------------------ */

export type { Paginated }


/* ------------------------------------------------------------------ */
/* Suricata rules                                                      */
/* ------------------------------------------------------------------ */

export interface SuricataRuleParams extends PageParams {
  enabled?: boolean
  supported?: boolean
  severity?: string
  protocol?: string
  source?: string
  category?: string
  action?: string
  search?: string
  /** Adds per-analysis hit counts to each rule. */
  analysis_id?: string
}

export interface SuricataAlertParams extends PageParams {
  severity?: string
  search?: string
}

/**
 * `POST /api/suricata/rules/import` — multipart upload of one or more
 * `.rules` files. Uses XMLHttpRequest so a large rule set reports progress.
 */
export function importSuricataRules(
  files: File[],
  options: UploadOptions = {},
): Promise<SuricataImportResult> {
  const { onProgress, signal } = options
  return new Promise<SuricataImportResult>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const url = apiUrl(`/suricata/rules/import${buildQuery({ enabled: true })}`)

    const onAbort = () => xhr.abort()
    const cleanup = () => {
      if (signal) signal.removeEventListener('abort', onAbort)
    }

    xhr.open('POST', url, true)
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.responseType = 'text'
    xhr.upload.onprogress = (event: ProgressEvent) => {
      if (!onProgress) return
      const total = event.lengthComputable ? event.total : 0
      onProgress({
        loaded: event.loaded,
        total,
        percent: total > 0 ? Math.min(100, (event.loaded / total) * 100) : 0,
      })
    }
    xhr.onload = () => {
      cleanup()
      const text = typeof xhr.response === 'string' ? xhr.response : xhr.responseText
      let body: unknown
      try {
        body = text ? JSON.parse(text) : undefined
      } catch {
        body = undefined
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body as SuricataImportResult)
        return
      }
      const parsed = parseErrorEnvelope(body)
      reject(
        new ApiError(
          xhr.status,
          parsed.code ?? 'http_error',
          parsed.message ?? `Import failed with status ${xhr.status}`,
          parsed.details ?? {},
        ),
      )
    }
    xhr.onerror = () => {
      cleanup()
      reject(ApiError.network(NETWORK_ERROR_MESSAGE, { url }))
    }
    xhr.onabort = () => {
      cleanup()
      reject(new ApiError(0, 'aborted', 'Import cancelled', { url }))
    }
    if (signal) {
      if (signal.aborted) {
        reject(new ApiError(0, 'aborted', 'Import cancelled', { url }))
        return
      }
      signal.addEventListener('abort', onAbort)
    }

    const form = new FormData()
    for (const file of files) form.append('file', file, file.name)
    xhr.send(form)
  })
}

/* ------------------------------------------------------------------ */
/* Built-in detection rules                                            */
/* ------------------------------------------------------------------ */

export const detectionApi = {
  /**
   * Every built-in rule with its effective configuration. With an analysis id
   * each rule also reports how many findings it produced in that capture.
   */
  rules: (analysisId?: string | null) =>
    request<DetectionRulesResponse>(
      `/detection/rules${buildQuery({ analysis_id: analysisId ?? undefined })}`,
    ),

  rule: (ruleId: string, analysisId?: string | null) =>
    request<DetectionRule>(
      `/detection/rules/${encodeURIComponent(ruleId)}${buildQuery({
        analysis_id: analysisId ?? undefined,
      })}`,
    ),

  /** Enable/disable, re-tune thresholds, or reset one rule to its defaults. */
  update: (ruleId: string, payload: DetectionRuleUpdate, analysisId?: string | null) =>
    request<DetectionRule>(
      `/detection/rules/${encodeURIComponent(ruleId)}${buildQuery({
        analysis_id: analysisId ?? undefined,
      })}`,
      { method: 'PUT', json: payload },
    ),
}

export const suricataApi = {
  rules: (params?: SuricataRuleParams) =>
    request<SuricataRulesResponse>(`/suricata/rules${buildQuery(params as Record<string, unknown>)}`),

  stats: () => request<SuricataRuleStats>('/suricata/rules/stats'),

  rule: (sid: number) => request<SuricataRule>(`/suricata/rules/${sid}`),

  createRule: (raw: string, enabled = true) =>
    request<SuricataRule>('/suricata/rules', { method: 'POST', json: { raw, enabled } }),

  updateRule: (sid: number, payload: SuricataRuleUpdate) =>
    request<SuricataRule>(`/suricata/rules/${sid}`, { method: 'PUT', json: payload }),

  deleteRule: (sid: number) =>
    request<{ ok: boolean; sid: number }>(`/suricata/rules/${sid}`, { method: 'DELETE' }),

  /**
   * Put one rule back to the definition the vendored rule tree carries. Only a
   * vendored rule has a default; the API answers 404 `no_bundled_default` for an
   * uploaded or hand-written one.
   */
  restoreRule: (sid: number) =>
    request<SuricataRule>(`/suricata/rules/${sid}/restore`, { method: 'POST' }),

  /** Import the rule sets vendored under backend/rules/. */
  seedRules: () =>
    request<SuricataImportResult & { stats: SuricataRuleStats }>('/suricata/rules/seed', {
      method: 'POST',
    }),

  importRules: importSuricataRules,

  config: () => request<SuricataConfig>('/suricata/config'),

  updateConfig: (payload: Partial<SuricataConfig>) =>
    request<SuricataConfig>('/suricata/config', { method: 'PUT', json: payload }),

  /** Evaluate the enabled rules against an analysed capture. */
  run: (analysisId: string) =>
    request<SuricataRunResult>(`/analyses/${analysisId}/suricata/run`, { method: 'POST' }),

  alerts: (analysisId: string, params?: SuricataAlertParams) =>
    request<SuricataAlertsResponse>(
      `/analyses/${analysisId}/suricata/alerts${buildQuery(params as Record<string, unknown>)}`,
    ),
}
export interface ConversationAlertsParams {
  /** `informational | low | medium | high`; the endpoint defaults to `medium`. */
  min_severity?: Severity
  /** `suricata` (default) excludes the built-in engine's findings. */
  source?: 'suricata' | 'all'
}

/**
 * Alerts tied to conversations, for the flow overlay.
 *
 * A separate endpoint from `suricataApi.alerts`: this one resolves each finding's
 * recorded frames to a stream id, so its `by_conversation` map is keyed exactly
 * the way `FlowBand.keys` and `FlowNode.keys` are.
 */
export const alertsApi = {
  conversations: (analysisId: string, params?: ConversationAlertsParams) =>
    request<ConversationAlertsResponse>(
      `/analyses/${analysisId}/alerts/conversations${buildQuery(params as Record<string, unknown>)}`,
    ),
}

/* ------------------------------------------------------------------ */
/* Threat Map (docs/THREAT_HUNT.md §2)                                */
/* ------------------------------------------------------------------ */

export interface ThreatHuntParams {
  /** Seconds per bucket for every time series; the endpoint defaults to 60 (5–3600). */
  window?: number
  /** Rows per ranked visual; the endpoint defaults to 12 (1–50). */
  top?: number
}

/**
 * `GET /api/analyses/{id}/threat-hunt` — the whole section in one response.
 *
 * Read-only over the analysis index: the backend dissects nothing again, and a
 * card whose detection cannot be computed says so (`availability`) instead of
 * rendering a zero. The page owns this one query; cards take its indicators as
 * props so they stay presentational.
 */
export const threatHuntApi = {
  get: (analysisId: string, params?: ThreatHuntParams) =>
    request<ThreatHuntResponse>(
      `/analyses/${analysisId}/threat-hunt${buildQuery(params as Record<string, unknown>)}`,
    ),
}

/* ------------------------------------------------------------------ */
/* Hunt: entity profile (docs/ENTITY_PROFILE.md section 2)               */
/* ------------------------------------------------------------------ */

/**
 * The two read-only queries the Hunt page runs.
 *
 * `search` resolves what the reader typed to the entities that match it - an
 * address, a domain name, or a URL - and `get` returns everything the capture
 * recorded about one of them. Both are SQL over the analysis index: nothing is
 * dissected again, and a question the capture cannot answer comes back as
 * `availability: "not_applicable"` with a reason rather than a zero.
 */
export const profileApi = {
  search: (analysisId: string, q: string, limit?: number) =>
    request<ProfileSearch>(
      `/analyses/${analysisId}/profile${buildQuery({ q, limit } as Record<string, unknown>)}`,
    ),
  get: (analysisId: string, kind: ProfileKind, entity: string) =>
    request<EntityProfile>(`/analyses/${analysisId}/profile/${kind}/${encodeURIComponent(entity)}`),
}

/* ------------------------------------------------------------------ */
/* Protocol sessions: Email, SSH, FTP, VoIP, SMB (docs/PROTOCOLS.md)    */
/* ------------------------------------------------------------------ */

/**
 * The four calls the five protocol-session pages make.
 *
 * `list` is one endpoint with a `family` filter, which is why five pages share one
 * component: Email asks for `email` (`smtp`, `pop3`, `imap`), VoIP for `voip` (`sip`,
 * `rtp`, `rtcp`), and the other three for a single protocol each. `rescan` exists because
 * the extractor runs as a pipeline stage: a capture indexed before this section existed
 * holds no rows until it is re-read, and the page offers that rather than reporting an
 * empty capture as a clean one.
 */
export const protocolsApi = {
  list: (analysisId: string, params: ProtocolListParams = {}) =>
    request<ProtocolSessionsResponse>(
      `/analyses/${analysisId}/protocols${buildQuery(params as Record<string, unknown>)}`,
    ),
  summary: (analysisId: string) =>
    request<ProtocolSummaryResponse>(`/analyses/${analysisId}/protocols/summary`),
  get: (analysisId: string, sessionId: number) =>
    request<ProtocolSessionDetail>(`/analyses/${analysisId}/protocols/${String(sessionId)}`),
  rescan: (analysisId: string) =>
    request<{ job_id: string; status: string }>(`/analyses/${analysisId}/protocols/rescan`, {
      method: 'POST',
    }),
}

/* ------------------------------------------------------------------ */
/* Geography: where the capture's public addresses are (docs/GEOGRAPHY.md) */
/* ------------------------------------------------------------------ */

/**
 * The three calls the geographic view makes.
 *
 * `status` answers whether the location dataset is installed at all, `refresh` is the only
 * thing in APackets that downloads anything (a public CC BY 4.0 dataset, on an explicit
 * request, never at render time), and `geography` is the capture's own per-country totals.
 */
export const geoApi = {
  status: () => request<GeoipStatus>('/geoip/status'),
  refresh: () => request<{ job_id: string; kind: string; status: string }>('/geoip/refresh', { method: 'POST' }),
  geography: (analysisId: string) => request<GeographyResponse>(`/analyses/${analysisId}/geography`),
  /** The destination panel: one country's directions, ports, addresses and conversations. */
  country: (analysisId: string, code: string) =>
    request<GeographyCountryDetail>(
      `/analyses/${analysisId}/geography/${encodeURIComponent(code)}`,
    ),
}

/* ------------------------------------------------------------------ */
/* The packet pivot: the capture in Wireshark                           */
/* ------------------------------------------------------------------ */

/**
 * The two calls behind "Pivot to Wireshark" in the IP context menu.
 *
 * `status` starts nothing and reports whether this installation has a Wireshark
 * GUI to open. `launch` sends an address and, at most, which of its
 * conversations is meant — never a display filter: the backend composes that, so
 * no request from here can put syntax on a command line.
 */
/* ------------------------------------------------------------------ */
/* The baseline network                                                */
/* ------------------------------------------------------------------ */

export const baselineApi = {
  /** What the baseline is, whether baseline mode is on, and what it holds. */
  status: () => request<BaselineStatus>('/baseline'),

  /** Choose the baseline capture (or null to clear it) and/or switch the mode. */
  update: (payload: { analysis_id?: string | null; enabled?: boolean; label?: string | null }) =>
    request<BaselineStatus>('/baseline', { method: 'PUT', json: payload }),

  clear: () => request<BaselineStatus>('/baseline', { method: 'DELETE' }),

  /** One capture diffed against the baseline: counts and samples. */
  compare: (analysisId: string) =>
    request<BaselineSummary>(`/analyses/${analysisId}/baseline`),

  /** Re-run the baseline rules over every analysis; the sweep reports through `recalc`. */
  recalculate: () => request<BaselineStatus>('/baseline/recalculate', { method: 'POST' }),
}

export const wiresharkApi = {
  status: (analysisId: string) =>
    request<WiresharkAvailability>(`/analyses/${analysisId}/wireshark`),
  launch: (
    analysisId: string,
    payload: {
      ip: string
      /** The other end of the conversation; with `ip` the filter becomes a direction. */
      peer_ip?: string | null
      transport?: string | null
      stream_id?: number | null
      port?: number | null
    },
  ) =>
    request<WiresharkLaunchResult>(`/analyses/${analysisId}/wireshark`, {
      method: 'POST',
      json: payload,
    }),
}
