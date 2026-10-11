/**
 * API types — mirror docs/CONTRACT.md §3 (database schema), §6 (/summary), §7
 * (packet summary vs detail) and the §5 endpoint shapes.
 *
 * All timestamps are Unix epoch SECONDS (REAL). Optional / absent values are
 * `null`, never a placeholder (contract §0).
 */

/* ------------------------------------------------------------------ */
/* Enumerations                                                        */
/* ------------------------------------------------------------------ */

export type AnalysisStatus =
  | 'pending'
  | 'processing'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type JobStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type Severity = 'informational' | 'low' | 'medium' | 'high'

export type Transport = 'tcp' | 'udp'

export type ConversationState =
  | 'established'
  | 'reset'
  | 'half_open'
  | 'closed'
  | 'unknown'

export type HandshakeStatus =
  | 'complete'
  | 'client_hello_only'
  | 'server_hello_only'
  | 'alert'
  | 'unknown'

export type ObjectStatus = 'complete' | 'partial' | 'failed'

export type IndicatorType = 'ip' | 'domain' | 'port' | 'ja3' | 'ja4' | 'ua' | 'sha256'

export type SortOrder = 'asc' | 'desc'

/* ------------------------------------------------------------------ */
/* Common envelopes (contract §2)                                      */
/* ------------------------------------------------------------------ */

export interface Paginated<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  /** Total page count (returned by every paginated endpoint on the live API). */
  pages?: number
}

export interface ItemsEnvelope<T> {
  items: T[]
}

export interface ApiErrorDetail {
  code: string
  message: string
  details?: Record<string, unknown>
}

/** Every non-2xx response body is exactly `{ "error": { code, message, details } }`. */
export interface ApiErrorBody {
  error: ApiErrorDetail
}

export interface ActionOk {
  ok: boolean
  [key: string]: unknown
}

export interface DeleteAnalysisResult {
  ok: boolean
  id: string
}

/* ------------------------------------------------------------------ */
/* /api/health                                                         */
/* ------------------------------------------------------------------ */

export interface TsharkInfo {
  available: boolean
  version: string | null
  path: string | null
  /** Full `tshark -v` first line, when reported. */
  banner?: string | null
  error?: string | null
}

export interface HealthResponse {
  status: string
  tshark: TsharkInfo
  version: string
  /** Live-API extras. */
  data_dir?: string
  local_only?: boolean
}

/* ------------------------------------------------------------------ */
/* analyses + jobs (contract §3, §5)                                   */
/* ------------------------------------------------------------------ */

export interface Analysis {
  id: string
  original_filename: string
  stored_path: string
  file_size: number
  file_sha256: string | null
  file_type: string | null
  encapsulation: string | null
  status: AnalysisStatus
  progress: number
  stage: string | null
  error: string | null
  packet_count: number | null
  bytes_total: number | null
  capture_start: number | null
  capture_end: number | null
  duration: number | null
  src_ip_count: number | null
  dst_ip_count: number | null
  tcp_count: number | null
  udp_count: number | null
  dns_count: number | null
  http_count: number | null
  tls_count: number | null
  created_at: number | null
  updated_at: number | null
  started_at: number | null
  finished_at: number | null
  /** Present on `GET /api/analyses` list items. */
  job_status?: JobStatus | null
}

/** `GET /api/analyses/{id}` — analysis object plus `job`, `progress`, `stage`. */
export interface AnalysisDetail extends Analysis {
  job: Job | null
  /** Live-API extras. */
  disk_usage?: number | null
  upload_retained?: boolean | null
  warnings?: string[] | null
}

export interface Job {
  id: string
  analysis_id: string
  kind: string
  status: JobStatus
  stage: string | null
  progress: number
  message: string | null
  error: string | null
  cancel_requested: number
  created_at: number | null
  started_at: number | null
  finished_at: number | null
}

export type AnalysesListResponse = Paginated<Analysis>
export type JobsResponse = ItemsEnvelope<Job>

/** `POST /api/analyses` returns 202 with the analysis object. */
export type UploadAnalysisResponse = Analysis

/* ------------------------------------------------------------------ */
/* /summary (contract §6)                                              */
/* ------------------------------------------------------------------ */

export interface SummaryTotals {
  packets: number | null
  bytes: number | null
  duration: number | null
  unique_src_ips: number | null
  unique_dst_ips: number | null
  tcp_packets: number | null
  udp_packets: number | null
  dns_queries: number | null
  http_requests: number | null
  tls_connections: number | null
  conversations: number | null
  hosts: number | null
  findings: number | null
  start_time: number | null
  end_time: number | null
}

export interface ProtocolDistributionEntry {
  protocol: string
  packets: number
  bytes: number
}

export interface TrafficSeriesPoint {
  t: number
  packets: number
  bytes: number
}

export interface TopTalker {
  ip: string
  /** `source` | `destination` (contract example uses `source`). */
  direction: string
  packets: number
  bytes: number
}

export interface TopPort {
  port: number
  protocol: string
  packets: number
  service: string | null
  bytes?: number
}

export interface TopConversation {
  conv_id: string
  endpoint_a: string
  endpoint_b: string
  transport: string
  bytes_total: number
  packets_total: number
  ip_a?: string
  ip_b?: string
  protocols?: string | null
  state?: string | null
  duration?: number | null
}

export interface FindingsSummaryEntry {
  id: string
  severity: Severity
  title: string
  rule_id: string
}

export interface ProtocolHierarchyEntry {
  protocol: string
  frames: number
  bytes: number
  depth: number
}

export interface SeverityCounts {
  high: number
  medium: number
  low: number
  informational: number
}

export interface AnalysisSummary {
  analysis: Analysis & { job_status?: JobStatus | null }
  totals: SummaryTotals
  protocol_distribution: ProtocolDistributionEntry[]
  traffic_series: TrafficSeriesPoint[]
  /** Bucket width in seconds (240 buckets max). */
  series_interval: number | null
  top_talkers: TopTalker[]
  top_ports: TopPort[]
  top_conversations: TopConversation[]
  findings_summary: FindingsSummaryEntry[]
  protocol_hierarchy: ProtocolHierarchyEntry[]
  severity_counts: SeverityCounts
  notes: string[]
}

/* ------------------------------------------------------------------ */
/* packets (contract §7)                                               */
/* ------------------------------------------------------------------ */

/**
 * Packet summary row (`GET .../packets` items) — never payloads.
 *
 * Wire-naming note (verified against a live backend): contract §7 names the
 * frame length `length` and the hardware addresses `src_mac`/`dst_mac`, but the
 * API currently sends `frame_len`, `eth_src` and `eth_dst`. Both spellings are
 * modelled so callers can read whichever is present; the `frame_len`/`eth_*`
 * fields are the ones actually populated today.
 */
export interface PacketSummary {
  number: number
  time_epoch: number | null
  time_relative: number | null
  src_ip: string | null
  src_port: number | null
  dst_ip: string | null
  dst_port: number | null
  protocol: string | null
  transport: string | null
  /** Frame length in bytes — what the API sends today. */
  frame_len?: number | null
  /** Contract §7 spelling of `frame_len`. */
  length?: number | null
  tcp_flags: string | null
  info: string | null
  protocols: string | null
  /** Source MAC — what the API sends today. */
  eth_src?: string | null
  /** Destination MAC — what the API sends today. */
  eth_dst?: string | null
  /** Contract §7 spellings of `eth_src`/`eth_dst`. */
  src_mac?: string | null
  dst_mac?: string | null
  vlan_id: number | null
  ttl: number | null
  ip_version?: number | null
  tcp_stream?: number | null
  dns_query: string | null
  http_method: string | null
  http_host: string | null
  http_uri: string | null
  http_status: number | null
  tls_sni: string | null
  tls_version?: string | null
}

export interface HexDumpLine {
  offset: number
  hex: string
  ascii: string
  bytes: number
}

/** Packet summary plus dissection detail, hex dump and raw bytes. */
export interface PacketDetail extends PacketSummary {
  /** Raw `layers` object from `tshark -T json` with `*_tree` keys flattened. */
  layers: Record<string, unknown>
  layer_order: string[]
  hex_dump: HexDumpLine[]
  raw_hex: string
  /** ASCII rendering of the captured bytes, truncated at 8192 chars. */
  raw_text: string
  raw_len: number
  raw_truncated: boolean
}

export interface PacketListParams {
  page?: number
  page_size?: number
  sort?: string
  order?: SortOrder
  filter?: string
  ip?: string
  src_ip?: string
  dst_ip?: string
  port?: number | string
  src_port?: number | string
  dst_port?: number | string
  protocol?: string
  transport?: Transport | string
  tcp_flags?: string
  min_length?: number | string
  max_length?: number | string
  start_time?: number | string
  end_time?: number | string
  search?: string
}

/** Includes `filter_valid` / `filter_error` so zero-results is distinguishable
 *  from an invalid filter (contract §5). */
export interface PacketListResponse extends Paginated<PacketSummary> {
  filter_valid: boolean
  filter_error: string | null
  /** Echo of the display filter the backend applied. */
  filter?: string | null
}

export interface PacketFilterRequest {
  filter: string
  page?: number
  page_size?: number
}

/** `POST /api/analyses/{id}/filter` — never 422s for an invalid filter. */
export interface PacketFilterResponse {
  valid: boolean
  reason: string | null
  total: number
  items: PacketSummary[]
  page?: number
  page_size?: number
  pages?: number
}

export interface NeighborsResponse {
  packet_number: number | null
}

/* ------------------------------------------------------------------ */
/* conversations + streams (contract §3, §5)                           */
/* ------------------------------------------------------------------ */

export interface Conversation {
  analysis_id: string
  conv_id: string
  transport: Transport
  stream_id: number
  endpoint_a: string
  endpoint_b: string
  ip_a: string
  port_a: number | null
  ip_b: string
  port_b: number | null
  packets_a_to_b: number
  bytes_a_to_b: number
  packets_b_to_a: number
  bytes_b_to_a: number
  packets_total: number
  bytes_total: number
  start_time: number | null
  end_time: number | null
  duration: number | null
  state: ConversationState
  /** Comma-separated app protocols observed in the stream, e.g. `http,tls`. */
  protocols: string | null
}

export type ConversationsListResponse = Paginated<Conversation> & {
  total_bytes: number
}

export interface Stream {
  analysis_id: string
  stream_id: number
  transport: Transport
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  payload_bytes_client: number | null
  payload_bytes_server: number | null
  packets: number | null
  start_time: number | null
  end_time: number | null
}

export interface StreamChunk {
  /** 0 = node0 -> node1, 1 = node1 -> node0. */
  direction: number
  byte_len: number
  /** Position of the chunk in the reassembled stream (live API). */
  index?: number
  /** Decoded text preview — what the API sends today. */
  text_preview?: string | null
  /** Lowercase hex preview — what the API sends today. */
  hex_preview?: string | null
  /** Contract §4 spellings (`data`/`hex`); not sent by the current backend. */
  data?: string
  hex?: string
}

export interface StreamFollowSide {
  bytes: number
  text: string
  hex: string
  direction?: number
  truncated?: boolean
}

export interface StreamFollow {
  node0: string | null
  node1: string | null
  client_to_server: StreamFollowSide
  server_to_client: StreamFollowSide
  chunks: StreamChunk[]
  /** Live-API extras. */
  stream_id?: number
  transport?: Transport
  client_node?: number
  server_node?: number
  client_endpoint?: string | null
  server_endpoint?: string | null
  chunk_count?: number
  chunks_truncated?: boolean
  truncated?: boolean
}

export interface StreamDetail {
  stream: Stream
  follow: StreamFollow
}

export type StreamMode = 'ascii' | 'hex' | 'raw'

/* ------------------------------------------------------------------ */
/* http (contract §3, §5)                                              */
/* ------------------------------------------------------------------ */

export interface HttpTransaction {
  id: number
  analysis_id: string
  stream_id: number | null
  request_packet: number | null
  response_packet: number | null
  time_epoch: number | null
  response_time: number | null
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  method: string | null
  host: string | null
  uri: string | null
  full_uri: string | null
  version: string | null
  status_code: number | null
  status_text: string | null
  user_agent: string | null
  referer: string | null
  content_type: string | null
  server_header: string | null
  request_len: number | null
  response_len: number | null
  request_headers: Record<string, string> | null
  response_headers: Record<string, string> | null
  request_body: string | null
  response_body: string | null
  request_body_size: number | null
  response_body_size: number | null
  response_body_truncated: number | null
  /** JSON array of lead strings. */
  flags: string[] | null
}

export type HttpListResponse = Paginated<HttpTransaction> & {
  methods: string[]
  hosts: string[]
  status_classes: Record<string, number>
}

/* ------------------------------------------------------------------ */
/* dns (contract §3, §5)                                               */
/* ------------------------------------------------------------------ */

export interface DnsQuery {
  id: number
  analysis_id: string
  dns_id: number | null
  time_epoch: number | null
  packet_number: number | null
  response_packet: number | null
  response_time: number | null
  response_delay: number | null
  client_ip: string | null
  server_ip: string | null
  query_name: string | null
  query_type: string | null
  is_response: number | null
  rcode: number | null
  rcode_name: string | null
  /** JSON array of answer records. */
  answers: unknown[] | null
  /** Comma separated. */
  answer_ips: string | null
  /** Comma separated. */
  cnames: string | null
  min_ttl: number | null
  authoritative: number | null
  truncated: number | null
  name_length: number | null
  label_count: number | null
  longest_label: number | null
  entropy: number | null
  /** JSON array of lead strings. */
  flags: string[] | null
}

export interface DnsTopClient {
  client_ip: string
  count: number
}

export type DnsListResponse = Paginated<DnsQuery> & {
  qtypes: string[]
  rcodes: string[]
  top_clients: DnsTopClient[]
}

export interface DnsDomainRow {
  query_name: string
  queries: number
  clients: number
  rcodes: Record<string, number>
  ips: string[]
  first_seen: number | null
  last_seen: number | null
  /** Live-API extras. */
  answered?: number
  nxdomain?: number
}

export type DnsDomainsResponse = ItemsEnvelope<DnsDomainRow>

/* ------------------------------------------------------------------ */
/* tls (contract §3, §5)                                               */
/* ------------------------------------------------------------------ */

export interface TlsSession {
  id: number
  analysis_id: string
  stream_id: number | null
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  client_packet: number | null
  server_packet: number | null
  time_epoch: number | null
  client_version: string | null
  server_version: string | null
  version: string | null
  sni: string | null
  /** Comma separated. */
  alpn: string | null
  selected_alpn: string | null
  cipher_suite: string | null
  ja3: string | null
  ja3_full: string | null
  ja3s: string | null
  ja4: string | null
  cert_subject: string | null
  cert_issuer: string | null
  cert_not_before: string | null
  cert_not_after: string | null
  cert_serial: string | null
  handshake_status: HandshakeStatus | string | null
  alert: string | null
  record_count: number | null
  /** JSON array of lead strings. */
  flags: string[] | null
}

export type TlsListResponse = Paginated<TlsSession> & {
  snis: string[]
  versions: string[]
}

export interface TlsFingerprintRow {
  fingerprint: string
  type: 'ja3' | 'ja3s' | 'ja4' | string
  sessions: number
  snis: string[]
  clients: string[]
}

export type TlsFingerprintsResponse = ItemsEnvelope<TlsFingerprintRow>

/* ------------------------------------------------------------------ */
/* hosts (contract §3, §5)                                             */
/* ------------------------------------------------------------------ */

export interface HostPortCount {
  port: number
  count: number
  direction: string
}

export interface Host {
  analysis_id: string
  ip: string
  mac: string | null
  first_seen: number | null
  last_seen: number | null
  packets_sent: number
  packets_received: number
  bytes_sent: number
  bytes_received: number
  ports: HostPortCount[] | null
  protocols: Record<string, number> | null
  dns_names: string[] | null
  tls_sni: string[] | null
  is_private: number | null
  ip_version: number | null
  peer_count: number | null
  peers: string[] | null
}

export type HostsListResponse = Paginated<Host> & {
  total_bytes: number
  total_hosts?: number
}

export interface HostDetail extends Host {
  conversations: Conversation[]
  dns_queries: DnsQuery[]
  http_transactions: HttpTransaction[]
  tls_sessions: TlsSession[]
  packet_count: number
  /** Cap the backend applied to each detail list (≤50 per contract §5). */
  detail_limit?: number
}

export interface HostGraphNode {
  id: string
  label: string
  mac: string | null
  packets: number
  bytes: number
  is_private: boolean
}

export interface HostGraphEdge {
  source: string
  target: string
  packets: number
  bytes: number
  protocols: string
  ports: number[]
  /** Number of conversations collapsed into this edge (live API). */
  conversations?: number
}

export interface HostGraph {
  nodes: HostGraphNode[]
  edges: HostGraphEdge[]
}

/* ------------------------------------------------------------------ */
/* findings (contract §3, §5)                                          */
/* ------------------------------------------------------------------ */

export interface FindingEntities {
  ips: string[]
  hostnames: string[]
  ports: number[]
  uris: string[]
}

export interface Finding {
  id: string
  analysis_id: string
  rule_id: string
  severity: Severity
  title: string
  description: string | null
  reason: string | null
  /** JSON evidence blob (shape depends on the rule). */
  evidence: unknown
  packet_numbers: number[] | null
  entities: FindingEntities | null
  recommendation: string | null
  created_at: number | null
}

export type FindingsListResponse = Paginated<Finding> & {
  counts: SeverityCounts
}

/**
 * `GET /api/analyses/{id}/findings/rules`.
 *
 * Contract §5 specifies "id, title, severity, description, enabled, and hit
 * count" without naming the hit-count field. The live API sends `rule_id` and
 * `hits`; `id`/`count`/`hit_count` are accepted as fallbacks.
 */
export interface FindingRule {
  rule_id: string
  title: string
  severity: Severity
  description: string
  enabled: boolean
  /** Findings produced by this rule in the analysed capture. */
  hits?: number
  count?: number
  hit_count?: number
  id?: string
  /** Live-API extras: configured thresholds and rule notes. */
  notes?: string | null
  threshold?: unknown
  thresholds?: unknown
  defaults?: unknown
}

export type FindingRulesResponse = ItemsEnvelope<FindingRule>

/* ------------------------------------------------------------------ */
/* objects (contract §3, §5)                                           */
/* ------------------------------------------------------------------ */

export interface CaptureObject {
  id: string
  /** Ready-made download URL reported by the backend. */
  export_url?: string
  analysis_id: string
  filename: string
  original_filename: string | null
  /** Relative to the analysis directory, always under `objects/`. */
  stored_path: string
  protocol: string | null
  content_type: string | null
  size: number | null
  sha256: string | null
  sha1: string | null
  md5: string | null
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  stream_id: number | null
  packet_numbers: number[] | null
  status: ObjectStatus
  note: string | null
  created_at: number | null
}

/** Non-paginated is acceptable; the standard envelope is supported. */
export interface ObjectsResponse {
  items: CaptureObject[]
  total?: number
  page?: number
  page_size?: number
}

export interface ExtractObjectsResponse {
  ok: boolean
  extracted: number
}

/* ------------------------------------------------------------------ */
/* settings + indicators (contract §3, §5)                             */
/* ------------------------------------------------------------------ */

export interface Settings {
  data_dir: string
  max_upload_mb: number
  retain_uploads: boolean
  max_object_bytes: number
  body_preview_bytes: number
  tshark_timeout_s: number
  tshark: TsharkInfo
  /** Read-only subset, present when the backend exposes it. */
  max_packet_rows?: number
  max_dns_rows?: number
  worker_threads?: number
  host?: string
  port?: number
  log_level?: string
  uploads_dir?: string
  analyses_dir?: string
  exports_dir?: string
  version?: string
  updated_at?: number | null
  /** Live-API extras. */
  db_path?: string
  allowed_extensions?: string[]
  max_export_rows?: number
  local_only?: boolean
  telemetry?: boolean
}

/** Mutable keys accepted by `PUT /api/settings`. */
export interface SettingsUpdate {
  max_upload_mb?: number
  retain_uploads?: boolean
  max_object_bytes?: number
  body_preview_bytes?: number
  tshark_timeout_s?: number
}

/**
 * `PUT /api/settings` response. Contract §5 says it "returns the new effective
 * settings"; the live API wraps them as `{ ok, changed, settings }`, so the
 * effective settings live under `.settings`.
 */
export interface SettingsUpdateResponse {
  ok: boolean
  changed: string[]
  settings: Settings
}

export interface Indicator {
  id: number
  /** NULL = global. */
  analysis_id: string | null
  type: IndicatorType
  value: string
  note: string | null
  created_at: number | null
}

export interface IndicatorCreate {
  analysis_id?: string | null
  type: IndicatorType
  value: string
  note?: string | null
}

export type IndicatorsResponse = ItemsEnvelope<Indicator>

/* ------------------------------------------------------------------ */
/* query helper types                                                  */
/* ------------------------------------------------------------------ */

export type QueryValue = string | number | boolean | null | undefined

export type QueryParams = Record<string, QueryValue>
