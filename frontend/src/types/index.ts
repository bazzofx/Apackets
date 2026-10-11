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

/**
 * Busiest host by bytes on one direction, from the `hosts` table.
 * `null` in `traffic_extremes` means nothing was sent (or received).
 */
export interface SummaryTrafficExtreme {
  ip: string
  mac: string | null
  bytes: number
  packets: number
  bytes_sent: number
  bytes_received: number
  is_private: number | null
  /** Precise endpoint classification; see `HostGraphNode.scope`. */
  scope?: string | null
  ip_version: number | null
  /** Up to 5 names seen for this address on this capture. */
  hostnames: string[]
}

/**
 * Traffic attributed to a domain: the IPs this capture saw in DNS answers, then
 * the conversations with those addresses. Empty is a legitimate answer - names
 * that were resolved but never contacted are absent by design.
 */
export interface SummaryTopDomain {
  domain: string
  ips: string[]
  address_count: number
  clients: string[]
  client_count: number
  bytes_sent: number
  bytes_received: number
  bytes_total: number
  packets: number
}

export interface SummaryTrafficExtremes {
  max_sender: SummaryTrafficExtreme | null
  max_receiver: SummaryTrafficExtreme | null
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
  /** Busiest sender / receiver, ranked by bytes on that direction. */
  traffic_extremes?: SummaryTrafficExtremes
  /** Domains this capture actually exchanged traffic with, ranked by bytes. */
  top_domains?: SummaryTopDomain[]
  /** Why `top_domains` can be empty - always rendered next to that panel. */
  top_domains_note?: string | null
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
  /** Total conversations for the current filter (returned alongside `total`). */
  total_conversations?: number
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
  /** Which follow node is the client: `'node0'` or `'node1'` (the API sends a string). */
  client_node?: string | null
  server_node?: string | null
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
  /** Precise endpoint classification; see `HostGraphNode.scope`. */
  scope?: string | null
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
  is_private: boolean | null
  /**
   * Precise endpoint classification from the API: `private`, `public`,
   * `multicast`, `broadcast`, `loopback`, `link_local`, `unspecified` or
   * `reserved`. Preferred over `is_private`, which cannot distinguish a
   * broadcast or multicast address from a public internet host.
   */
  scope?: string | null
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


/* ------------------------------------------------------------------ */
/* suricata rules (analyst editable detection signatures)              */
/* ------------------------------------------------------------------ */

export interface SuricataRule {
  sid: number
  rev: number
  action: string
  protocol: string
  src_net: string
  src_port: string
  direction: string
  dst_net: string
  dst_port: string
  msg: string
  classtype: string | null
  priority: number | null
  severity: Severity
  reference: string | null
  metadata: string | null
  /** Parsed, evaluable rule options. */
  options: unknown[]
  /** Options the built-in matcher cannot honour (rule is stored but skipped). */
  unsupported: string[]
  supported: boolean
  /** Content had no buffer selector: matched against extracted fields. */
  approximate: boolean
  enabled: boolean
  source: string
  category: string | null
  /** Verbatim rule text as stored (editable). */
  raw: string
  created_at: number | null
  updated_at: number | null
  /** Findings produced by this rule for the requested analysis. */
  hits?: number | null
}

export interface SuricataRuleStats {
  total: number
  enabled: number
  supported: number
  unsupported: number
  approximate: number
  severities: SeverityCounts
  sources: { source: string; rules: number }[]
  categories: { category: string; rules: number }[]
}

export interface SuricataEngineInfo {
  engine: string
  suricata_binary: string | null
  note: string
}

export interface SuricataConfig {
  home_net: string[]
  variables: Record<string, string>
  max_findings_per_rule: number
  include_unsupported: boolean
  variables_default?: Record<string, string>
  bundled_rules_dir?: string
  bundled_files?: number
  engine?: SuricataEngineInfo
}

export interface SuricataImportFileReport {
  file: string
  imported: number
  updated: number
  errors: number
}

export interface SuricataImportResult {
  ok: boolean
  files: SuricataImportFileReport[]
  imported: number
  updated: number
  skipped_files: number
  errors: string[]
  stats: SuricataRuleStats
}

export interface SuricataRunResult {
  ok: boolean
  analysis_id: string
  rules_evaluated: number
  rules_packet_scope?: number
  rules_http_scope?: number
  rules_matched: number
  findings: number
  packets_scanned?: number
  http_scanned?: number
  by_severity: SeverityCounts
  seconds?: number
  note?: string
}

export interface SuricataRuleUpdate {
  raw?: string
  enabled?: boolean
}

export type SuricataRulesResponse = Paginated<SuricataRule>
export type SuricataAlertsResponse = Paginated<Finding>

/* ------------------------------------------------------------------ */
/* finding context (Findings workbench)                                */
/* ------------------------------------------------------------------ */

export interface FindingContextAnalysis {
  id: string
  original_filename: string
  status: AnalysisStatus
  packet_count: number | null
  bytes_total: number | null
  capture_start: number | null
  capture_end: number | null
  duration: number | null
  file_type: string | null
  encapsulation: string | null
  finished_at: number | null
}

export interface FindingEndpointPort {
  port: number
  transport: string | null
  /** Service name from the local services database, not capture content. */
  service: string | null
  /** Packets of this alert that used the port. */
  packets: number
}

export interface FindingEndpoint {
  ip: string
  direction: 'source' | 'destination' | string
  ports: FindingEndpointPort[]
  packets_in_alert: number
  mac: string | null
  hostnames: string[]
  tls_sni: string[]
  is_private: number | null
  first_seen: number | null
  last_seen: number | null
  packets_sent: number | null
  packets_received: number | null
  bytes_sent: number | null
  bytes_received: number | null
}

/** A packet row from the context endpoint: a summary plus why it is here. */
export interface FindingContextPacket extends PacketSummary {
  udp_stream?: number | null
  /** True for every packet returned here - they all come from the finding. */
  alerting?: boolean
}

export interface FindingStreamBlock {
  stream: Stream | null
  follow: StreamFollow | null
  /** Present when the stream content could not be reassembled (e.g. capture purged). */
  unavailable?: { code: string; message: string }
}

export interface FindingObject extends CaptureObject {
  /** How the file was tied to this finding. */
  match?: 'stream' | 'packet' | 'inferred-uri' | string
}

export interface RelatedFinding {
  id: string
  rule_id: string
  severity: Severity
  title: string
  created_at: number | null
  /** Shared artefacts, e.g. `ip:10.0.0.5`, `uri:/x`, `packet:42`. */
  shared: string[]
}

export interface FindingTimelineEntry {
  t: number
  kind: 'packet' | 'http' | 'dns' | 'tls' | string
  packet: number | null
  label: string
}

export interface FindingContextCounts {
  packets: number
  alerting_packets: number
  conversations: number
  streams: number
  http: number
  dns: number
  tls: number
  objects: number
  endpoints: number
  related: number
}

export interface FindingContextTruncated {
  packets: boolean
  streams: boolean
  http: boolean
  dns: boolean
  tls: boolean
  objects: boolean
  endpoints: boolean
  related: boolean
  timeline: boolean
}

export interface FindingContextLimits {
  packets: number
  streams: number
  http: number
  dns: number
  tls: number
  objects: number
  related: number
  endpoints: number
  timeline: number
}

/** `GET /api/analyses/{id}/findings/{finding_id}/context` */
export interface FindingContext {
  finding: Finding
  rule: SuricataRule | null
  analysis: FindingContextAnalysis
  endpoints: FindingEndpoint[]
  packets: FindingContextPacket[]
  conversations: Conversation[]
  streams: FindingStreamBlock[]
  http: HttpTransaction[]
  dns: DnsQuery[]
  tls: TlsSession[]
  objects: FindingObject[]
  related: RelatedFinding[]
  timeline: FindingTimelineEntry[]
  limits: FindingContextLimits
  counts: FindingContextCounts
  truncated: FindingContextTruncated
  follow_mode: StreamMode | string
  include_follow: boolean
}

export interface FindingRescanResult {
  ok: boolean
  findings: number
  by_severity: SeverityCounts
  rules_run: number
  rule_errors: Record<string, string>
  seconds: number | null
}
/* ------------------------------------------------------------------ */
/* alerts tied to conversations                                        */
/* (GET /api/analyses/{id}/alerts/conversations)                       */
/* ------------------------------------------------------------------ */

/** One alert, as the conversations overlay needs it. */
export interface ConversationAlertFinding {
  finding_id: string
  rule_id: string
  severity: Severity
  title: string
  /** Frames the finding records; how it was placed on a conversation. */
  packet_numbers: number[]
  /** Conversation keys (`transport:stream_id`) this finding links to. */
  conversations: string[]
  /** `packets` when it was placed through the frame index, `none` when not. */
  linked_by: string
}

/** Everything the endpoint knows about one conversation's alerts. */
export interface ConversationAlertLink {
  severity: Severity
  finding_ids: string[]
  rules: string[]
  titles: string[]
}

/**
 * Everything it knows about one address's alerts, for entities the diagram
 * cannot address by stream id.
 */
export interface ConversationAlertAddressLink {
  severity: Severity
  finding_ids: string[]
  conversations: string[]
}

export interface ConversationAlertsResponse {
  analysis_id: string
  min_severity: Severity
  source: string
  /** Alerts at or above `min_severity`. */
  counts: SeverityCounts
  /** Every alert, whatever its severity, so "+N below the threshold" is honest. */
  all_counts: SeverityCounts
  alerts: ConversationAlertFinding[]
  /** Conversation key -> its alerts. This is what the diagram matches on. */
  by_conversation: Record<string, ConversationAlertLink>
  by_ip: Record<string, ConversationAlertAddressLink>
  linked_conversations: number
  /** Findings that could not be placed on the diagram. Never hidden. */
  unlinked_findings: number
  packets_scanned: number
  packets_truncated: boolean
  note: string
}

/* ------------------------------------------------------------------ */
/* Threat Map (docs/THREAT_HUNT.md §3 and §4)                         */
/* ------------------------------------------------------------------ */

/**
 * `ok`        — computed, and there is something worth showing.
 * `empty`     — computable, and the honest answer is "nothing matched"
 *               (`availability_reason` states the threshold that was applied).
 * `not_applicable` — the capture cannot answer the detection at all.
 */
export type ThreatHuntAvailability = 'ok' | 'empty' | 'not_applicable'

/** Presentation only — never a verdict. */
export type ThreatHuntTone = 'info' | 'watch' | 'warn'

export type ThreatHuntVisualKind =
  | 'bars'
  | 'timeline'
  | 'histogram'
  | 'scatter'
  | 'heatmap'
  | 'table'

/** A real count/measure. `0` only ever means "nothing matched" (§3). */
export interface ThreatHuntHeadline {
  value: number
  label: string
  tone: ThreatHuntTone
}

/** A link into the rest of the app. Only the parameters of §5 may appear. */
export interface ThreatHuntLink {
  to: string
  label: string
}

export interface ThreatHuntBarsItem {
  label: string
  value: number
  to?: string | null
}

/** Ranked horizontal bars: `items` arrive sorted largest first and capped. */
export interface ThreatHuntBarsVisual {
  kind: 'bars'
  title?: string | null
  items: ThreatHuntBarsItem[]
  unit?: string | null
  note?: string | null
}

export interface ThreatHuntTimelinePoint {
  /** Epoch seconds — the bucket start. */
  t: number
  value: number
  /** Highlights this bucket. */
  marker?: boolean | null
}

/** Time series, capped by the backend at 240 buckets. */
export interface ThreatHuntTimelineVisual {
  kind: 'timeline'
  title?: string | null
  points: ThreatHuntTimelinePoint[]
  unit?: string | null
  note?: string | null
}

export interface ThreatHuntHistogramBucket {
  /** The bucket's own description, e.g. `30-60 s`. */
  label: string
  value: number
}

/** Distribution over labelled buckets. */
export interface ThreatHuntHistogramVisual {
  kind: 'histogram'
  title?: string | null
  buckets: ThreatHuntHistogramBucket[]
  unit?: string | null
  note?: string | null
}

export interface ThreatHuntScatterPoint {
  x: number
  y: number
  /** Names the point; `to` links it. */
  label: string
  to?: string | null
}

/** Scatter, capped by the backend at 200 points. */
export interface ThreatHuntScatterVisual {
  kind: 'scatter'
  title?: string | null
  points: ThreatHuntScatterPoint[]
  x_label?: string | null
  y_label?: string | null
  note?: string | null
}

export interface ThreatHuntHeatmapRow {
  label: string
  /** `cells[i]` lines up with `columns[i]`; a missing column is 0. */
  cells: number[]
}

/** Matrix of counts: rows against columns. */
export interface ThreatHuntHeatmapVisual {
  kind: 'heatmap'
  title?: string | null
  columns: string[]
  rows: ThreatHuntHeatmapRow[]
  unit?: string | null
  note?: string | null
}

export interface ThreatHuntTableCell {
  text: string
  to?: string | null
  tone?: ThreatHuntTone | null
}

export interface ThreatHuntTableRow {
  cells: ThreatHuntTableCell[]
}

/** Table, capped by the backend at 50 rows. */
export interface ThreatHuntTableVisual {
  kind: 'table'
  title?: string | null
  columns: string[]
  rows: ThreatHuntTableRow[]
  note?: string | null
}

/** `visuals[]` entries, discriminated by `kind`. */
export type ThreatHuntVisual =
  | ThreatHuntBarsVisual
  | ThreatHuntTimelineVisual
  | ThreatHuntHistogramVisual
  | ThreatHuntScatterVisual
  | ThreatHuntHeatmapVisual
  | ThreatHuntTableVisual

/** One detection: a lead, with what it may indicate and what it does not prove. */
export interface ThreatHuntIndicator {
  /** Stable id from §1; this is what the frontend switches on. */
  id: string
  title: string
  question: string
  availability: ThreatHuntAvailability
  /** Required whenever `availability` is not `"ok"`. */
  availability_reason: string | null
  headline: ThreatHuntHeadline
  visuals: ThreatHuntVisual[]
  interpretation: string
  caveat: string
  links: ThreatHuntLink[]
}

/** `GET /api/analyses/{analysis_id}/threat-hunt`. */
export interface ThreatHuntResponse {
  analysis_id: string
  /** Server clock, float epoch seconds. */
  generated_at: number
  /** Rows in the packet index for this analysis. */
  packets_scanned: number
  window: number
  top: number
  /** What the whole page is (and is not). */
  note: string
  /** The 17 indicators of §1, in contract order. */
  indicators: ThreatHuntIndicator[]
}

/* ------------------------------------------------------------------ */
/* Entity profile: the Investigate section (docs/ENTITY_PROFILE.md)     */
/* ------------------------------------------------------------------ */

/** What was looked up. */
export type ProfileKind = 'ip' | 'domain' | 'url'

/** One search result. `entity` is the exact value the profile endpoint takes. */
export interface ProfileMatch {
  kind: ProfileKind
  entity: string
  label: string
  /** One short line of context. Never a verdict. */
  hint: string
  /** Rows behind this match, used for ordering. */
  count: number
  to: string
}

/** `GET /api/analyses/{id}/profile?q=<query>` */
export interface ProfileSearch {
  analysis_id: string
  query: string
  matches: ProfileMatch[]
  truncated: boolean
}

/** The entity's own header facts. */
export interface ProfileSummary {
  label: string
  scope: string | null
  mac: string | null
  hostnames: string[]
  first_seen: number | null
  last_seen: number | null
  packets: number
  bytes: number
  note: string | null
}

/**
 * `GET /api/analyses/{id}/profile/{kind}/{entity}`.
 *
 * `questions` deliberately reuses the Threat Map card contract - the same fields,
 * the same visual kinds - so one set of renderers draws both sections and the two
 * cannot drift apart.
 */
export interface EntityProfile {
  analysis_id: string
  kind: ProfileKind
  entity: string
  generated_at: number
  summary: ProfileSummary
  questions: ThreatHuntIndicator[]
  truncated: Record<string, boolean>
}
