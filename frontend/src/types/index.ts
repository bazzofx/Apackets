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
  /**
   * ISO 3166-1 alpha-2 code from the installed DB-IP country dataset, or `null`.
   *
   * Computed per request rather than stored (see `routes_hosts._host_row`), so a
   * capture analysed before the dataset was installed gains locations the moment
   * it is. `null` means "not known here" — a private address, an IPv6 address
   * (this build indexes the dataset's IPv4 rows), an address outside every range,
   * or no dataset installed at all.
   */
  country?: string | null
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

/* ------------------------------------------------------------------ */
/* IP registration lookup (docs/IP_LOOKUP.md)                          */
/* ------------------------------------------------------------------ */

/**
 * How the address is classified before anything is queried. Only `public`
 * addresses have a registry to ask, so `lookup_possible` follows from this.
 */
export type IpLookupKind =
  | 'public'
  | 'private'
  | 'reserved'
  | 'loopback'
  | 'multicast'
  | 'link_local'
  | 'unknown'

export interface IpLookupContact {
  role: string | null
  handle: string | null
  name: string | null
  emails: string[]
}

/** Origin AS, from Team Cymru's DNS service or from the RDAP record. */
export interface IpLookupAsn {
  number: string
  prefix: string | null
  country: string | null
  registry: string | null
  allocated: string | null
}

/** The normalised registration record; every field may be absent. */
export interface IpLookupRecord {
  registry: string | null
  network_name: string | null
  handle: string | null
  range: { start: string; end: string } | null
  allocation_type: string | null
  status: string[]
  /** Country as *registered* by the RIR — not where a packet went. */
  country: string | null
  port43: string | null
  rdap_url: string | null
  asn: IpLookupAsn | null
  contacts: IpLookupContact[]
  remarks: string[]
  /** Steps that failed during a partial lookup, named rather than hidden. */
  failures?: string[]
}

/** What the capture itself says about this address. Never sent anywhere. */
export interface IpLookupLocal {
  /** Geolocated from the local DB-IP Lite copy, not from the registry. */
  country: string | null
  country_source: string | null
  names: { name: string; from: string; rows: number }[]
  names_truncated: boolean
}

export interface IpLookupCache {
  fetched_at: number | null
  age_days: number | null
  stale: boolean
  source: string | null
}

export interface IpLookupResponse {
  ip: string
  kind: IpLookupKind
  lookup_possible: boolean
  reason: string | null
  cache: IpLookupCache | null
  /** `null` until a lookup has been run, or for any non-public address. */
  record: IpLookupRecord | null
  local: IpLookupLocal
  note: string | null
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
/* The packet pivot: opening a capture in Wireshark                     */
/* ------------------------------------------------------------------ */

/** Whether this installation can open the capture in the Wireshark GUI. */
export interface WiresharkAvailability {
  analysis_id: string
  available: boolean
  executable: string | null
  /** Wireshark ships with TShark, so this is the dissection tool's version. */
  version: string | null
  /** Why it is unavailable, when it is. */
  reason: string | null
}

/** What a launch produced: the filter is composed by the backend, not the client. */
export interface WiresharkLaunchResult {
  analysis_id: string
  launched: boolean
  executable: string
  filter: string
  pid: number
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
 * `GET /api/detection/rules` — the built-in heuristics the detection stage runs.
 *
 * Unlike `SuricataRule` these are code, not data: the shape of a rule is fixed and
 * only its `enabled` flag and its thresholds are mutable. `threshold` is the
 * human-readable sentence rendered from the effective `thresholds`, so the list
 * and the finding panel always describe the same numbers the engine compares.
 */
export interface DetectionRule {
  id: string
  rule_id: string
  title: string
  severity: Severity
  description: string
  enabled: boolean
  /** Rendered from `thresholds`; e.g. "5 or more NXDOMAIN responses for one client". */
  threshold: string
  thresholds: Record<string, unknown>
  /** The documented defaults, for the reset action and the "changed" marker. */
  defaults: Record<string, unknown>
  notes: string
  /** Findings this rule produced in the requested analysis (0 without one). */
  hits: number
  /** True when the rule is disabled or a threshold differs from its default. */
  modified?: boolean
  /** The threshold keys that differ from their defaults, plus 'enabled'. */
  differs?: string[]
  /** Only echoed by a single-rule response. */
  effective?: Record<string, unknown>
}

export interface DetectionRulesResponse extends ItemsEnvelope<DetectionRule> {
  total: number
  enabled: number
  severities: SeverityCounts
  analysis_id: string | null
}

export interface DetectionRuleUpdate {
  enabled?: boolean
  /** Keyed by threshold name; unknown names are rejected by the API. */
  thresholds?: Record<string, unknown>
  reset?: boolean
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
  /**
   * Credential discovery (docs/CREDENTIALS.md §7). Both are absent from a
   * backend that does not expose them, which the Settings block reports rather
   * than guessing a default for.
   */
  credential_scan_enabled?: boolean
  credential_protocols?: string[]
  /** The protocols the backend will accept, so the block offers its list, not its own. */
  credential_protocols_available?: string[]
}

/** Mutable keys accepted by `PUT /api/settings`. */
export interface SettingsUpdate {
  max_upload_mb?: number
  retain_uploads?: boolean
  max_object_bytes?: number
  body_preview_bytes?: number
  tshark_timeout_s?: number
  /** docs/CREDENTIALS.md §7 — the credential stage's own switch and protocol list. */
  credential_scan_enabled?: boolean
  credential_protocols?: string[]
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
/* Credential discovery (docs/CREDENTIALS.md §5–§9)                     */
/* ------------------------------------------------------------------ */

/**
 * Every kind the scanner can record (docs/CREDENTIALS.md §6). The five
 * `other_secret` kinds are not one vocabulary: the five named kinds are what a
 * location said the value was, and the seven shape kinds are what §3.3's
 * patterns recognised inside such a value.
 */
export type CredentialKind =
  | 'username'
  | 'password'
  | 'api_key'
  | 'bearer_token'
  | 'other_secret'
  | 'aws_access_key'
  | 'jwt'
  | 'pem_private_key'
  | 'github_token'
  | 'slack_token'
  | 'google_api_key'
  | 'stripe_key'

/** §4 — stored, shown, never silently upgraded. */
export type CredentialConfidence = 'high' | 'medium' | 'low'

/** The protocols whose locations the scanner reads (§2). */
export type CredentialProtocol = 'http' | 'ftp' | 'smtp' | 'pop3' | 'imap'

/** Which side of the conversation carried the value, when that is known. */
export type CredentialDirection = 'client_to_server' | 'server_to_client'

/**
 * §7 — the runtime settings' current state, reported by both read endpoints so
 * the page can never present an empty list as if the capture were clean.
 *
 * The two halves are deliberately separate: `enabled`/`protocols` are the settings that
 * would apply if the stage ran again, and `stage_ran`, `scanned_at` and the counts
 * describe the run that produced the rows. Turning the scan off does not delete what it
 * found, so the block has to be able to report both at once.
 */
export interface CredentialScanState {
  enabled: boolean
  protocols: string[]
  /** Epoch seconds the last run wrote its rows at. */
  scanned_at: number | null
  /** False when the stage has never run for this analysis — not the same as finding nothing. */
  stage_ran?: boolean
  /** The protocols the last run actually read. */
  protocols_scanned?: string[]
  /** Rows the last run wrote, and how long it took. */
  findings?: number
  seconds?: number | null
  /** Rows the table holds for this analysis now, and when the newest was written. */
  rows?: number
  rows_written_at?: number | null
}

/** One stream the findings were recorded in, as the summary groups them (§8.2). */
export interface CredentialStreamGroup {
  stream_id: number | null
  protocol: string
  findings: number
}

/**
 * One finding (§6's row as §8.1 serves it).
 *
 * `value` is present **only** when the request asked for `reveal=1` (§5): every
 * other response carries `value_preview` and no full value anywhere.
 */
export interface CredentialFinding {
  id: number
  kind: string
  /** The value with its middle removed (`ab…yz`); what every list response shows. */
  value_preview: string
  /** The full value, served only under `?reveal=1`. */
  value?: string | null
  value_length: number
  value_truncated: boolean
  protocol: string
  transport: string | null
  stream_id: number | null
  direction: string | null
  /** Where it was read, e.g. `authorization_basic`, `form_body`, `ftp_user_command`. */
  location: string
  /** The field name that selected it, when one did. */
  source_field: string | null
  /** How it was derived, e.g. `basic_decode`, `form_field`, `command_arg`. */
  method: string
  confidence: string
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  packet_first: number | null
  packet_last: number | null
  /** One redacted line of context (§5). */
  evidence: string | null
  /** Why it was scored as it was, in one sentence. */
  note: string | null
  /** When the row was written — the time of the scan, not the time of the traffic. */
  created_at?: number | null
  /**
   * How many times this value appeared in the capture.
   *
   * The listing shows one row per distinct value (`?unique=1`, the default), so a
   * credential the capture carried seven times is one row with `occurrences: 7`
   * rather than seven rows saying the same thing. The row is the earliest
   * occurrence — its value, preview, method and source field are that stored row's
   * own — and the rest are named by `stream_ids` / `locations`.
   */
  occurrences?: number
  /** Every stream the value was seen in, ascending; the row's own `stream_id` is the first. */
  stream_ids?: number[]
  /** Every protocol the value was seen in, when more than one. */
  protocols?: string[]
  /** Every location the value was read from, when more than one. */
  locations?: string[]
}

/** The list envelope's own counts. */
export interface CredentialCounts {
  total?: number
  by_kind?: Record<string, number>
  by_confidence?: Record<string, number>
  /** Stored occurrences behind those distinct values, so "seen seven times" is visible. */
  occurrences?: number
}

/** `GET /api/analyses/{id}/credentials` (§8.1). */
export interface CredentialsListResponse {
  items: CredentialFinding[]
  total: number
  page: number
  page_size: number
  /** True when this response carried full values, i.e. it was asked for `reveal=1`. */
  reveal: boolean
  /** True when the listing is one row per distinct value — the default view. */
  unique?: boolean
  scan: CredentialScanState
  counts: CredentialCounts
  note?: string | null
}

/**
 * `GET /api/analyses/{id}/credentials/summary` (§8.2): counts by kind, by
 * protocol and by confidence, the streams involved, and the same `scan` block —
 * and no values at all, not even previews.
 *
 * `streams` is served as one entry per distinct `(protocol, stream_id)` pair the findings
 * were recorded in, with `stream_count` alongside it. The page reads the scalar when it is
 * there and falls back to the array's length, so a backend that serves only one of the two
 * spellings still gets a real figure rather than an em dash.
 */
export interface CredentialsSummaryResponse {
  analysis_id?: string
  generated_at?: number
  total?: number
  by_kind?: Record<string, number>
  by_protocol?: Record<string, number>
  by_confidence?: Record<string, number>
  /** Distinct protocol/stream pairs the findings were recorded in. */
  streams?: CredentialStreamGroup[] | number
  stream_count?: number
  /** Findings at `high` confidence, offered separately by the endpoint. */
  high_confidence?: number
  counts?: CredentialCounts & { by_protocol?: Record<string, number> }
  scan?: CredentialScanState
  note?: string | null
  /** The scanner's own reading of the contract's ambiguities, one note per item. */
  limits?: string[]
}

/** `POST /api/analyses/{id}/credentials/scan` — 202 with the job it started (§8.3). */
export interface CredentialScanResult {
  job_id: string
  kind: string
  status: string
}

/** Query parameters of the list endpoint (§8.1). */
export interface CredentialListParams {
  kind?: string
  protocol?: string
  confidence?: string
  stream_id?: number
  /** `1` to include `value` on every item, which is what a reveal asks for. */
  reveal?: number
  /** `confidence` (the endpoint's default), `kind`, `protocol` or `created_at`. */
  sort?: string
  order?: string
  page?: number
  page_size?: number
}

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
  /**
   * True when the stored rule is not the definition the vendored rule tree
   * carries: its text was edited, its `rev` differs, or it is disabled.
   */
  modified?: boolean
  /** False for uploaded and hand-written rules, which have no vendored default. */
  restorable?: boolean
  /** What moved, in the words the tooltip uses: 'text', 'revision', 'disabled'. */
  differs?: string[]
}

export interface SuricataRuleStats {
  total: number
  enabled: number
  supported: number
  unsupported: number
  approximate: number
  /** Rules that are not running their vendored default. */
  modified?: number
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
  /** The built-in rule behind a non-Suricata finding; null for `suricata:<sid>`. */
  detection_rule: DetectionRule | null
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
/* Entity profile: the Hunt section (docs/ENTITY_PROFILE.md)            */
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

/* ------------------------------------------------------------------ */
/* Protocol sessions: Email, SSH, FTP, VoIP, SMB (docs/PROTOCOLS.md)    */
/* ------------------------------------------------------------------ */

/** The five pages of the protocol-session family. */
export type ProtocolFamily = 'email' | 'ssh' | 'ftp' | 'voip' | 'smb'

/** The protocols a session row can belong to. */
export type ProtocolName = 'smtp' | 'pop3' | 'imap' | 'ssh' | 'ftp' | 'sip' | 'rtp' | 'rtcp' | 'smb'

/** Sort keys the endpoint allows (contract §5.1). */
export type ProtocolSort = 'start_time' | 'bytes' | 'packets' | 'duration'

/**
 * One session: a stream in which the protocol appeared.
 *
 * `detail` holds the protocol's own keys (contract §3) and `flags` the lead flags as the
 * application's `code` / `"code: detail"` strings, exactly as HTTP, DNS and TLS return
 * them, so one badge component renders all of them.
 */
export interface ProtocolSessionRow {
  id: number
  analysis_id: string
  protocol: ProtocolName
  stream_id: number | null
  transport: string | null
  client_ip: string | null
  client_port: number | null
  server_ip: string | null
  server_port: number | null
  first_frame: number | null
  last_frame: number | null
  start_time: number | null
  end_time: number | null
  duration: number | null
  packets: number
  bytes: number
  client_packets: number
  client_bytes: number
  server_packets: number
  server_bytes: number
  detail: Record<string, unknown>
  flags: string[]
  note: string | null
}

/** Envelope totals for one page of sessions. */
export interface ProtocolCounts {
  by_protocol: Record<string, number>
  sessions: number
  flagged: number
  bytes: number
  packets: number
  first_seen: number | null
  last_seen: number | null
}

/** `GET /api/analyses/{id}/protocols`. */
export interface ProtocolSessionsResponse {
  analysis_id: string
  generated_at: number
  family: ProtocolFamily | null
  protocols: ProtocolName[]
  total: number
  page: number
  page_size: number
  counts: ProtocolCounts
  note: string
  /** False when the analysis has never been through the extraction stage (contract §5.1). */
  extracted: boolean
  /** True when `SESSION_CAP` cut the rows this response could carry (contract §6). */
  capped: boolean
  /** The cap that applied, so a capped response can state its own limit. */
  session_cap: number
  /** Rows the analysis actually holds, whether or not this page could read them all. */
  stored_rows: number
  rows: ProtocolSessionRow[]
}

/** Per-family totals, for the header of each of the five pages. */
export interface ProtocolFamilySummary {
  protocols: ProtocolName[]
  sessions: number
  flagged: number
  bytes: number
  packets: number
  first_seen: number | null
  last_seen: number | null
}

/** `GET /api/analyses/{id}/protocols/summary`. */
export interface ProtocolSummaryResponse {
  analysis_id: string
  generated_at: number
  extracted: boolean
  families: Record<string, ProtocolFamilySummary>
  note: string
}

/** `GET /api/analyses/{id}/protocols/{session_id}`. */
export interface ProtocolSessionDetail extends ProtocolSessionRow {
  links: { to: string; label: string }[]
}

/** Query parameters of the list endpoint. */
export interface ProtocolListParams {
  protocol?: string
  family?: string
  q?: string
  flagged?: boolean
  sort?: string
  /** `asc` or `desc`; omitted means the endpoint's descending default. */
  order?: string
  page?: number
  page_size?: number
}

/* ------------------------------------------------------------------ */
/* Geography: where the capture's public addresses are (docs/GEOGRAPHY.md) */
/* ------------------------------------------------------------------ */

/** One country the capture sent traffic to. */
export interface GeographyCountry {
  /** ISO 3166-1 alpha-2, or `ZZ` for "no country known". */
  code: string
  /** English name, or null when the standard has no name for the code. */
  name: string | null
  addresses: number
  packets: number
  bytes: number
  /** The addresses themselves, capped by the API's `GEO_IP_CAP`. */
  ips: string[]
  ips_truncated: boolean
}

/** The capture's own side. A private address has no country, so this is never a map point. */
export interface GeographyOrigin {
  label: string
  addresses: number
  packets: number
  bytes: number
}

/** Addresses the dataset could not place: counted, drawn nowhere. */
export interface GeographyUnknown extends GeographyOrigin {
  ips: string[]
  ips_truncated: boolean
}

/** `GET /api/geoip/status`, and the `dataset` block of the geography response. */
export interface GeoipStatus {
  available: boolean
  /** Provenance of the file on disk, or null when there is none. */
  source: {
    dataset: string
    url: string
    licence: string
    attribution: string
    file: string
    bytes: number
    sha256: string
    ranges: number
    countries: number
    dataset_month: string
    fetched_at: number
  } | null
  /** Why the dataset is unavailable, in a sentence a reader can act on. */
  reason: string | null
  note: string
}

/** One direction's totals, always from the capture's own side (contract §5.4). */
export interface GeographyDirection {
  packets: number
  bytes: number
}

/** A port from a conversation, and the side that owned it. */
export interface GeographyPort {
  port: number
  /** `remote` = the destination's address (the service port); `local` = this side's. */
  side: 'remote' | 'local'
  packets: number
  bytes: number
  addresses: number
}

/** The earliest conversation involving one address: what `Follow conversation` opens. */
export interface GeographyConversationRef {
  conv_id: string
  transport: string
  /**
   * `null` when the conversation was never reassembled into a stream. The panel then cannot
   * build the application's conversation link, and says so instead of linking to `tcp:null`.
   */
  stream_id: number | null
  packets: number
  bytes: number
  start_time: number | null
}

/** One address inside a country, with its own counts, ports and first conversation. */
export interface GeographyTarget {
  ip: string
  packets: number
  bytes: number
  sent: GeographyDirection
  received: GeographyDirection
  ports: GeographyPort[]
  /** True when the address uses more than `PORT_CAP` ports and the list was cut. */
  ports_truncated: boolean
  protocols: string[]
  first_conversation: GeographyConversationRef | null
}

/** `GET /api/analyses/{id}/geography/{code}` — the destination panel. */
export interface GeographyCountryDetail {
  analysis_id: string
  code: string
  generated_at: number
  counts: {
    addresses: number
    packets: number
    bytes: number
    sent: GeographyDirection
    received: GeographyDirection
  }
  ports: GeographyPort[]
  ports_truncated: boolean
  targets: GeographyTarget[]
  targets_truncated: boolean
  note: string
}

/** `GET /api/analyses/{id}/geography`. */
export interface GeographyResponse {
  analysis_id: string
  generated_at: number
  dataset: { available: boolean; source: GeoipStatus['source']; reason: string | null }
  origin: GeographyOrigin
  countries: GeographyCountry[]
  unknown: GeographyUnknown
  counts: {
    addresses: number
    located: number
    countries: number
    unknown: number
    local: number
    /** True when `COUNTRY_CAP` cut the country list. */
    countries_truncated?: boolean
  }
  note: string
}
