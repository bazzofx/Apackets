import type {
  ConversationAlertAddressLink,
  ConversationAlertLink,
  ConversationAlertsResponse,
  Severity,
  SeverityCounts,
} from '@/types'

/**
 * The alert overlay's logic, kept pure so it can be tested without a DOM.
 *
 * Matching is deliberately trivial, because the two sides already agree: a band
 * or node carries `keys`, the conversation keys behind it, and the endpoint's
 * `by_conversation` map is keyed the same way (`transport:stream_id`). So an
 * element is flagged when any of its keys is in the map, and its level is the
 * worst severity among the keys that matched.
 */

/** Worst last. */
const SEVERITY_RANK: Record<Severity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
}

/** The two levels this overlay draws. Anything lower is not highlighted. */
export type AlertLevel = 'high' | 'medium'

export interface AlertEvidence {
  level: AlertLevel
  severity: Severity
  /** Rule ids behind the match, sorted. */
  rules: string[]
  titles: string[]
  findingIds: string[]
  /** The element's own keys that matched, sorted. */
  keys: string[]
  /** How the element was matched, for the tooltip. */
  matchedBy: 'conversation' | 'address'
}

/** The endpoint's response, narrowed to what the diagram needs. */
export interface ConversationAlerts {
  minSeverity: Severity
  source: string
  counts: SeverityCounts
  allCounts: SeverityCounts
  byConversation: Record<string, ConversationAlertLink>
  byIp: Record<string, ConversationAlertAddressLink>
  linkedConversations: number
  unlinkedFindings: number
  packetsScanned: number
  packetsTruncated: boolean
  note: string
}

export function toConversationAlerts(response: ConversationAlertsResponse): ConversationAlerts {
  return {
    minSeverity: response.min_severity,
    source: response.source,
    counts: response.counts,
    allCounts: response.all_counts,
    byConversation: response.by_conversation,
    byIp: response.by_ip,
    linkedConversations: response.linked_conversations,
    unlinkedFindings: response.unlinked_findings,
    packetsScanned: response.packets_scanned,
    packetsTruncated: response.packets_truncated,
    note: response.note,
  }
}

/** An empty result, used before the request lands and when it fails. */
export function emptyConversationAlerts(): ConversationAlerts {
  return {
    minSeverity: 'medium',
    source: 'suricata',
    counts: { informational: 0, low: 0, medium: 0, high: 0 },
    allCounts: { informational: 0, low: 0, medium: 0, high: 0 },
    byConversation: {},
    byIp: {},
    linkedConversations: 0,
    unlinkedFindings: 0,
    packetsScanned: 0,
    packetsTruncated: false,
    note: '',
  }
}

/** `high` / `medium` for the two levels that are drawn, null for anything lower. */
export function alertLevelForSeverity(severity: Severity | null | undefined): AlertLevel | null {
  if (severity === 'high') return 'high'
  if (severity === 'medium') return 'medium'
  return null
}

function worstSeverity(left: Severity, right: Severity): Severity {
  return SEVERITY_RANK[right] > SEVERITY_RANK[left] ? right : left
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
}

/**
 * The alert behind a list of conversation keys, or null when none of them is
 * flagged. The level is the worst severity among the keys that matched.
 */
export function alertEvidenceForKeys(
  keys: readonly string[],
  byConversation: Record<string, ConversationAlertLink> | undefined,
): AlertEvidence | null {
  if (byConversation === undefined) return null
  const matched: string[] = []
  const rules = new Set<string>()
  const titles = new Set<string>()
  const findingIds = new Set<string>()
  let severity: Severity | null = null
  for (const key of keys) {
    const link = byConversation[key]
    if (link === undefined) continue
    matched.push(key)
    severity = severity === null ? link.severity : worstSeverity(severity, link.severity)
    for (const rule of link.rules) rules.add(rule)
    for (const title of link.titles) titles.add(title)
    for (const id of link.finding_ids) findingIds.add(id)
  }
  const level = alertLevelForSeverity(severity)
  if (severity === null || level === null) return null
  return {
    level,
    severity,
    rules: sorted(rules),
    titles: sorted(titles),
    findingIds: sorted(findingIds),
    keys: sorted(matched),
    matchedBy: 'conversation',
  }
}

/**
 * The alert behind a node, falling back to the address map.
 *
 * `by_ip` exists for entities the diagram cannot address by stream id, so it is
 * consulted second: a node matched through its keys is never overridden by it.
 */
export function alertEvidenceForEntity(
  entity: { keys: readonly string[]; ip?: string | null },
  alerts: ConversationAlerts | null | undefined,
): AlertEvidence | null {
  if (alerts === null || alerts === undefined) return null
  const byKeys = alertEvidenceForKeys(entity.keys, alerts.byConversation)
  if (byKeys !== null) return byKeys
  const ip = entity.ip ?? null
  if (ip === null || ip === '') return null
  const link = alerts.byIp[ip]
  if (link === undefined) return null
  const level = alertLevelForSeverity(link.severity)
  if (level === null) return null
  /* by_ip carries no rules, so they are collected from the conversations it names. */
  const rules = new Set<string>()
  const titles = new Set<string>()
  for (const key of link.conversations) {
    const conversation = alerts.byConversation[key]
    if (conversation === undefined) continue
    for (const rule of conversation.rules) rules.add(rule)
    for (const title of conversation.titles) titles.add(title)
  }
  return {
    level,
    severity: link.severity,
    rules: sorted(rules),
    titles: sorted(titles),
    findingIds: sorted(link.finding_ids),
    keys: sorted(link.conversations),
    matchedBy: 'address',
  }
}

export interface AlertCountsSummary {
  high: number
  medium: number
  /** Alerts at or above the threshold, which is what the overlay draws. */
  above: number
  /** Alerts below the threshold, for an honest "+N" note. */
  below: number
  /** Every alert the endpoint knows about. */
  total: number
  /** True when there is nothing to highlight at all. */
  empty: boolean
  /** True when alerts exist, but only below the threshold. */
  onlyLower: boolean
}

export function alertCountsSummary(alerts: ConversationAlerts | null | undefined): AlertCountsSummary {
  const counts: SeverityCounts = alerts?.counts ?? { informational: 0, low: 0, medium: 0, high: 0 }
  const all: SeverityCounts = alerts?.allCounts ?? { informational: 0, low: 0, medium: 0, high: 0 }
  const high = counts.high ?? 0
  const medium = counts.medium ?? 0
  const above = high + medium
  const total = (all.high ?? 0) + (all.medium ?? 0) + (all.low ?? 0) + (all.informational ?? 0)
  return {
    high,
    medium,
    above,
    below: Math.max(0, total - above),
    total,
    empty: total === 0,
    onlyLower: total > 0 && above === 0,
  }
}

/** The one-line provenance shown for a flagged element. */
export function alertEvidenceLine(evidence: AlertEvidence): string {
  const rules = evidence.rules.length > 0 ? evidence.rules.join(', ') : 'no rule id'
  const title = evidence.titles.length > 0 ? evidence.titles[0] : 'no title'
  return rules + ' · ' + evidence.severity + ' · ' + title
}