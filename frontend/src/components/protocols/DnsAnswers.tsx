import clsx from 'clsx'
import { CopyButton } from '@/components/CopyButton'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import { DNS_SHAPE_THRESHOLDS } from '@/components/protocols/ProtocolFlags'
import { EMPTY, formatNumber } from '@/utils/format'

/**
 * DNS answer records and name-shape metrics.
 *
 * NOTE: `src/types/index.ts` types `DnsQuery.answers` as `unknown[]` on purpose —
 * the live API sends a list of JSON objects whose keys are not part of the frozen
 * schema. The renderer below therefore reads the fields it recognises
 * (`type`/`value` and a few aliases) and prints every remaining key verbatim
 * rather than guessing at a structure.
 */

interface AnswerEntry {
  label: string
  value: string
  extra: { key: string; value: string }[]
}

/** Keys checked, in order, for the "type" and "value" of an answer record. */
const TYPE_KEYS = ['type', 'record_type', 'rrtype', 'kind']
const VALUE_KEYS = ['value', 'data', 'rdata', 'address', 'ip', 'target', 'text']

function stringify(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function toEntries(answers: unknown[] | null | undefined): AnswerEntry[] {
  const list = answers ?? []
  const entries: AnswerEntry[] = []
  for (const item of list) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      // A bare scalar answer (the backend sends objects today; stay safe anyway).
      entries.push({ label: 'record', value: stringify(item), extra: [] })
      continue
    }
    const record = item as Record<string, unknown>
    const typeKey = TYPE_KEYS.find((key) => record[key] !== undefined && record[key] !== null)
    const valueKey = VALUE_KEYS.find((key) => record[key] !== undefined && record[key] !== null)
    const extra = Object.entries(record)
      .filter(([key, value]) => key !== typeKey && key !== valueKey && value !== null && value !== '')
      .map(([key, value]) => ({ key, value: stringify(value) }))
    entries.push({
      label: typeKey ? stringify(record[typeKey]) : 'record',
      value: valueKey ? stringify(record[valueKey]) : '',
      extra,
    })
  }
  return entries
}

export interface DnsAnswersProps {
  answers: unknown[] | null | undefined
  /** Comma-separated answer IPs as sent by the API. */
  answerIps: string | null | undefined
  /** Comma-separated CNAME targets. */
  cnames: string | null | undefined
  minTtl: number | null | undefined
  rcodeName: string | null | undefined
  queryType: string | null | undefined
}

/** Answer records the analyser merged into this query row. */
export function DnsAnswers({
  answers,
  answerIps,
  cnames,
  minTtl,
  rcodeName,
  queryType,
}: DnsAnswersProps) {
  const entries = toEntries(answers)
  const ips = (answerIps ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value !== '')
  const cnameList = (cnames ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value !== '')

  const copyValue = [
    ...ips.map((ip) => `A/AAAA ${ip}`),
    ...cnameList.map((name) => `CNAME ${name}`),
    ...(minTtl !== null && minTtl !== undefined ? [`min TTL ${minTtl}`] : []),
  ].join('\n')

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs uppercase tracking-wider text-muted">
          Answers · {formatNumber(entries.length)} record{entries.length === 1 ? '' : 's'}
        </span>
        <CopyButton value={copyValue} label="Copy answer summary" />
      </div>

      {entries.length === 0 ? (
        <SectionNote>
          The analyser stored no answer records for this query.
          {rcodeName && rcodeName !== 'NOERROR'
            ? ` The response code was ${rcodeName}, which normally carries no answer records.`
            : ' That is also what a positive answer with no address or CNAME record looks like — the backend only builds records from A, AAAA and CNAME fields, so answer data of any other type is not represented here.'}
        </SectionNote>
      ) : (
        <table className="dt">
          <thead>
            <tr>
              <th className="w-20">Type</th>
              <th>Value</th>
              <th>Other fields</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => (
              <tr key={index}>
                <td className="align-top text-accent2">{entry.label || EMPTY}</td>
                <td className="whitespace-pre-wrap break-all text-text">
                  {entry.value === '' ? <span className="text-faint">{EMPTY}</span> : entry.value}
                </td>
                <td className="whitespace-pre-wrap break-all text-muted">
                  {entry.extra.length === 0
                    ? EMPTY
                    : entry.extra.map((pair) => `${pair.key}=${pair.value}`).join('  ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <DetailGrid columns={3}>
        <DetailItem label="Answer IPs" value={ips.join(', ')} />
        <DetailItem label="CNAMEs" value={cnameList.join(', ')} />
        <DetailItem label="Minimum TTL" value={minTtl === null || minTtl === undefined ? null : `${formatNumber(minTtl)} s`} />
      </DetailGrid>

      {queryType === 'TXT' ? (
        <SectionNote>
          This is a TXT query. The backend derives answer records from A, AAAA and CNAME fields only,
          so the text carried by a TXT answer is not stored on this row — the packet bytes or the
          extracted objects are the place to read it.
        </SectionNote>
      ) : null}
    </div>
  )
}

export interface DnsShapeMetricsProps {
  nameLength: number | null | undefined
  labelCount: number | null | undefined
  longestLabel: number | null | undefined
  entropy: number | null | undefined
  /** Flags the analyser actually recorded for this row. */
  recordedFlags: readonly string[] | null | undefined
  className?: string
}

interface MetricRow {
  label: string
  value: number | null
  /** Fraction digits used when rendering the value. */
  digits: number
  /** Threshold text, and whether the analyser's threshold is met. */
  comparator: number | null
  comparatorText: string
  flag: string
  explain: string
}

/**
 * The computed shape of a query name, next to the thresholds the analyser uses,
 * so it is obvious *why* a name was flagged.
 */
export function DnsShapeMetrics({
  nameLength,
  labelCount,
  longestLabel,
  entropy,
  recordedFlags,
  className,
}: DnsShapeMetricsProps) {
  const flags = recordedFlags ?? []
  const rows: MetricRow[] = [
    {
      label: 'Name length',
      value: nameLength ?? null,
      digits: 0,
      comparator: DNS_SHAPE_THRESHOLDS.longName,
      comparatorText: `≥ ${DNS_SHAPE_THRESHOLDS.longName} characters raises long_name`,
      flag: 'long_name',
      explain:
        'Total characters of the fully qualified name. Longer names can carry more data per query, and are equally normal for cloud, CDN and anti-abuse names that embed identifiers.',
    },
    {
      label: 'Longest label',
      value: longestLabel ?? null,
      digits: 0,
      comparator: DNS_SHAPE_THRESHOLDS.longLabel,
      comparatorText: `≥ ${DNS_SHAPE_THRESHOLDS.longLabel} characters raises long_label`,
      flag: 'long_label',
      explain:
        'The longest single dot-separated part. DKIM selectors, ACME certificate-validation names and some CDN labels are legitimately this long.',
    },
    {
      label: 'Labels',
      value: labelCount ?? null,
      digits: 0,
      comparator: null,
      comparatorText: 'no threshold of its own; ≥ 3 labels is required before entropy can raise a flag',
      flag: '',
      explain:
        'How many dot-separated parts the name has. Many labels make a name harder to read at a glance but are not unusual by themselves — sub-domains are ordinary.',
    },
    {
      label: 'Entropy',
      value: entropy ?? null,
      digits: 2,
      comparator: DNS_SHAPE_THRESHOLDS.highEntropy,
      comparatorText: `> ${DNS_SHAPE_THRESHOLDS.highEntropy} bits/char (with ≥ 3 labels) raises high_entropy`,
      flag: 'high_entropy',
      explain:
        'Shannon entropy of the name\u2019s letters: higher means more random-looking. Domain-generation algorithms and DNS tunnels look like this, and so do CDN edges, cloud hostnames and telemetry endpoints with random IDs. It is a ranking signal, not a verdict.',
    },
  ]

  return (
    <div className={clsx('flex flex-col gap-2', className)}>
      <span className="text-2xs uppercase tracking-wider text-muted">
        Computed name shape — why this row was flagged
      </span>
      <table className="dt">
        <thead>
          <tr>
            <th className="w-32">Metric</th>
            <th className="w-20 text-right">Value</th>
            <th>Threshold in this build</th>
            <th className="w-40">Recorded</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const raised = row.flag !== '' && flags.includes(row.flag)
            const over =
              row.comparator !== null &&
              row.value !== null &&
              (row.flag === 'high_entropy' ? row.value > row.comparator : row.value >= row.comparator)
            return (
              <tr key={row.label}>
                <td className="align-top text-text" title={row.explain}>
                  {row.label}
                </td>
                <td className="text-right align-top">
                  {row.value === null ? (
                    <span className="text-faint">{EMPTY}</span>
                  ) : (
                    row.value.toFixed(row.digits)
                  )}
                </td>
                <td className={clsx('whitespace-normal align-top', over ? 'text-warn' : 'text-muted')}>
                  {row.comparatorText}
                </td>
                <td className="align-top">
                  {row.flag === '' ? (
                    <span className="text-faint">—</span>
                  ) : raised ? (
                    <span className="chip border-warn/40 bg-warn/10 text-warn">{row.flag}</span>
                  ) : (
                    <span className="chip border-border2 bg-surface2 text-faint">
                      {row.flag} not raised
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <SectionNote>
        These numbers describe the <em>shape</em> of the name, not the intent behind it. Long,
        random-looking, label-heavy names are also what legitimate CDN, cloud, telemetry, DKIM and
        certificate-validation domains look like — use the shape to decide what to read next, and
        the answers, timing and surrounding traffic to decide what it means.
      </SectionNote>
    </div>
  )
}
