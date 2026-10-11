import clsx from 'clsx'
import { CopyButton } from '@/components/CopyButton'
import { DetailGrid, DetailItem, SectionNote } from '@/components/protocols/ProtocolDetail'
import { EMPTY, formatTimestamp } from '@/utils/format'

/**
 * TLS certificate presentation.
 *
 * The backend deliberately stores NULL rather than a guess, and TShark's
 * subject/issuer fields are not usable for every certificate — so a certificate
 * with a serial and a validity window but no subject is a normal outcome. The
 * panel says that out loud instead of implying the certificate is missing.
 */

export interface CertificateFields {
  cert_subject: string | null
  cert_issuer: string | null
  cert_not_before: string | null
  cert_not_after: string | null
  cert_serial: string | null
}

/** True when any certificate column was decoded (`has_cert` in the API). */
export function hasCertificate(fields: CertificateFields): boolean {
  return Boolean(
    fields.cert_subject ||
      fields.cert_issuer ||
      fields.cert_not_before ||
      fields.cert_not_after ||
      fields.cert_serial,
  )
}

/** Short, factual status used in table cells and tooltips. */
export function certificateSummary(fields: CertificateFields): string {
  if (!hasCertificate(fields)) {
    return 'No certificate was decoded for this session. TLS 1.3 encrypts the Certificate message and an incomplete capture can also explain it.'
  }
  const parts: string[] = []
  if (fields.cert_serial) parts.push(`serial ${fields.cert_serial}`)
  if (fields.cert_not_after) parts.push(`valid until ${fields.cert_not_after}`)
  if (!fields.cert_subject && !fields.cert_issuer) {
    parts.push('subject and issuer were not usable for this certificate')
  }
  return parts.length > 0 ? `Certificate present: ${parts.join(' · ')}` : 'Certificate present.'
}

/**
 * Parse a TShark certificate timestamp such as `2023-01-01 00:00:00 (UTC)`.
 * Returns epoch seconds, or `null` when the format is not understood.
 */
function parseCertTime(value: string | null): number | null {
  if (!value) return null
  const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(value.trim())
  if (!match) return null
  const [, year, month, day, hour, minute, second] = match
  const ms = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
  )
  return Number.isFinite(ms) ? ms / 1000 : null
}

export interface CertificatePanelProps {
  fields: CertificateFields
  /** Session time, so validity is judged at capture time when possible. */
  evaluatedAt?: number | null
  className?: string
}

/** Certificate panel for a TLS session detail view. */
export function CertificatePanel({ fields, evaluatedAt, className }: CertificatePanelProps) {
  const present = hasCertificate(fields)
  const notBefore = parseCertTime(fields.cert_not_before)
  const notAfter = parseCertTime(fields.cert_not_after)
  const reference = evaluatedAt ?? Date.now() / 1000
  const referenceLabel =
    evaluatedAt !== null && evaluatedAt !== undefined
      ? `at this session's time (${formatTimestamp(evaluatedAt)})`
      : 'at the current time'

  let validity: { tone: 'ok' | 'warn' | 'default'; text: string } = {
    tone: 'default',
    text: 'The validity window could not be read, so no comparison is made.',
  }
  if (notBefore !== null || notAfter !== null) {
    if (notBefore !== null && reference < notBefore) {
      validity = { tone: 'warn', text: `Not yet valid ${referenceLabel}.` }
    } else if (notAfter !== null && reference > notAfter) {
      validity = { tone: 'warn', text: `Expired ${referenceLabel}.` }
    } else {
      validity = { tone: 'ok', text: `Within the validity window ${referenceLabel}.` }
    }
  }

  return (
    <section className={clsx('flex flex-col gap-2', className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs uppercase tracking-wider text-muted">
          Certificate {present ? 'decoded from this session' : 'not decoded'}
        </span>
        {present ? (
          <CopyButton
            value={[fields.cert_subject, fields.cert_issuer, fields.cert_not_before, fields.cert_not_after, fields.cert_serial]
              .filter((value): value is string => Boolean(value))
              .join('\n')}
            label="Copy certificate fields"
          />
        ) : null}
      </div>

      <DetailGrid columns={2}>
        <DetailItem
          label="Subject"
          value={fields.cert_subject}
          tone={fields.cert_subject ? 'ok' : 'default'}
          unavailableReason="TShark reported no usable subject for this certificate; the backend stores NULL rather than a guess."
        />
        <DetailItem
          label="Issuer"
          value={fields.cert_issuer}
          tone={fields.cert_issuer ? 'ok' : 'default'}
          unavailableReason="TShark reported no usable issuer for this certificate; the backend stores NULL rather than a guess."
        />
        <DetailItem label="Serial" value={fields.cert_serial} />
        <DetailItem label="Validity from" value={fields.cert_not_before} />
        <DetailItem label="Validity to" value={fields.cert_not_after} />
        <DetailItem
          label="Validity check"
          mono={false}
          tone={validity.tone}
          value={validity.text}
        />
      </DetailGrid>

      {present ? (
        <SectionNote>
          A certificate is present even when Subject and Issuer show {EMPTY}: TShark&apos;s
          subject/issuer fields are not usable for every certificate (format, encoding or a
          partially captured handshake), and the backend stores NULL instead of a wrong value. Judge
          the certificate by the fields that are populated, and confirm anything that matters
          against the extracted certificate object or the packet bytes.
        </SectionNote>
      ) : (
        <SectionNote tone="warn">
          No certificate was decoded for this session. TLS 1.3 encrypts the Certificate message, a
          capture can end before the certificate flight, and a failed handshake never reaches it —
          so this is a statement about the capture, not evidence that the peer presented no
          certificate or that a client rejected one.
        </SectionNote>
      )}

      {notBefore === null && notAfter === null && present ? (
        <SectionNote>
          Neither validity date could be parsed from what was stored, so no expiry comparison is
          shown. The raw values are above.
        </SectionNote>
      ) : null}
    </section>
  )
}

export default CertificatePanel
