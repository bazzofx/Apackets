import { Download, Package } from 'lucide-react'
import CopyButton from '@/components/CopyButton'
import EmptyState from '@/components/EmptyState'
import MonoCell from '@/components/MonoCell'
import { objectsApi } from '@/services/api'
import { formatBytes, formatNumber, truncate } from '@/utils/format'
import type { FindingObject } from '@/types'

export interface FindingObjectsProps {
  analysisId: string
  objects: FindingObject[]
  truncated: boolean
}

const MATCH_LABEL: Record<string, string> = {
  stream: 'matched by stream',
  packet: 'matched by packet',
  'inferred-uri': 'inferred from the request URI',
}

/** Files transferred over the streams the alert touches. */
export function FindingObjects({ analysisId, objects, truncated }: FindingObjectsProps) {
  if (objects.length === 0) {
    return (
      <EmptyState
        variant="plain"
        icon={Package}
        title="No extracted file for this alert"
        description="Object extraction only covers cleartext HTTP bodies. Encrypted traffic, or a capture without HTTP objects, leaves this empty."
        className="py-8"
      />
    )
  }
  return (
    <div className="flex flex-col">
      <div className="overflow-auto">
        <table className="dt">
          <thead>
            <tr>
              <th>File</th>
              <th>Protocol</th>
              <th>Type</th>
              <th className="text-right">Size</th>
              <th>Status</th>
              <th>SHA-256</th>
              <th>Link</th>
              <th>Download</th>
            </tr>
          </thead>
          <tbody>
            {objects.map((item) => (
              <tr key={item.id}>
                <td>
                  <MonoCell maxWidth={280} title={item.filename}>
                    {item.filename}
                  </MonoCell>
                </td>
                <td className="text-muted">{item.protocol ?? '-'}</td>
                <td>
                  <MonoCell maxWidth={160}>{item.content_type}</MonoCell>
                </td>
                <td className="text-right">{formatBytes(item.size)}</td>
                <td className="text-muted">{item.status}</td>
                <td>
                  <div className="flex items-center gap-1">
                    <MonoCell maxWidth={220} title={item.sha256 ?? undefined}>
                      {item.sha256 ? truncate(item.sha256, 20) : null}
                    </MonoCell>
                    <CopyButton value={item.sha256} label="Copy SHA-256" />
                  </div>
                </td>
                <td className="text-2xs text-faint">{MATCH_LABEL[item.match ?? ''] ?? '—'}</td>
                <td>
                  <a
                    className="btn px-1.5 py-1"
                    href={objectsApi.exportUrl(analysisId, item.id)}
                    download={item.filename}
                    title="Download the extracted file"
                  >
                    <Download size={12} aria-hidden />
                    Save
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-3 py-2 text-2xs text-faint">
        {formatNumber(objects.length)} file(s)
        {truncated ? ' — capped, more objects belong to this alert' : ''}. “Inferred from the request
        URI” means the object store had no stream or packet link, so the filename was matched against
        the request path.
      </div>
    </div>
  )
}

export default FindingObjects