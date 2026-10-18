import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ImageOff, Package, Search } from 'lucide-react'
import pageBackground from '@/assets/images_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import Panel from '@/components/Panel'
import { SectionNote } from '@/components/protocols/ProtocolDetail'
import { useAnalysis } from '@/hooks/useAnalysis'
import { objectsApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatBytes, formatNumber } from '@/utils/format'
import type { CaptureObject } from '@/types'

/**
 * Images — the pictures a capture carried in the clear.
 *
 * Every object here was carved out of a capture by the extraction stage: an HTTP
 * response body (or, as more extractors arrive, the body of another unencrypted
 * protocol) that happened to be a picture. Nothing on this page fetches anything: the
 * thumbnails are the stored bytes, served by the export route with `inline=1`, which
 * will only ever answer with a raster image type.
 *
 * The grid is deliberately not a second Files and Objects page. That page is a ledger of
 * every extracted file; this one answers a single question - what did this capture show
 * me - so it draws the pictures and links out for everything else.
 */

/** How many images the grid asks for. The list endpoint caps page_size well above this. */
const PAGE_SIZE = 120

/** One card, with its own decode-failure state. */
function ImageCard({ analysisId, item }: { analysisId: string; item: CaptureObject }) {
  const [broken, setBroken] = useState(false)
  const download = objectsApi.exportUrl(analysisId, item.id)
  const preview = objectsApi.inlineUrl(analysisId, item.id)

  return (
    <div className="panel flex flex-col overflow-hidden" data-image-card={item.id}>
      <a
        href={preview}
        target="_blank"
        rel="noreferrer"
        className="relative flex h-40 items-center justify-center border-b border-border bg-bg/60"
        title={'Open ' + item.filename + ' at full size'}
      >
        {broken ? (
          <span className="flex flex-col items-center gap-1 px-3 text-center text-2xs text-faint">
            <ImageOff size={18} aria-hidden />
            not a picture this browser can draw ({item.content_type ?? 'type not recorded'})
          </span>
        ) : (
          <img
            src={preview}
            alt={item.filename}
            loading="lazy"
            decoding="async"
            className="max-h-40 max-w-full object-contain"
            onError={() => setBroken(true)}
          />
        )}
      </a>

      <div className="flex min-w-0 flex-col gap-1 p-2">
        <span className="mono truncate text-2xs text-text" title={item.filename}>
          {item.filename}
        </span>
        <div className="flex flex-wrap items-center gap-1 text-2xs text-faint">
          <span className="mono">{formatBytes(item.size ?? 0)}</span>
          {item.protocol !== null && item.protocol !== undefined ? (
            <span className="chip border-border2 bg-surface2">{item.protocol}</span>
          ) : null}
          {item.status !== 'complete' ? (
            <span className="chip border-warn/50 bg-warn/10 text-warn">{item.status}</span>
          ) : null}
        </div>
        {item.src_ip !== null && item.src_ip !== undefined ? (
          <span className="mono truncate text-2xs text-muted" title={item.src_ip + ' -> ' + (item.dst_ip ?? '')}>
            {item.src_ip} <span className="text-faint">→</span> {item.dst_ip ?? '—'}
          </span>
        ) : null}
        <div className="mt-1 flex items-center gap-1.5">
          <a href={download} className="btn px-1.5 py-0.5" download={item.filename}>
            Download
          </a>
          <Link
            to={'/objects?search=' + encodeURIComponent(item.filename)}
            className="btn px-1.5 py-0.5"
            title="Open this object in Files and Objects"
          >
            Details
          </Link>
        </div>
      </div>
    </div>
  )
}

function ImagesBody() {
  const { analysisId } = useAnalysis()
  const [search, setSearch] = useState('')

  const query = useQuery({
    queryKey: ['objects', analysisId, 'images', search],
    queryFn: () =>
      objectsApi.list(analysisId as string, {
        page: 1,
        page_size: PAGE_SIZE,
        content_type: 'image',
        search: search.trim() === '' ? undefined : search.trim(),
      }),
    enabled: Boolean(analysisId),
  })

  if (query.isLoading) return <LoadingState label="Looking for images in this capture…" rows={3} />
  if (query.error) {
    return (
      <ErrorState
        error={query.error}
        title="Could not load the extracted images"
        onRetry={() => void query.refetch()}
      />
    )
  }

  const items = query.data?.items ?? []
  const total = query.data?.total ?? 0
  const bytes = items.reduce((sum, item) => sum + (item.size ?? 0), 0)

  return (
    <div className="flex flex-col gap-3">
      <SectionNote>
        Pictures are what the extraction stage carved out of unencrypted bodies — HTTP
        responses today, other cleartext protocols as their extractors arrive. Encrypted
        traffic is never decrypted, so an image behind TLS is not here and cannot be.
      </SectionNote>

      <Panel
        title="Extracted images"
        subtitle={
          formatNumber(total) +
          (total === 1 ? ' image' : ' images') +
          (items.length > 0 ? ' · ' + formatBytes(bytes) + ' drawn below' : '') +
          (total > items.length ? ' · first ' + formatNumber(items.length) + ' shown' : '')
        }
        actions={
          <label className="flex items-center gap-1 text-2xs text-muted" title="Filter by file name">
            <Search size={12} aria-hidden />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="file name"
              className="w-40 rounded border border-border bg-surface2 px-1.5 py-1 text-2xs text-text placeholder:text-faint focus:border-accent focus:outline-none"
            />
          </label>
        }
      >
        {items.length === 0 ? (
          <EmptyState
            variant="plain"
            icon={Package}
            title={search.trim() === '' ? 'No images were extracted from this capture' : 'No image matches that name'}
            description={
              search.trim() === ''
                ? 'The extraction stage found no picture in a cleartext response body. Files and Objects lists everything that was carved, including the ones that are not pictures, and its Extract button can re-run the stage.'
                : 'Nothing in the extracted images matches that text. Clear the filter to see them all.'
            }
            action={
              <Link to="/objects" className="btn btn-primary">
                <Package size={13} aria-hidden />
                Files and Objects
              </Link>
            }
          />
        ) : (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
            {items.map((item) => (
              <ImageCard key={item.id} analysisId={analysisId as string} item={item} />
            ))}
          </div>
        )}
      </Panel>

      <p className="text-2xs leading-relaxed text-faint">
        Each thumbnail is the stored bytes, served inline only when the type is a raster
        image (PNG, JPEG, GIF, BMP, WebP, TIFF, ICO). An SVG is never rendered: it is a
        document that can carry script, and this application does not execute capture
        content. A card that says it cannot be drawn is a body whose type was recorded as
        something else — its bytes are still there to download and inspect.
      </p>
    </div>
  )
}

export function ImagesPage() {
  return (
    <Page section={SECTIONS.images} headerImage={pageBackground}>
      <AnalysisGuard>
        <ImagesBody />
      </AnalysisGuard>
    </Page>
  )
}

export default ImagesPage
