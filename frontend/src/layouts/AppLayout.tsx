import { Fragment } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeftRight,
  Database,
  FolderOpen,
  Globe,
  Info,
  LayoutDashboard,
  List,
  Lock,
  Network,
  Package,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  Unplug,
  Upload,
  type LucideIcon,
} from 'lucide-react'
import StatusChip from '@/components/StatusChip'
import { useAnalysis, useHealth } from '@/hooks/useAnalysis'
import { findingsApi } from '@/services/api'
import { formatNumber } from '@/utils/format'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  badge?: string
  badgeTone?: 'default' | 'danger'
  title?: string
  /** A subsection label rendered immediately above this item. */
  section?: string
}

/**
 * A labelled subsection in the sidebar.
 *
 * The rule is always drawn, so the grouping still reads on the icon-only rail below
 * `lg`, where there is no room for the words.
 */
function NavSection({ label }: { label: string }) {
  return (
    <div className="mt-1.5 border-t border-border px-3 pb-1 pt-2">
      <span className="hidden text-2xs font-semibold uppercase tracking-wider text-faint lg:inline">
        {label}
      </span>
    </div>
  )
}

function TsharkStatus() {
  const health = useHealth()

  if (health.isLoading) {
    return (
      <div className="flex items-center gap-1.5 text-2xs text-faint">
        <Database size={12} aria-hidden />
        <span className="hidden lg:inline">checking tshark…</span>
      </div>
    )
  }

  if (health.error) {
    return (
      <div
        className="flex items-center gap-1.5 text-2xs text-danger"
        title="The APackets backend is not reachable on this port."
      >
        <Unplug size={12} aria-hidden />
        <span className="hidden lg:inline">backend offline</span>
      </div>
    )
  }

  const tshark = health.data?.tshark
  if (tshark?.available) {
    return (
      <div
        className="flex items-center gap-1.5 text-2xs text-ok"
        title={tshark.path ? `tshark ${tshark.version ?? ''} — ${tshark.path}` : undefined}
      >
        <Database size={12} aria-hidden />
        <span className="hidden truncate lg:inline">tshark {tshark.version ?? 'available'}</span>
      </div>
    )
  }

  return (
    <div
      className="flex items-center gap-1.5 text-2xs text-danger"
      title="TShark was not found. Set the path in Settings or add it to PATH."
    >
      <Unplug size={12} aria-hidden />
      <span className="hidden lg:inline">tshark unavailable</span>
    </div>
  )
}

function AnalysisPicker() {
  const { analysisId, analyses, setAnalysisId, isLoading } = useAnalysis()

  if (isLoading) {
    return <div className="h-6 w-56 animate-pulse rounded bg-surface2" aria-hidden />
  }

  if (analyses.length === 0) {
    return <span className="text-2xs text-faint">no captures uploaded</span>
  }

  return (
    <label className="flex items-center gap-1.5">
      <span className="sr-only">Active analysis</span>
      <select
        className="select max-w-[22rem]"
        value={analysisId ?? ''}
        onChange={(event) => setAnalysisId(event.target.value || null)}
      >
        {analysisId === null ? <option value="">— select a capture —</option> : null}
        {analyses.map((analysis) => (
          <option key={analysis.id} value={analysis.id}>
            {analysis.original_filename} · {analysis.status}
            {analysis.packet_count !== null ? ` · ${analysis.packet_count} pkts` : ''}
          </option>
        ))}
      </select>
    </label>
  )
}

/** Application shell: fixed sidebar, dense top bar, scrollable content area. */
export function AppLayout() {
  const { analysisId, analyses, selected, refresh } = useAnalysis()
  const queryClient = useQueryClient()

  const ready = analysisId !== null && selected?.status === 'completed'

  const findingsCounts = useQuery({
    queryKey: ['findings-counts', analysisId],
    queryFn: () => findingsApi.list(analysisId as string, { page: 1, page_size: 1 }),
    enabled: ready,
    staleTime: 10_000,
    // The badge tracks the same findings the Dashboard shows, so it follows the
    // analysis finishing (or Suricata rules being re-run) without a reload.
    refetchOnWindowFocus: true,
    refetchInterval: ready ? 10_000 : false,
  })

  const counts = findingsCounts.data?.counts
  const findingsTotal = counts
    ? counts.high + counts.medium + counts.low + counts.informational
    : findingsCounts.data?.total

  const onRefresh = () => {
    refresh()
    void queryClient.invalidateQueries()
  }

  const navItems: NavItem[] = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/info', label: 'Info', icon: Info, title: 'Full reference view for this capture' },
    { to: '/conversations', label: 'Conversations', icon: ArrowLeftRight },
    { to: '/hosts', label: 'Hosts', icon: Server },
    {
      to: '/findings',
      label: 'Findings',
      icon: ShieldAlert,
      badge: findingsTotal !== undefined ? formatNumber(findingsTotal) : undefined,
      badgeTone: counts && counts.high > 0 ? 'danger' : 'default',
      title: counts
        ? `high ${counts.high} · medium ${counts.medium} · low ${counts.low} · info ${counts.informational}`
        : undefined,
    },
    {
      to: '/threat-hunt',
      label: 'Threat Hunt',
      icon: Radar,
      title: 'The brief’s detections, computed over this capture’s indexed tables',
    },
    { to: '/objects', label: 'Files and Objects', icon: Package },
    { to: '/packets', label: 'Packets', icon: List },
    /* The protocol browsers are their own subsection: they answer "what did this
       protocol say", where everything above answers "what is in this capture". */
    { to: '/http', label: 'HTTP', icon: Globe, section: 'Protocols' },
    { to: '/dns', label: 'DNS', icon: Search },
    { to: '/tls', label: 'TLS', icon: Lock },
    {
      to: '/files',
      label: 'PCAP Files',
      icon: FolderOpen,
      badge: analyses.length > 0 ? String(analyses.length) : undefined,
      title: 'Uploaded captures',
    },
    { to: '/settings', label: 'Settings', icon: SettingsIcon },
  ]

  return (
    <div className="min-h-screen bg-bg">
      <aside className="fixed inset-y-0 left-0 z-20 flex w-14 flex-col border-r border-border bg-surface lg:w-52">
        <div className="flex h-12 items-center gap-2 border-b border-border px-3">
          <Network size={16} className="shrink-0 text-accent2" aria-hidden />
          <span className="hidden text-sm font-semibold tracking-wide text-text lg:inline">
            APackets
          </span>
        </div>

        <div className="hidden border-b border-border px-3 py-2 lg:block">
          <TsharkStatus />
        </div>
        <div className="flex justify-center border-b border-border px-1 py-2 lg:hidden">
          <TsharkStatus />
        </div>

        <nav className="flex-1 overflow-y-auto py-1">
          {navItems.map((item) => (
            <Fragment key={item.to}>
              {item.section !== undefined ? <NavSection label={item.section} /> : null}
              <NavLink
                to={item.to}
                end={item.to === '/'}
                title={item.label}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center gap-2 border-l-2 px-3 py-1.5 text-xs transition-colors',
                    isActive
                      ? 'border-accent bg-accent/10 text-text'
                      : 'border-transparent text-muted hover:bg-surface2 hover:text-text',
                  )
                }
              >
                <item.icon size={15} className="shrink-0" aria-hidden />
                <span className="hidden flex-1 truncate lg:inline">{item.label}</span>
                {item.badge !== undefined ? (
                  <span
                    className={clsx(
                      'chip hidden shrink-0 lg:inline-flex',
                      item.badgeTone === 'danger'
                        ? 'border-danger/50 bg-danger/15 text-red-300'
                        : 'border-border2 bg-surface2 text-muted',
                    )}
                    title={item.title}
                  >
                    {item.badge}
                  </span>
                ) : null}
              </NavLink>
            </Fragment>
          ))}
        </nav>

        <div className="hidden border-t border-border px-3 py-2 text-2xs text-faint lg:block">
          Local-only tool · no telemetry
        </div>
      </aside>

      <div className="ml-14 flex min-h-screen flex-col lg:ml-52">
        <header className="sticky top-0 z-10 flex h-12 items-center gap-3 border-b border-border bg-surface/95 px-3 backdrop-blur">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            {selected ? (
              <>
                <span
                  className="truncate text-xs font-medium text-text"
                  title={selected.original_filename}
                >
                  {selected.original_filename}
                </span>
                <StatusChip status={selected.status} />
                <span className="hidden mono text-2xs text-muted xl:inline">
                  {selected.packet_count !== null
                    ? `${formatNumber(selected.packet_count)} packets`
                    : 'packet count pending'}
                </span>
              </>
            ) : (
              <span className="text-xs text-faint">No capture selected</span>
            )}
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <AnalysisPicker />
            <button
              type="button"
              className="btn"
              onClick={onRefresh}
              title="Refresh analyses and the current view"
            >
              <RefreshCw size={13} aria-hidden />
              <span className="hidden xl:inline">Refresh</span>
            </button>
            <Link to="/files" className="btn btn-primary" title="Upload a capture">
              <Upload size={13} aria-hidden />
              <span className="hidden xl:inline">Upload</span>
            </Link>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-auto p-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

export default AppLayout
