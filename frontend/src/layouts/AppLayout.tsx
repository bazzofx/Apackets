import { Suspense, useCallback, useEffect, useState, type CSSProperties } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import clsx from 'clsx'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeftRight,
  Crosshair,
  Database,
  FolderOpen,
  FolderUp,
  Globe,
  Image,
  Info,
  KeyRound,
  LayoutDashboard,
  List,
  Lock,
  Mail,
  Package,
  PhoneCall,
  Radar,
  RefreshCw,
  Scale,
  ScanSearch,
  Search,
  Server,
  Settings as SettingsIcon,
  Share2,
  ShieldAlert,
  SlidersHorizontal,
  Terminal,
  Unplug,
  Upload,
} from 'lucide-react'
import LoadingState from '@/components/LoadingState'
import AppHeader from '@/components/layout/AppHeader'
import Sidebar, { type SidebarItem } from '@/components/layout/Sidebar'
import { useAnalysis, useHealth } from '@/hooks/useAnalysis'
import { baselineApi, detectionApi, findingsApi, suricataApi } from '@/services/api'
import { sectionForRoute } from '@/theme/sections'
import { formatNumber } from '@/utils/format'

/** The TShark / backend line the sidebar carries above the navigation. */
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
        title="The ShadowPackets backend is not reachable on this port."
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

/**
 * Application shell: the cinematic banner on top, the navigation on the left, and the
 * scrolling page body inside it.
 *
 * The banner spans the full width on purpose - it is the application's identity, not a
 * toolbar above one column - and the sidebar sits *in flow* under it, so the page body
 * keeps the definite viewport height the Findings workbench resolves its panes against.
 */
export function AppLayout() {
  const { analysisId, analyses, selected, setAnalysisId, refresh } = useAnalysis()
  const queryClient = useQueryClient()
  const location = useLocation()
  const [fullscreen, setFullscreen] = useState(false)

  /* The whole shell takes its hue from the section being viewed. Pages set the same
     variable again themselves, which keeps `Page` correct outside this shell. */
  const section = sectionForRoute(location.pathname)
  const shellStyle = { '--s-accent': `var(${section.hueVar})` } as CSSProperties

  const ready = analysisId !== null && selected?.status === 'completed'

  const findingsCounts = useQuery({
    queryKey: ['findings-counts', analysisId],
    queryFn: () => findingsApi.list(analysisId as string, { page: 1, page_size: 1 }),
    enabled: ready,
    staleTime: 10_000,
    refetchOnWindowFocus: true,
    refetchInterval: ready ? 10_000 : false,
  })

  const counts = findingsCounts.data?.counts
  const findingsTotal = counts
    ? counts.high + counts.medium + counts.low + counts.informational
    : findingsCounts.data?.total

  /* Rules that are not running their default, counted across both families. Alert
     Settings reads the same two queries with the same keys, so this is one request per
     list, not four, and the badge follows an edit made there. */
  const detectionRules = useQuery({
    queryKey: ['detection-rules', analysisId],
    queryFn: () => detectionApi.rules(analysisId),
    staleTime: 10_000,
    refetchOnWindowFocus: true,
  })
  const suricataStats = useQuery({
    queryKey: ['suricata-stats'],
    queryFn: () => suricataApi.stats(),
    staleTime: 10_000,
    refetchOnWindowFocus: true,
  })
  /* Baseline mode, read here so the indicator is on every page. Same query key as PCAP
     Files, so the two cannot disagree. */
  const baseline = useQuery({
    queryKey: ['baseline'],
    queryFn: () => baselineApi.status(),
    staleTime: 10_000,
    refetchOnWindowFocus: true,
  })

  const modifiedRules =
    (detectionRules.data?.items ?? []).filter((rule) => rule.modified).length +
    (suricataStats.data?.modified ?? 0)

  const onRefresh = useCallback(() => {
    refresh()
    void queryClient.invalidateQueries()
  }, [queryClient, refresh])

  /* The shell's three controls. They are built here rather than inside `Sidebar`
     because they call queries and a handler; the sidebar only gives them the place.
     Their markup is the navigation's own: the stylesheet gives `.nav-action` the same
     left inset as `.nav-link`, so the icons line up rather than nearly line up. */
  const baselineOn = baseline.data?.active === true
  const shellActions = (
    <>
      <Link
        to="/baseline-check"
        className={clsx('nav-action nav-action-baseline', baselineOn ? 'is-on' : 'is-off')}
        title={
          baselineOn
            ? 'Baseline mode is on: every analysis is compared against ' +
              (baseline.data?.baseline?.original_filename ?? 'the baseline capture')
            : 'No baseline network is set - choose one on PCAP Files'
        }
      >
        <Crosshair size={15} className="shrink-0" aria-hidden />
        <span className="nav-action-label">
          {'Baseline mode : '}
          {baselineOn ? 'enabled' : 'off'}
        </span>
      </Link>
      <button
        type="button"
        className="nav-action"
        onClick={onRefresh}
        title="Refresh analyses and the current view"
      >
        <RefreshCw size={15} className="shrink-0" aria-hidden />
        <span className="nav-action-label">Refresh</span>
      </button>
      <Link to="/files" className="nav-action nav-action-upload" title="Upload a capture">
        <Upload size={15} className="shrink-0" aria-hidden />
        <span className="nav-action-label">Upload</span>
      </Link>
    </>
  )

  /* Full screen is the browser's own, and the button reflects it: if the reader leaves
     with Esc the label has to follow, which is why the state is read from the document
     rather than assumed. */
  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement !== null)
    document.addEventListener('fullscreenchange', onChange)
    onChange()
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])

  const onToggleFullscreen = useCallback(() => {
    if (document.fullscreenElement !== null) {
      void document.exitFullscreen?.()
      return
    }
    void document.documentElement.requestFullscreen?.()
  }, [])

  const navItems: SidebarItem[] = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, section: 'Dashboard' },
    { to: '/info', label: 'Info', icon: Info, title: 'Full reference view for this capture' },
    { to: '/hosts', label: 'Hosts', icon: Server, title: 'Address inventory for this capture' },
    { to: '/conversations', label: 'Conversations', icon: ArrowLeftRight, section: 'Analysis' },
    { to: '/packets', label: 'Packets', icon: List },
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
      label: 'Threat Map',
      icon: Radar,
      section: 'Investigate',
      title: 'The brief’s detections, computed over this capture’s indexed tables',
    },
    {
      to: '/baseline-check',
      label: 'Baseline Check',
      icon: Scale,
      badge: baseline.data?.active ? 'on' : undefined,
      badgeTone: 'warn',
      title:
        baseline.data?.active && baseline.data.baseline
          ? 'What this capture holds that ' + baseline.data.baseline.original_filename + ' never did'
          : 'What this capture holds that the baseline network never did - pick a baseline on PCAP Files',
    },
    {
      to: '/investigate',
      label: 'Hunt',
      icon: ScanSearch,
      title: 'Look up one address, domain or URL and see everything this capture knows about it',
    },
    { to: '/objects', label: 'Files and Objects', icon: Package },
    {
      to: '/images',
      label: 'Images',
      icon: Image,
      title: 'Pictures carved out of unencrypted response bodies, drawn from the stored bytes',
    },
    {
      to: '/credentials',
      label: 'Users and Passwords',
      icon: KeyRound,
      title:
        'Cleartext users, passwords, keys and tokens the dissectors could read, with the locations the scanner reads and the ones it cannot',
    },
    { to: '/http', label: 'HTTP', icon: Globe, section: 'Protocols' },
    { to: '/dns', label: 'DNS', icon: Search },
    { to: '/tls', label: 'TLS', icon: Lock },
    { to: '/email', label: 'Email', icon: Mail, title: 'SMTP, POP3 and IMAP sessions' },
    { to: '/ssh', label: 'SSH', icon: Terminal, title: 'SSH banners, algorithms and handshakes' },
    { to: '/ftp', label: 'FTP', icon: FolderUp, title: 'FTP commands, files asked for and data connections' },
    { to: '/voip', label: 'VoIP', icon: PhoneCall, title: 'SIP signalling and the RTP/RTCP streams it produced' },
    { to: '/smb', label: 'SMB', icon: Share2, title: 'SMB dialects, shares and file names' },
    {
      to: '/files',
      label: 'PCAP Files',
      icon: FolderOpen,
      section: 'Settings',
      badge: analyses.length > 0 ? String(analyses.length) : undefined,
      title: 'Uploaded captures',
    },
    { to: '/settings', label: 'Settings', icon: SettingsIcon },
    {
      to: '/alert-settings',
      label: 'Alert Settings',
      icon: SlidersHorizontal,
      badge: modifiedRules > 0 ? String(modifiedRules) : undefined,
      badgeTone: 'warn',
      title:
        modifiedRules > 0
          ? modifiedRules +
            ' rule(s) are not at their defaults - the built-in heuristics and the imported signatures'
          : 'Alert Settings: the built-in detection rules and the imported Suricata rules',
    },
  ]

  return (
    <div className="flex h-dvh flex-col overflow-hidden bg-bg" style={shellStyle} data-section={section.id}>
      <AppHeader
        analyses={analyses}
        analysisId={analysisId}
        selected={selected}
        onSelectAnalysis={setAnalysisId}
        fullscreen={fullscreen}
        onToggleFullscreen={onToggleFullscreen}
      />

      {/* The sidebar is in flow under the banner. The content column keeps a definite
          height, so a page can size its own panes with `h-full` and scroll a list without
          moving the toolbar or the page underneath it. */}
      <div className="flex min-h-0 flex-1">
        <Sidebar items={navItems} status={<TsharkStatus />} actions={shellActions} />

        <main className="min-w-0 flex-1 overflow-auto p-3 lg:p-4">
          <Suspense fallback={<LoadingState label="Loading this section…" rows={3} />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  )
}

export default AppLayout
