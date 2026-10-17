import { lazy } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import { FileQuestion } from 'lucide-react'
import AppLayout from '@/layouts/AppLayout'
import EmptyState from '@/components/EmptyState'
import IpContextMenu from '@/components/context/IpContextMenu'
import DashboardPage from '@/pages/DashboardPage'

/**
 * Every page except the Dashboard is loaded on demand.
 *
 * The shell (layout, top bar, theme, the right-click menu) and the Dashboard are the
 * only code the first paint needs; the other pages - the five protocol browsers, the
 * Findings workbench, the Threat Map, the charts - used to be downloaded, parsed and
 * kept in memory before the analyst had opened any of them. Splitting them per route
 * makes the first visit download the shell only, and each page arrives when it is
 * requested (and then stays cached, so the second visit is instant).
 *
 * The Dashboard is eager on purpose: it is the landing page, so making it a second
 * round trip would trade one stall for another.
 */
const PcapFilesPage = lazy(() => import('@/pages/PcapFilesPage'))
const PacketsPage = lazy(() => import('@/pages/PacketsPage'))
const ConversationsPage = lazy(() => import('@/pages/ConversationsPage'))
const HttpPage = lazy(() => import('@/pages/HttpPage'))
const DnsPage = lazy(() => import('@/pages/DnsPage'))
const TlsPage = lazy(() => import('@/pages/TlsPage'))
const HostsPage = lazy(() => import('@/pages/HostsPage'))
const ObjectsPage = lazy(() => import('@/pages/ObjectsPage'))
const ImagesPage = lazy(() => import('@/pages/ImagesPage'))
const CredentialsPage = lazy(() => import('@/pages/CredentialsPage'))
const FindingsPage = lazy(() => import('@/pages/FindingsPage'))
const InvestigatePage = lazy(() => import('@/pages/InvestigatePage'))
const ProtocolSessionsPage = lazy(() => import('@/pages/ProtocolSessionsPage'))
const ThreatHuntPage = lazy(() => import('@/pages/ThreatHuntPage'))
const BaselineCheckPage = lazy(() => import('@/pages/BaselineCheckPage'))
const SettingsPage = lazy(() => import('@/pages/SettingsPage'))
const AlertSettingsPage = lazy(() => import('@/pages/AlertSettingsPage'))
const InfoPage = lazy(() => import('@/pages/InfoPage'))

function NotFoundPage() {
  return (
    <EmptyState
      icon={FileQuestion}
      title="Page not found"
      description="That route does not exist in ShinboShark."
      action={
        <Link to="/" className="btn btn-primary">
          Back to Dashboard
        </Link>
      }
      className="mx-auto mt-8 max-w-xl"
    />
  )
}

export function App() {
  return (
    <>
      {/* One right-click menu for every address in the application: it delegates
          from the document, so any element that carries a `data-ip` attribute is
          menu-able without its component knowing this exists. */}
      <IpContextMenu />
      {/* The Suspense boundary for the lazy pages lives inside the layout's <main>,
          so a chunk arriving replaces the page body and never the shell. */}
      <Routes>
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/info" element={<InfoPage />} />
            <Route path="/files" element={<PcapFilesPage />} />
            <Route path="/packets" element={<PacketsPage />} />
            <Route path="/conversations" element={<ConversationsPage />} />
            <Route path="/http" element={<HttpPage />} />
            <Route path="/dns" element={<DnsPage />} />
            <Route path="/tls" element={<TlsPage />} />
            {/* The five session pages are one component with a family: same table, same
                filters, same flag legend, a different protocol set (docs/PROTOCOLS.md). */}
            <Route path="/email" element={<ProtocolSessionsPage family="email" />} />
            <Route path="/ssh" element={<ProtocolSessionsPage family="ssh" />} />
            <Route path="/ftp" element={<ProtocolSessionsPage family="ftp" />} />
            <Route path="/voip" element={<ProtocolSessionsPage family="voip" />} />
            <Route path="/smb" element={<ProtocolSessionsPage family="smb" />} />
            <Route path="/hosts" element={<HostsPage />} />
            <Route path="/objects" element={<ObjectsPage />} />
            <Route path="/images" element={<ImagesPage />} />
            <Route path="/credentials" element={<CredentialsPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:findingId" element={<FindingsPage />} />
            <Route path="/threat-hunt" element={<ThreatHuntPage />} />
            <Route path="/baseline-check" element={<BaselineCheckPage />} />
            <Route path="/investigate" element={<InvestigatePage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/alert-settings" element={<AlertSettingsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
      </Routes>
    </>
  )
}

export default App
