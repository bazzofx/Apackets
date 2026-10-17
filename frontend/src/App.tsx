import { Link, Route, Routes } from 'react-router-dom'
import { FileQuestion } from 'lucide-react'
import AppLayout from '@/layouts/AppLayout'
import EmptyState from '@/components/EmptyState'
import IpContextMenu from '@/components/context/IpContextMenu'
import DashboardPage from '@/pages/DashboardPage'
import InfoPage from '@/pages/InfoPage'
import PcapFilesPage from '@/pages/PcapFilesPage'
import PacketsPage from '@/pages/PacketsPage'
import ConversationsPage from '@/pages/ConversationsPage'
import HttpPage from '@/pages/HttpPage'
import DnsPage from '@/pages/DnsPage'
import TlsPage from '@/pages/TlsPage'
import HostsPage from '@/pages/HostsPage'
import ObjectsPage from '@/pages/ObjectsPage'
import CredentialsPage from '@/pages/CredentialsPage'
import FindingsPage from '@/pages/FindingsPage'
import InvestigatePage from '@/pages/InvestigatePage'
import ProtocolSessionsPage from '@/pages/ProtocolSessionsPage'
import ThreatHuntPage from '@/pages/ThreatHuntPage'
import BaselineCheckPage from '@/pages/BaselineCheckPage'
import SettingsPage from '@/pages/SettingsPage'
import AlertSettingsPage from '@/pages/AlertSettingsPage'

function NotFoundPage() {
  return (
    <EmptyState
      icon={FileQuestion}
      title="Page not found"
      description="That route does not exist in APackets."
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
