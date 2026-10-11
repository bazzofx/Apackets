import { Link, Route, Routes } from 'react-router-dom'
import { FileQuestion } from 'lucide-react'
import AppLayout from '@/layouts/AppLayout'
import EmptyState from '@/components/EmptyState'
import DashboardPage from '@/pages/DashboardPage'
import PcapFilesPage from '@/pages/PcapFilesPage'
import PacketsPage from '@/pages/PacketsPage'
import ConversationsPage from '@/pages/ConversationsPage'
import HttpPage from '@/pages/HttpPage'
import DnsPage from '@/pages/DnsPage'
import TlsPage from '@/pages/TlsPage'
import HostsPage from '@/pages/HostsPage'
import ObjectsPage from '@/pages/ObjectsPage'
import FindingsPage from '@/pages/FindingsPage'
import SettingsPage from '@/pages/SettingsPage'

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
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/files" element={<PcapFilesPage />} />
        <Route path="/packets" element={<PacketsPage />} />
        <Route path="/conversations" element={<ConversationsPage />} />
        <Route path="/http" element={<HttpPage />} />
        <Route path="/dns" element={<DnsPage />} />
        <Route path="/tls" element={<TlsPage />} />
        <Route path="/hosts" element={<HostsPage />} />
        <Route path="/objects" element={<ObjectsPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:findingId" element={<FindingsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  )
}

export default App
