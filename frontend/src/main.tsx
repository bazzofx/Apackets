import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from '@/App'
import { AnalysisProvider } from '@/hooks/useAnalysis'
import { ThemeProvider } from '@/theme/ThemeProvider'
import './index.css'

/** React Query defaults: local backend, so retries are cheap but bounded. */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
    },
    mutations: {
      retry: 0,
    },
  },
})

const container = document.getElementById('root')
if (!container) throw new Error('APackets: #root container is missing from index.html')

createRoot(container).render(
  <StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AnalysisProvider>
            <App />
          </AnalysisProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)