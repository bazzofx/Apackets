import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { analysesApi, healthApi, toApiError, type ApiError } from '@/services/api'
import type { Analysis, AnalysisDetail, AnalysisSummary, HealthResponse } from '@/types'

/** localStorage key holding the app-wide active analysis id. */
export const ANALYSIS_STORAGE_KEY = 'shadowpackets.analysisId'

/** The key this selection used before the rename; read once, then migrated. */
const LEGACY_ANALYSIS_STORAGE_KEY = 'apackets.analysisId'

export const ANALYSES_QUERY_KEY = ['analyses'] as const
export const HEALTH_QUERY_KEY = ['health'] as const

function readStoredId(): string | null {
  try {
    const raw =
      window.localStorage.getItem(ANALYSIS_STORAGE_KEY) ??
      window.localStorage.getItem(LEGACY_ANALYSIS_STORAGE_KEY)
    if (raw === null || raw.trim() === '') return null
    window.localStorage.setItem(ANALYSIS_STORAGE_KEY, raw)
    return raw
  } catch {
    return null
  }
}

function writeStoredId(id: string | null): void {
  try {
    if (id === null) window.localStorage.removeItem(ANALYSIS_STORAGE_KEY)
    else window.localStorage.setItem(ANALYSIS_STORAGE_KEY, id)
  } catch {
    /* storage unavailable (private mode) — selection stays in memory only */
  }
}

function isInFlight(analysis: Pick<Analysis, 'status'> | undefined | null): boolean {
  return analysis?.status === 'pending' || analysis?.status === 'processing'
}

/**
 * `GET /api/analyses` shared query. Polls every 2 s while any analysis is still
 * pending/processing, so progress and stage stay live across the app.
 */
export function useAnalyses() {
  return useQuery({
    queryKey: ANALYSES_QUERY_KEY,
    queryFn: () => analysesApi.list({ page: 1, page_size: 200 }),
    refetchInterval: (query) => (query.state.data?.items.some(isInFlight) ? 2000 : false),
  })
}

/** `GET /api/analyses/{id}`; polls every 2 s while the analysis is in flight. */
export function useAnalysisDetail(analysisId: string | null | undefined) {
  return useQuery({
    queryKey: ['analysis', analysisId],
    queryFn: () => analysesApi.get(analysisId as string),
    enabled: Boolean(analysisId),
    refetchInterval: (query) => (isInFlight(query.state.data) ? 2000 : false),
  })
}

export interface SummaryOptions {
  /** Poll interval while the analysis is fresh (a just-finished run, or rules re-run). */
  refetchInterval?: number | false
  refetchOnWindowFocus?: boolean
}

/**
 * `GET /api/analyses/{id}/summary` — Dashboard payload.
 *
 * Refreshes when the window regains focus by default: findings change when an
 * analysis finishes or when Suricata rules are re-run from Settings, and the
 * dashboard must not keep showing the previous counts.
 */
export function useAnalysisSummary(
  analysisId: string | null | undefined,
  options: SummaryOptions = {},
) {
  return useQuery<AnalysisSummary>({
    queryKey: ['summary', analysisId],
    queryFn: () => analysesApi.summary(analysisId as string),
    enabled: Boolean(analysisId),
    refetchOnWindowFocus: options.refetchOnWindowFocus ?? true,
    refetchInterval: options.refetchInterval ?? false,
  })
}

/** `GET /api/health` — TShark availability for the sidebar status line. */
export function useHealth() {
  return useQuery<HealthResponse>({
    queryKey: HEALTH_QUERY_KEY,
    queryFn: () => healthApi.get(),
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

/* ------------------------------------------------------------------ */
/* Global analysis selection                                           */
/* ------------------------------------------------------------------ */

export interface AnalysisContextValue {
  /** Active analysis id, or null when none is usable. */
  analysisId: string | null
  setAnalysisId: (id: string | null) => void
  /** All analyses, newest first. */
  analyses: Analysis[]
  /** The active analysis row, when present in the list. */
  selected: Analysis | null
  isLoading: boolean
  error: ApiError | null
  refresh: () => void
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [analysisId, setAnalysisIdState] = useState<string | null>(() => readStoredId())
  const query = useAnalyses()

  const analyses = useMemo<Analysis[]>(() => query.data?.items ?? [], [query.data])

  const setAnalysisId = useCallback((id: string | null) => {
    setAnalysisIdState(id)
    writeStoredId(id)
  }, [])

  // First load: adopt the most recent analysis when nothing is stored, when the
  // stored id is stale (no longer returned by the backend), or when the stored
  // capture was deleted. Only a successful response may change the selection —
  // a backend that is down must not wipe the analyst's choice.
  useEffect(() => {
    if (!query.isSuccess) return
    if (analyses.length === 0) {
      if (analysisId !== null) setAnalysisId(null)
      return
    }
    const stillPresent = analysisId !== null && analyses.some((a) => a.id === analysisId)
    if (!stillPresent) setAnalysisId(analyses[0].id)
  }, [analyses, analysisId, query.isSuccess, setAnalysisId])

  const refresh = useCallback(() => {
    void query.refetch()
  }, [query])

  const value = useMemo<AnalysisContextValue>(
    () => ({
      analysisId,
      setAnalysisId,
      analyses,
      selected: analyses.find((a) => a.id === analysisId) ?? null,
      isLoading: query.isLoading,
      error: query.error ? toApiError(query.error) : null,
      refresh,
    }),
    [analysisId, setAnalysisId, analyses, query.isLoading, query.error, refresh],
  )

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis(): AnalysisContextValue {
  const ctx = useContext(AnalysisContext)
  if (!ctx) throw new Error('useAnalysis must be used inside <AnalysisProvider>')
  return ctx
}

export type { AnalysisDetail }
