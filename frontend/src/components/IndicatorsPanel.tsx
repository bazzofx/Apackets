import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Panel from '@/components/Panel'
import Toolbar from '@/components/Toolbar'
import MonoCell from '@/components/MonoCell'
import { settingsApi } from '@/services/api'
import { useState } from 'react'
import type { Indicator, IndicatorType } from '@/types'
import { formatTimestamp } from '@/utils/format'

const INDICATOR_TYPES: IndicatorType[] = ['ip', 'domain', 'port', 'ja3', 'ja4', 'ua', 'sha256']

const INDICATOR_HINTS: Record<IndicatorType, string> = {
  ip: '10.0.0.9',
  domain: 'c2.example.net',
  port: '4444',
  ja3: '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0',
  ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  ua: 'Mozilla/5.0 (compatible; suspicious-agent)',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}

/**
 * Analyst-supplied indicators: the values the `indicator_match` rule looks for.
 *
 * These live on the Alert Settings page because they are detection *input*, not
 * configuration of the installation: an address entered here is the only reason that rule
 * can fire at all. Every row added is global - it is matched against every analysis - and
 * nothing here scopes one to a capture.
 */
export function IndicatorsPanel() {
  const queryClient = useQueryClient()
  const indicators = useQuery({
    queryKey: ['indicators'],
    queryFn: () => settingsApi.indicators.list(),
  })

  const [newType, setNewType] = useState<IndicatorType>('ip')
  const [newValue, setNewValue] = useState('')
  const [newNote, setNewNote] = useState('')
  const [indicatorError, setIndicatorError] = useState(null as string | null)

  const createIndicator = useMutation({
    mutationFn: () =>
      settingsApi.indicators.create({
        type: newType,
        value: newValue.trim(),
        note: newNote.trim() || null,
      }),
    onSuccess: () => {
      setNewValue('')
      setNewNote('')
      setIndicatorError(null)
      void queryClient.invalidateQueries({ queryKey: ['indicators'] })
    },
  })

  const deleteIndicator = useMutation({
    mutationFn: (id: number) => settingsApi.indicators.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['indicators'] })
    },
  })

  const onAddIndicator = () => {
    const value = newValue.trim()
    if (value === '') {
      setIndicatorError('An indicator needs a value.')
      return
    }
    if (newType === 'port') {
      const port = Number(value)
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setIndicatorError('A port indicator must be an integer between 1 and 65535.')
        return
      }
    }
    if (newType === 'ip' && value.includes(' ')) {
      setIndicatorError('An IP indicator must not contain spaces.')
      return
    }
    setIndicatorError(null)
    createIndicator.mutate()
  }

  const items: Indicator[] = indicators.data?.items ?? []

  return (
    <Panel
      title="Indicators"
      subtitle="analyst-supplied indicators matched by the indicator_match rule (global scope)"
      flush
      actions={
        <span className="chip border-border2 bg-surface2 text-muted" title="Total indicators">
          {items.length}
        </span>
      }
    >
      <Toolbar>
        <select
          className="select"
          value={newType}
          onChange={(event) => setNewType(event.target.value as IndicatorType)}
          title="Indicator type"
        >
          {INDICATOR_TYPES.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
        <input
          className="input w-80"
          placeholder={INDICATOR_HINTS[newType]}
          value={newValue}
          onChange={(event) => setNewValue(event.target.value)}
        />
        <input
          className="input w-56"
          placeholder="note (optional, shown in the finding)"
          value={newNote}
          onChange={(event) => setNewNote(event.target.value)}
        />
        <button
          type="button"
          className="btn btn-primary"
          onClick={onAddIndicator}
          disabled={createIndicator.isPending}
        >
          <Plus size={13} aria-hidden />
          Add indicator
        </button>
      </Toolbar>

      {indicatorError ? <div className="px-3 py-2 text-xs text-danger">{indicatorError}</div> : null}
      {createIndicator.error ? (
        <ErrorState
          error={createIndicator.error}
          variant="plain"
          title="Could not add the indicator"
          className="py-3"
        />
      ) : null}
      {deleteIndicator.error ? (
        <ErrorState
          error={deleteIndicator.error}
          variant="plain"
          title="Could not delete the indicator"
          className="py-3"
        />
      ) : null}

      {indicators.isLoading ? (
        <LoadingState label="Loading indicators…" rows={3} />
      ) : indicators.error ? (
        <ErrorState
          error={indicators.error}
          variant="plain"
          title="Could not load indicators"
          onRetry={() => void indicators.refetch()}
        />
      ) : items.length === 0 ? (
        <div className="px-3 py-8 text-center text-xs text-muted">
          No indicators defined. Indicators you add here are matched against every analysis.
        </div>
      ) : (
        <div className="overflow-auto">
          <table className="dt">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Note</th>
                <th>Scope</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((indicator) => (
                <tr key={indicator.id}>
                  <td>
                    <span className="chip border-accent/50 bg-accent/15 text-accent2">
                      {indicator.type}
                    </span>
                  </td>
                  <td>
                    <MonoCell maxWidth={360}>{indicator.value}</MonoCell>
                  </td>
                  <td className="font-sans">
                    <span
                      className="block max-w-72 truncate text-muted"
                      title={indicator.note ?? undefined}
                    >
                      {indicator.note ?? '—'}
                    </span>
                  </td>
                  <td className="text-muted">{indicator.analysis_id ?? 'global'}</td>
                  <td>{formatTimestamp(indicator.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-danger px-1.5 py-1"
                      title="Delete this indicator"
                      disabled={deleteIndicator.isPending}
                      onClick={() => deleteIndicator.mutate(indicator.id)}
                    >
                      <Trash2 size={12} aria-hidden />
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

export default IndicatorsPanel
