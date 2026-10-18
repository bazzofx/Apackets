import { useMemo, useState } from 'react'
import clsx from 'clsx'
import ninjaMark from '@/assets/ninja-ridge.svg'
import { flagUrl } from '@/theme/countryFlags'
import { countryName } from '@/theme/worldMap'
import { formatBytes, formatNumber } from '@/utils/format'
import type { Analysis, GeographyResponse, TopPort } from '@/types'

export type DestinationTab = 'countries' | 'ports'

export interface DestinationSummaryProps {
  /** The same geography response the map draws: the panel never re-queries it. */
  geography: GeographyResponse | undefined
  /** The Dashboard summary's ranked ports - the same rows the summary already computed. */
  topPorts: TopPort[]
  /** The capture the application is showing, for the status line. */
  selected: Analysis | null
  /** The country the map has pinned, so a row and the map agree. */
  focused: string | null
  onFocus: (code: string | null) => void
}

/** One ranking row: optional flag, label, count, share, and a thin bar in the metric's hue. */
function RankRow({
  icon,
  label,
  hint,
  value,
  percent,
  tone,
  active,
  onClick,
}: {
  icon?: React.ReactNode
  label: string
  hint?: string
  value: string
  percent: number
  tone: 'red' | 'cyan'
  active: boolean
  onClick: () => void
}) {
  const bar = clsx('h-1 rounded-full', tone === 'red' ? 'bg-accent' : 'bg-accent2')
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={clsx(
        'flex w-full flex-col gap-1 border-b border-border/60 px-2.5 py-1.5 text-left transition-colors last:border-0',
        active ? 'bg-accent/10' : 'hover:bg-surface2/60',
      )}
      title={hint}
    >
      <span className="flex w-full items-center gap-2">
        {icon}
        <span className={clsx('min-w-0 flex-1 truncate text-xs', active ? 'text-text' : 'text-muted')}>
          {label}
        </span>
        <span className="mono text-xs text-text">{value}</span>
        <span className="mono w-11 text-right text-2xs text-faint">{percent.toFixed(1)}%</span>
      </span>
      <span className="h-1 w-full overflow-hidden rounded-full bg-surface2">
        <span className={bar} style={{ width: Math.max(2, Math.min(100, percent)) + '%', display: 'block', height: '100%' }} />
      </span>
    </button>
  )
}

/**
 * Destination intelligence: the ranking that goes with the map.
 *
 * Both tabs read data the Dashboard already fetched - the geography response the map
 * draws, and the summary's `top_ports` - so nothing is aggregated a second time and
 * nothing is invented. A row selects the same country the map's dots select, so the
 * existing destination panel opens exactly as it does from the map.
 */
export function DestinationSummary({
  geography,
  topPorts,
  selected,
  focused,
  onFocus,
}: DestinationSummaryProps) {
  const [tab, setTab] = useState<DestinationTab>('countries')

  /* Countries ranked by addresses - the same metric the map badge counts, so the two
     cannot describe different populations. */
  const countries = useMemo(() => {
    const rows = [...(geography?.countries ?? [])].sort(
      (left, right) => right.addresses - left.addresses || left.code.localeCompare(right.code),
    )
    const total = rows.reduce((sum, row) => sum + row.addresses, 0)
    return { rows, total }
  }, [geography])

  const ports = useMemo(() => {
    const rows = [...topPorts].sort((left, right) => right.packets - left.packets)
    const total = rows.reduce((sum, row) => sum + row.packets, 0)
    return { rows, total }
  }, [topPorts])

  const unknown = geography?.unknown
  const counts = geography?.counts
  const captureState = selected?.status === 'completed' ? 'Capture Ready' : selected ? 'Capture ' + selected.status : 'No Capture'
  const dotClass =
    selected?.status === 'completed'
      ? 'bg-ok'
      : selected?.status === 'pending' || selected?.status === 'processing'
        ? 'bg-warn'
        : 'bg-faint'

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-md border border-border bg-surface">
      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border px-2 pt-1">
        {(['countries', 'ports'] as const).map((value) => {
          const active = tab === value
          return (
            <button
              key={value}
              type="button"
              onClick={() => setTab(value)}
              aria-current={active ? 'page' : undefined}
              className={clsx(
                '-mb-px border-b-2 px-2 py-1.5 text-2xs font-semibold uppercase tracking-wider transition-colors',
                active ? 'border-accent text-text' : 'border-transparent text-muted hover:text-text',
              )}
            >
              {value === 'countries' ? 'Top countries' : 'Top ports'}
            </button>
          )
        })}
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {tab === 'countries' ? (
          countries.rows.length === 0 ? (
            <p className="px-3 py-4 text-2xs leading-relaxed text-faint">
              No country in the dataset matches an address in this capture. Private addresses have no
              country by definition, and an unplaced public address is counted under “not placed”.
            </p>
          ) : (
            <>
              {countries.rows.map((country) => {
                /* The flag comes from the same resolver the host and credential tables use:
                   a code the build has no flag for draws a small code chip instead, never a
                   neighbour's flag and never a guessed placeholder. */
                const flag = flagUrl(country.code)
                return (
                  <RankRow
                    key={country.code}
                    icon={
                      flag !== null ? (
                        <img
                          src={flag}
                          alt=""
                          aria-hidden
                          data-country={country.code}
                          className="host-flag shrink-0"
                        />
                      ) : (
                        <span className="mono w-4 shrink-0 text-center text-2xs text-faint" aria-hidden>
                          {country.code === 'ZZ' ? '—' : country.code.slice(0, 2)}
                        </span>
                      )
                    }
                    label={country.name ?? countryName(country.code)}
                    hint={
                      country.code +
                      ' · ' +
                      formatNumber(country.addresses) +
                      ' address(es) · ' +
                      formatNumber(country.packets) +
                      ' packet(s) · ' +
                      formatBytes(country.bytes)
                    }
                    value={formatNumber(country.addresses)}
                    percent={countries.total === 0 ? 0 : (100 * country.addresses) / countries.total}
                    tone="red"
                    active={focused === country.code}
                    onClick={() => onFocus(focused === country.code ? null : country.code)}
                  />
                )
              })}
              {unknown !== undefined && unknown.addresses > 0 ? (
                <div className="flex items-center justify-between border-t border-border/60 px-2.5 py-1.5 text-2xs text-faint">
                  <span>not placed</span>
                  <span className="mono">{formatNumber(unknown.addresses)}</span>
                </div>
              ) : null}
              {counts?.countries_truncated === true ? (
                <p className="px-2.5 py-1.5 text-2xs text-warn">
                  The API capped the country list; the ones beyond it are not ranked here.
                </p>
              ) : null}
            </>
          )
        ) : ports.rows.length === 0 ? (
          <p className="px-3 py-4 text-2xs leading-relaxed text-faint">
            No destination port ranked for this capture.
          </p>
        ) : (
          ports.rows.map((port) => (
            <RankRow
              key={port.port + '/' + port.protocol}
              label={String(port.port) + (port.service ? ' · ' + port.service : '')}
              hint={
                port.protocol +
                ' · ' +
                formatNumber(port.packets) +
                ' packet(s)' +
                (port.bytes !== undefined ? ' · ' + formatBytes(port.bytes) : '')
              }
              value={formatNumber(port.packets)}
              percent={ports.total === 0 ? 0 : (100 * port.packets) / ports.total}
              tone="cyan"
              active={false}
              onClick={() => undefined}
            />
          ))
        )}
      </div>

      {/* Capture status + the one decorative element of the section. */}
      <div className="flex items-center gap-2 border-t border-border px-2.5 py-2">
        <span className={clsx('h-1.5 w-1.5 shrink-0 rounded-full', dotClass)} aria-hidden />
        <span className="text-2xs text-muted">{captureState}</span>
        <span className="mono truncate text-2xs text-faint" title={selected?.original_filename ?? undefined}>
          {selected?.original_filename ?? 'no capture'}
        </span>
        <span className="mono ml-auto shrink-0 text-2xs text-text">
          {formatNumber(selected?.packet_count ?? 0)} pkts
        </span>
        <img src={ninjaMark} alt="" aria-hidden className="h-8 w-auto shrink-0 opacity-80" />
      </div>
    </div>
  )
}

export default DestinationSummary
