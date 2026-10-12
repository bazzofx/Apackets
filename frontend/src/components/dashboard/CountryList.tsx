import clsx from 'clsx'
import { Globe2, HelpCircle, Network } from 'lucide-react'
import { countryName } from '@/theme/worldMap'
import { formatBytes, formatNumber } from '@/utils/format'
import type { GeographyResponse } from '@/types'

/**
 * The countries the capture talked to, under the map (docs/GEOGRAPHY.md §6).
 *
 * This list is why the map can be one dot per country: every address behind a dot is here,
 * grouped under its country with the volume it moved, so no reader has to guess which
 * addresses a country stands for. Addresses are buttons — the same host page the map and the
 * conversation graph open — and the row a reader is focused on is highlighted both here and
 * on the map, because the two are one selection.
 *
 * The two buckets that are not countries are listed too, and never mixed into a country's
 * totals: the capture's own side (which has no location) and the addresses the dataset could
 * not place. An unknown address is a result, not a rounding error.
 */

export interface CountryListProps {
  data: GeographyResponse
  focused: string | null
  onFocus: (code: string | null) => void
  onSelectIp: (ip: string) => void
}

/** One address chip. Buttons, not links, so the page decides where a host opens. */
function IpChips({
  ips,
  total,
  truncated,
  onSelectIp,
}: {
  ips: string[]
  total: number
  truncated: boolean
  onSelectIp: (ip: string) => void
}) {
  const shown = ips.slice(0, 8)
  const hidden = Math.max(0, total - shown.length)
  return (
    <span className="flex flex-wrap items-center gap-1">
      {shown.map((ip) => (
        <button
          key={ip}
          type="button"
          className="chip border-border2 bg-surface2 text-muted hover:border-accent hover:text-text"
          onClick={() => onSelectIp(ip)}
          title={`Open ${ip}`}
        >
          {ip}
        </button>
      ))}
      {hidden > 0 ? (
        <span
          className="text-2xs text-faint"
          title={
            truncated
              ? `The API returned the first ${formatNumber(ips.length)} of this country's addresses.`
              : undefined
          }
        >
          +{formatNumber(hidden)} more
        </span>
      ) : null}
    </span>
  )
}

export function CountryList({ data, focused, onFocus, onSelectIp }: CountryListProps) {
  const countries = data.countries ?? []
  const { unknown, origin, counts } = data

  return (
    <div className="flex flex-col" data-country-list>
      {/* The capture's own side, first: it is what every arc leaves from. */}
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-border px-2.5 py-2">
        <span className="flex items-center gap-1.5 text-xs font-medium text-text">
          <Network size={12} className="text-accent2" aria-hidden />
          {origin.label}
        </span>
        <span className="text-2xs text-muted">
          {formatNumber(origin.addresses)} address(es) · {formatBytes(origin.bytes)} ·{' '}
          {formatNumber(origin.packets)} packet(s)
        </span>
        <span className="ml-auto text-2xs text-faint" title="These addresses are private, loopback, link-local or multicast: they carry no country and are never drawn on the map.">
          not placed on the map — a private address has no country
        </span>
      </div>

      {countries.length === 0 ? (
        <p className="px-2.5 py-3 text-2xs leading-relaxed text-muted">
          {data.dataset?.available === false
            ? 'No country can be shown until the location dataset is built. The addresses are still counted above; nothing has been guessed.'
            : 'The dataset placed no address in this capture in a country. Every public address was either unknown to it or is listed below.'}
        </p>
      ) : (
        <ul className="flex flex-col">
          {countries.map((country) => {
            const isFocused = focused === country.code
            return (
              <li
                key={country.code}
                data-country-row={country.code}
                className={clsx(
                  'flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border/50 px-2.5 py-1.5 last:border-0',
                  isFocused ? 'bg-accent/10' : 'hover:bg-surface2/60',
                )}
              >
                <button
                  type="button"
                  className="flex min-w-0 items-baseline gap-2 text-left"
                  onClick={() => onFocus(isFocused ? null : country.code)}
                  title={`Highlight ${countryName(country.code)} on the map`}
                >
                  <span className="chip border-border2 bg-surface2 text-text">{country.code}</span>
                  <span className="truncate text-xs text-text">
                    {country.name ?? countryName(country.code)}
                  </span>
                </button>
                <span className="text-2xs text-muted">
                  {formatNumber(country.addresses)} address(es)
                </span>
                <span className="mono text-2xs text-muted">{formatBytes(country.bytes)}</span>
                <span className="hidden text-2xs text-faint sm:inline">
                  {formatNumber(country.packets)} packet(s)
                </span>
                <span className="ml-auto min-w-0">
                  <IpChips
                    ips={country.ips}
                    total={country.addresses}
                    truncated={country.ips_truncated}
                    onSelectIp={onSelectIp}
                  />
                </span>
              </li>
            )
          })}
        </ul>
      )}

      {/* The unknown bucket, and the count of countries beyond the cap, kept separate. */}
      {unknown.addresses > 0 ? (
        <div
          className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border px-2.5 py-2"
          data-country-unknown
        >
          <span className="flex items-center gap-1.5 text-xs text-muted">
            <HelpCircle size={12} className="text-faint" aria-hidden />
            No country in the dataset
          </span>
          <span className="text-2xs text-muted">
            {formatNumber(unknown.addresses)} address(es) · {formatBytes(unknown.bytes)}
          </span>
          <span className="ml-auto min-w-0">
            <IpChips
              ips={unknown.ips}
              total={unknown.addresses}
              truncated={unknown.ips_truncated}
              onSelectIp={onSelectIp}
            />
          </span>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2.5 py-1.5 text-2xs text-faint">
        <Globe2 size={11} aria-hidden />
        <span>
          {formatNumber(counts.countries)} of {formatNumber(counts.located)} located address(es) fall in a
          country
          {counts.countries_truncated === true
            ? " — the API's country cap cut this list, so the countries beyond it are not shown"
            : ''}
          .
        </span>
        <span className="ml-auto" title={data.note}>
          a country is where the address block is registered, not where the host is
        </span>
      </div>
    </div>
  )
}

export default CountryList
