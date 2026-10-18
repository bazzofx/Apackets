import { Fragment, createContext, useContext, useMemo, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import AddressFlag from '@/components/AddressFlag'
import { geoApi } from '@/services/api'
import { isIpv4 } from '@/utils/privateIp'

/**
 * Flags beside the addresses the Threat Map prints.
 *
 * A detection's visuals carry addresses as *text* - `3.254.239.146 (115 pkt)`,
 * `192.168.8.178:22 (SSH)`, `176.255.246.112 \u2194 192.168.8.229` - so there is no field to
 * hang a country on. The country is read from an endpoint that already exists and that the
 * Dashboard already uses: `/geography` lists each country with the addresses it holds, and
 * that is what this provider turns into an address -> code map. No new request is invented
 * and no country is guessed: an address the map does not list gets the local-machine icon if
 * it is private, and nothing at all if it is public and simply outside the listed set.
 *
 * The flag itself is `AddressFlag`, the same component the host inventory and the credentials
 * page use, so it draws the same 1.3rem box the Dashboard's map does. Every flag is
 * `alt=""` and decorative: the address is printed beside it, so nothing is conveyed by the
 * image alone.
 */

const IpCountryContext = createContext<Map<string, string> | null>(null)

export interface IpCountryProviderProps {
  analysisId: string | null
  children: ReactNode
}

/**
 * Reads the geography response once and publishes an address -> country map.
 *
 * The query key is the Dashboard's own (`['geography', analysisId]`), so visiting both
 * sections costs one request, not two. While it is in flight - or when the dataset is not
 * installed, in which case every country bucket is empty - the map is empty and the
 * addresses are drawn without flags rather than with wrong ones.
 */
export function IpCountryProvider({ analysisId, children }: IpCountryProviderProps) {
  const query = useQuery({
    queryKey: ['geography', analysisId],
    queryFn: () => geoApi.geography(analysisId as string),
    enabled: Boolean(analysisId),
    staleTime: 60_000,
  })

  const lookup = useMemo(() => {
    const map = new Map<string, string>()
    for (const country of query.data?.countries ?? []) {
      for (const ip of country.ips ?? []) map.set(ip, country.code)
    }
    return map
  }, [query.data])

  return <IpCountryContext.Provider value={lookup}>{children}</IpCountryContext.Provider>
}

/** The address -> country map, or null when no provider is above this component. */
export function useIpCountries(): Map<string, string> | null {
  return useContext(IpCountryContext)
}

/** One piece of a label: either plain text or an address that gets a flag. */
interface LabelPart {
  ip: string | null
  text: string
}

/** Dotted quads only: a dotted decimal that is not a valid address is left as text. */
const ADDRESS_PATTERN = /(?:\d{1,3}\.){3}\d{1,3}/g

/**
 * Split a label into text runs and the addresses inside it.
 *
 * The match is validated (`isIpv4`) before it is treated as an address, so `1.2.3.999` or a
 * version number stays text. Ports and suffixes are left in the text run beside the address,
 * which is what keeps `192.168.8.178:22 (SSH)` reading as it was written.
 */
export function splitAddresses(label: string): LabelPart[] {
  const parts: LabelPart[] = []
  let cursor = 0
  for (const match of label.matchAll(ADDRESS_PATTERN)) {
    const start = match.index ?? 0
    const value = match[0]
    if (!isIpv4(value)) continue
    if (start > cursor) parts.push({ ip: null, text: label.slice(cursor, start) })
    parts.push({ ip: value, text: value })
    cursor = start + value.length
  }
  if (cursor < label.length) parts.push({ ip: null, text: label.slice(cursor) })
  return parts
}

export interface IpLabelProps {
  /** The label exactly as the backend wrote it. */
  text: string
}

/**
 * A label with a flag before every address in it.
 *
 * Nothing about the text changes - the same characters in the same order - so a label can
 * be flagged without altering what it says. A label with no address in it renders as one
 * text node and costs one regex.
 */
export function IpLabel({ text }: IpLabelProps) {
  const countries = useIpCountries()
  const parts = useMemo(() => splitAddresses(text), [text])

  if (!parts.some((part) => part.ip !== null)) return <>{text}</>

  return (
    <>
      {parts.map((part, index) =>
        part.ip === null ? (
          <Fragment key={`text-${String(index)}`}>{part.text}</Fragment>
        ) : (
          <span key={`ip-${String(index)}-${part.ip}`} className="ip-label">
            <AddressFlag ip={part.ip} country={countries?.get(part.ip) ?? null} />
            <span className="mono">{part.ip}</span>
          </span>
        ),
      )}
    </>
  )
}

export default IpLabel