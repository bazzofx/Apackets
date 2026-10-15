import { flagUrl, LOCAL_ICON_URL } from '@/theme/countryFlags'
import { countryName } from '@/theme/worldMap'
import { isLocalAddress } from '@/utils/privateIp'

export interface AddressFlagProps {
  /** The address the icon is drawn for; decides the local-machine icon. */
  ip: string
  /**
   * The address's registered country, when the caller knows one. A caller that does not
   * (the credentials page reads no country for a row) passes nothing and gets no flag
   * rather than a guess — `flagUrl()` returns null for an unknown code by design.
   */
  country?: string | null
}

/**
 * The icon before an address: the local-machine icon when the address is one of ours,
 * otherwise the country's flag, otherwise nothing.
 *
 * The rule is a CIDR check (`utils/privateIp.ts`) — an address in an internal block is
 * local and gets `pc.png`; no flag is drawn for it either way, because a private address
 * has no country. Everything is decorative (`alt=""`) with a tooltip that carries the fact
 * in words, so the mark is never the only statement of it.
 *
 * Extracted from `components/hosts/HostsTable.tsx`, which had this as a private component
 * and needed it in one place; the Users & Passwords page draws it beside an endpoint too,
 * so it lives here rather than being copied. The stylesheet classes keep their original
 * names (`.host-flag`, `.host-flag-local` in `index.css`), because they size a flag and the
 * box they draw is the same box wherever an address is listed.
 */
export function AddressFlag({ ip, country }: AddressFlagProps) {
  const local = isLocalAddress(ip)
  const url = local ? LOCAL_ICON_URL : flagUrl(country)
  if (url === null) return null

  if (local) {
    return (
      <img
        src={url}
        alt=""
        width={16}
        height={11}
        loading="lazy"
        className="host-flag host-flag-local"
        title={`${ip} is a local address — private, loopback, link-local or reserved, so no country applies`}
        data-country="local"
      />
    )
  }

  const code = String(country ?? '').trim().toUpperCase()
  return (
    <img
      src={url}
      alt=""
      width={16}
      height={11}
      loading="lazy"
      className="host-flag"
      title={`${countryName(code)} (${code}) — where this address block is registered, not necessarily where the host is`}
      data-country={code}
    />
  )
}

export default AddressFlag
