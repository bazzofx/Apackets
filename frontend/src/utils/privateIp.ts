/**
 * Is this address one of "ours" rather than something out on the internet?
 *
 * A short list of internal CIDR blocks and a range check — that is the whole
 * rule. It decides one thing: whether the host inventory draws the local-machine
 * icon (`pc.png`) instead of a country flag. The backend classifies addresses
 * properly (`host_analyzer.address_scope`, sent as `scope`); this is the display
 * rule, kept here so the icon logic is one small readable function.
 */

/** Base address and prefix length, as numbers. */
const BLOCKS: Array<[string, number]> = [
  ['10.0.0.0', 8], // RFC 1918
  ['172.16.0.0', 12], // RFC 1918
  ['192.168.0.0', 16], // RFC 1918
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local
  ['100.64.0.0', 10], // RFC 6598 carrier-grade NAT
  ['0.0.0.0', 8], // "this network"
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, including 255.255.255.255
]

/** "a.b.c.d" as one 32-bit number, or null. */
function toInt(address: string): number | null {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value
}

const RANGES = BLOCKS.map(([base, bits]) => {
  const start = toInt(base)
  if (start === null) throw new Error(`privateIp: bad base address ${base}`)
  // 2 ** 32 - 2 ** (32 - bits), without the shift operators' 32-bit wrap.
  const size = 2 ** (32 - bits)
  return { start, end: start + size - 1 }
})

/**
 * True when the address is not a public internet address.
 *
 * IPv4 is matched against the blocks above. IPv6 is matched by its well-known
 * prefixes: `::1` loopback, `fc00::/7` unique-local, `fe80::/10` link-local —
 * and an IPv4-mapped address (`::ffff:192.168.1.1`) is unwrapped first, the same
 * reading the rest of the application gives it.
 */
export function isLocalAddress(ip: string | null | undefined): boolean {
  if (ip === null || ip === undefined) return false
  const value = ip.trim().toLowerCase()
  if (value === '') return false

  if (value.startsWith('::ffff:') && value.includes('.')) return isLocalAddress(value.slice(7))

  if (value.includes(':')) {
    if (value === '::1' || value === '0:0:0:0:0:0:0:1') return true
    const first = Number.parseInt(value.split(':')[0] || '0', 16)
    if (Number.isFinite(first)) {
      if ((first & 0xfe00) === 0xfc00) return true // fc00::/7
      if ((first & 0xffc0) === 0xfe80) return true // fe80::/10
    }
    return false
  }

  const numeric = toInt(value)
  if (numeric === null) return false
  return RANGES.some((range) => numeric >= range.start && numeric <= range.end)
}
