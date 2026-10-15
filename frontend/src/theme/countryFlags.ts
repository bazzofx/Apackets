/**
 * Country flags, by ISO 3166-1 alpha-2 code.
 *
 * The images live in `src/country-flags/` as `.ico` files. Most are named after
 * the code (`us.ico`), a few after the country (`kosovo.ico`, `uk.ico`,
 * `sint_maarten.ico`), and one is named `by_.ico`. Rather than hand-writing which
 * is which, both sides are compared **by name**:
 *
 * * every file name is normalised — lower-case, accents folded, anything that is
 *   not a letter or digit becomes `_`, repeats collapsed — so `sint_maarten`
 *   matches "Sint Maarten", `curacao` matches "Curaçao", and `by_` matches `BY`;
 * * a code is looked up first as itself, then through any name the
 *   `mledoze/countries` dataset records for it (common name, official name, CIOC
 *   code, alt spellings), which is what finds `uk.ico` for `GB` — "UK" is one of
 *   the United Kingdom's own alt spellings;
 * * a file whose name matches no country name is never used. Nothing here looks
 *   at the picture: a flag is chosen because a name says so.
 *
 * The four codes that need a name other than their own are generated into
 * `countryFlags.generated.ts` by `.tmp/ui-flags/build_flag_names.py`.
 *
 * Nothing is invented for a code with no flag: `flagUrl()` returns `null` and the
 * caller draws no image — a missing flag is a missing flag, not the flag of a
 * neighbour and not a placeholder that would read as one. Codes the GeoIP dataset
 * can report and this build cannot draw are listed in
 * `Documentation/Hosts.md` §2.3.
 */

import { COUNTRY_FLAG_FILES } from '@/theme/countryFlags.generated'

const modules = import.meta.glob(
  ['../country-flags/*.ico', '../country-flags/*.png'],
  { eager: true, query: '?url', import: 'default' },
) as Record<string, string>

/** The one spelling used on both sides of the comparison. */
export function flagKey(value: string): string {
  return value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
}

/** Normalised file name → the URL Vite resolved for that file. */
export const FLAG_URLS: Record<string, string> = Object.fromEntries(
  Object.entries(modules).map(([path, url]) => {
    const stem = (path.split('/').pop() ?? '').replace(/\.(ico|png)$/i, '')
    return [flagKey(stem), url]
  }),
)

/** The flag for a country code, or `null` when no flag file is named for it. */
export function flagUrl(code: string | null | undefined): string | null {
  if (code === null || code === undefined) return null
  const key = code.trim().toLowerCase()
  if (key === '' || key === 'zz') return null
  for (const candidate of [key, COUNTRY_FLAG_FILES[code.trim().toUpperCase()] ?? '']) {
    if (candidate === '') continue
    const url = FLAG_URLS[flagKey(candidate)]
    if (url !== undefined) return url
  }
  return null
}

/** How many flags this build carries — used by the documentation checks. */
export const FLAG_COUNT = Object.keys(FLAG_URLS).length

/**
 * The local-machine icon (`pc.png`), drawn for addresses that are not public.
 *
 * It lives in the flag directory, and its file name is `pc`, so it would never be
 * reached by a country code — it is addressed by name here, once, and the caller
 * decides *when* an address is local (see `utils/privateIp.ts`).
 */
export const LOCAL_ICON_URL: string | null = FLAG_URLS[flagKey('pc')] ?? null
