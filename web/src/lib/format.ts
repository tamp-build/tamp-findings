import i18n from '@/i18n'

// Locale-aware formatting.
//
// The codebase currently reaches for `toFixed(1)` in ~20 places. That is not a
// formatting function — it is a US-English formatting function wearing a
// neutral name. It hardcodes "." as the decimal separator, which is wrong for
// most of Europe, and it never groups thousands. `Intl` does both correctly
// for whatever locale is active.
//
// Formatter construction is the expensive part of Intl, so instances are
// cached per (locale, options) and dropped when the language changes.

const cache = new Map<string, Intl.NumberFormat | Intl.DateTimeFormat | Intl.RelativeTimeFormat>()

i18n.on('languageChanged', () => cache.clear())

function activeLocale(): string {
  // Intl wants a BCP-47 tag. The pseudo-locale (en-XA) is a valid private-use
  // tag, and Intl resolves it to English formatting — which is what we want:
  // the pseudo-locale tests STRING handling, not number handling.
  return i18n.language || 'en'
}

function cached<T>(kind: string, key: string, build: () => T): T {
  const id = `${kind}|${activeLocale()}|${key}`
  const hit = cache.get(id)
  if (hit) return hit as T
  const made = build()
  cache.set(id, made as never)
  return made
}

/** Plain number, grouped per locale. */
export function formatNumber(value: number, opts: Intl.NumberFormatOptions = {}): string {
  return cached('num', JSON.stringify(opts), () => new Intl.NumberFormat(activeLocale(), opts))
    .format(value)
}

/**
 * A score or coverage figure already expressed on a 0–100 scale.
 * Note this is NOT `style: 'percent'` — that would multiply by 100 again.
 */
export function formatPercent(value: number, fractionDigits = 1): string {
  const n = cached('num', `pct${fractionDigits}`, () =>
    new Intl.NumberFormat(activeLocale(), {
      minimumFractionDigits: fractionDigits,
      maximumFractionDigits: fractionDigits,
    })).format(value)
  return `${n}%`
}

/** A ratio in 0–1 rendered as a percentage. */
export function formatRatio(value: number, fractionDigits = 1): string {
  return cached('num', `ratio${fractionDigits}`, () =>
    new Intl.NumberFormat(activeLocale(), {
      style: 'percent',
      minimumFractionDigits: fractionDigits,
      maximumFractionDigits: fractionDigits,
    })).format(value)
}

/** Byte counts, for SBOM and artifact sizes. */
export function formatBytes(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB', 'TB']
  let v = bytes
  let u = 0
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++ }
  return `${formatNumber(v, { maximumFractionDigits: u === 0 ? 0 : 1 })} ${units[u]}`
}

const DATE_STYLES: Record<'short' | 'medium' | 'long', Intl.DateTimeFormatOptions> = {
  short: { year: 'numeric', month: 'numeric', day: 'numeric' },
  medium: { year: 'numeric', month: 'short', day: 'numeric' },
  long: { year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' },
}

export function formatDate(value: string | Date | null | undefined, style: keyof typeof DATE_STYLES = 'medium'): string {
  if (!value) return '—'
  const d = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(d.getTime())) return '—'
  return cached('date', style, () => new Intl.DateTimeFormat(activeLocale(), DATE_STYLES[style])).format(d)
}

const RELATIVE_STEPS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 31_536_000_000],
  ['month', 2_592_000_000],
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
]

/**
 * "3 days ago" / "in 2 months". Used for finding age and POA&M due dates,
 * where the distance matters more than the calendar date.
 */
export function formatRelative(value: string | Date | null | undefined): string {
  if (!value) return '—'
  const d = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(d.getTime())) return '—'

  const diff = d.getTime() - Date.now()
  const abs = Math.abs(diff)
  const fmt = cached('rel', 'auto', () =>
    new Intl.RelativeTimeFormat(activeLocale(), { numeric: 'auto' }))

  for (const [unit, ms] of RELATIVE_STEPS) {
    if (abs >= ms) return fmt.format(Math.round(diff / ms), unit)
  }
  return fmt.format(0, 'minute')
}
