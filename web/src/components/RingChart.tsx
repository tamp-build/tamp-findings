import type { ScannerDetail, SbomHealthCounts, SecretsHealthCounts, LicenseTierCounts, SeverityCounts } from '@/lib/api'
import { cn } from '@/lib/utils'

// Three concentric segmented donuts driving the Overview tab. Moving
// inward = closer to "exploitable right now":
//
//   Outer  — Code Quality   (OpenGrep / Roslyn while TAM-262 blocked).
//             Severity buckets (Critical…Info) + lifecycle (Closed,
//             Suppressed, Accepted).
//   Middle — SBOM dep health (F6.3 / F6.4). Vulnerable / Outdated /
//             Current; Outdated requires registry enrichment, which
//             runs as part of every Ingest.
//   Inner  — Secrets. TruffleHog open findings: Critical = Verified
//             (live credential), High = Unverified (pattern match).
//
// Each ring is clickable and emits a click event the OverviewView turns
// into a cross-tab nav to a filtered list. Tables to the right mirror
// the same color language and same click-through.
//
// As we onboard more tamp scanners the catalog of rings will grow.
// Centralising the geometry + buckets here keeps the visual coherent
// even as the data widens.

const SAST_PREFERENCE = ['OpenGrep', 'Roslyn', 'CodeQL'] as const

const SEGMENT_COLORS = {
  critical:   '#dc2626',  high:       '#f97316',  medium:     '#f59e0b',
  low:        '#facc15',  info:       '#38bdf8',  closed:     '#22c55e',
  suppressed: '#a3a3a3',  accepted:   '#737373',
} as const
const SEGMENT_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'closed', 'suppressed', 'accepted'] as const
type SegKey = (typeof SEGMENT_ORDER)[number]
const SEGMENT_LABELS: Record<SegKey, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  info: 'Info', closed: 'Closed', suppressed: 'Suppressed', accepted: 'Accepted',
}

const SBOM_COLORS = {
  vulnerable: '#dc2626', outdated: '#f59e0b', current: '#22c55e',
} as const
const SBOM_ORDER = ['vulnerable', 'outdated', 'current'] as const
type SbomKey = (typeof SBOM_ORDER)[number]
const SBOM_LABELS: Record<SbomKey, string> = {
  vulnerable: 'Vulnerable', outdated: 'Outdated', current: 'Current',
}

const SECRETS_COLORS = {
  verified:   '#dc2626',  // red — credential is live
  unverified: '#f59e0b',  // amber — pattern hit, didn't verify
  clean:      '#22c55e',  // green — fills the ring when nothing leaked
} as const
const SECRETS_ORDER = ['verified', 'unverified'] as const
type SecretsKey = (typeof SECRETS_ORDER)[number]
const SECRETS_LABELS: Record<SecretsKey, string> = {
  verified: 'Verified', unverified: 'Unverified',
}

// License ring: green gradient that darkens with restrictiveness, red
// for explicitly denied (AGPL/SSPL family), neutral for unknown.
const LICENSE_COLORS = {
  permissive:     '#86efac',  // green-300 — MIT, Apache-2.0, BSD, ISC…
  weakCopyleft:   '#22c55e',  // green-500 — MPL, LGPL-2.1, EPL
  strongCopyleft: '#15803d',  // green-700 — GPL-2.0, LGPL-3.0
  denied:         '#b91c1c',  // red-700  — GPL-3.0, AGPL, SSPL
  unknown:        '#9ca3af',  // gray-400 — couldn't categorize
} as const
const LICENSE_ORDER = ['permissive', 'weakCopyleft', 'strongCopyleft', 'denied', 'unknown'] as const
type LicenseKey = (typeof LICENSE_ORDER)[number]

// IaC bullseye — same severity palette as the outer Code Quality ring.
// Grey ("unscanned") fill takes over when the API says no Trivy signal
// has ever landed in scope; that's the user's explicit "no containers/
// IaC" affordance — not the same as "scanned clean".
const IAC_COLORS = {
  critical: '#dc2626', high: '#f97316', medium: '#f59e0b',
  low: '#facc15',     info: '#38bdf8',
  unscanned: '#9ca3af',  // gray-400
  clean:     '#22c55e',  // green-500
} as const
const IAC_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
type IacSevKey = (typeof IAC_SEVERITY_ORDER)[number]
const IAC_SEVERITY_LABELS: Record<IacSevKey, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}

// ----- shared helpers ----------------------------------------------------

function pickPrimaryScanner(details: ScannerDetail[]): ScannerDetail | null {
  for (const preferred of SAST_PREFERENCE) {
    const hit = details.find(d => d.scanner === preferred)
    if (hit && totalOf(hit) > 0) return hit
  }
  return details.find(d => totalOf(d) > 0) ?? details[0] ?? null
}
function totalOf(d: ScannerDetail): number {
  return d.open.total + d.closed + d.suppressed + d.accepted
}
function countFor(d: ScannerDetail, k: SegKey): number {
  switch (k) {
    case 'closed':     return d.closed
    case 'suppressed': return d.suppressed
    case 'accepted':   return d.accepted
    default:           return d.open[k] as number
  }
}

// ----- geometry ----------------------------------------------------------

const SIZE = 380
const RINGS = {
  outer:    { radius: 158, width: 22 },
  upper:    { radius: 124, width: 20 },
  middle:   { radius: 92,  width: 18 },
  lower:    { radius: 62,  width: 16 },
  inner:    { radius: 34,  width: 14 },
} as const
type RingSlot = keyof typeof RINGS

type Arc = { key: string; color: string; dashArray: string; dashOffset: number }
function buildArcs(
  buckets: Array<{ key: string; count: number; color: string }>,
  total: number,
  radius: number,
): Arc[] {
  if (total === 0) return []
  const circumference = 2 * Math.PI * radius
  let offset = 0
  const arcs: Arc[] = []
  for (const seg of buckets) {
    if (seg.count <= 0) continue
    const segLen = (seg.count / total) * circumference
    arcs.push({
      key: seg.key,
      color: seg.color,
      dashArray: `${segLen} ${circumference - segLen}`,
      dashOffset: -offset,
    })
    offset += segLen
  }
  return arcs
}

function ConcentricRing({
  slot, arcs, cleanFill, onClick, ariaLabel,
}: {
  slot: RingSlot
  arcs: Arc[]
  // When arcs is empty AND cleanFill is set, draw a full ring in that
  // color (the "all clear" state for the secrets ring). When cleanFill
  // is undefined, draw the neutral gray track instead.
  cleanFill?: string
  onClick?: () => void
  ariaLabel?: string
}) {
  const { radius, width } = RINGS[slot]
  const cx = SIZE / 2
  const cy = SIZE / 2
  const interactive = !!onClick
  return (
    <>
      <circle
        cx={cx} cy={cy} r={radius}
        fill="none"
        stroke={arcs.length === 0 && cleanFill ? cleanFill : 'rgb(229 231 235)'}
        strokeWidth={width}
        opacity={arcs.length === 0 ? 1 : 0.2}
      />
      {interactive && (
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="transparent"
          strokeWidth={width}
          style={{ cursor: 'pointer' }}
          onClick={onClick}
          tabIndex={0}
          role="button"
          aria-label={ariaLabel}
        />
      )}
      <g transform={`rotate(-90 ${cx} ${cy})`} style={{ pointerEvents: 'none' }}>
        {arcs.map(seg => (
          <circle
            key={`${slot}-${seg.key}`}
            cx={cx} cy={cy} r={radius}
            fill="none"
            stroke={seg.color}
            strokeWidth={width}
            strokeDasharray={seg.dashArray}
            strokeDashoffset={seg.dashOffset}
            strokeLinecap="butt"
          />
        ))}
      </g>
    </>
  )
}

// ----- main chart --------------------------------------------------------

export function RingChart({
  scannerDetails,
  sbomHealth,
  secretsHealth,
  licenseTiers,
  iac,
  onScannerClick,
  onSbomClick,
  onSecretsClick,
  onLicenseClick,
  onIacClick,
}: {
  scannerDetails: ScannerDetail[]
  sbomHealth?: SbomHealthCounts
  secretsHealth?: SecretsHealthCounts
  licenseTiers?: LicenseTierCounts
  iac?: { counts: SeverityCounts; scanned: boolean }
  onScannerClick?: (scanner: string) => void
  onSbomClick?: () => void
  onSecretsClick?: () => void
  onLicenseClick?: () => void
  onIacClick?: () => void
}) {
  const primary = pickPrimaryScanner(scannerDetails)
  const outerTotal = primary ? totalOf(primary) : 0
  const outerArcs = buildArcs(
    SEGMENT_ORDER.map(k => ({ key: k, count: primary ? countFor(primary, k) : 0, color: SEGMENT_COLORS[k] })),
    outerTotal,
    RINGS.outer.radius,
  )

  const sbomTotal = sbomHealth ? sbomHealth.current + sbomHealth.outdated + sbomHealth.vulnerable : 0
  const sbomArcs = sbomHealth
    ? buildArcs(SBOM_ORDER.map(k => ({ key: k, count: sbomHealth[k], color: SBOM_COLORS[k] })), sbomTotal, RINGS.upper.radius)
    : []

  const secretsTotal = secretsHealth ? secretsHealth.verified + secretsHealth.unverified : 0
  const secretsArcs = secretsHealth
    ? buildArcs(SECRETS_ORDER.map(k => ({ key: k, count: secretsHealth[k], color: SECRETS_COLORS[k] })), secretsTotal, RINGS.lower.radius)
    : []
  const lowerCleanFill = secretsHealth && secretsTotal === 0 ? SECRETS_COLORS.clean : undefined

  const licenseTotal = licenseTiers
    ? licenseTiers.permissive + licenseTiers.weakCopyleft + licenseTiers.strongCopyleft + licenseTiers.denied + licenseTiers.unknown
    : 0
  const licenseArcs = licenseTiers
    ? buildArcs(
        LICENSE_ORDER.map(k => ({ key: k, count: licenseTiers[k], color: LICENSE_COLORS[k] })),
        licenseTotal,
        RINGS.lower.radius,
      )
    : []

  const iacTotal = iac
    ? iac.counts.critical + iac.counts.high + iac.counts.medium + iac.counts.low + iac.counts.info
    : 0
  // Three states for the bullseye:
  //   unscanned (no Trivy signal in scope)  → solid grey
  //   scanned + zero counts                 → solid green
  //   scanned + counts > 0                  → segmented arcs by severity
  const iacUnscanned = iac && !iac.scanned
  const iacCleanFill = iac && iac.scanned && iacTotal === 0 ? IAC_COLORS.clean
                     : iacUnscanned ? IAC_COLORS.unscanned
                     : undefined
  const iacArcs = iac && iac.scanned && iacTotal > 0
    ? buildArcs(
        IAC_SEVERITY_ORDER.map(k => ({ key: k, count: iac.counts[k], color: IAC_COLORS[k] })),
        iacTotal,
        RINGS.inner.radius,
      )
    : []

  return (
    <div className="flex flex-col items-center">
      <div className="text-center">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">Risk rings</p>
        <p className="text-base font-semibold">Code Quality · SBOM · Secrets · Licenses · IaC</p>
        {primary && primary.scanner !== 'OpenGrep' && (
          <p className="text-[11px] text-muted-foreground">
            outer via {primary.scanner} · OpenGrep pending TAM-262
          </p>
        )}
      </div>

      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="mt-2 w-full max-w-[340px]" role="img" aria-label="Risk rings: code quality, SBOM, secrets, licenses, IaC">
        <ConcentricRing
          slot="outer"
          arcs={outerArcs}
          onClick={onScannerClick && primary ? () => onScannerClick(primary.scanner) : undefined}
          ariaLabel={primary ? `Open ${primary.scanner} findings` : undefined}
        />
        <ConcentricRing
          slot="upper"
          arcs={sbomArcs}
          onClick={onSbomClick}
          ariaLabel="Browse SBOM components"
        />
        <ConcentricRing
          slot="middle"
          arcs={secretsArcs}
          cleanFill={lowerCleanFill}
          onClick={secretsHealth && secretsTotal > 0 ? onSecretsClick : undefined}
          ariaLabel={secretsTotal > 0 ? 'Open TruffleHog findings' : undefined}
        />
        <ConcentricRing
          slot="lower"
          arcs={licenseArcs}
          onClick={onLicenseClick && licenseTotal > 0 ? onLicenseClick : undefined}
          ariaLabel="Browse license breakdown"
        />
        <ConcentricRing
          slot="inner"
          arcs={iacArcs}
          cleanFill={iacCleanFill}
          onClick={onIacClick && iac?.scanned && iacTotal > 0 ? onIacClick : undefined}
          ariaLabel={iac?.scanned && iacTotal > 0 ? 'Open Trivy IaC findings' : undefined}
        />

        {/* Compact center text */}
        <text x={SIZE / 2} y={SIZE / 2 - 3} textAnchor="middle" fontSize="20" fontWeight="700" className="fill-foreground">
          {outerTotal}
        </text>
        <text x={SIZE / 2} y={SIZE / 2 + 11} textAnchor="middle" fontSize="8" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
          findings
        </text>
      </svg>

      <div className="mt-2 text-center text-[11px] text-muted-foreground">
        outer → findings · 2 → components · 3 → secrets · 4 → licenses · 5 → IaC
      </div>
    </div>
  )
}

// IaC table — same severity color language as the outer Code Quality
// table but smaller scope (Trivy only). When the scope is unscanned
// (no Trivy data at all), the table reads as a single neutral row
// instead of an "all green" row that would falsely imply a clean scan.
export function IacHealthTable({
  iac,
  onRowClick,
}: {
  iac?: { counts: SeverityCounts; scanned: boolean }
  onRowClick?: (severity: IacSevKey) => void
}) {
  if (!iac) return null
  const total = iac.counts.total
  const rows = IAC_SEVERITY_ORDER
    .map(k => ({ k, count: iac.counts[k] }))
    .filter(r => r.count > 0)

  return (
    <CompactTable title="IaC misconfig (Trivy)">
      {!iac.scanned && (
        <tr>
          <td colSpan={3} className="px-3 py-3 text-center text-xs">
            <span className="inline-flex items-center gap-1.5 text-muted-foreground">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: IAC_COLORS.unscanned }} />
              No IaC / container artifacts in scope
            </span>
          </td>
        </tr>
      )}
      {iac.scanned && rows.length === 0 && (
        <tr>
          <td colSpan={3} className="px-3 py-3 text-center text-xs">
            <span className="inline-flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: IAC_COLORS.clean }} />
              Scanned · no misconfig detected
            </span>
          </td>
        </tr>
      )}
      {iac.scanned && rows.map(({ k, count }) => (
        <Row
          key={k}
          color={IAC_COLORS[k]}
          label={IAC_SEVERITY_LABELS[k]}
          count={count}
          pct={total > 0 ? (count / total) * 100 : 0}
          onClick={onRowClick ? () => onRowClick(k) : undefined}
        />
      ))}
      {iac.scanned && total > 0 && <TotalRow total={total} />}
    </CompactTable>
  )
}

// ----- right-hand tables -------------------------------------------------

export function FindingsTypeTable({
  scannerDetails,
  onRowClick,
}: {
  scannerDetails: ScannerDetail[]
  onRowClick?: (segment: SegKey, scanner: string) => void
}) {
  const primary = pickPrimaryScanner(scannerDetails)
  const total = primary ? totalOf(primary) : 0
  const rows = SEGMENT_ORDER
    .map(k => ({ k, count: primary ? countFor(primary, k) : 0 }))
    .filter(r => r.count > 0)

  return (
    <CompactTable title="Code Quality types">
      {rows.length === 0 && <EmptyRow />}
      {rows.map(({ k, count }) => (
        <Row
          key={k}
          color={SEGMENT_COLORS[k]}
          label={SEGMENT_LABELS[k]}
          count={count}
          pct={total > 0 ? (count / total) * 100 : 0}
          onClick={primary && onRowClick ? () => onRowClick(k, primary.scanner) : undefined}
        />
      ))}
      <TotalRow total={total} />
    </CompactTable>
  )
}

export function SbomHealthTable({
  health,
  onRowClick,
}: {
  health?: SbomHealthCounts
  onRowClick?: (bucket: SbomKey) => void
}) {
  const total = health ? health.current + health.outdated + health.vulnerable : 0
  const rows = health
    ? SBOM_ORDER.map(k => ({ k, count: health[k] })).filter(r => r.count > 0)
    : []
  return (
    <CompactTable title="SBOM dep health">
      {rows.length === 0 && <EmptyRow />}
      {rows.map(({ k, count }) => (
        <Row
          key={k}
          color={SBOM_COLORS[k]}
          label={SBOM_LABELS[k]}
          count={count}
          pct={total > 0 ? (count / total) * 100 : 0}
          onClick={onRowClick ? () => onRowClick(k) : undefined}
        />
      ))}
      <TotalRow total={total} />
    </CompactTable>
  )
}

// License classifier mirroring the server's LicensePolicy.Classify — keeps
// each row's swatch color in lockstep with the tier it'd land in.
function tierForLicense(spdx: string): LicenseKey {
  const norm = spdx.trim()
  if (!norm || norm === '(unknown)') return 'unknown'
  // Exact SPDX-id matches — covers virtually every row on a normal repo.
  if (PERMISSIVE_IDS.has(norm)) return 'permissive'
  if (WEAK_IDS.has(norm)) return 'weakCopyleft'
  if (STRONG_IDS.has(norm)) return 'strongCopyleft'
  if (DENIED_IDS.has(norm)) return 'denied'
  // Composite expression: take loosest atom.
  const atoms = norm
    .replace(/[()]/g, ' ')
    .split(/\s+(?:OR|AND|WITH)\s+|,/i)
    .map(s => s.trim())
    .filter(Boolean)
  let best: LicenseKey | null = null
  const order: LicenseKey[] = ['permissive', 'weakCopyleft', 'strongCopyleft', 'denied']
  for (const a of atoms) {
    if (PERMISSIVE_IDS.has(a))     best = bestTier(best, 'permissive', order)
    else if (WEAK_IDS.has(a))      best = bestTier(best, 'weakCopyleft', order)
    else if (STRONG_IDS.has(a))    best = bestTier(best, 'strongCopyleft', order)
    else if (DENIED_IDS.has(a))    best = bestTier(best, 'denied', order)
  }
  return best ?? 'unknown'
}
function bestTier(cur: LicenseKey | null, candidate: LicenseKey, order: LicenseKey[]): LicenseKey {
  if (cur === null) return candidate
  return order.indexOf(candidate) < order.indexOf(cur) ? candidate : cur
}

// Mirror of LicensePolicy.cs — keep these in sync. Exhaustive enough
// for the SPDX ids that show up in mainstream OSS today.
const PERMISSIVE_IDS = new Set([
  'MIT', 'MIT-0', 'Apache-2.0',
  'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear',
  'ISC', '0BSD', 'Unlicense', 'CC0-1.0',
  'CC-BY-4.0', 'CC-BY-3.0', 'PostgreSQL', 'BlueOak-1.0.0',
  'Zlib', 'WTFPL', 'Python-2.0', 'MS-PL',
])
const WEAK_IDS = new Set([
  'MPL-2.0', 'MPL-1.1', 'EPL-1.0', 'EPL-2.0',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'CDDL-1.0', 'CDDL-1.1', 'MS-RL',
])
const STRONG_IDS = new Set([
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
])
const DENIED_IDS = new Set([
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'SSPL-1.0', 'Commons-Clause',
])

export function LicenseTable({
  byLicense,
  onRowClick,
  topN = 10,
}: {
  byLicense?: Record<string, number>
  onRowClick?: (license: string) => void
  topN?: number
}) {
  const entries = byLicense ? Object.entries(byLicense) : []
  const total = entries.reduce((s, [, v]) => s + v, 0)
  const sorted = entries.sort((a, b) => b[1] - a[1])
  const visible = sorted.slice(0, topN)
  const restCount = sorted.slice(topN).reduce((s, [, v]) => s + v, 0)
  const restLicenses = sorted.slice(topN).length

  return (
    <CompactTable title="Licenses (% of deps)">
      {visible.length === 0 && <EmptyRow />}
      {visible.map(([lic, count]) => {
        const tier = tierForLicense(lic)
        return (
          <Row
            key={lic}
            color={LICENSE_COLORS[tier]}
            label={lic}
            count={count}
            pct={total > 0 ? (count / total) * 100 : 0}
            onClick={onRowClick ? () => onRowClick(lic) : undefined}
          />
        )
      })}
      {restCount > 0 && (
        <tr className="border-b last:border-b-0 text-muted-foreground">
          <td className="flex items-center gap-2 px-3 py-1.5">
            <span className="inline-block size-2.5 rounded-sm border" />
            <span className="italic">… {restLicenses} more</span>
          </td>
          <td className="px-3 py-1.5 text-right tabular-nums">{restCount}</td>
          <td className="w-14 px-3 py-1.5 text-right text-xs tabular-nums">{total > 0 ? ((restCount / total) * 100).toFixed(1) : '0'}%</td>
        </tr>
      )}
      <TotalRow total={total} />
    </CompactTable>
  )
}

export function SecretsHealthTable({
  health,
  onRowClick,
}: {
  health?: SecretsHealthCounts
  onRowClick?: (bucket: SecretsKey) => void
}) {
  const total = health ? health.verified + health.unverified : 0
  const rows = health
    ? SECRETS_ORDER.map(k => ({ k, count: health[k] })).filter(r => r.count > 0)
    : []
  return (
    <CompactTable title="Secrets">
      {rows.length === 0 && (
        <tr>
          <td colSpan={3} className="px-3 py-3 text-center text-xs">
            <span className="inline-flex items-center gap-1.5 text-emerald-700 dark:text-emerald-400">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: SECRETS_COLORS.clean }} />
              No secrets detected
            </span>
          </td>
        </tr>
      )}
      {rows.map(({ k, count }) => (
        <Row
          key={k}
          color={SECRETS_COLORS[k]}
          label={SECRETS_LABELS[k]}
          count={count}
          pct={total > 0 ? (count / total) * 100 : 0}
          onClick={onRowClick ? () => onRowClick(k) : undefined}
        />
      ))}
      {total > 0 && <TotalRow total={total} />}
    </CompactTable>
  )
}

// ----- table primitives --------------------------------------------------

function CompactTable({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border bg-background">
      <div className="border-b px-3 py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      <table className="w-full text-sm">
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

function Row({
  color, label, count, pct, onClick,
}: {
  color: string; label: string; count: number; pct: number; onClick?: () => void
}) {
  const clickable = !!onClick
  return (
    <tr
      className={cn(
        'border-b last:border-b-0',
        clickable && 'cursor-pointer hover:bg-muted/40 focus-within:bg-muted/40',
      )}
      onClick={onClick}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={clickable
        ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick?.() } }
        : undefined}
    >
      <td className="flex items-center gap-2 px-3 py-1.5">
        <span className="inline-block size-2.5 rounded-sm" style={{ background: color }} />
        {label}
      </td>
      <td className="px-3 py-1.5 text-right tabular-nums">{count}</td>
      <td className="w-14 px-3 py-1.5 text-right text-xs text-muted-foreground tabular-nums">{pct.toFixed(1)}%</td>
    </tr>
  )
}

function TotalRow({ total }: { total: number }) {
  return (
    <tr className={cn('bg-muted/30 font-semibold')}>
      <td className="px-3 py-1.5">Total</td>
      <td className="px-3 py-1.5 text-right tabular-nums">{total}</td>
      <td className="px-3 py-1.5 text-right text-xs text-muted-foreground tabular-nums">{total > 0 ? '100.0%' : '—'}</td>
    </tr>
  )
}

function EmptyRow() {
  return (
    <tr>
      <td colSpan={3} className="px-3 py-3 text-center text-xs text-muted-foreground">
        No data
      </td>
    </tr>
  )
}
