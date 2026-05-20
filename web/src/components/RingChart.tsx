import type { ScannerDetail, SbomHealthCounts, SecretsHealthCounts, LicenseTierCounts, SeverityCounts, CoverageModuleSummary, FindingRuleSummary, Severity } from '@/lib/api'
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

// The Code Quality ring is scanner-agnostic: anything in SAST_SCANNERS
// folds into one "Code Quality" bucket. Adding a new SAST tool means
// listing it here — no other dashboard surface needs to know about it.
export const SAST_SCANNERS = ['ReSharper', 'Roslyn', 'OpenGrep', 'CodeQL'] as const

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

// Coverage outermost ring. Two segments: covered (green, sized to %) +
// uncovered (red, sized to remaining %). Unmeasured = solid grey, matching
// the IaC bullseye's grey-vs-green honesty rule (grey = "no data" not "ok").
// Tier helpers retained for the table swatch & summary header coloring.
const COVERAGE_COLORS = {
  covered:    '#22c55e',  // green-500   — executed lines
  uncovered:  '#dc2626',  // red-600     — unexecuted lines
  unmeasured: '#9ca3af',  // gray-400    — no coverage report in scope
  good:       '#22c55e',  // green-500   — ≥80% (for summary text)
  acceptable: '#f59e0b',  // amber-500   — 60..80%
  poor:       '#dc2626',  // red-600     — <60%
} as const

export function coverageTierColor(pct: number): string {
  if (pct >= 80) return COVERAGE_COLORS.good
  if (pct >= 60) return COVERAGE_COLORS.acceptable
  return COVERAGE_COLORS.poor
}

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

// Sum severity + lifecycle counts across every SAST scanner so the Code
// Quality ring/table reads as one bucket. Returns null when nothing in
// SAST_SCANNERS has any data (so the ring renders empty rather than a
// fake zero row).
export function aggregateSastCounts(details: ScannerDetail[]): ScannerDetail | null {
  const sast = details.filter(d => (SAST_SCANNERS as readonly string[]).includes(d.scanner))
  if (sast.length === 0) return null
  const agg: ScannerDetail = {
    scanner: 'Code Quality',
    open: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
    closed: 0,
    suppressed: 0,
    accepted: 0,
  }
  for (const d of sast) {
    agg.open.critical += d.open.critical
    agg.open.high     += d.open.high
    agg.open.medium   += d.open.medium
    agg.open.low      += d.open.low
    agg.open.info     += d.open.info
    agg.open.total    += d.open.total
    agg.closed        += d.closed
    agg.suppressed    += d.suppressed
    agg.accepted      += d.accepted
  }
  return totalOf(agg) === 0 ? null : agg
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

const SIZE = 400
const RINGS = {
  outer:    { radius: 180, width: 22 },  // Coverage
  upper:    { radius: 144, width: 18 },  // Code Quality
  middle:   { radius: 112, width: 18 },  // SBOM
  innerHi:  { radius: 82,  width: 16 },  // Secrets
  innerMid: { radius: 56,  width: 14 },  // Licenses
  inner:    { radius: 32,  width: 12 },  // IaC bullseye
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
  coverage,
  scanRuns,
  onScannerClick,
  onSbomClick,
  onSecretsClick,
  onLicenseClick,
  onIacClick,
  onCoverageClick,
}: {
  scannerDetails: ScannerDetail[]
  sbomHealth?: SbomHealthCounts
  secretsHealth?: SecretsHealthCounts
  licenseTiers?: LicenseTierCounts
  iac?: { counts: SeverityCounts; scanned: boolean }
  coverage?: { measured: boolean; sequenceCoverage: number | null; coveredSequences: number; totalSequences: number }
  // TFND-15: which scanners have produced a receipt in scope. Used to flip
  // 0-finding rings from grey (never scanned) to green (scanned · clean).
  scanRuns?: { scanner: string; status: string; findingsCount: number }[]
  onScannerClick?: (scanner: string) => void
  onSbomClick?: () => void
  onSecretsClick?: () => void
  onLicenseClick?: () => void
  onIacClick?: () => void
  onCoverageClick?: () => void
}) {
  const ranSuccessfully = (scanner: string) =>
    !!scanRuns?.some(r => r.scanner === scanner && r.status === 'Succeeded')
  const anySastRan = (SAST_SCANNERS as readonly string[]).some(s => ranSuccessfully(s))
  // Coverage (outermost). Two states mirror the IaC bullseye honesty rule:
  //   unmeasured (no coverage report)  → solid grey, no segments
  //   measured                         → covered arc (green) + uncovered arc (red)
  const coverageMeasured = coverage?.measured ?? false
  const coveragePct = coverageMeasured ? (coverage?.sequenceCoverage ?? 0) : 0
  const coverageCleanFill = !coverageMeasured ? COVERAGE_COLORS.unmeasured : undefined
  const coverageArcs = coverageMeasured && (coverage?.totalSequences ?? 0) > 0
    ? buildArcs(
        [
          { key: 'covered',   count: coverage!.coveredSequences,                                   color: COVERAGE_COLORS.covered },
          { key: 'uncovered', count: coverage!.totalSequences - coverage!.coveredSequences,        color: COVERAGE_COLORS.uncovered },
        ],
        coverage!.totalSequences,
        RINGS.outer.radius,
      )
    : []

  // Code Quality ring is scanner-agnostic — sum severities + lifecycle
  // counts across every SAST scanner so the visual reads as "Code Quality"
  // rather than "whichever single tool happened to win the preference race".
  const sastAgg = aggregateSastCounts(scannerDetails)
  const outerTotal = sastAgg ? totalOf(sastAgg) : 0
  const codeQualityArcs = buildArcs(
    SEGMENT_ORDER.map(k => ({ key: k, count: sastAgg ? countFor(sastAgg, k) : 0, color: SEGMENT_COLORS[k] })),
    outerTotal,
    RINGS.upper.radius,
  )
  // Honesty rule (TFND-15): if no SAST scanner has produced a receipt in
  // scope, the ring is grey ("never scanned"); if any has, but findings are
  // zero, it's green ("scanned · clean").
  const codeQualityCleanFill = outerTotal === 0
    ? (anySastRan ? SEGMENT_COLORS.closed : '#9ca3af')
    : undefined

  const sbomTotal = sbomHealth ? sbomHealth.current + sbomHealth.outdated + sbomHealth.vulnerable : 0
  const sbomArcs = sbomHealth
    ? buildArcs(SBOM_ORDER.map(k => ({ key: k, count: sbomHealth[k], color: SBOM_COLORS[k] })), sbomTotal, RINGS.middle.radius)
    : []

  const secretsTotal = secretsHealth ? secretsHealth.verified + secretsHealth.unverified : 0
  const secretsArcs = secretsHealth
    ? buildArcs(SECRETS_ORDER.map(k => ({ key: k, count: secretsHealth[k], color: SECRETS_COLORS[k] })), secretsTotal, RINGS.innerHi.radius)
    : []
  // Same honesty rule for Secrets: green requires a TruffleHog receipt; else grey.
  const trufflehogRan = ranSuccessfully('TruffleHog')
  const secretsCleanFill = secretsTotal === 0
    ? (trufflehogRan ? SECRETS_COLORS.clean : '#9ca3af')
    : undefined

  const licenseTotal = licenseTiers
    ? licenseTiers.permissive + licenseTiers.weakCopyleft + licenseTiers.strongCopyleft + licenseTiers.denied + licenseTiers.unknown
    : 0
  const licenseArcs = licenseTiers
    ? buildArcs(
        LICENSE_ORDER.map(k => ({ key: k, count: licenseTiers[k], color: LICENSE_COLORS[k] })),
        licenseTotal,
        RINGS.innerMid.radius,
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
        <p className="text-base font-semibold">Coverage · Code Quality · SBOM · Secrets · Licenses · IaC</p>
      </div>

      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="mt-2 w-full max-w-[360px]" role="img" aria-label="Risk rings: coverage, code quality, SBOM, secrets, licenses, IaC">
        <ConcentricRing
          slot="outer"
          arcs={coverageArcs}
          cleanFill={coverageCleanFill}
          onClick={onCoverageClick && coverageMeasured ? onCoverageClick : undefined}
          ariaLabel={coverageMeasured ? `Coverage ${coveragePct.toFixed(1)}%` : 'Coverage not measured'}
        />
        <ConcentricRing
          slot="upper"
          arcs={codeQualityArcs}
          cleanFill={codeQualityCleanFill}
          // Sentinel scanner name 'CodeQuality' tells the Findings view to
          // OR-filter across every SAST scanner rather than match a single one.
          onClick={onScannerClick && outerTotal > 0 ? () => onScannerClick('CodeQuality') : undefined}
          ariaLabel={outerTotal > 0 ? 'Browse code-quality findings' : undefined}
        />
        <ConcentricRing
          slot="middle"
          arcs={sbomArcs}
          onClick={onSbomClick}
          ariaLabel="Browse SBOM components"
        />
        <ConcentricRing
          slot="innerHi"
          arcs={secretsArcs}
          cleanFill={secretsCleanFill}
          onClick={secretsHealth && secretsTotal > 0 ? onSecretsClick : undefined}
          ariaLabel={secretsTotal > 0 ? 'Open TruffleHog findings' : undefined}
        />
        <ConcentricRing
          slot="innerMid"
          arcs={licenseArcs}
          onClick={onLicenseClick}
          ariaLabel="Browse license breakdown"
        />
        <ConcentricRing
          slot="inner"
          arcs={iacArcs}
          cleanFill={iacCleanFill}
          onClick={onIacClick && iac?.scanned && iacTotal > 0 ? onIacClick : undefined}
          ariaLabel={iac?.scanned && iacTotal > 0 ? 'Open Trivy IaC findings' : undefined}
        />

        {/* Compact center text — coverage% when we have it, else fall back to findings count */}
        {coverageMeasured ? (
          <>
            <text x={SIZE / 2} y={SIZE / 2 - 3} textAnchor="middle" fontSize="22" fontWeight="700" className="fill-foreground">
              {coveragePct.toFixed(0)}%
            </text>
            <text x={SIZE / 2} y={SIZE / 2 + 11} textAnchor="middle" fontSize="8" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
              coverage
            </text>
          </>
        ) : (
          <>
            <text x={SIZE / 2} y={SIZE / 2 - 3} textAnchor="middle" fontSize="20" fontWeight="700" className="fill-foreground">
              {outerTotal}
            </text>
            <text x={SIZE / 2} y={SIZE / 2 + 11} textAnchor="middle" fontSize="8" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
              findings
            </text>
          </>
        )}
      </svg>

      <div className="mt-2 text-center text-[11px] text-muted-foreground">
        outer → coverage · 2 → code quality · 3 → components · 4 → secrets · 5 → licenses · 6 → IaC
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

// Coverage table on the Overview — single Overall row only. Per-module
// breakdown lives in the detail view (Coverage tab) so the Overview stays
// scannable at a glance. Unmeasured renders a neutral "no report" row.
export function CoverageTable({
  coverage,
}: {
  coverage?: { measured: boolean; sequenceCoverage: number | null; coveredSequences: number; totalSequences: number; modules: CoverageModuleSummary[] }
}) {
  if (!coverage) return null
  const overall = coverage.sequenceCoverage ?? 0

  return (
    <CompactTable title="Test coverage">
      {!coverage.measured ? (
        <tr>
          <td colSpan={2} className="px-3 py-3 text-center text-xs">
            <span className="inline-flex items-center gap-1.5 text-muted-foreground">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: COVERAGE_COLORS.unmeasured }} />
              No coverage report in scope
            </span>
          </td>
        </tr>
      ) : (
        <tr className={cn('bg-muted/30 font-semibold')}>
          <td className="px-2 py-1.5 min-w-0">
            <div className="flex items-center gap-2 min-w-0">
              <span className="inline-block size-2.5 shrink-0 rounded-sm" style={{ background: coverageTierColor(overall) }} />
              <span className="truncate">Overall</span>
            </div>
          </td>
          <td className="w-14 px-2 py-1.5 text-right text-xs tabular-nums">{overall.toFixed(1)}%</td>
        </tr>
      )}
    </CompactTable>
  )
}

// TFND-18: Top rules table — bridge between Overview and FindingsView. The
// ring shows ALL SAST findings by severity, the FindingsTypeTable shows
// severity-by-severity; this fills the third dimension by surfacing which
// SPECIFIC rules drive the volume so the user can triage by "fix this rule
// first" rather than wading through 397 individual rows.
const TOP_RULES_SEV_DOT: Record<Severity, string> = {
  Critical: '#dc2626',
  High:     '#f97316',
  Medium:   '#f59e0b',
  Low:      '#facc15',
  Info:     '#38bdf8',
}
export function TopRulesTable({
  rules,
  onRowClick,
}: {
  rules?: FindingRuleSummary[]
  onRowClick?: (ruleId: string) => void
}) {
  const list = rules ?? []
  const total = list.reduce((s, r) => s + r.count, 0)
  return (
    <CompactTable title="Top Code Quality rules">
      {list.length === 0 && <EmptyRow />}
      {list.map(r => (
        <Row
          key={r.ruleId}
          color={TOP_RULES_SEV_DOT[r.severity]}
          label={r.ruleId}
          count={r.count}
          pct={total > 0 ? (r.count / total) * 100 : 0}
          onClick={onRowClick ? () => onRowClick(r.ruleId) : undefined}
        />
      ))}
    </CompactTable>
  )
}

export function FindingsTypeTable({
  scannerDetails,
  onRowClick,
}: {
  scannerDetails: ScannerDetail[]
  // Second arg used to be the primary scanner name; we now pass the sentinel
  // 'CodeQuality' so the Findings view OR-filters across every SAST scanner.
  onRowClick?: (segment: SegKey, scanner: string) => void
}) {
  const sastAgg = aggregateSastCounts(scannerDetails)
  const total = sastAgg ? totalOf(sastAgg) : 0
  const rows = SEGMENT_ORDER
    .map(k => ({ k, count: sastAgg ? countFor(sastAgg, k) : 0 }))
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
          onClick={onRowClick ? () => onRowClick(k, 'CodeQuality') : undefined}
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
      {rows.map(({ k, count }) => {
        // TFND-22: annotate the outdated row with how many of those have
        // been outdated for more than 180 days. Lets the user see "12 of
        // 66 outdated are stale" at a glance.
        const label = k === 'outdated' && health && health.stale > 0
          ? `${SBOM_LABELS[k]} · ${health.stale} stale >180d`
          : SBOM_LABELS[k]
        return (
          <Row
            key={k}
            color={SBOM_COLORS[k]}
            label={label}
            count={count}
            pct={total > 0 ? (count / total) * 100 : 0}
            onClick={onRowClick ? () => onRowClick(k) : undefined}
          />
        )
      })}
      <TotalRow total={total} />
    </CompactTable>
  )
}

// License classifier mirroring the server's LicensePolicy.Classify — keeps
// each row's swatch color in lockstep with the tier it'd land in.
export function tierForLicense(spdx: string): LicenseKey {
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
          <td className="px-2 py-1.5 min-w-0">
            <div className="flex items-center gap-2 min-w-0">
              <span className="inline-block size-2.5 shrink-0 rounded-sm border" />
              <span className="italic truncate">… {restLicenses} more</span>
            </div>
          </td>
          <td className="w-12 px-2 py-1.5 text-right tabular-nums">{restCount}</td>
          <td className="w-14 px-2 py-1.5 text-right text-xs tabular-nums">{total > 0 ? ((restCount / total) * 100).toFixed(1) : '0'}%</td>
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
    <div className="rounded-md border bg-background overflow-hidden">
      <div className="border-b px-2 py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground truncate">
        {title}
      </div>
      {/* table-layout:fixed honors the explicit w-12 / w-14 widths so the
          label column gets the remainder and truncates instead of pushing
          numbers outside the cell. */}
      <table className="w-full text-sm" style={{ tableLayout: 'fixed' }}>
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
      {/* flex-in-td breaks normal table column sizing; flex on an inner div is safe. */}
      <td className="px-2 py-1.5 min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="inline-block size-2.5 shrink-0 rounded-sm" style={{ background: color }} />
          <span className="truncate" title={label}>{label}</span>
        </div>
      </td>
      <td className="w-12 px-2 py-1.5 text-right tabular-nums">{count}</td>
      <td className="w-14 px-2 py-1.5 text-right text-xs text-muted-foreground tabular-nums">{pct.toFixed(1)}%</td>
    </tr>
  )
}

function TotalRow({ total }: { total: number }) {
  return (
    <tr className={cn('bg-muted/30 font-semibold')}>
      <td className="px-2 py-1.5">Total</td>
      <td className="w-12 px-2 py-1.5 text-right tabular-nums">{total}</td>
      <td className="w-14 px-2 py-1.5 text-right text-xs text-muted-foreground tabular-nums">{total > 0 ? '100.0%' : '—'}</td>
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
