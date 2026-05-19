import type { ScannerDetail, SbomHealthCounts } from '@/lib/api'
import { cn } from '@/lib/utils'

// Two concentric segmented donuts driving the Overview tab:
//   Outer ring — Code Quality (OpenGrep, fallback to Roslyn while
//     TAM-262 keeps the OpenGrep CLI install blocked). Each arc is
//     sized to that severity bucket's share of the scanner's lifetime
//     findings; clockwise from worst (Critical) to best (Closed).
//   Inner ring — SBOM health (F6.4 / F6.3). Three buckets: Vulnerable
//     (red, ≥1 known CVE), Outdated (yellow, newer version known
//     available — requires registry-enrichment that doesn't run yet),
//     and Current (green, the rest).
//
// Both rings are clickable. Outer drills into the Findings tab
// pre-filtered to the active scanner; inner navigates to Components.

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
  vulnerable: '#dc2626',  // red-600
  outdated:   '#f59e0b',  // amber-500
  current:    '#22c55e',  // green-500
} as const

const SBOM_ORDER = ['vulnerable', 'outdated', 'current'] as const
type SbomKey = (typeof SBOM_ORDER)[number]
const SBOM_LABELS: Record<SbomKey, string> = {
  vulnerable: 'Vulnerable', outdated: 'Outdated', current: 'Current',
}

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

const SIZE = 320
const OUTER_R = 130
const OUTER_WIDTH = 24
const INNER_R = 90
const INNER_WIDTH = 22

type Arc = { key: string; count: number; color: string; dashArray: string; dashOffset: number }

function buildArcs(
  buckets: Array<{ key: string; count: number; color: string }>,
  total: number,
  circumference: number,
): Arc[] {
  if (total === 0) return []
  let offset = 0
  const arcs: Arc[] = []
  for (const seg of buckets) {
    if (seg.count <= 0) continue
    const segLen = (seg.count / total) * circumference
    arcs.push({
      key: seg.key,
      count: seg.count,
      color: seg.color,
      dashArray: `${segLen} ${circumference - segLen}`,
      dashOffset: -offset,
    })
    offset += segLen
  }
  return arcs
}

export function RingChart({
  scannerDetails,
  sbomHealth,
  onScannerClick,
  onSbomClick,
}: {
  scannerDetails: ScannerDetail[]
  sbomHealth?: SbomHealthCounts
  onScannerClick?: (scanner: string) => void
  onSbomClick?: () => void
}) {
  const primary = pickPrimaryScanner(scannerDetails)
  const outerTotal = primary ? totalOf(primary) : 0
  const outerEmpty = outerTotal === 0

  const sbomTotal = sbomHealth ? sbomHealth.current + sbomHealth.outdated + sbomHealth.vulnerable : 0
  const innerEmpty = sbomTotal === 0

  const cx = SIZE / 2
  const cy = SIZE / 2
  const outerCircumference = 2 * Math.PI * OUTER_R
  const innerCircumference = 2 * Math.PI * INNER_R

  const outerArcs = buildArcs(
    SEGMENT_ORDER.map(k => ({
      key: k,
      count: primary ? countFor(primary, k) : 0,
      color: SEGMENT_COLORS[k],
    })),
    outerTotal,
    outerCircumference,
  )
  const innerArcs = sbomHealth ? buildArcs(
    SBOM_ORDER.map(k => ({ key: k, count: sbomHealth[k], color: SBOM_COLORS[k] })),
    sbomTotal,
    innerCircumference,
  ) : []

  const outerInteractive = !!onScannerClick && !!primary
  const innerInteractive = !!onSbomClick && !!sbomHealth && sbomTotal > 0

  return (
    <div className="flex flex-col items-center">
      <div className="text-center">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">Outer ring</p>
        <p className="text-base font-semibold">Code Quality</p>
        {primary && primary.scanner !== 'OpenGrep' && (
          <p className="text-[11px] text-muted-foreground">
            via {primary.scanner} · OpenGrep pending TAM-262
          </p>
        )}
        {!primary && (
          <p className="text-[11px] text-muted-foreground">no scanner data yet</p>
        )}
      </div>

      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="mt-2 w-full max-w-[300px]" role="img" aria-label="Code Quality + SBOM health donuts">
        {/* Outer track */}
        <circle
          cx={cx} cy={cy} r={OUTER_R}
          fill="none"
          stroke="rgb(229 231 235)"
          strokeWidth={OUTER_WIDTH}
          opacity={outerEmpty ? 1 : 0.2}
        />
        {/* Inner track */}
        <circle
          cx={cx} cy={cy} r={INNER_R}
          fill="none"
          stroke="rgb(229 231 235)"
          strokeWidth={INNER_WIDTH}
          opacity={innerEmpty ? 1 : 0.2}
        />

        {/* Clickable outer hit region — render before arcs so arcs sit on top visually */}
        {outerInteractive && (
          <circle
            cx={cx} cy={cy} r={OUTER_R}
            fill="none"
            stroke="transparent"
            strokeWidth={OUTER_WIDTH}
            style={{ cursor: 'pointer' }}
            onClick={() => primary && onScannerClick?.(primary.scanner)}
            tabIndex={0}
            role="button"
            aria-label={`Open ${primary?.scanner} findings`}
          />
        )}
        {/* Outer arcs */}
        <g transform={`rotate(-90 ${cx} ${cy})`} style={{ pointerEvents: 'none' }}>
          {outerArcs.map(seg => (
            <circle
              key={`o-${seg.key}`}
              cx={cx} cy={cy} r={OUTER_R}
              fill="none"
              stroke={seg.color}
              strokeWidth={OUTER_WIDTH}
              strokeDasharray={seg.dashArray}
              strokeDashoffset={seg.dashOffset}
              strokeLinecap="butt"
            >
              <title>{SEGMENT_LABELS[seg.key as SegKey]}: {seg.count}</title>
            </circle>
          ))}
        </g>

        {/* Clickable inner hit region */}
        {innerInteractive && (
          <circle
            cx={cx} cy={cy} r={INNER_R}
            fill="none"
            stroke="transparent"
            strokeWidth={INNER_WIDTH}
            style={{ cursor: 'pointer' }}
            onClick={() => onSbomClick?.()}
            tabIndex={0}
            role="button"
            aria-label="Browse SBOM components"
          />
        )}
        {/* Inner arcs */}
        <g transform={`rotate(-90 ${cx} ${cy})`} style={{ pointerEvents: 'none' }}>
          {innerArcs.map(seg => (
            <circle
              key={`i-${seg.key}`}
              cx={cx} cy={cy} r={INNER_R}
              fill="none"
              stroke={seg.color}
              strokeWidth={INNER_WIDTH}
              strokeDasharray={seg.dashArray}
              strokeDashoffset={seg.dashOffset}
              strokeLinecap="butt"
            >
              <title>{SBOM_LABELS[seg.key as SbomKey]}: {seg.count}</title>
            </circle>
          ))}
        </g>

        {/* Center text — quality outer total above, sbom inner total below */}
        <text x={cx} y={cy - 8} textAnchor="middle" fontSize="28" fontWeight="700" className="fill-foreground">
          {outerTotal}
        </text>
        <text x={cx} y={cy + 6} textAnchor="middle" fontSize="9" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
          findings
        </text>
        <text x={cx} y={cy + 24} textAnchor="middle" fontSize="14" fontWeight="600" className="fill-foreground">
          {sbomTotal}
        </text>
        <text x={cx} y={cy + 36} textAnchor="middle" fontSize="8" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
          sbom deps
        </text>
      </svg>

      <div className="mt-2 grid grid-cols-2 gap-3 text-[11px] text-muted-foreground">
        {outerInteractive && <span>Click outer → findings</span>}
        {innerInteractive && <span>Click inner → components</span>}
      </div>
    </div>
  )
}

// Compact table of severity buckets for the active code-quality scanner.
// Drops zero rows so the visual stays tight when only a few severities
// are populated. Each row is clickable when onRowClick is provided —
// fires with the segment key (severity name or "closed"/"suppressed"/
// "accepted") so the caller can navigate to a filtered Findings list.
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

// Same shape, different data — SBOM health buckets. Click row → caller
// receives the bucket key ('vulnerable' / 'outdated' / 'current').
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
