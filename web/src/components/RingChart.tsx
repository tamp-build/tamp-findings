import type { ScannerDetail } from '@/lib/api'
import { cn } from '@/lib/utils'

// Segmented donut for one scanner. The arc length of each color reflects
// that bucket's share of the scanner's lifetime finding total. Severities
// run clockwise from worst (Critical) to best (Closed = green).
//
// Outer ring is reserved for code-quality SAST (OpenGrep when its CLI
// install unblocks via TAM-262; Roslyn until then). The chart's header
// label is always "Code Quality" — that's the *category*, not the
// underlying tool.

const SAST_PREFERENCE = ['OpenGrep', 'Roslyn', 'CodeQL'] as const

const SEGMENT_COLORS = {
  critical:   '#dc2626',  // red-600
  high:       '#f97316',  // orange-500
  medium:     '#f59e0b',  // amber-500
  low:        '#facc15',  // yellow-400
  info:       '#38bdf8',  // sky-400
  closed:     '#22c55e',  // green-500
  suppressed: '#a3a3a3',  // neutral-400
  accepted:   '#737373',  // neutral-500
} as const

const SEGMENT_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'closed', 'suppressed', 'accepted'] as const
type SegKey = (typeof SEGMENT_ORDER)[number]

const SEGMENT_LABELS: Record<SegKey, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  info: 'Info', closed: 'Closed', suppressed: 'Suppressed', accepted: 'Accepted',
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

const SIZE = 280
const RING_WIDTH = 26
const RADIUS = 115

export function RingChart({
  scannerDetails,
  onScannerClick,
}: {
  scannerDetails: ScannerDetail[]
  onScannerClick?: (scanner: string) => void
}) {
  const primary = pickPrimaryScanner(scannerDetails)
  const total = primary ? totalOf(primary) : 0
  const empty = total === 0

  const cx = SIZE / 2
  const cy = SIZE / 2
  const circumference = 2 * Math.PI * RADIUS

  // Compute cumulative offsets for the stroke-dasharray trick.
  const drawn = SEGMENT_ORDER
    .map(key => ({ key, count: primary ? countFor(primary, key) : 0 }))
    .filter(s => s.count > 0)
  let offsetSoFar = 0
  const arcs = drawn.map(seg => {
    const segLen = (seg.count / total) * circumference
    const arc = {
      key: seg.key,
      count: seg.count,
      dashArray: `${segLen} ${circumference - segLen}`,
      dashOffset: -offsetSoFar,
    }
    offsetSoFar += segLen
    return arc
  })

  const interactive = !!onScannerClick && !!primary
  const handleClick = () => primary && onScannerClick?.(primary.scanner)

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

      <button
        type="button"
        onClick={handleClick}
        disabled={!interactive}
        aria-label={interactive ? `Open ${primary?.scanner} findings` : undefined}
        className={cn(
          'group mt-2 rounded-full transition-transform',
          interactive && 'cursor-pointer hover:scale-[1.02] focus-visible:scale-[1.02] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40',
        )}
      >
        <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full max-w-[260px]" role="img" aria-label="Code Quality findings donut">
          <circle
            cx={cx} cy={cy} r={RADIUS}
            fill="none"
            stroke="rgb(229 231 235)"
            strokeWidth={RING_WIDTH}
            opacity={empty ? 1 : 0.25}
          />
          <g transform={`rotate(-90 ${cx} ${cy})`}>
            {arcs.map(seg => (
              <circle
                key={seg.key}
                cx={cx} cy={cy} r={RADIUS}
                fill="none"
                stroke={SEGMENT_COLORS[seg.key]}
                strokeWidth={RING_WIDTH}
                strokeDasharray={seg.dashArray}
                strokeDashoffset={seg.dashOffset}
                strokeLinecap="butt"
              >
                <title>{SEGMENT_LABELS[seg.key]}: {seg.count}</title>
              </circle>
            ))}
          </g>
          <text x={cx} y={cy - 2} textAnchor="middle" fontSize="34" fontWeight="700" className="fill-foreground">
            {total}
          </text>
          <text x={cx} y={cy + 18} textAnchor="middle" fontSize="10" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
            {empty ? 'no findings' : 'total tracked'}
          </text>
        </svg>
      </button>

      {interactive && (
        <p className="mt-1 text-[11px] text-muted-foreground">
          Click to drill into the {primary?.scanner} findings list
        </p>
      )}
    </div>
  )
}

// Standalone type-breakdown table — same color language as the donut so
// they read as one chart. Used by the Overview view to the right of the
// ring; kept in this file so the segment order / colors stay in sync.
export function FindingsTypeTable({ scannerDetails }: { scannerDetails: ScannerDetail[] }) {
  const primary = pickPrimaryScanner(scannerDetails)
  const total = primary ? totalOf(primary) : 0

  return (
    <div className="rounded-md border bg-background">
      <table className="w-full text-sm">
        <thead className="border-b text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left font-medium">Type</th>
            <th className="px-3 py-2 text-right font-medium">Count</th>
            <th className="px-3 py-2 text-right font-medium">Share</th>
          </tr>
        </thead>
        <tbody>
          {SEGMENT_ORDER.map(k => {
            const count = primary ? countFor(primary, k) : 0
            const pct = total > 0 ? (count / total) * 100 : 0
            const muted = count === 0
            return (
              <tr key={k} className={cn('border-b last:border-b-0', muted && 'text-muted-foreground')}>
                <td className="flex items-center gap-2 px-3 py-2">
                  <span className="inline-block size-2.5 rounded-sm" style={{ background: SEGMENT_COLORS[k] }} />
                  {SEGMENT_LABELS[k]}
                </td>
                <td className="px-3 py-2 text-right tabular-nums">{count}</td>
                <td className="px-3 py-2 text-right tabular-nums">{pct.toFixed(1)}%</td>
              </tr>
            )
          })}
          <tr className="bg-muted/30 font-semibold">
            <td className="px-3 py-2">Total</td>
            <td className="px-3 py-2 text-right tabular-nums">{total}</td>
            <td className="px-3 py-2 text-right tabular-nums">{total > 0 ? '100.0%' : '—'}</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}
