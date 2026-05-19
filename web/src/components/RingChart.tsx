import type { ScannerDetail } from '@/lib/api'

// Segmented donut for one scanner. The arc length of each color reflects
// that bucket's share of the scanner's lifetime finding total. Severities
// run clockwise from worst (Critical) to best (Closed = green).
//
// Outer ring is reserved for OpenGrep per the design — it's the
// code-quality / pattern-SAST surface that should hit the eye first. If
// OpenGrep hasn't ingested anything yet (TAM-262 keeps the CLI install
// blocked on Windows), the chart falls back to the next available SAST
// scanner (Roslyn) so the visualization isn't a zero donut while we wait.

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
  // No preferred SAST scanner with data — fall back to whatever's first
  // with any signal at all so the donut isn't empty when we have results.
  return details.find(d => totalOf(d) > 0) ?? details[0] ?? null
}

function totalOf(d: ScannerDetail): number {
  return d.open.total + d.closed + d.suppressed + d.accepted
}

function segmentsOf(d: ScannerDetail): Array<{ key: SegKey; count: number }> {
  return [
    { key: 'critical',   count: d.open.critical },
    { key: 'high',       count: d.open.high     },
    { key: 'medium',     count: d.open.medium   },
    { key: 'low',        count: d.open.low      },
    { key: 'info',       count: d.open.info     },
    { key: 'closed',     count: d.closed        },
    { key: 'suppressed', count: d.suppressed    },
    { key: 'accepted',   count: d.accepted      },
  ]
}

const SIZE = 320
const RING_WIDTH = 28
const RADIUS = 130

export function RingChart({ scannerDetails }: { scannerDetails: ScannerDetail[] }) {
  const primary = pickPrimaryScanner(scannerDetails)
  const cx = SIZE / 2
  const cy = SIZE / 2
  const circumference = 2 * Math.PI * RADIUS

  const segments = primary ? segmentsOf(primary).filter(s => s.count > 0) : []
  const total = primary ? totalOf(primary) : 0
  const empty = total === 0

  // Compute cumulative offsets for the stroke-dasharray trick.
  const drawn: Array<{ key: SegKey; count: number; dashArray: string; dashOffset: number }> = []
  let offsetSoFar = 0
  for (const seg of segments) {
    const segLen = (seg.count / total) * circumference
    drawn.push({
      key: seg.key,
      count: seg.count,
      dashArray: `${segLen} ${circumference - segLen}`,
      dashOffset: -offsetSoFar,
    })
    offsetSoFar += segLen
  }

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="flex items-baseline gap-2">
        <p className="text-sm font-medium text-muted-foreground">Outer ring</p>
        {primary ? (
          <p className="text-xs text-muted-foreground">
            {primary.scanner === 'OpenGrep' ? 'OpenGrep' : `${primary.scanner} (OpenGrep blocked by TAM-262)`}
          </p>
        ) : (
          <p className="text-xs text-muted-foreground">OpenGrep (no data yet)</p>
        )}
      </div>

      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full max-w-sm" role="img" aria-label="Scanner findings donut">
        {/* Track ring (always drawn, so empty state still shows the circle) */}
        <circle
          cx={cx} cy={cy} r={RADIUS}
          fill="none"
          stroke="rgb(229 231 235)"
          strokeWidth={RING_WIDTH}
          opacity={empty ? 1 : 0.25}
        />
        {/* Segments — rotated -90° so segment 1 begins at 12 o'clock */}
        <g transform={`rotate(-90 ${cx} ${cy})`}>
          {drawn.map(seg => (
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
        {/* Center: total */}
        <text x={cx} y={cy - 6} textAnchor="middle" fontSize="36" fontWeight="700" className="fill-foreground">
          {total}
        </text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="11" letterSpacing="0.05em" className="fill-muted-foreground uppercase">
          {empty ? 'no findings' : 'total tracked'}
        </text>
      </svg>

      {/* Legend / per-segment chips */}
      <ul className="grid w-full max-w-sm grid-cols-4 gap-2 text-center text-xs">
        {SEGMENT_ORDER.map(k => {
          const count = primary
            ? (k === 'closed' ? primary.closed
               : k === 'suppressed' ? primary.suppressed
               : k === 'accepted' ? primary.accepted
               : primary.open[k as keyof typeof primary.open] as number)
            : 0
          if (count === 0) return null
          return (
            <li key={k} className="flex flex-col items-center">
              <span className="flex items-center gap-1.5">
                <span className="inline-block size-2.5 rounded-sm" style={{ background: SEGMENT_COLORS[k] }} />
                <span className="text-base font-semibold tabular-nums">{count}</span>
              </span>
              <span className="text-muted-foreground">{SEGMENT_LABELS[k]}</span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
