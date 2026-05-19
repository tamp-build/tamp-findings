import type { SeverityCounts } from '@/lib/api'

// Qodana-style concentric ring chart. Outer ring = code-smell territory
// (Info severity, high tolerance), innermost ring = Critical security.
// Each ring is colored by count vs. a per-severity threshold:
//   count == 0                      → green
//   0 < count <= warningThreshold   → amber
//   count >  warningThreshold       → red
// Critical's threshold is 0, so any non-zero critical is red — there's
// no "yellow" tolerance for a critical finding.

type Ring = {
  key: keyof Omit<SeverityCounts, 'total'>
  label: string
  warnAt: number
  radius: number
}

const RINGS: Ring[] = [
  { key: 'info',     label: 'Info',     warnAt: 100, radius: 140 },
  { key: 'low',      label: 'Low',      warnAt: 50,  radius: 115 },
  { key: 'medium',   label: 'Medium',   warnAt: 10,  radius: 90  },
  { key: 'high',     label: 'High',     warnAt: 1,   radius: 65  },
  { key: 'critical', label: 'Critical', warnAt: 0,   radius: 40  },
]

const RING_WIDTH = 22
const SIZE = 320
const CENTER = SIZE / 2

function colorFor(count: number, warnAt: number): { stroke: string; text: string } {
  if (count === 0) return { stroke: 'rgb(34 197 94)', text: 'rgb(21 128 61)' }     // green
  if (count <= warnAt) return { stroke: 'rgb(245 158 11)', text: 'rgb(180 83 9)' } // amber
  return { stroke: 'rgb(220 38 38)', text: 'rgb(153 27 27)' }                       // red
}

export function RingChart({ counts, title }: { counts: SeverityCounts; title?: string }) {
  return (
    <div className="flex flex-col items-center gap-3">
      {title && <p className="text-sm font-medium text-muted-foreground">{title}</p>}
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full max-w-sm">
        {RINGS.map(ring => {
          const count = counts[ring.key]
          const { stroke } = colorFor(count, ring.warnAt)
          return (
            <circle
              key={ring.key}
              cx={CENTER}
              cy={CENTER}
              r={ring.radius}
              fill="none"
              stroke={stroke}
              strokeWidth={RING_WIDTH}
              opacity={0.85}
            />
          )
        })}
        {/* Center: total count */}
        <text
          x={CENTER}
          y={CENTER - 6}
          textAnchor="middle"
          fontSize="36"
          fontWeight="700"
          className="fill-foreground"
        >
          {counts.total}
        </text>
        <text
          x={CENTER}
          y={CENTER + 16}
          textAnchor="middle"
          fontSize="11"
          letterSpacing="0.05em"
          className="fill-muted-foreground uppercase"
        >
          total open
        </text>
      </svg>
      <ul className="grid grid-cols-5 gap-2 text-center text-xs">
        {RINGS.map(ring => {
          const count = counts[ring.key]
          const { text } = colorFor(count, ring.warnAt)
          return (
            <li key={ring.key} className="flex flex-col items-center">
              <span className="text-base font-semibold tabular-nums" style={{ color: text }}>{count}</span>
              <span className="text-muted-foreground">{ring.label}</span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
