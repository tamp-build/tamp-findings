import type { SeverityCounts, Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

const order: Array<{ key: keyof SeverityCounts; label: Severity; cls: string }> = [
  { key: 'critical', label: 'Critical', cls: 'text-red-600' },
  { key: 'high', label: 'High', cls: 'text-orange-500' },
  { key: 'medium', label: 'Medium', cls: 'text-amber-500' },
  { key: 'low', label: 'Low', cls: 'text-sky-500' },
  { key: 'info', label: 'Info', cls: 'text-muted-foreground' },
]

export function SeverityCountsBar({
  counts,
  active,
  onToggle,
}: {
  counts: SeverityCounts
  active: Set<Severity>
  onToggle: (s: Severity) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {order.map(({ key, label, cls }) => {
        const n = counts[key] as number
        const isActive = active.has(label)
        const isMuted = active.size > 0 && !isActive
        return (
          <button
            key={key}
            type="button"
            onClick={() => onToggle(label)}
            className={cn(
              'flex items-baseline gap-1.5 rounded-md border px-2.5 py-1.5 text-sm transition-colors',
              'hover:bg-muted/60',
              isActive && 'border-foreground bg-muted',
              isMuted && 'opacity-50',
            )}
          >
            <span className={cn('text-base font-semibold tabular-nums', cls)}>{n}</span>
            <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
          </button>
        )
      })}
      <div className="ml-auto text-sm text-muted-foreground">
        <span className="font-semibold tabular-nums text-foreground">{counts.total}</span> total
      </div>
    </div>
  )
}
