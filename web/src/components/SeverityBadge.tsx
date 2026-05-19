import { cn } from '@/lib/utils'
import type { Severity } from '@/lib/api'

const styles: Record<Severity, string> = {
  Critical: 'bg-red-600 text-white border-red-700',
  High: 'bg-orange-500 text-white border-orange-600',
  Medium: 'bg-amber-400 text-amber-950 border-amber-500',
  Low: 'bg-sky-200 text-sky-900 border-sky-300 dark:bg-sky-900/40 dark:text-sky-200 dark:border-sky-800',
  Info: 'bg-muted text-muted-foreground border-border',
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide',
        styles[severity],
        className,
      )}
    >
      {severity}
    </span>
  )
}
