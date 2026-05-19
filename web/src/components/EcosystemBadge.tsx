import { cn } from '@/lib/utils'

const styles: Record<string, string> = {
  nuget: 'bg-violet-500/20 text-violet-700 border-violet-500/30 dark:text-violet-300',
  npm:   'bg-red-500/20 text-red-700 border-red-500/30 dark:text-red-300',
  pypi:  'bg-amber-500/20 text-amber-800 border-amber-500/30 dark:text-amber-300',
  go:    'bg-cyan-500/20 text-cyan-700 border-cyan-500/30 dark:text-cyan-300',
}

export function EcosystemBadge({ ecosystem, className }: { ecosystem: string; className?: string }) {
  const cls = styles[ecosystem] ?? 'bg-muted text-muted-foreground border-border'
  return (
    <span className={cn('inline-flex items-center rounded-md border px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide', cls, className)}>
      {ecosystem}
    </span>
  )
}
