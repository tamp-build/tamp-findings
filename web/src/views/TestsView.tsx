import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ChevronRight, CheckCircle2, XCircle, MinusCircle } from 'lucide-react'
import { fetchTestResultsTree, fetchTestSuite } from '@/lib/api'
import type { TestTreeAssembly, TestTreeSuite, TestCaseDetail, TestOutcome } from '@/lib/api'
import { cn } from '@/lib/utils'

// TFND-20: Tests tab. Mirrors CoverageView's two-pane structure:
//   left  — Assembly → Test class tree, rows colored by worst outcome
//   right — Suite detail: case list with outcome + duration + error message
//           for failed cases.

const OUTCOME_DOT: Record<TestOutcome, string> = {
  Passed:       'bg-emerald-500',
  Failed:       'bg-red-600',
  Skipped:      'bg-yellow-400',
  Inconclusive: 'bg-slate-400',
}

export function TestsView() {
  const tree = useQuery({
    queryKey: ['test-results-tree'],
    queryFn: () => fetchTestResultsTree(),
  })

  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const toggleAssembly = (name: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })

  const detail = useQuery({
    queryKey: ['test-suite', selectedId],
    queryFn: () => fetchTestSuite(selectedId!),
    enabled: !!selectedId,
  })

  if (tree.isLoading) return <p className="text-sm text-muted-foreground">Loading tests…</p>
  if (tree.isError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
        <AlertCircle className="size-5 text-destructive" />
        <div>
          <p className="text-sm font-medium">Couldn't load test results</p>
          <p className="text-xs text-muted-foreground">{(tree.error as Error)?.message}</p>
        </div>
      </div>
    )
  }
  if (!tree.data?.measured) {
    return (
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        No test results in scope. Run <code>nuke Test Ingest</code> to populate.
      </div>
    )
  }

  const data = tree.data
  const overallTone = data.failedCount > 0
    ? 'text-red-700 dark:text-red-400'
    : 'text-emerald-700 dark:text-emerald-400'

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="space-y-2">
        <header className="rounded-md border bg-card p-3">
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Tests</p>
          <p className={cn('mt-0.5 text-2xl font-semibold tabular-nums', overallTone)}>
            {data.passedCount} / {data.totalCount}
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] tabular-nums">
            <Pill icon={<CheckCircle2 className="size-3" />} tone="emerald" label={`${data.passedCount} passed`} />
            {data.failedCount > 0 && (
              <Pill icon={<XCircle className="size-3" />} tone="red" label={`${data.failedCount} failed`} />
            )}
            {data.skippedCount > 0 && (
              <Pill icon={<MinusCircle className="size-3" />} tone="yellow" label={`${data.skippedCount} skipped`} />
            )}
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {data.durationMs.toFixed(0)} ms total · {data.completedAt ? new Date(data.completedAt).toLocaleString() : '—'}
          </p>
        </header>

        <div className="rounded-md border bg-card p-2 max-h-[calc(100vh-260px)] overflow-auto">
          {data.assemblies.map(a => (
            <AssemblyNode
              key={a.name}
              assembly={a}
              expanded={expanded.has(a.name)}
              onToggle={() => toggleAssembly(a.name)}
              selectedId={selectedId}
              onSelectSuite={setSelectedId}
            />
          ))}
        </div>
      </aside>

      <main className="rounded-md border bg-card min-h-[400px]">
        {!selectedId && (
          <p className="p-6 text-sm text-muted-foreground">Select a test class from the tree to view its cases.</p>
        )}
        {selectedId && detail.isLoading && (
          <p className="p-6 text-sm text-muted-foreground">Loading suite…</p>
        )}
        {selectedId && detail.isError && (
          <p className="p-6 text-sm text-destructive">Couldn't load suite: {(detail.error as Error)?.message}</p>
        )}
        {selectedId && detail.data && (
          <SuiteDetail detail={detail.data} />
        )}
      </main>
    </div>
  )
}

function AssemblyNode({
  assembly, expanded, onToggle, selectedId, onSelectSuite,
}: {
  assembly: TestTreeAssembly
  expanded: boolean
  onToggle: () => void
  selectedId: string | null
  onSelectSuite: (id: string) => void
}) {
  const dot = assembly.failedCount > 0
    ? OUTCOME_DOT.Failed
    : assembly.skippedCount > 0 ? OUTCOME_DOT.Skipped : OUTCOME_DOT.Passed
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-1 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
      >
        <ChevronRight className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
        <span className={cn('inline-block size-2 rounded-full', dot)} />
        <span className="flex-1 truncate text-left font-medium">{assembly.name}</span>
        <span className="ml-auto text-[11px] tabular-nums text-muted-foreground">
          {assembly.passedCount}/{assembly.totalCount}
        </span>
      </button>
      {expanded && (
        <div className="ml-6 mt-0.5 space-y-0.5">
          {assembly.suites.map(s => (
            <SuiteRow
              key={s.id}
              suite={s}
              selected={s.id === selectedId}
              onClick={() => onSelectSuite(s.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function SuiteRow({
  suite, selected, onClick,
}: {
  suite: TestTreeSuite
  selected: boolean
  onClick: () => void
}) {
  const short = suite.className.split('.').pop() ?? suite.className
  const dot = suite.failedCount > 0
    ? OUTCOME_DOT.Failed
    : suite.skippedCount > 0 ? OUTCOME_DOT.Skipped : OUTCOME_DOT.Passed
  return (
    <button
      type="button"
      onClick={onClick}
      title={suite.className}
      className={cn(
        'flex w-full items-center gap-1.5 rounded-md px-2 py-1 text-left text-xs hover:bg-muted/40',
        selected && 'bg-muted',
      )}
    >
      <span className={cn('inline-block size-2 rounded-full', dot)} />
      <span className="flex-1 truncate">{short}</span>
      <span className="text-[10px] tabular-nums text-muted-foreground">
        {suite.passedCount}/{suite.totalCount}
      </span>
    </button>
  )
}

function Pill({ icon, tone, label }: { icon: React.ReactNode; tone: 'emerald' | 'red' | 'yellow'; label: string }) {
  const cls = {
    emerald: 'text-emerald-700 dark:text-emerald-400',
    red:     'text-red-700 dark:text-red-400',
    yellow:  'text-yellow-700 dark:text-yellow-400',
  }[tone]
  return <span className={cn('inline-flex items-center gap-1', cls)}>{icon}{label}</span>
}

function SuiteDetail({ detail }: { detail: { assemblyName: string; className: string; totalCount: number; passedCount: number; failedCount: number; skippedCount: number; durationMs: number; cases: TestCaseDetail[] } }) {
  const failedFirst = useMemo(() => [...detail.cases].sort((a, b) => {
    if (a.outcome === 'Failed' && b.outcome !== 'Failed') return -1
    if (b.outcome === 'Failed' && a.outcome !== 'Failed') return 1
    return a.name.localeCompare(b.name)
  }), [detail.cases])

  return (
    <div className="flex h-full flex-col">
      <header className="border-b px-4 py-3">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{detail.assemblyName}</p>
        <p className="font-semibold">{detail.className}</p>
        <p className="mt-1 text-xs text-muted-foreground tabular-nums">
          {detail.passedCount}p / {detail.failedCount}f / {detail.skippedCount}s · {detail.durationMs.toFixed(0)} ms · {detail.cases.length} cases
        </p>
      </header>

      <ul className="divide-y max-h-[calc(100vh-260px)] overflow-auto">
        {failedFirst.map((c, i) => (
          <li key={`${c.name}-${i}`} className={cn(c.outcome === 'Failed' && 'bg-red-500/5')}>
            <div className="flex items-start gap-2 px-4 py-2">
              <span className={cn('mt-1 inline-block size-2 rounded-full shrink-0', OUTCOME_DOT[c.outcome])} />
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2">
                  <span className="font-mono text-xs truncate">{c.name}</span>
                  <span className="ml-auto text-[11px] tabular-nums text-muted-foreground">
                    {c.durationMs.toFixed(c.durationMs < 10 ? 2 : 0)} ms
                  </span>
                </div>
                {c.outcome === 'Failed' && c.errorMessage && (
                  <pre className="mt-1 whitespace-pre-wrap rounded border border-red-500/20 bg-red-500/5 p-2 text-[11px] text-red-800 dark:text-red-300">
                    {c.errorMessage}
                  </pre>
                )}
                {c.outcome === 'Failed' && c.errorStackTrace && (
                  <pre className="mt-1 whitespace-pre-wrap rounded border bg-muted/30 p-2 font-mono text-[10px] text-muted-foreground max-h-40 overflow-auto">
                    {c.errorStackTrace}
                  </pre>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
