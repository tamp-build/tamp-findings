import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ChevronRight, FileCode } from 'lucide-react'
import { fetchCoverageTree, fetchCoverageClass } from '@/lib/api'
import type { CoverageTreeModule, CoverageTreeClass } from '@/lib/api'
import { cn } from '@/lib/utils'

// Two-pane Coverage view modeled on VS Test Explorer:
//   left  — Module → Class tree, each row colored by its own coverage %
//   right — Source viewer for the selected class with line-level red/green
//           backgrounds (red = unvisited executable, green = visited).
//
// Lines not in either VisitedLines or UnvisitedLines are non-executable
// (comments, blank, declarations); the source viewer renders them with a
// neutral background so the eye reads them as "doesn't count."
export function CoverageView() {
  const tree = useQuery({
    queryKey: ['coverage-tree'],
    queryFn: () => fetchCoverageTree(),
  })

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // Auto-expand all modules + select the first class on first load so the
  // user lands on something rather than a wall of collapsed nodes.
  const expandedEffective = useMemo(() => {
    if (expanded.size > 0 || !tree.data) return expanded
    return new Set(tree.data.modules.map(m => m.name))
  }, [expanded, tree.data])

  const effectiveSelectedId = useMemo(() => {
    if (selectedId) return selectedId
    if (!tree.data) return null
    for (const m of tree.data.modules) {
      if (m.classes.length > 0) return m.classes[0].id
    }
    return null
  }, [selectedId, tree.data])

  const detail = useQuery({
    queryKey: ['coverage-class', effectiveSelectedId],
    queryFn: () => fetchCoverageClass(effectiveSelectedId!),
    enabled: !!effectiveSelectedId,
  })

  if (tree.isLoading) return <p className="text-sm text-muted-foreground">Loading coverage…</p>
  if (tree.isError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
        <AlertCircle className="size-5 text-destructive" />
        <div>
          <p className="text-sm font-medium">Couldn't load coverage tree</p>
          <p className="text-xs text-muted-foreground">{(tree.error as Error)?.message}</p>
        </div>
      </div>
    )
  }
  if (!tree.data?.measured) {
    return (
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        No coverage report in scope. Run <code>nuke Ingest</code> after a Test run to populate this view.
      </div>
    )
  }

  const overall = tree.data.sequenceCoverage ?? 0

  return (
    <div className="grid grid-cols-[320px_1fr] gap-4">
      <aside className="space-y-2">
        <header className="rounded-md border bg-card p-3">
          <p className="text-xs uppercase tracking-wide text-muted-foreground">Test coverage</p>
          <p className={cn('mt-0.5 text-2xl font-semibold tabular-nums', tierTextClass(overall))}>
            {overall.toFixed(1)}%
          </p>
          <p className="text-xs text-muted-foreground tabular-nums">
            {tree.data.coveredSequences} / {tree.data.totalSequences} lines
          </p>
        </header>

        <div className="rounded-md border bg-card p-2 max-h-[calc(100vh-220px)] overflow-auto">
          {tree.data.modules.map(m => (
            <ModuleNode
              key={m.name}
              module={m}
              expanded={expandedEffective.has(m.name)}
              onToggle={() => setExpanded(p => {
                const n = new Set(p.size === 0 ? Array.from(expandedEffective) : p)
                n.has(m.name) ? n.delete(m.name) : n.add(m.name)
                return n
              })}
              selectedId={effectiveSelectedId}
              onSelectClass={setSelectedId}
            />
          ))}
        </div>
      </aside>

      <main className="rounded-md border bg-card min-h-[400px]">
        {!effectiveSelectedId && (
          <p className="p-6 text-sm text-muted-foreground">Select a class from the tree to view its source.</p>
        )}
        {effectiveSelectedId && detail.isLoading && (
          <p className="p-6 text-sm text-muted-foreground">Loading source…</p>
        )}
        {effectiveSelectedId && detail.isError && (
          <p className="p-6 text-sm text-destructive">Couldn't load source: {(detail.error as Error)?.message}</p>
        )}
        {effectiveSelectedId && detail.data && (
          <SourceViewer detail={detail.data} />
        )}
      </main>
    </div>
  )
}

function ModuleNode({
  module,
  expanded,
  onToggle,
  selectedId,
  onSelectClass,
}: {
  module: CoverageTreeModule
  expanded: boolean
  onToggle: () => void
  selectedId: string | null
  onSelectClass: (id: string) => void
}) {
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        className={cn(
          'flex w-full items-center gap-1 rounded-md px-2 py-1 text-sm hover:bg-muted/40',
        )}
      >
        <ChevronRight className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
        <CoverageDot pct={module.sequenceCoverage} />
        <span className="flex-1 truncate text-left font-medium">{module.name}</span>
        <span className={cn('ml-auto text-[11px] tabular-nums', tierTextClass(module.sequenceCoverage))}>
          {module.sequenceCoverage.toFixed(1)}%
        </span>
      </button>
      {expanded && (
        <div className="ml-6 mt-0.5 space-y-0.5">
          {module.classes.length === 0 && (
            <p className="px-2 py-1 text-[11px] italic text-muted-foreground">
              No classes — re-run Ingest after the schema change to populate.
            </p>
          )}
          {module.classes.map(c => (
            <ClassRow key={c.id} cls={c} selected={c.id === selectedId} onClick={() => onSelectClass(c.id)} />
          ))}
        </div>
      )}
    </div>
  )
}

function ClassRow({
  cls, selected, onClick,
}: {
  cls: CoverageTreeClass
  selected: boolean
  onClick: () => void
}) {
  // Strip namespace for the row label; the full name shows on hover.
  const short = cls.fullName.split('.').pop() ?? cls.fullName
  return (
    <button
      type="button"
      onClick={onClick}
      title={`${cls.fullName}\n${cls.sourceFileRelativePath}`}
      className={cn(
        'flex w-full items-center gap-1.5 rounded-md px-2 py-1 text-left text-xs hover:bg-muted/40',
        selected && 'bg-muted',
      )}
    >
      <FileCode className="size-3 text-muted-foreground" />
      <CoverageDot pct={cls.sequenceCoverage} />
      <span className="flex-1 truncate">{short}</span>
      <span className={cn('text-[10px] tabular-nums', tierTextClass(cls.sequenceCoverage))}>
        {cls.sequenceCoverage.toFixed(0)}%
      </span>
    </button>
  )
}

function CoverageDot({ pct }: { pct: number }) {
  const color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#f59e0b' : '#dc2626'
  return <span className="inline-block size-2 rounded-full" style={{ background: color }} />
}

function tierTextClass(pct: number): string {
  if (pct >= 80) return 'text-emerald-700 dark:text-emerald-400'
  if (pct >= 60) return 'text-amber-700 dark:text-amber-400'
  return 'text-red-700 dark:text-red-400'
}

function SourceViewer({ detail }: { detail: { sourceText: string; visitedLines: number[]; unvisitedLines: number[]; fullName: string; moduleName: string; sourceFileRelativePath: string; sequenceCoverage: number; coveredSequences: number; totalSequences: number } }) {
  const visited = useMemo(() => new Set(detail.visitedLines), [detail.visitedLines])
  const unvisited = useMemo(() => new Set(detail.unvisitedLines), [detail.unvisitedLines])
  const lines = useMemo(() => detail.sourceText.split('\n'), [detail.sourceText])

  return (
    <div className="flex h-full flex-col">
      <header className="border-b px-4 py-3">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{detail.moduleName}</p>
        <p className="font-semibold">{detail.fullName}</p>
        <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
          <span className="font-mono">{detail.sourceFileRelativePath}</span>
          <span>·</span>
          <span className={cn('tabular-nums', tierTextClass(detail.sequenceCoverage))}>
            {detail.sequenceCoverage.toFixed(1)}% · {detail.coveredSequences}/{detail.totalSequences} lines
          </span>
        </div>
      </header>

      <div className="overflow-auto max-h-[calc(100vh-280px)]">
        {detail.sourceText.length === 0 ? (
          <p className="p-6 text-sm text-muted-foreground">No source text was captured for this class.</p>
        ) : (
          <pre className="text-[12px] leading-[1.4] font-mono">
            {lines.map((line, i) => {
              const lineNum = i + 1
              const isVisited = visited.has(lineNum)
              const isUnvisited = unvisited.has(lineNum)
              return (
                <div
                  key={lineNum}
                  className={cn(
                    'flex',
                    // Subtle backgrounds — the eye reads color but the code stays legible.
                    isVisited && 'bg-emerald-500/15',
                    isUnvisited && 'bg-red-500/20',
                  )}
                >
                  <span className="w-12 select-none px-2 text-right tabular-nums text-muted-foreground/70 border-r">
                    {lineNum}
                  </span>
                  <span className="whitespace-pre px-3">{line || ' '}</span>
                </div>
              )
            })}
          </pre>
        )}
      </div>
    </div>
  )
}
