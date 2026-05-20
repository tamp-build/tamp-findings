import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ChevronRight, FileCode } from 'lucide-react'
import { fetchFindingsTree, fetchFindingsFile } from '@/lib/api'
import type { FindingsTreeModule, FindingsTreeFile, FindingsFileItem, Severity } from '@/lib/api'
import type { FindingsPreset } from '@/App'
import { cn } from '@/lib/utils'

// FindingsView mirrors CoverageView's two-pane Test Explorer:
//   left  — Module → File tree, each row colored by its worst finding's severity
//   right — Source viewer with severity-tinted line backgrounds + a findings
//           list below, ordered by line.
//
// Search and scanner-filter sidebars from the old list-based view are gone —
// scanner-agnostic was the explicit design decision. Severity filtering is
// expressed via tree row coloring (max severity per file) so the eye finds
// the worst files first.

const SEV_BG: Record<Severity, string> = {
  Critical: 'bg-red-600/25',
  High:     'bg-orange-500/25',
  Medium:   'bg-amber-500/25',
  Low:      'bg-yellow-400/20',
  Info:     'bg-sky-400/20',
}
const SEV_DOT: Record<Severity, string> = {
  Critical: 'bg-red-600',
  High:     'bg-orange-500',
  Medium:   'bg-amber-500',
  Low:      'bg-yellow-400',
  Info:     'bg-sky-400',
}
const SEV_TEXT: Record<Severity, string> = {
  Critical: 'text-red-700 dark:text-red-300',
  High:     'text-orange-700 dark:text-orange-300',
  Medium:   'text-amber-700 dark:text-amber-300',
  Low:      'text-yellow-700 dark:text-yellow-300',
  Info:     'text-sky-700 dark:text-sky-300',
}
const SEV_RANK: Record<Severity, number> = { Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 }

export function FindingsView({
  search: _search,
  preset,
}: {
  // Search is retained for prop compatibility; the tree-based view doesn't
  // surface free-text search. Preset is honoured for the ruleId filter
  // (TFND-18) — drilling from Overview's Top Rules table lands here scoped
  // to that single rule.
  search: string
  preset: FindingsPreset
}) {
  const [ruleFilter, setRuleFilter] = useState<string | null>(preset.ruleId ?? null)
  // Re-seed when the user clicks a new top-rule row (nonce bumps).
  useEffect(() => { setRuleFilter(preset.ruleId ?? null) }, [preset.nonce, preset.ruleId])

  const tree = useQuery({
    queryKey: ['findings-tree', ruleFilter],
    queryFn: () => fetchFindingsTree({ ruleId: ruleFilter ?? undefined }),
  })

  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  // Reset tree expansion + selection when the rule filter changes so the
  // user lands on a clean state showing only files that match the rule.
  useEffect(() => { setExpanded(new Set()); setSelectedPath(null) }, [ruleFilter])

  const toggleModule = (name: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })

  const detail = useQuery({
    queryKey: ['findings-file', selectedPath, ruleFilter],
    queryFn: () => fetchFindingsFile(selectedPath!, ruleFilter ?? undefined),
    enabled: !!selectedPath,
  })

  if (tree.isLoading) return <p className="text-sm text-muted-foreground">Loading findings…</p>
  if (tree.isError) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
        <AlertCircle className="size-5 text-destructive" />
        <div>
          <p className="text-sm font-medium">Couldn't load findings tree</p>
          <p className="text-xs text-muted-foreground">{(tree.error as Error)?.message}</p>
        </div>
      </div>
    )
  }
  if (!tree.data || tree.data.totalCount === 0) {
    return (
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        No findings in scope. Run <code>nuke ScanAll Ingest</code> to populate.
      </div>
    )
  }

  const overall = tree.data.counts

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="space-y-2">
        <header className="rounded-md border bg-card p-3">
          <p className="text-xs uppercase tracking-wide text-muted-foreground">
            {ruleFilter ? 'Findings · filtered' : 'Findings'}
          </p>
          <p className="mt-0.5 text-2xl font-semibold tabular-nums">{tree.data.totalCount}</p>
          <SeverityCountsRow counts={overall} />
          {ruleFilter && (
            <div className="mt-1 flex items-center justify-between gap-2 rounded border bg-muted/40 px-2 py-1 text-[11px]">
              <span className="truncate font-mono" title={ruleFilter}>{ruleFilter}</span>
              <button
                type="button"
                onClick={() => setRuleFilter(null)}
                className="shrink-0 text-muted-foreground hover:text-foreground"
              >
                clear
              </button>
            </div>
          )}
          {tree.data.noPathCount > 0 && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              {tree.data.noPathCount} additional finding(s) without a file path.
            </p>
          )}
        </header>

        <div className="rounded-md border bg-card p-2 max-h-[calc(100vh-260px)] overflow-auto">
          {tree.data.modules.map(m => (
            <ModuleNode
              key={m.name}
              module={m}
              expanded={expanded.has(m.name)}
              onToggle={() => toggleModule(m.name)}
              selectedPath={selectedPath}
              onSelectFile={setSelectedPath}
            />
          ))}
        </div>
      </aside>

      <main className="rounded-md border bg-card min-h-[400px]">
        {!selectedPath && (
          <p className="p-6 text-sm text-muted-foreground">Select a file from the tree to view its source + findings.</p>
        )}
        {selectedPath && detail.isLoading && (
          <p className="p-6 text-sm text-muted-foreground">Loading source…</p>
        )}
        {selectedPath && detail.isError && (
          <p className="p-6 text-sm text-destructive">Couldn't load source: {(detail.error as Error)?.message}</p>
        )}
        {selectedPath && detail.data && (
          <FileDetail detail={detail.data} />
        )}
      </main>
    </div>
  )
}

function ModuleNode({
  module,
  expanded,
  onToggle,
  selectedPath,
  onSelectFile,
}: {
  module: FindingsTreeModule
  expanded: boolean
  onToggle: () => void
  selectedPath: string | null
  onSelectFile: (path: string) => void
}) {
  const maxSev = module.files.reduce<Severity>(
    (worst, f) => (SEV_RANK[f.maxSeverity] > SEV_RANK[worst] ? f.maxSeverity : worst),
    'Info',
  )
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-1 rounded-md px-2 py-1 text-sm hover:bg-muted/40"
      >
        <ChevronRight className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
        <span className={cn('inline-block size-2 rounded-full', SEV_DOT[maxSev])} />
        <span className="flex-1 truncate text-left font-medium">{module.name}</span>
        <span className="ml-auto text-[11px] tabular-nums text-muted-foreground">
          {module.counts.total}
        </span>
      </button>
      {expanded && (
        <div className="ml-6 mt-0.5 space-y-0.5">
          {module.files.map(f => (
            <FileRow
              key={f.relativePath}
              file={f}
              selected={f.relativePath === selectedPath}
              onClick={() => onSelectFile(f.relativePath)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function FileRow({
  file, selected, onClick,
}: {
  file: FindingsTreeFile
  selected: boolean
  onClick: () => void
}) {
  // Strip the leading "src/<module>/" or "web/" prefix so the row reads as
  // the path within its module: "Endpoints/FindingsListEndpoints.cs".
  const short = file.relativePath.replace(/^src\/[^/]+\//, '').replace(/^web\//, '')
  return (
    <button
      type="button"
      onClick={onClick}
      title={file.relativePath}
      className={cn(
        'flex w-full items-center gap-1.5 rounded-md px-2 py-1 text-left text-xs hover:bg-muted/40',
        selected && 'bg-muted',
      )}
    >
      <FileCode className="size-3 text-muted-foreground" />
      <span className={cn('inline-block size-2 rounded-full', SEV_DOT[file.maxSeverity])} />
      <span className="flex-1 truncate">{short}</span>
      <span className="text-[10px] tabular-nums text-muted-foreground">{file.counts.total}</span>
    </button>
  )
}

function SeverityCountsRow({ counts }: { counts: { critical: number; high: number; medium: number; low: number; info: number } }) {
  const items = (['Critical', 'High', 'Medium', 'Low', 'Info'] as Severity[]).map(s => {
    const v = counts[s.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info']
    return { s, v }
  }).filter(x => x.v > 0)
  if (items.length === 0) return null
  return (
    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] tabular-nums">
      {items.map(({ s, v }) => (
        <span key={s} className={cn('inline-flex items-center gap-1', SEV_TEXT[s])}>
          <span className={cn('inline-block size-1.5 rounded-full', SEV_DOT[s])} />
          {v} {s}
        </span>
      ))}
    </div>
  )
}

function FileDetail({ detail }: { detail: { relativePath: string; sourceAvailable: boolean; sourceText: string; findings: FindingsFileItem[] } }) {
  const lines = useMemo(() => detail.sourceText.split('\n'), [detail.sourceText])

  // For each line, pick the worst-severity finding that lands on it. Drives
  // the source-viewer's per-line background tint.
  const worstByLine = useMemo(() => {
    const map = new Map<number, Severity>()
    for (const f of detail.findings) {
      if (f.line == null) continue
      const cur = map.get(f.line)
      if (!cur || SEV_RANK[f.severity] > SEV_RANK[cur]) map.set(f.line, f.severity)
    }
    return map
  }, [detail.findings])

  // Scroll handling: clicking a finding row jumps to + flashes the line.
  const lineRefs = useRef(new Map<number, HTMLDivElement>())
  const [flashLine, setFlashLine] = useState<number | null>(null)
  const scrollToLine = (line: number) => {
    const el = lineRefs.current.get(line)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
    setFlashLine(line)
    setTimeout(() => setFlashLine(prev => (prev === line ? null : prev)), 1400)
  }
  // Group findings by line so the list below can collapse same-line entries.
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of detail.findings) c[f.severity.toLowerCase() as keyof typeof c] += 1
    return c
  }, [detail.findings])

  return (
    <div className="flex h-full flex-col">
      <header className="border-b px-4 py-3">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{detail.findings.length} finding(s)</p>
        <p className="font-mono text-sm">{detail.relativePath}</p>
        <div className="mt-1">
          <SeverityCountsRow counts={counts} />
        </div>
      </header>

      <div className="overflow-auto max-h-[calc(100vh-360px)]">
        {!detail.sourceAvailable ? (
          <p className="p-6 text-sm text-muted-foreground">
            Source isn't captured for this file (no coverage data covers it). The findings list below still works.
          </p>
        ) : (
          <pre className="text-[12px] leading-[1.4] font-mono">
            {lines.map((line, i) => {
              const lineNum = i + 1
              const sev = worstByLine.get(lineNum)
              const flashed = flashLine === lineNum
              return (
                <div
                  key={lineNum}
                  ref={el => { if (el) lineRefs.current.set(lineNum, el); else lineRefs.current.delete(lineNum) }}
                  className={cn(
                    'flex transition-colors',
                    sev && SEV_BG[sev],
                    flashed && 'outline outline-2 outline-primary/60',
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

      <div className="border-t">
        <div className="border-b px-4 py-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Findings on this file
        </div>
        <ul className="divide-y max-h-[280px] overflow-auto">
          {detail.findings.length === 0 && (
            <li className="px-4 py-3 text-sm text-muted-foreground">None</li>
          )}
          {detail.findings.map(f => (
            <li key={f.id}>
              <button
                type="button"
                onClick={() => f.line != null && scrollToLine(f.line)}
                className="flex w-full items-start gap-2 px-4 py-2 text-left text-sm hover:bg-muted/40"
              >
                <span className={cn('mt-1 inline-block size-2 rounded-full shrink-0', SEV_DOT[f.severity])} />
                <span className="w-10 shrink-0 text-right text-xs tabular-nums text-muted-foreground">
                  {f.line ?? '—'}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="font-mono text-xs text-muted-foreground">{f.ruleId}</span>
                  <span className="ml-2">{f.title}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
