import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight, AlertCircle, Boxes, ShieldAlert } from 'lucide-react'
import {
  fetchClients,
  fetchProjects,
  fetchComponents,
  fetchAggregates,
} from '@/lib/api'
import type { AggregatesFilters } from '@/lib/api'
import { RingChart } from '@/components/RingChart'
import { cn } from '@/lib/utils'

type Selection =
  | { kind: 'all' }
  | { kind: 'client'; clientId: string }
  | { kind: 'project'; projectId: string }
  | { kind: 'component'; componentId: string }

function toFilters(sel: Selection): AggregatesFilters {
  switch (sel.kind) {
    case 'client':    return { clientId: sel.clientId }
    case 'project':   return { projectId: sel.projectId }
    case 'component': return { componentId: sel.componentId }
    default:          return {}
  }
}

export function OverviewView() {
  const [selection, setSelection] = useState<Selection>({ kind: 'all' })

  const aggregates = useQuery({
    queryKey: ['aggregates', selection],
    queryFn: () => fetchAggregates(toFilters(selection)),
  })

  return (
    <div className="grid grid-cols-[300px_1fr] gap-6">
      <aside>
        <HierarchyTree selection={selection} onSelect={setSelection} />
      </aside>
      <main className="space-y-6">
        {aggregates.isLoading && (
          <p className="text-sm text-muted-foreground">Loading…</p>
        )}
        {aggregates.isError && (
          <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
            <AlertCircle className="size-5 text-destructive" />
            <div>
              <p className="text-sm font-medium">Couldn't load aggregates</p>
              <p className="text-xs text-muted-foreground">{(aggregates.error as Error)?.message}</p>
            </div>
          </div>
        )}
        {aggregates.data && (
          <>
            <header>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">
                {aggregates.data.scope.level} view
              </p>
              <h2 className="mt-0.5 text-2xl font-semibold tracking-tight">
                {aggregates.data.scope.label}
              </h2>
            </header>

            <section className="grid grid-cols-[auto_1fr] gap-8 rounded-md border bg-card p-6">
              <RingChart
                counts={aggregates.data.findings.counts}
                title="Findings by severity"
              />
              <div className="space-y-4">
                <Metric icon={<ShieldAlert className="size-5" />} label="Open findings" value={aggregates.data.findings.counts.total} />
                <Metric icon={<Boxes className="size-5" />} label="SBOM components" value={aggregates.data.sbom.componentsCount} />
                <Metric icon={<ShieldAlert className="size-5 text-destructive" />} label="Known CVEs" value={aggregates.data.sbom.vulnerabilitiesCount} highlight={aggregates.data.sbom.vulnerabilitiesCount > 0} />

                <Breakdown title="By scanner" map={aggregates.data.findings.byScanner} />
                <Breakdown title="By status" map={aggregates.data.findings.byStatus} />
                <Breakdown title="By ecosystem" map={aggregates.data.sbom.byEcosystem} />
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  )
}

function HierarchyTree({
  selection,
  onSelect,
}: {
  selection: Selection
  onSelect: (s: Selection) => void
}) {
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const [expandedClients, setExpandedClients] = useState<Set<string>>(new Set())
  const [expandedProjects, setExpandedProjects] = useState<Set<string>>(new Set())

  const toggleClient = (id: string) =>
    setExpandedClients(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })
  const toggleProject = (id: string) =>
    setExpandedProjects(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })

  return (
    <div className="rounded-md border bg-card p-2">
      <TreeRow
        active={selection.kind === 'all'}
        depth={0}
        onClick={() => onSelect({ kind: 'all' })}
      >
        <span className="font-medium">All</span>
      </TreeRow>

      {clients.data?.map(c => {
        const expanded = expandedClients.has(c.id)
        const active = selection.kind === 'client' && selection.clientId === c.id
        return (
          <div key={c.id}>
            <TreeRow
              depth={1}
              active={active}
              expandable
              expanded={expanded}
              onToggle={() => toggleClient(c.id)}
              onClick={() => onSelect({ kind: 'client', clientId: c.id })}
            >
              <span className="font-medium">{c.name}</span>
              <span className="ml-auto text-xs text-muted-foreground">{c.projectCount}p</span>
            </TreeRow>
            {expanded && <ProjectsBranch clientId={c.id} selection={selection} onSelect={onSelect} expanded={expandedProjects} onToggleProject={toggleProject} />}
          </div>
        )
      })}
    </div>
  )
}

function ProjectsBranch({
  clientId, selection, onSelect, expanded, onToggleProject,
}: {
  clientId: string
  selection: Selection
  onSelect: (s: Selection) => void
  expanded: Set<string>
  onToggleProject: (id: string) => void
}) {
  const projects = useQuery({
    queryKey: ['projects', clientId],
    queryFn: () => fetchProjects(clientId),
  })

  if (projects.isLoading) return <div className="px-8 py-1 text-xs text-muted-foreground">Loading…</div>
  return (
    <>
      {projects.data?.map(p => {
        const isExpanded = expanded.has(p.id)
        const active = selection.kind === 'project' && selection.projectId === p.id
        return (
          <div key={p.id}>
            <TreeRow
              depth={2}
              active={active}
              expandable
              expanded={isExpanded}
              onToggle={() => onToggleProject(p.id)}
              onClick={() => onSelect({ kind: 'project', projectId: p.id })}
            >
              <span>{p.name}</span>
              <span className="ml-auto text-xs text-muted-foreground">{p.componentCount}c</span>
            </TreeRow>
            {isExpanded && <ComponentsBranch projectId={p.id} selection={selection} onSelect={onSelect} />}
          </div>
        )
      })}
    </>
  )
}

function ComponentsBranch({
  projectId, selection, onSelect,
}: {
  projectId: string
  selection: Selection
  onSelect: (s: Selection) => void
}) {
  const components = useQuery({
    queryKey: ['components', projectId],
    queryFn: () => fetchComponents(projectId),
  })

  if (components.isLoading) return <div className="px-12 py-1 text-xs text-muted-foreground">Loading…</div>
  return (
    <>
      {components.data?.map(c => {
        const active = selection.kind === 'component' && selection.componentId === c.id
        return (
          <TreeRow
            key={c.id}
            depth={3}
            active={active}
            onClick={() => onSelect({ kind: 'component', componentId: c.id })}
          >
            <span>{c.name}</span>
            {c.kind && (
              <span className="ml-auto text-xs text-muted-foreground">{c.kind}</span>
            )}
          </TreeRow>
        )
      })}
    </>
  )
}

function TreeRow({
  depth, active, children, onClick, expandable, expanded, onToggle,
}: {
  depth: number
  active: boolean
  expandable?: boolean
  expanded?: boolean
  children: React.ReactNode
  onClick?: () => void
  onToggle?: () => void
}) {
  return (
    <div className={cn(
      'flex items-center gap-1 rounded-md px-2 py-1 text-sm hover:bg-muted/40',
      active && 'bg-muted',
    )}>
      <div style={{ width: depth * 14 }} />
      {expandable ? (
        <button
          type="button"
          onClick={onToggle}
          className="rounded p-0.5 hover:bg-muted/60"
          aria-label={expanded ? 'Collapse' : 'Expand'}
        >
          <ChevronRight className={cn('size-3.5 transition-transform', expanded && 'rotate-90')} />
        </button>
      ) : (
        <div className="size-[18px]" />
      )}
      <button
        type="button"
        onClick={onClick}
        className="flex flex-1 items-center text-left"
      >
        {children}
      </button>
    </div>
  )
}

function Metric({
  icon, label, value, highlight,
}: { icon: React.ReactNode; label: string; value: number; highlight?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <div className={cn('rounded-md border bg-background p-2 text-muted-foreground', highlight && 'border-destructive/50 text-destructive')}>
        {icon}
      </div>
      <div>
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
        <p className={cn('text-xl font-semibold tabular-nums', highlight && 'text-destructive')}>{value}</p>
      </div>
    </div>
  )
}

function Breakdown({ title, map }: { title: string; map: Record<string, number> }) {
  const entries = Object.entries(map)
  if (entries.length === 0) return null
  return (
    <div>
      <p className="mb-1 text-xs uppercase tracking-wide text-muted-foreground">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {entries.map(([k, v]) => (
          <span key={k} className="inline-flex items-baseline gap-1 rounded-md border bg-background px-2 py-0.5 text-xs">
            <span className="font-semibold tabular-nums">{v}</span>
            <span className="text-muted-foreground">{k}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
