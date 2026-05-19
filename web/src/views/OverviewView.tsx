import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight, AlertCircle } from 'lucide-react'
import {
  fetchClients,
  fetchProjects,
  fetchComponents,
  fetchAggregates,
} from '@/lib/api'
import type { AggregatesFilters, ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import type { FindingsPreset, ComponentsPreset } from '@/App'
import { RingChart, FindingsTypeTable, SbomHealthTable, SecretsHealthTable } from '@/components/RingChart'

// Which Findings filter does a Code-Quality table row map to? Severities
// fold into the severity filter (default-status Open); the lifecycle
// rows (closed/suppressed/accepted) clear severity and switch the
// status filter so the user lands on the right population.
const SEVERITY_FROM_SEGMENT: Record<string, Severity | undefined> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}
const STATUS_FROM_SEGMENT: Record<string, FindingStatus | undefined> = {
  closed: 'Fixed', suppressed: 'Suppressed', accepted: 'Accepted',
}
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

export function OverviewView({
  onDrillToFindings,
  onDrillToComponents,
}: {
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
}) {
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

            <section className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-6 rounded-md border bg-card p-6">
              <RingChart
                scannerDetails={aggregates.data.findings.byScannerDetail}
                sbomHealth={aggregates.data.sbom.health}
                secretsHealth={aggregates.data.secrets.health}
                onScannerClick={(scanner) =>
                  onDrillToFindings?.({ scanners: [scanner as ScannerKind] })
                }
                onSbomClick={() => onDrillToComponents?.()}
                onSecretsClick={() => onDrillToFindings?.({ scanners: ['TruffleHog'] })}
              />
              <div className="grid grid-cols-3 gap-4">
                <FindingsTypeTable
                  scannerDetails={aggregates.data.findings.byScannerDetail}
                  onRowClick={(segment, scanner) => {
                    const sev = SEVERITY_FROM_SEGMENT[segment]
                    const status = STATUS_FROM_SEGMENT[segment]
                    onDrillToFindings?.({
                      scanners: [scanner as ScannerKind],
                      severities: sev ? [sev] : [],
                      statuses: status ? [status] : [],
                    })
                  }}
                />
                <SbomHealthTable
                  health={aggregates.data.sbom.health}
                  onRowClick={(bucket) => onDrillToComponents?.({ sbomStatus: bucket as SbomHealthStatus })}
                />
                <SecretsHealthTable
                  health={aggregates.data.secrets.health}
                  onRowClick={(bucket) => onDrillToFindings?.({
                    scanners: ['TruffleHog'],
                    severities: bucket === 'verified' ? ['Critical'] : ['High'],
                  })}
                />
              </div>
            </section>

            <section className="grid grid-cols-3 gap-3 text-sm">
              <ContextTile label="Open findings (all scanners)" value={aggregates.data.findings.counts.total} />
              <ContextTile label="SBOM components" value={aggregates.data.sbom.componentsCount} />
              <ContextTile label="Known CVEs" value={aggregates.data.sbom.vulnerabilitiesCount} alert={aggregates.data.sbom.vulnerabilitiesCount > 0} />
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

function ContextTile({ label, value, alert }: { label: string; value: number; alert?: boolean }) {
  return (
    <div className={cn(
      'rounded-md border bg-card px-3 py-2',
      alert && 'border-destructive/50',
    )}>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn('mt-0.5 text-xl font-semibold tabular-nums', alert && 'text-destructive')}>{value}</p>
    </div>
  )
}
