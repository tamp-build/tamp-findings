import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight } from 'lucide-react'
import { fetchClients, fetchProjects, fetchComponents } from '@/lib/api'
import { ScopeCard } from '@/components/ScopeCard'
import { cn } from '@/lib/utils'

// Home page. Lists one card per client; clicking anywhere on a card
// navigates to that client's page (which then lists project cards).
// Drill-through into Findings/Components/Coverage/Tests is *not*
// available at this level — you reach details only by clicking through
// to a project card. The hierarchy tree on the left is browse-only.
export function OverviewView({
  onSelectClient,
}: {
  onSelectClient: (clientId: string) => void
}) {
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })

  if (clients.data && clients.data.length === 0) {
    return (
      <div className="rounded-md border bg-card p-6 text-sm">
        <p className="font-medium">No clients yet</p>
        <p className="text-muted-foreground">
          Add a client from the <strong>+</strong> menu in the header to start ingesting findings.
        </p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-[240px_minmax(0,1fr)]">
      <aside>
        <HierarchyTree />
      </aside>
      <main className="space-y-3 sm:space-y-6">
        {clients.data?.map(c => (
          <ScopeCard
            key={c.id}
            scope={{ kind: 'client', id: c.id, name: c.name }}
            onCardClick={() => onSelectClient(c.id)}
          />
        ))}
      </main>
    </div>
  )
}

// Browse-only hierarchy. Chevrons toggle expansion so the user can see
// the tree structure for every client/project/component, but rows are
// not clickable filters today. The real role of this nav will be
// nailed down separately (jump-to-card, pin scope, etc.).
function HierarchyTree() {
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const [expandedClients, setExpandedClients] = useState<Set<string>>(new Set())
  const [expandedProjects, setExpandedProjects] = useState<Set<string>>(new Set())

  const toggleClient = (id: string) =>
    setExpandedClients(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })
  const toggleProject = (id: string) =>
    setExpandedProjects(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })

  return (
    <div className="rounded-md border bg-card p-2">
      {clients.data?.map(c => {
        const expanded = expandedClients.has(c.id)
        return (
          <div key={c.id}>
            <TreeRow
              depth={1}
              expandable
              expanded={expanded}
              onToggle={() => toggleClient(c.id)}
            >
              <span className="font-medium">{c.name}</span>
              <span className="ml-auto text-xs text-muted-foreground">{c.projectCount}p</span>
            </TreeRow>
            {expanded && <ProjectsBranch clientId={c.id} expanded={expandedProjects} onToggleProject={toggleProject} />}
          </div>
        )
      })}
    </div>
  )
}

function ProjectsBranch({
  clientId, expanded, onToggleProject,
}: {
  clientId: string
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
        return (
          <div key={p.id}>
            <TreeRow
              depth={2}
              expandable
              expanded={isExpanded}
              onToggle={() => onToggleProject(p.id)}
            >
              <span>{p.name}</span>
              <span className="ml-auto text-xs text-muted-foreground">{p.componentCount}c</span>
            </TreeRow>
            {isExpanded && <ComponentsBranch projectId={p.id} />}
          </div>
        )
      })}
    </>
  )
}

function ComponentsBranch({ projectId }: { projectId: string }) {
  const components = useQuery({
    queryKey: ['components', projectId],
    queryFn: () => fetchComponents(projectId),
  })

  if (components.isLoading) return <div className="px-12 py-1 text-xs text-muted-foreground">Loading…</div>
  return (
    <>
      {components.data?.map(c => (
        <TreeRow key={c.id} depth={3}>
          <span>{c.name}</span>
          {c.kind && (
            <span className="ml-auto text-xs text-muted-foreground">{c.kind}</span>
          )}
        </TreeRow>
      ))}
    </>
  )
}

function TreeRow({
  depth, children, expandable, expanded, onToggle,
}: {
  depth: number
  expandable?: boolean
  expanded?: boolean
  children: React.ReactNode
  onToggle?: () => void
}) {
  return (
    <div className="flex items-center gap-1 rounded-md px-2 py-1 text-sm hover:bg-muted/40">
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
      <div className="flex flex-1 items-center text-left">
        {children}
      </div>
    </div>
  )
}
