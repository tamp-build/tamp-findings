import { useQuery } from '@tanstack/react-query'
import { ChevronLeft } from 'lucide-react'
import { fetchClients, fetchProjects } from '@/lib/api'
import { ScopeCard } from '@/components/ScopeCard'

// One client's page. Lists project cards underneath the client; each
// project card is itself a link to that project's detail page (where
// rings and tables become drillable into Findings / Components / etc).
export function ClientPageView({
  clientId,
  onBack,
  onSelectProject,
}: {
  clientId: string
  onBack: () => void
  onSelectProject: (projectId: string) => void
}) {
  // Resolve the client name for the breadcrumb without firing a dedicated
  // GET. /clients is already cached by react-query in most flows.
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const client = clients.data?.find(c => c.id === clientId) ?? null

  const projects = useQuery({
    queryKey: ['projects', clientId],
    queryFn: () => fetchProjects(clientId),
  })

  return (
    <div className="space-y-4">
      <nav className="flex items-baseline gap-2 text-sm">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="size-3.5" /> All clients
        </button>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">{client?.name ?? '…'}</span>
      </nav>

      {projects.isLoading && <p className="text-sm text-muted-foreground">Loading projects…</p>}

      {projects.data && projects.data.length === 0 && (
        <div className="rounded-md border bg-card p-6 text-sm">
          <p className="font-medium">No projects yet</p>
          <p className="text-muted-foreground">
            Add a project under <strong>{client?.name}</strong> from the <strong>+</strong> menu in the header.
          </p>
        </div>
      )}

      <div className="space-y-3 sm:space-y-6">
        {projects.data?.map(p => (
          <ScopeCard
            key={p.id}
            scope={{ kind: 'project', id: p.id, name: p.name }}
            onCardClick={() => onSelectProject(p.id)}
          />
        ))}
      </div>
    </div>
  )
}
