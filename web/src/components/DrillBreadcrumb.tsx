import { useQuery } from '@tanstack/react-query'
import { fetchClients, fetchProjects } from '@/lib/api'

// Breadcrumb back to the project context for any detail view drilled
// into from ProjectPageView (Coverage / Components / Findings / Tests).
// Renders nothing when no project context is set — the detail views
// can still be reached via legacy paths today, and we don't want to
// surface a misleading breadcrumb when we don't know where the user
// came from.
export function DrillBreadcrumb({
  clientId,
  projectId,
  currentLabel,
  onSelectOverview,
  onSelectClient,
  onSelectProject,
}: {
  clientId: string | null
  projectId: string | null
  currentLabel: string
  onSelectOverview: () => void
  onSelectClient: (clientId: string) => void
  onSelectProject: (projectId: string) => void
}) {
  // Names are looked up from the same /clients + /projects queries the
  // hierarchy tree already caches, so this is usually free.
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const projects = useQuery({ queryKey: ['projects', null], queryFn: () => fetchProjects() })

  if (!projectId) return null
  const project = projects.data?.find(p => p.id === projectId)
  const resolvedClientId = clientId ?? project?.clientId ?? null
  const client = resolvedClientId ? clients.data?.find(c => c.id === resolvedClientId) : null

  return (
    <nav className="mb-4 flex items-baseline gap-2 text-sm">
      <button
        type="button"
        onClick={onSelectOverview}
        className="text-muted-foreground hover:text-foreground"
      >
        All clients
      </button>
      <span className="text-muted-foreground">/</span>
      <button
        type="button"
        onClick={() => resolvedClientId && onSelectClient(resolvedClientId)}
        className="text-muted-foreground hover:text-foreground"
      >
        {client?.name ?? '…'}
      </button>
      <span className="text-muted-foreground">/</span>
      <button
        type="button"
        onClick={() => onSelectProject(projectId)}
        className="text-muted-foreground hover:text-foreground"
      >
        {project?.name ?? '…'}
      </button>
      <span className="text-muted-foreground">/</span>
      <span className="font-semibold">{currentLabel}</span>
    </nav>
  )
}
