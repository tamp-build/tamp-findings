import { useQuery } from '@tanstack/react-query'
import { ChevronLeft } from 'lucide-react'
import { fetchClients, fetchProjects } from '@/lib/api'
import { ScopeCard } from '@/components/ScopeCard'
import type { FindingsPreset, ComponentsPreset } from '@/App'

// One project's detail page. Single ScopeCard with rings + tables, and
// drill-throughs (ring/row clicks) enabled — clicking lands in the
// Findings / Components / Coverage / Tests views.
export function ProjectPageView({
  projectId,
  onBack,
  onBackToOverview,
  onDrillToFindings,
  onDrillToComponents,
  onDrillToCoverage,
}: {
  projectId: string
  onBack: () => void
  onBackToOverview: () => void
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
  onDrillToCoverage?: () => void
}) {
  // /projects already returns clientId + clientName per row — cheaper
  // than a dedicated project-by-id GET for the breadcrumb.
  const allProjects = useQuery({ queryKey: ['projects', null], queryFn: () => fetchProjects() })
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const project = allProjects.data?.find(p => p.id === projectId) ?? null

  if (allProjects.data && !project) {
    return (
      <div className="rounded-md border bg-card p-6 text-sm">
        <p className="font-medium">Project not found</p>
        <button type="button" onClick={onBackToOverview} className="mt-2 text-muted-foreground hover:text-foreground">
          ← Back to clients
        </button>
      </div>
    )
  }

  const clientName = project?.clientName
    ?? clients.data?.find(c => c.id === project?.clientId)?.name
    ?? '…'

  return (
    <div className="space-y-4">
      <nav className="flex items-baseline gap-2 text-sm">
        <button
          type="button"
          onClick={onBackToOverview}
          className="text-muted-foreground hover:text-foreground"
        >
          All clients
        </button>
        <span className="text-muted-foreground">/</span>
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="size-3.5" /> {clientName}
        </button>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">{project?.name ?? '…'}</span>
      </nav>

      {project && (
        <ScopeCard
          scope={{ kind: 'project', id: project.id, name: project.name }}
          onDrillToFindings={onDrillToFindings}
          onDrillToComponents={onDrillToComponents}
          onDrillToCoverage={onDrillToCoverage}
        />
      )}
    </div>
  )
}
