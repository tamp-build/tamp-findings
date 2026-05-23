import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight, AlertCircle, Settings } from 'lucide-react'
import {
  fetchClients,
  fetchProjects,
  fetchComponents,
  fetchAggregates,
} from '@/lib/api'
import type { ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import type { FindingsPreset, ComponentsPreset } from '@/App'
import { RingChart, FindingsTypeTable, SbomHealthTable, SecretsHealthTable, LicenseTable, IacHealthTable, CoverageTable, SAST_SCANNERS } from '@/components/RingChart'
import { ClientSettingsDialog } from '@/components/ClientSettingsDialog'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

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

export function OverviewView({
  onDrillToFindings,
  onDrillToComponents,
  onDrillToCoverage,
}: {
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
  onDrillToCoverage?: () => void
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
        {/* Tree is visual-only for now — it shows the hierarchy but does
            NOT filter the dashboard. Selection-as-filter was confusing
            once we wanted to see every client at once; the dashboard now
            stacks one card per client unconditionally. The left nav will
            grow a real purpose (jump-to / pin / drill scope) later. */}
        <HierarchyTree />
      </aside>
      <main className="space-y-3 sm:space-y-6">
        {clients.data?.map(c => (
          <ClientCard
            key={c.id}
            clientId={c.id}
            clientName={c.name}
            onDrillToFindings={onDrillToFindings}
            onDrillToComponents={onDrillToComponents}
            onDrillToCoverage={onDrillToCoverage}
          />
        ))}
      </main>
    </div>
  )
}

function ClientCard({
  clientId,
  clientName,
  onDrillToFindings,
  onDrillToComponents,
  onDrillToCoverage,
}: {
  clientId: string
  clientName: string
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
  onDrillToCoverage?: () => void
}) {
  const { user } = useAuth()
  const [settingsOpen, setSettingsOpen] = useState(false)
  // Owner-of-project check goes here once TFND-3 role assignments are
  // surfaced on /auth/me. Today admin sees the gear on every card.
  const canManage = user?.isAdmin ?? false

  const aggregates = useQuery({
    queryKey: ['aggregates', { clientId }],
    queryFn: () => fetchAggregates({ clientId }),
  })

  return (
    <section className="overflow-hidden rounded-md border bg-card">
      {/* Title bar — client name always present, level chip for symmetry.
          Rendered before the aggregates resolve so the card chrome shows
          immediately for every client, including empty ones. */}
      <div className="flex items-center justify-between border-b border-border bg-muted/30 px-4 py-2">
        <div className="flex items-baseline gap-2">
          <h2 className="text-base font-semibold tracking-tight">{clientName}</h2>
          {canManage && (
            <button
              type="button"
              onClick={() => setSettingsOpen(true)}
              title="Project settings"
              aria-label={`Settings for ${clientName}`}
              className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            >
              <Settings className="size-3.5" />
            </button>
          )}
        </div>
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Client</p>
      </div>

      {settingsOpen && (
        <ClientSettingsDialog
          clientId={clientId}
          clientName={clientName}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {aggregates.isLoading && (
        <p className="px-4 py-6 text-sm text-muted-foreground">Loading…</p>
      )}
      {aggregates.isError && (
        <div className="flex items-start gap-3 border-t border-border bg-card p-4">
          <AlertCircle className="size-5 text-destructive" />
          <div>
            <p className="text-sm font-medium">Couldn't load aggregates</p>
            <p className="text-xs text-muted-foreground">{(aggregates.error as Error)?.message}</p>
          </div>
        </div>
      )}
      {aggregates.data && (
        <div className="grid grid-cols-1 items-start gap-4 p-4 lg:grid-cols-[auto_minmax(0,1fr)]">
          <RingChart
            scannerDetails={aggregates.data.findings.byScannerDetail}
            sbomHealth={aggregates.data.sbom.health}
            secretsHealth={aggregates.data.secrets.health}
            licenseTiers={aggregates.data.licenses.tiers}
            iac={aggregates.data.iac}
            coverage={aggregates.data.coverage}
            scanRuns={aggregates.data.scanRuns}
            onScannerClick={(scanner) => {
              // Sentinel 'CodeQuality' fans out to every SAST scanner so
              // the Findings view doesn't pretend one tool is canonical.
              const scanners = scanner === 'CodeQuality'
                ? [...SAST_SCANNERS] as ScannerKind[]
                : [scanner as ScannerKind]
              onDrillToFindings?.({ scanners })
            }}
            onSbomClick={() => onDrillToComponents?.()}
            onSecretsClick={() => onDrillToFindings?.({ scanners: ['TruffleHog'] })}
            onLicenseClick={() => onDrillToComponents?.()}
            onIacClick={() => onDrillToFindings?.({ scanners: ['Trivy'] })}
            onCoverageClick={() => onDrillToCoverage?.()}
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-md transition-shadow">
              <CoverageTable coverage={aggregates.data.coverage} />
            </div>
            <FindingsTypeTable
              scannerDetails={aggregates.data.findings.byScannerDetail}
              onRowClick={(segment, scanner) => {
                const sev = SEVERITY_FROM_SEGMENT[segment]
                const status = STATUS_FROM_SEGMENT[segment]
                const scanners = scanner === 'CodeQuality'
                  ? [...SAST_SCANNERS] as ScannerKind[]
                  : [scanner as ScannerKind]
                onDrillToFindings?.({
                  scanners,
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
            <LicenseTable
              byLicense={aggregates.data.licenses.byLicense}
              topN={3}
              onRowClick={(license) => onDrillToComponents?.({ license })}
            />
            <IacHealthTable
              iac={aggregates.data.iac}
              onRowClick={(severity) => {
                const map: Record<string, Severity> = {
                  critical: 'Critical', high: 'High', medium: 'Medium',
                  low: 'Low', info: 'Info',
                }
                onDrillToFindings?.({
                  scanners: ['Trivy'],
                  severities: [map[severity]],
                })
              }}
            />
          </div>
        </div>
      )}
    </section>
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
