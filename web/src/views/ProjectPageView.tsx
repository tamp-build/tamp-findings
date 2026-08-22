import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, Settings, FileCheck2, Radio } from 'lucide-react'
import { fetchClients, fetchProjects, fetchAggregates } from '@/lib/api'
import type { ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import type { FindingsPreset, ComponentsPreset } from '@/App'
import {
  RingChart, FindingsTypeTable, SbomHealthTable, SecretsHealthTable,
  LicenseTable, IacHealthTable, CoverageTable, SAST_SCANNERS,
} from '@/components/RingChart'
import { RiskBadge } from '@/components/RiskBadge'
import { BuildReceiptsPanel } from '@/components/BuildReceiptsPanel'
import { ProjectSettingsDialog } from '@/components/ProjectSettingsDialog'
import { useAuth } from '@/lib/auth'

// Same segment → severity/status mapping the ScopeCard uses for drills.
const SEVERITY_FROM_SEGMENT: Record<string, Severity | undefined> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}
const STATUS_FROM_SEGMENT: Record<string, FindingStatus | undefined> = {
  closed: 'Fixed', suppressed: 'Suppressed', accepted: 'Accepted',
}

export function ProjectPageView({
  projectId,
  onBack,
  onBackToOverview,
  onDrillToFindings,
  onDrillToComponents,
  onDrillToCoverage,
  onDrillToAttestation,
  onDrillToDast,
}: {
  projectId: string
  onBack: () => void
  onBackToOverview: () => void
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
  onDrillToCoverage?: () => void
  onDrillToAttestation?: () => void
  onDrillToDast?: () => void
}) {
  const { user } = useAuth()
  const allProjects = useQuery({ queryKey: ['projects', null], queryFn: () => fetchProjects() })
  const clients = useQuery({ queryKey: ['clients'], queryFn: fetchClients })
  const project = allProjects.data?.find(p => p.id === projectId) ?? null
  const [settingsOpen, setSettingsOpen] = useState(false)
  const canManage = user?.isAdmin ?? false

  const aggregates = useQuery({
    queryKey: ['aggregates', 'project', projectId],
    queryFn: () => fetchAggregates({ projectId }),
  })

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

  const data = aggregates.data
  const risk = data?.risk ?? null

  // Drill helpers — preserves the click-through behavior the ScopeCard
  // wired up, just adapted to call the page-level handlers.
  const drillFindingsSAST = () =>
    onDrillToFindings?.({ scanners: [...SAST_SCANNERS] as ScannerKind[] })

  return (
    <div className="space-y-6">
      <nav className="flex items-baseline gap-2 text-sm">
        <button type="button" onClick={onBackToOverview} className="text-muted-foreground hover:text-foreground">
          All clients
        </button>
        <span className="text-muted-foreground">/</span>
        <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-muted-foreground hover:text-foreground">
          <ChevronLeft className="size-3.5" /> {clientName}
        </button>
        <span className="text-muted-foreground">/</span>
        <span className="font-semibold">{project?.name ?? '…'}</span>
        {canManage && project && (
          <button
            type="button"
            onClick={() => setSettingsOpen(true)}
            title="Project settings (policy + gates)"
            aria-label={`Settings for ${project.name}`}
            className="ml-1 rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            <Settings className="size-3.5" />
          </button>
        )}
        {project && onDrillToDast && (
          <button
            type="button"
            onClick={onDrillToDast}
            title="Browse dynamic-scan (ZAP / Nuclei) findings by endpoint (TFND-38)"
            className="ml-auto inline-flex items-center gap-1 rounded-md border bg-background px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            <Radio className="size-3.5" />
            Dynamic scan
          </button>
        )}
        {project && onDrillToAttestation && (
          <button
            type="button"
            onClick={onDrillToAttestation}
            title="Open CISA SSDF attestation for this project (TFND-31)"
            className="inline-flex items-center gap-1 rounded-md border bg-background px-2.5 py-1 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            <FileCheck2 className="size-3.5" />
            SSDF attestation
          </button>
        )}
      </nav>

      {settingsOpen && project && (
        <ProjectSettingsDialog
          projectId={project.id}
          projectName={project.name}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {/* ---- Top: ring graph + build receipts -------------------- */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-[auto_minmax(0,1fr)]">
        <div className="rounded-md border bg-card p-4">
          <div className="flex items-baseline justify-between gap-3 pb-2">
            <h2 className="text-base font-semibold tracking-tight">{project?.name}</h2>
            <RiskBadge risk={risk} />
          </div>
          {data && (
            <RingChart
              scannerDetails={data.findings.byScannerDetail}
              sbomHealth={data.sbom.health}
              secretsHealth={data.secrets.health}
              licenseTiers={data.licenses.tiers}
              iac={data.iac}
              coverage={data.coverage}
              scanRuns={data.scanRuns}
              onScannerClick={(scanner) => {
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
          )}
        </div>
        <div className="flex flex-col rounded-md border bg-card p-4">
          <div className="flex shrink-0 items-baseline justify-between pb-3">
            <h3 className="text-sm font-semibold">Build receipts</h3>
            <p className="text-[11px] text-muted-foreground">
              {/* Per-build risk delta (pass/fail vs prior) lands with /risk-history — TODO. */}
              Risk delta (pass/fail) is a follow-up
            </p>
          </div>
          <div className="min-h-0 flex-1">
            <BuildReceiptsPanel projectId={projectId} />
          </div>
        </div>
      </section>

      {/* ---- Test Coverage ---------------------------------------- */}
      <DetailSection
        title="Test Coverage"
        actionLabel="Open coverage tree →"
        onAction={onDrillToCoverage}
      >
        {data ? (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <CoverageTable coverage={data.coverage} />
            {data.coverage.measured && data.coverage.modules.length > 0 ? (
              <table className="text-xs">
                <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr><th className="py-1">Module</th><th className="py-1 text-right">Sequence</th><th className="py-1 text-right">Covered / Total</th></tr>
                </thead>
                <tbody>
                  {data.coverage.modules.map(m => (
                    <tr key={m.name} className="border-t border-border">
                      <td className="py-1.5 font-mono">{m.name}</td>
                      <td className="py-1.5 text-right tabular-nums">{m.sequenceCoverage.toFixed(1)}%</td>
                      <td className="py-1.5 text-right tabular-nums text-muted-foreground">{m.coveredSequences} / {m.totalSequences}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-xs text-muted-foreground">No coverage report ingested for this project.</p>
            )}
          </div>
        ) : <SectionLoading />}
      </DetailSection>

      {/* ---- Code Quality ----------------------------------------- */}
      <DetailSection
        title="Code Quality"
        actionLabel="Open SAST findings →"
        onAction={drillFindingsSAST}
      >
        {data ? (
          <FindingsTypeTable
            scannerDetails={data.findings.byScannerDetail}
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
        ) : <SectionLoading />}
      </DetailSection>

      {/* ---- SBOM -------------------------------------------------- */}
      <DetailSection
        title="SBOM"
        actionLabel="Open components →"
        onAction={() => onDrillToComponents?.()}
      >
        {data ? (
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <SbomHealthTable
              health={data.sbom.health}
              onRowClick={(bucket) => onDrillToComponents?.({ sbomStatus: bucket as SbomHealthStatus })}
            />
            <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
              <Stat label="Components" value={data.sbom.componentsCount} />
              <Stat label="Known CVEs" value={data.sbom.vulnerabilitiesCount} alert={data.sbom.vulnerabilitiesCount > 0} />
              <Stat label="npm" value={data.sbom.byEcosystem.npm ?? 0} />
              <Stat label="nuget" value={data.sbom.byEcosystem.nuget ?? 0} />
              {(data.sbom.byEcosystem.other ?? 0) > 0 && <Stat label="other" value={data.sbom.byEcosystem.other ?? 0} />}
            </dl>
          </div>
        ) : <SectionLoading />}
      </DetailSection>

      {/* ---- License ---------------------------------------------- */}
      <DetailSection
        title="License"
        actionLabel="Open components →"
        onAction={() => onDrillToComponents?.()}
      >
        {data ? (
          <LicenseTable
            byLicense={data.licenses.byLicense}
            topN={20}
            onRowClick={(license) => onDrillToComponents?.({ license })}
          />
        ) : <SectionLoading />}
      </DetailSection>

      {/* ---- Secrets ---------------------------------------------- */}
      <DetailSection
        title="Secrets"
        actionLabel="Open TruffleHog findings →"
        onAction={() => onDrillToFindings?.({ scanners: ['TruffleHog'] })}
      >
        {data ? (
          <SecretsHealthTable
            health={data.secrets.health}
            onRowClick={(bucket) => onDrillToFindings?.({
              scanners: ['TruffleHog'],
              severities: bucket === 'verified' ? ['Critical'] : ['High'],
            })}
          />
        ) : <SectionLoading />}
      </DetailSection>

      {/* ---- IaC -------------------------------------------------- */}
      <DetailSection
        title="IaC / Container scans"
        actionLabel="Open Trivy findings →"
        onAction={() => onDrillToFindings?.({ scanners: ['Trivy'] })}
      >
        {data ? (
          <IacHealthTable
            iac={data.iac}
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
        ) : <SectionLoading />}
      </DetailSection>
    </div>
  )
}

function DetailSection({
  title, actionLabel, onAction, children,
}: {
  title: string
  actionLabel?: string
  onAction?: () => void
  children: React.ReactNode
}) {
  return (
    <section className="rounded-md border bg-card">
      <div className="flex items-baseline justify-between border-b border-border px-4 py-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        {onAction && actionLabel && (
          <button
            type="button"
            onClick={onAction}
            className="inline-flex items-center gap-0.5 text-xs text-muted-foreground hover:text-foreground"
          >
            {actionLabel}<ChevronRight className="size-3" />
          </button>
        )}
      </div>
      <div className="px-4 py-3">{children}</div>
    </section>
  )
}

function SectionLoading() {
  return <p className="text-xs text-muted-foreground">Loading…</p>
}

function Stat({ label, value, alert }: { label: string; value: number | string; alert?: boolean }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={`text-right tabular-nums ${alert ? 'text-destructive font-semibold' : ''}`}>{value}</dd>
    </>
  )
}
