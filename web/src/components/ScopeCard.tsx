import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, Settings, ChevronRight } from 'lucide-react'
import { fetchAggregates } from '@/lib/api'
import type { ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import type { FindingsPreset, ComponentsPreset } from '@/App'
import {
  RingChart, FindingsTypeTable, SbomHealthTable, SecretsHealthTable,
  LicenseTable, IacHealthTable, CoverageTable, SAST_SCANNERS,
} from '@/components/RingChart'
import { ClientSettingsDialog } from '@/components/ClientSettingsDialog'
import { RiskBadge } from '@/components/RiskBadge'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

// Cross-tab segment → severity / status mapping. Mirrored from
// OverviewView so the drill-through carries the right filter.
const SEVERITY_FROM_SEGMENT: Record<string, Severity | undefined> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}
const STATUS_FROM_SEGMENT: Record<string, FindingStatus | undefined> = {
  closed: 'Fixed', suppressed: 'Suppressed', accepted: 'Accepted',
}

export type ScopeRef =
  | { kind: 'client'; id: string; name: string }
  | { kind: 'project'; id: string; name: string }

// One card, three roles:
//   1. Home-level client tile (onCardClick set → drill-throughs ignored).
//   2. Client-page project tile (same — onCardClick navigates to project).
//   3. Project-page detail card (no onCardClick, drill-throughs enabled).
// The card always renders rings + tables for the given scope; only the
// click behavior on the chrome differs.
export function ScopeCard({
  scope,
  onCardClick,
  onDrillToFindings,
  onDrillToComponents,
  onDrillToCoverage,
}: {
  scope: ScopeRef
  onCardClick?: () => void
  onDrillToFindings?: (preset: Omit<FindingsPreset, 'nonce'>) => void
  onDrillToComponents?: (preset?: Omit<ComponentsPreset, 'nonce'>) => void
  onDrillToCoverage?: () => void
}) {
  const { user } = useAuth()
  const [settingsOpen, setSettingsOpen] = useState(false)
  const canManage = user?.isAdmin ?? false

  const aggregates = useQuery({
    queryKey: ['aggregates', scope.kind, scope.id],
    queryFn: () => fetchAggregates(
      scope.kind === 'client' ? { clientId: scope.id } : { projectId: scope.id },
    ),
  })

  const interactive = !!onCardClick

  return (
    <section
      className={cn(
        'overflow-hidden rounded-md border bg-card',
        interactive && 'cursor-pointer transition hover:border-foreground/40 hover:shadow-sm',
      )}
      onClick={interactive ? onCardClick : undefined}
    >
      <div className="flex items-center justify-between border-b border-border bg-muted/30 px-4 py-2">
        <div className="flex items-baseline gap-2">
          <h2 className="text-base font-semibold tracking-tight">{scope.name}</h2>
          {canManage && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); setSettingsOpen(true) }}
              title={`${capitalize(scope.kind)} settings`}
              aria-label={`Settings for ${scope.name}`}
              className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            >
              <Settings className="size-3.5" />
            </button>
          )}
        </div>
        <div className="flex items-center gap-3">
          <RiskBadge risk={aggregates.data?.risk ?? null} />
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
            {capitalize(scope.kind)}
          </p>
          {interactive && (
            <ChevronRight className="size-4 text-muted-foreground" aria-hidden="true" />
          )}
        </div>
      </div>

      {settingsOpen && scope.kind === 'client' && (
        <ClientSettingsDialog
          clientId={scope.id}
          clientName={scope.name}
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
            // Drill handlers only when the card isn't itself a link.
            onScannerClick={interactive ? undefined : (scanner) => {
              const scanners = scanner === 'CodeQuality'
                ? [...SAST_SCANNERS] as ScannerKind[]
                : [scanner as ScannerKind]
              onDrillToFindings?.({ scanners })
            }}
            onSbomClick={interactive ? undefined : () => onDrillToComponents?.()}
            onSecretsClick={interactive ? undefined : () => onDrillToFindings?.({ scanners: ['TruffleHog'] })}
            onLicenseClick={interactive ? undefined : () => onDrillToComponents?.()}
            onIacClick={interactive ? undefined : () => onDrillToFindings?.({ scanners: ['Trivy'] })}
            onCoverageClick={interactive ? undefined : () => onDrillToCoverage?.()}
          />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="rounded-md transition-shadow">
              <CoverageTable coverage={aggregates.data.coverage} />
            </div>
            <FindingsTypeTable
              scannerDetails={aggregates.data.findings.byScannerDetail}
              onRowClick={interactive ? undefined : (segment, scanner) => {
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
              onRowClick={interactive ? undefined : (bucket) =>
                onDrillToComponents?.({ sbomStatus: bucket as SbomHealthStatus })}
            />
            <SecretsHealthTable
              health={aggregates.data.secrets.health}
              onRowClick={interactive ? undefined : (bucket) => onDrillToFindings?.({
                scanners: ['TruffleHog'],
                severities: bucket === 'verified' ? ['Critical'] : ['High'],
              })}
            />
            <LicenseTable
              byLicense={aggregates.data.licenses.byLicense}
              topN={3}
              onRowClick={interactive ? undefined : (license) =>
                onDrillToComponents?.({ license })}
            />
            <IacHealthTable
              iac={aggregates.data.iac}
              onRowClick={interactive ? undefined : (severity) => {
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

function capitalize(s: string) { return s.charAt(0).toUpperCase() + s.slice(1) }
