import { useEffect, useMemo, useState } from 'react'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { AlertCircle, X } from 'lucide-react'
import { fetchFindings } from '@/lib/api'
import type { FindingListItem, Severity, ScannerKind, FindingStatus } from '@/lib/api'
import type { FindingsPreset } from '@/App'
import { SeverityBadge } from '@/components/SeverityBadge'
import { SeverityCountsBar } from '@/components/SeverityCountsBar'
import { cn } from '@/lib/utils'

const ALL_SCANNERS: ScannerKind[] = [
  'Roslyn', 'OpenGrep', 'TruffleHog', 'Trivy', 'CodeQL', 'OsvScanner',
  'Syft', 'Grype', 'Checkov', 'Tfsec', 'Kics', 'Zap', 'Spectral',
  'Oasdiff', 'Cosign', 'NetArchTest', 'DependencyCruiser', 'Stryker', 'Coverlet',
]

const STATUS_OPTIONS: FindingStatus[] = ['Open', 'Suppressed', 'Fixed', 'Accepted']

export function FindingsView({
  search,
  preset,
}: {
  search: string
  preset: FindingsPreset
}) {
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set())
  const [activeScanners, setActiveScanners] = useState<Set<ScannerKind>>(new Set())
  // Default to no explicit status filter — the server applies Status=Open
  // when this set is empty. A preset can land us here with statuses set
  // (e.g. clicking the "Closed" row on Overview).
  const [activeStatuses, setActiveStatuses] = useState<Set<FindingStatus>>(new Set())
  const [selected, setSelected] = useState<FindingListItem | null>(null)

  // When the parent bumps `preset.nonce` (the Overview's row-drill or
  // donut-drill click) seed local state from the new preset payload.
  // Replaces rather than merges so previous clicks don't ghost.
  useEffect(() => {
    setActiveScanners(new Set(preset.scanners ?? []))
    setActiveSeverities(new Set(preset.severities ?? []))
    setActiveStatuses(new Set(preset.statuses ?? []))
  }, [preset.nonce])

  const filters = useMemo(() => ({
    severities: [...activeSeverities],
    scanners: [...activeScanners],
    statuses: [...activeStatuses],
    search: search.trim() || undefined,
    take: 200,
  }), [activeSeverities, activeScanners, activeStatuses, search])

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => fetchFindings(filters),
    placeholderData: keepPreviousData,
  })

  const toggleSeverity = (s: Severity) => {
    setActiveSeverities(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s); else next.add(s)
      return next
    })
  }
  const toggleScanner = (s: ScannerKind) => {
    setActiveScanners(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s); else next.add(s)
      return next
    })
  }
  const toggleStatus = (s: FindingStatus) => {
    setActiveStatuses(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s); else next.add(s)
      return next
    })
  }

  const visibleScanners = useMemo(() => {
    const seen = new Set<ScannerKind>()
    data?.items?.forEach(f => seen.add(f.scanner))
    return ALL_SCANNERS.filter(s => seen.has(s) || activeScanners.has(s))
  }, [data, activeScanners])

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-[220px_minmax(0,1fr)] md:gap-6">
      <aside className="space-y-6">
        <section>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Scanner</h2>
          <ul className="space-y-1">
            {visibleScanners.length === 0 && (
              <li className="text-xs text-muted-foreground">No findings yet — run ScanAll + Ingest.</li>
            )}
            {visibleScanners.map(s => {
              const checked = activeScanners.has(s)
              return (
                <li key={s}>
                  <button
                    type="button"
                    onClick={() => toggleScanner(s)}
                    className={cn(
                      'flex w-full items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/60',
                      checked && 'bg-muted',
                    )}
                  >
                    <span className={cn('size-3.5 rounded border', checked ? 'bg-primary border-primary' : 'border-input')} />
                    <span>{s}</span>
                  </button>
                </li>
              )
            })}
          </ul>
          {activeScanners.size > 0 && (
            <button
              type="button"
              onClick={() => setActiveScanners(new Set())}
              className="mt-2 text-xs text-muted-foreground hover:text-foreground"
            >
              Clear scanners
            </button>
          )}
        </section>

        <section>
          <h2 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Status</h2>
          <ul className="space-y-1">
            {STATUS_OPTIONS.map(s => {
              const checked = activeStatuses.has(s)
              return (
                <li key={s}>
                  <button
                    type="button"
                    onClick={() => toggleStatus(s)}
                    className={cn(
                      'flex w-full items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/60',
                      checked && 'bg-muted',
                    )}
                  >
                    <span className={cn('size-3.5 rounded border', checked ? 'bg-primary border-primary' : 'border-input')} />
                    <span>{s}</span>
                  </button>
                </li>
              )
            })}
          </ul>
          {activeStatuses.size > 0 && (
            <button
              type="button"
              onClick={() => setActiveStatuses(new Set())}
              className="mt-2 text-xs text-muted-foreground hover:text-foreground"
            >
              Clear status (defaults to Open)
            </button>
          )}
        </section>
      </aside>

      <main className="space-y-4">
        {data && (
          <SeverityCountsBar
            counts={data.counts}
            active={activeSeverities}
            onToggle={toggleSeverity}
          />
        )}

        {isError && (
          <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
            <AlertCircle className="size-5 text-destructive" />
            <div>
              <p className="text-sm font-medium">Couldn't load findings</p>
              <p className="text-xs text-muted-foreground">{(error as Error)?.message}</p>
            </div>
          </div>
        )}

        <FindingsTable
          isLoading={isLoading}
          items={data?.items ?? []}
          totalCount={data?.totalCount ?? 0}
          selectedId={selected?.id ?? null}
          onSelect={setSelected}
        />

        {selected && (
          <DetailPanel finding={selected} onClose={() => setSelected(null)} />
        )}
      </main>
    </div>
  )
}

function FindingsTable({
  isLoading, items, totalCount, selectedId, onSelect,
}: {
  isLoading: boolean
  items: FindingListItem[]
  totalCount: number
  selectedId: string | null
  onSelect: (f: FindingListItem) => void
}) {
  return (
    <div className="rounded-md border bg-card">
      <div className="border-b px-4 py-2 text-xs text-muted-foreground">
        {isLoading ? 'Loading…' : `Showing ${items.length} of ${totalCount}`}
      </div>
      <div className="divide-y">
        {items.map(f => (
          <button
            key={f.id}
            type="button"
            onClick={() => onSelect(f)}
            className={cn(
              'flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-muted/40',
              selectedId === f.id && 'bg-muted/60',
            )}
          >
            <SeverityBadge severity={f.severity} className="mt-0.5" />
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-xs text-muted-foreground">{f.ruleId}</span>
                <span className="truncate font-medium">{f.title}</span>
              </div>
              <div className="mt-0.5 truncate text-xs text-muted-foreground">
                {f.filePath ?? '(no file)'}{f.line != null && <span>:{f.line}</span>}
                <span className="mx-2 opacity-50">·</span>
                {f.clientName} / {f.projectName} / {f.componentName} @ {f.versionString}
              </div>
            </div>
            <span className="shrink-0 self-center text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {f.scanner}
            </span>
          </button>
        ))}
        {!isLoading && items.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            No findings match the current filters.
          </div>
        )}
      </div>
    </div>
  )
}

function DetailPanel({ finding, onClose }: { finding: FindingListItem; onClose: () => void }) {
  return (
    <aside className="fixed inset-y-0 right-0 w-full max-w-[460px] overflow-y-auto border-l border-border bg-card shadow-xl">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="font-mono text-sm">{finding.ruleId}</span>
        </div>
        <button type="button" onClick={onClose} className="rounded-md p-1 hover:bg-muted" aria-label="Close">
          <X className="size-4" />
        </button>
      </div>
      <div className="space-y-4 p-4 text-sm">
        <p className="font-medium leading-snug">{finding.title}</p>
        <Field label="Scanner" value={finding.scanner} mono />
        <Field label="Status" value={finding.status} />
        <Field
          label="Location"
          value={finding.filePath ? `${finding.filePath}${finding.line != null ? `:${finding.line}` : ''}` : '(no location)'}
          mono
        />
        <Field
          label="Scope"
          value={`${finding.clientName} / ${finding.projectName} / ${finding.componentName} @ ${finding.versionString}`}
        />
        <Field label="First seen" value={new Date(finding.firstSeen).toLocaleString()} />
        <Field label="Last seen" value={new Date(finding.lastSeen).toLocaleString()} />
        <Field label="Finding ID" value={finding.id} mono />
      </div>
    </aside>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn('mt-0.5 break-all', mono && 'font-mono text-xs')}>{value}</p>
    </div>
  )
}
