import { useEffect, useMemo, useState } from 'react'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { AlertCircle, Search, X, ShieldAlert, ArrowUpCircle } from 'lucide-react'
import { fetchSbomComponents, fetchSbomComponent } from '@/lib/api'
import type { SbomComponentListItem, SbomHealthStatus } from '@/lib/api'
import type { ComponentsPreset } from '@/App'
import { EcosystemBadge } from '@/components/EcosystemBadge'
import { cn } from '@/lib/utils'

const STATUS_LABELS: Record<SbomHealthStatus, string> = {
  vulnerable: 'Vulnerable',
  outdated: 'Outdated',
  current: 'Current',
}

export function ComponentsView({ preset }: { preset?: ComponentsPreset }) {
  const [ecosystem, setEcosystem] = useState<string | null>(null)
  const [healthStatus, setHealthStatus] = useState<SbomHealthStatus | null>(null)
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  // Seed from preset when the parent bumps the nonce (Overview SBOM
  // table row click). Bumping `nonce` even with no sbomStatus clears.
  useEffect(() => {
    if (!preset) return
    setHealthStatus(preset.sbomStatus ?? null)
  }, [preset?.nonce])

  const filters = useMemo(() => ({
    ecosystem: ecosystem ?? undefined,
    status: healthStatus ?? undefined,
    search: search.trim() || undefined,
    take: 200,
  }), [ecosystem, healthStatus, search])

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['sbom-components', filters],
    queryFn: () => fetchSbomComponents(filters),
    placeholderData: keepPreviousData,
  })

  const items = data?.items ?? []
  const counts = data?.counts

  return (
    <>
      <div className="mb-4 flex items-center gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <EcosystemFilter
            label="all"
            count={counts?.total ?? 0}
            active={ecosystem === null}
            onClick={() => setEcosystem(null)}
          />
          {(['nuget', 'npm', 'other'] as const).map(e => (
            <EcosystemFilter
              key={e}
              label={e}
              count={counts?.[e] ?? 0}
              active={ecosystem === e}
              onClick={() => setEcosystem(prev => prev === e ? null : e)}
            />
          ))}
          {healthStatus && (
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
              status: {STATUS_LABELS[healthStatus]}
              <button
                type="button"
                onClick={() => setHealthStatus(null)}
                className="ml-1 rounded p-0.5 hover:bg-amber-500/20"
                aria-label="Clear status filter"
              >
                <X className="size-3" />
              </button>
            </span>
          )}
        </div>
        <div className="relative ml-auto w-72">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name or purl…"
            className="w-full rounded-md border bg-background py-2 pl-8 pr-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </div>
      </div>

      {isError && (
        <div className="flex items-start gap-3 rounded-md border border-destructive/50 bg-card p-4">
          <AlertCircle className="size-5 text-destructive" />
          <div>
            <p className="text-sm font-medium">Couldn't load SBOM</p>
            <p className="text-xs text-muted-foreground">{(error as Error)?.message}</p>
          </div>
        </div>
      )}

      <div className="rounded-md border bg-card">
        <div className="border-b px-4 py-2 text-xs text-muted-foreground">
          {isLoading ? 'Loading…' : `Showing ${items.length} of ${data?.totalCount ?? 0}`}
          {data && data.totalVulnerabilities > 0 && (
            <span className="ml-3 text-destructive">· {data.totalVulnerabilities} vulns</span>
          )}
        </div>
        <div className="divide-y">
          {items.map(c => (
            <ComponentRow
              key={c.id}
              c={c}
              selected={selectedId === c.id}
              onClick={() => setSelectedId(c.id)}
            />
          ))}
          {!isLoading && items.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No components match the current filters.
            </div>
          )}
        </div>
      </div>

      {selectedId && (
        <ComponentDetailPanel id={selectedId} onClose={() => setSelectedId(null)} />
      )}
    </>
  )
}

function EcosystemFilter({
  label, count, active, onClick,
}: { label: string; count: number; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex items-baseline gap-1.5 rounded-md border px-2.5 py-1.5 text-sm transition-colors hover:bg-muted/60',
        active && 'border-foreground bg-muted',
      )}
    >
      <span className="text-base font-semibold tabular-nums">{count}</span>
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
    </button>
  )
}

function ComponentRow({
  c, selected, onClick,
}: { c: SbomComponentListItem; selected: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-muted/40',
        selected && 'bg-muted/60',
      )}
    >
      <EcosystemBadge ecosystem={c.ecosystem} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="truncate font-medium">{c.name}</span>
          <span className="font-mono text-xs text-muted-foreground">{c.version}</span>
          {c.latestVersion && c.latestVersion !== c.version && (
            <span className="font-mono text-xs text-amber-700 dark:text-amber-400">
              → {c.latestVersion}
            </span>
          )}
        </div>
        <div className="truncate text-xs text-muted-foreground">
          {c.license ?? '(unknown license)'}
          <span className="mx-2 opacity-50">·</span>
          <span className="font-mono">{c.purl}</span>
        </div>
      </div>
      {c.latestVersion && c.latestVersion !== c.version && (
        <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-400" title={`Outdated: latest ${c.latestVersion}`}>
          <ArrowUpCircle className="size-3.5" />
          outdated
        </span>
      )}
      {c.vulnerabilityCount > 0 && (
        <span className="inline-flex shrink-0 items-center gap-1 rounded-md border border-destructive/40 bg-destructive/10 px-1.5 py-0.5 text-xs font-medium text-destructive">
          <ShieldAlert className="size-3.5" />
          {c.vulnerabilityCount}
        </span>
      )}
    </button>
  )
}

function ComponentDetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['sbom-component', id],
    queryFn: () => fetchSbomComponent(id),
  })

  return (
    <aside className="fixed inset-y-0 right-0 w-[520px] overflow-y-auto border-l border-border bg-card shadow-xl">
      <div className="sticky top-0 z-10 flex items-center justify-between border-b bg-card px-4 py-3">
        <div className="flex items-center gap-2">
          {data && <EcosystemBadge ecosystem={data.ecosystem} />}
          <span className="font-medium">{data?.name ?? '…'}</span>
          {data && <span className="font-mono text-xs text-muted-foreground">{data.version}</span>}
        </div>
        <button type="button" onClick={onClose} className="rounded-md p-1 hover:bg-muted" aria-label="Close">
          <X className="size-4" />
        </button>
      </div>
      <div className="space-y-4 p-4 text-sm">
        {isLoading && <p className="text-muted-foreground">Loading…</p>}
        {isError && <p className="text-destructive">Failed to load component.</p>}
        {data && (
          <>
            <Field label="PURL" value={data.purl} mono />
            <Field label="License" value={data.license ?? '(unknown)'} />
            <Field label="Kind" value={data.kind ?? '(unknown)'} />
            <Field label="Component version" value={`${data.versionString} (${data.componentVersionId.slice(0, 8)}…)`} mono />

            <section>
              <h3 className="mb-1.5 text-xs uppercase tracking-wide text-muted-foreground">
                Vulnerabilities ({data.vulnerabilities.length})
              </h3>
              {data.vulnerabilities.length === 0 ? (
                <p className="text-xs text-muted-foreground">Clean — no advisories known for this version.</p>
              ) : (
                <ul className="space-y-2">
                  {data.vulnerabilities.map(v => (
                    <li key={v.id} className="rounded-md border bg-background p-2.5">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-xs font-medium text-destructive">{v.severity}</span>
                        <code className="text-xs">{v.advisoryId}</code>
                        <span className="ml-auto text-xs text-muted-foreground">via {v.source}</span>
                      </div>
                      {v.title && <p className="mt-1 text-xs">{v.title}</p>}
                      {v.fixedInVersion && (
                        <p className="mt-1 text-xs text-muted-foreground">Fixed in <code>{v.fixedInVersion}</code></p>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section>
              <h3 className="mb-1.5 text-xs uppercase tracking-wide text-muted-foreground">
                Depends on ({data.dependsOnPurls.length})
              </h3>
              {data.dependsOnPurls.length === 0 ? (
                <p className="text-xs text-muted-foreground">No outgoing edges in this snapshot.</p>
              ) : (
                <ul className="space-y-0.5 text-xs">
                  {data.dependsOnPurls.slice(0, 20).map(p => (
                    <li key={p} className="font-mono truncate">{p}</li>
                  ))}
                  {data.dependsOnPurls.length > 20 && (
                    <li className="text-muted-foreground">… and {data.dependsOnPurls.length - 20} more</li>
                  )}
                </ul>
              )}
            </section>

            <section>
              <h3 className="mb-1.5 text-xs uppercase tracking-wide text-muted-foreground">
                Depended on by ({data.dependentPurls.length})
              </h3>
              {data.dependentPurls.length === 0 ? (
                <p className="text-xs text-muted-foreground">No incoming edges (top-level dep).</p>
              ) : (
                <ul className="space-y-0.5 text-xs">
                  {data.dependentPurls.slice(0, 20).map(p => (
                    <li key={p} className="font-mono truncate">{p}</li>
                  ))}
                  {data.dependentPurls.length > 20 && (
                    <li className="text-muted-foreground">… and {data.dependentPurls.length - 20} more</li>
                  )}
                </ul>
              )}
            </section>
          </>
        )}
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
