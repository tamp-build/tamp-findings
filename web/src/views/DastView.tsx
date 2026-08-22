import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ChevronRight, Globe, Radio } from 'lucide-react'
import { fetchDastTree } from '@/lib/api'
import type { DastHostNode, DastRouteNode, DastFinding, Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

// DastView is the dynamic-scan sibling of FindingsView.
//
// FindingsView is a module → file tree backed by a source viewer, which a DAST
// finding can't use: it has no source file, only the request the scanner made.
// Those findings land in /findings/tree's NoPathCount and never render. Same
// two-pane grammar here, different spine — host → route on the left, the
// findings on that route on the right.
//
// FIRST PASS. Known gaps, in rough priority order:
//   - No request/response detail. Tamp.Sarif only started modelling
//     webRequest/webResponse in TAM-279; until a release ships and the ingest
//     path carries them, all we hold is rule + severity + URL + evidence.
//   - No CWE. Same dependency (run.taxonomies / result.taxa).
//   - No suppression or triage actions — FindingsView doesn't have them here
//     either; they live in the list view.
//   - Route grouping is derived from the URL at read time rather than stored.
//     Once Finding gains TargetUrl / HttpMethod / Param columns this should
//     group on those instead, and show method per row.

const SEV_DOT: Record<Severity, string> = {
  Critical: 'bg-red-600',
  High: 'bg-orange-500',
  Medium: 'bg-amber-500',
  Low: 'bg-yellow-400',
  Info: 'bg-sky-400',
}
const SEV_TEXT: Record<Severity, string> = {
  Critical: 'text-red-700 dark:text-red-300',
  High: 'text-orange-700 dark:text-orange-300',
  Medium: 'text-amber-700 dark:text-amber-300',
  Low: 'text-yellow-700 dark:text-yellow-300',
  Info: 'text-sky-700 dark:text-sky-300',
}
const SEV_BORDER: Record<Severity, string> = {
  Critical: 'border-l-red-600',
  High: 'border-l-orange-500',
  Medium: 'border-l-amber-500',
  Low: 'border-l-yellow-400',
  Info: 'border-l-sky-400',
}
const SEV_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']

type Counts = { info: number; low: number; medium: number; high: number; critical: number }

function countFor(c: Counts, sev: Severity): number {
  switch (sev) {
    case 'Critical': return c.critical
    case 'High': return c.high
    case 'Medium': return c.medium
    case 'Low': return c.low
    case 'Info': return c.info
  }
}

function SeverityPips({ counts }: { counts: Counts }) {
  const shown = SEV_ORDER.filter(s => countFor(counts, s) > 0)
  if (shown.length === 0) return null
  return (
    <span className="flex items-center gap-2 text-[11px] tabular-nums">
      {shown.map(s => (
        <span key={s} className={cn('inline-flex items-center gap-1', SEV_TEXT[s])}>
          <span className={cn('inline-block size-1.5 rounded-full', SEV_DOT[s])} />
          {countFor(counts, s)}
        </span>
      ))}
    </span>
  )
}

export function DastView({ projectId }: { projectId?: string }) {
  const tree = useQuery({
    queryKey: ['dast-tree', projectId],
    queryFn: () => fetchDastTree({ projectId }),
  })

  const [selected, setSelected] = useState<{ host: string; route: string } | null>(null)

  // Explicitly annotated: useQuery's generic inference resolves to `any` in
  // this project, so anything derived from tree.data lands as an implicit any
  // and trips noImplicitAny under `tsc -b`.
  const hosts: DastHostNode[] = tree.data?.hosts ?? []

  // Default the right pane to the worst route so the view opens on something
  // worth reading rather than an empty panel.
  const active: DastRouteNode | null = useMemo(() => {
    if (hosts.length === 0) return null
    if (selected) {
      const h = hosts.find(x => x.host === selected.host)
      const r = h?.routes.find(x => x.route === selected.route)
      if (r) return r
    }
    return hosts[0].routes[0] ?? null
  }, [hosts, selected])

  if (tree.isLoading) {
    return <div className="p-8 text-sm text-muted-foreground">Loading dynamic scan results…</div>
  }

  if (tree.isError) {
    return (
      <div className="flex items-center gap-2 p-8 text-sm text-red-600 dark:text-red-400">
        <AlertCircle className="size-4" />
        Couldn’t load dynamic scan results.
      </div>
    )
  }

  if ((tree.data?.totalCount ?? 0) === 0) {
    return (
      <div className="mx-auto max-w-lg p-10 text-center">
        <Radio className="mx-auto mb-3 size-8 text-muted-foreground/60" />
        <p className="text-sm font-medium">No dynamic scan findings</p>
        <p className="mt-2 text-xs text-muted-foreground">
          Nothing has been ingested from a DAST scanner for this scope. Run a ZAP or
          Nuclei scan against a deployed environment and post its SARIF to
          <code className="mx-1 rounded bg-muted px-1 py-0.5">/ingest/findings</code>.
        </p>
        <p className="mt-3 text-xs text-muted-foreground">
          An empty result here is not the same as a clean one — a project with no DAST
          receipt at all caps SSDF PW.8.1 at <em>Partial</em>.
        </p>
      </div>
    )
  }

  return (
    <div className="flex h-[calc(100vh-9rem)] gap-4 px-4 pb-4">
      {/* Left — host → route tree */}
      <aside className="w-[22rem] shrink-0 overflow-y-auto rounded-md border border-border">
        <div className="sticky top-0 flex items-baseline justify-between border-b border-border bg-card px-3 py-2">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Endpoints
          </h2>
          <span className="text-[11px] tabular-nums text-muted-foreground">
            {tree.data!.totalCount} open
          </span>
        </div>
        {hosts.map(host => (
          <HostGroup
            key={host.host}
            host={host}
            activeRoute={active?.route ?? null}
            onSelect={route => setSelected({ host: host.host, route })}
          />
        ))}
      </aside>

      {/* Right — findings on the selected route */}
      <section className="min-w-0 flex-1 overflow-y-auto rounded-md border border-border">
        {active ? <RouteDetail route={active} /> : (
          <div className="p-8 text-sm text-muted-foreground">Select a route.</div>
        )}
      </section>
    </div>
  )
}

function HostGroup({
  host, activeRoute, onSelect,
}: {
  host: DastHostNode
  activeRoute: string | null
  onSelect: (route: string) => void
}) {
  const [open, setOpen] = useState(true)
  return (
    <div className="border-b border-border last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/50"
      >
        <ChevronRight className={cn('size-3.5 shrink-0 transition-transform', open && 'rotate-90')} />
        <Globe className="size-3.5 shrink-0 text-muted-foreground" />
        <span className="truncate text-sm font-medium" title={host.host}>{host.host}</span>
        <span className="ml-auto shrink-0"><SeverityPips counts={host.counts} /></span>
      </button>
      {open && host.routes.map(route => (
        <button
          key={route.route}
          type="button"
          onClick={() => onSelect(route.route)}
          className={cn(
            'flex w-full items-center gap-2 border-l-2 py-1.5 pl-9 pr-3 text-left hover:bg-muted/50',
            SEV_BORDER[route.maxSeverity],
            activeRoute === route.route && 'bg-muted',
          )}
        >
          {/* Routes get the full string as a title — a long path with query
              parameter names truncates hard at this width. */}
          <span className="truncate font-mono text-xs" title={route.route}>{route.route}</span>
          <span className="ml-auto shrink-0"><SeverityPips counts={route.counts} /></span>
        </button>
      ))}
    </div>
  )
}

function RouteDetail({ route }: { route: DastRouteNode }) {
  return (
    <div>
      <div className="sticky top-0 border-b border-border bg-card px-4 py-3">
        <h2 className="break-all font-mono text-sm font-semibold">{route.route}</h2>
        <div className="mt-1 flex items-center gap-3">
          <SeverityPips counts={route.counts} />
          <span className="text-[11px] text-muted-foreground">
            {route.findings.length} finding{route.findings.length === 1 ? '' : 's'}
          </span>
        </div>
      </div>
      <ul className="divide-y divide-border">
        {route.findings.map(f => <FindingRow key={f.id} finding={f} />)}
      </ul>
    </div>
  )
}

function FindingRow({ finding }: { finding: DastFinding }) {
  const [open, setOpen] = useState(false)
  return (
    <li className={cn('border-l-2 px-4 py-3', SEV_BORDER[finding.severity])}>
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-start gap-2 text-left"
      >
        <span className={cn('mt-1.5 inline-block size-2 shrink-0 rounded-full', SEV_DOT[finding.severity])} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{finding.title}</span>
          <span className="mt-0.5 block text-[11px] text-muted-foreground">
            <span className={SEV_TEXT[finding.severity]}>{finding.severity}</span>
            {' · '}{finding.scanner}
            {' · '}<span className="font-mono">{finding.ruleId}</span>
          </span>
        </span>
        <ChevronRight className={cn('mt-1 size-3.5 shrink-0 text-muted-foreground transition-transform', open && 'rotate-90')} />
      </button>

      {open && (
        <div className="mt-3 space-y-3 pl-4">
          {finding.description && (
            <p className="whitespace-pre-wrap text-xs text-muted-foreground">{finding.description}</p>
          )}
          {finding.evidence && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                Evidence
              </p>
              <pre className="overflow-x-auto rounded bg-muted px-2 py-1.5 font-mono text-[11px]">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.url && (
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                Request URL
              </p>
              {/* Deliberately NOT a link. This URL carries the scanner's attack
                  payload; making it clickable invites someone to fire it from a
                  browser that's carrying their session. */}
              <pre className="overflow-x-auto rounded bg-muted px-2 py-1.5 font-mono text-[11px] break-all whitespace-pre-wrap">
                {finding.url}
              </pre>
            </div>
          )}
        </div>
      )}
    </li>
  )
}
