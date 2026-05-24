import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CheckCircle2, XCircle, MinusCircle, AlertCircle, ChevronLeft, ChevronRight, Filter } from 'lucide-react'
import { fetchProjectScanReceipts } from '@/lib/api'
import type { BuildReceipt, ScanReceiptRow } from '@/lib/api'
import { cn } from '@/lib/utils'

// 5 commit rows ≈ the height of the ring chart card to its left. Each
// row is the consolidated "what scanners ran in this build cycle" —
// not broken out by ComponentVersion / flavor, because a single scanner
// run (OpenGrep, TruffleHog, etc.) frequently walks multiple source
// trees and attaching its receipt to one flavor would imply it skipped
// the others. The build cycle is the truth; the receipts list reflects
// that directly.
const PAGE_SIZE = 5

export function BuildReceiptsPanel({ projectId }: { projectId: string }) {
  // Default to canonical-only builds (main branch, no PR). Branch/PR
  // scans are acceptance gates — their findings never affect the risk
  // score — and are hidden from the receipts list until the user
  // explicitly toggles them in. Mirrors what /aggregates does for score.
  const [includeNonCanonical, setIncludeNonCanonical] = useState(false)
  const [page, setPage] = useState(0)
  const q = useQuery({
    queryKey: ['scan-receipts', projectId, includeNonCanonical],
    queryFn: () => fetchProjectScanReceipts(projectId, { take: 50, includeNonCanonical }),
  })

  const groups = useMemo(() => groupByCommit(q.data?.builds ?? []), [q.data])
  useEffect(() => { setPage(0) }, [includeNonCanonical, groups.length])

  const totalPages = Math.max(1, Math.ceil(groups.length / PAGE_SIZE))
  const safePage = Math.min(page, totalPages - 1)
  const pageGroups = groups.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE)

  return (
    <div className="flex h-full flex-col gap-2">
      <div className="flex items-center justify-end">
        <button
          type="button"
          onClick={() => setIncludeNonCanonical(v => !v)}
          title="Branch + PR builds run as acceptance gates — they never affect the risk score."
          className={cn(
            'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px]',
            includeNonCanonical
              ? 'border-foreground/40 bg-muted/50 text-foreground'
              : 'border-border text-muted-foreground hover:text-foreground hover:bg-muted/40',
          )}
        >
          <Filter className="size-3" />
          {includeNonCanonical ? 'Showing branch + PR' : 'Main only'}
        </button>
      </div>

      {q.isLoading && <p className="text-sm text-muted-foreground">Loading build history…</p>}
      {q.isError && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 p-3 text-xs">
          <AlertCircle className="size-4 text-destructive" />
          <span>{(q.error as Error)?.message}</span>
        </div>
      )}
      {!q.isLoading && !q.isError && groups.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {includeNonCanonical
            ? 'No builds ingested for this project yet.'
            : 'No main-branch builds ingested. Toggle the filter to see branch / PR builds.'}
        </p>
      )}
      {pageGroups.length > 0 && (
        <ul className="flex-1 space-y-2 overflow-y-auto">
          {pageGroups.map(g => <CommitRow key={g.key} group={g} />)}
        </ul>
      )}

      {groups.length > PAGE_SIZE && (
        <div className="flex items-center justify-between border-t border-border pt-2 text-[11px] text-muted-foreground">
          <span>
            {safePage * PAGE_SIZE + 1}–{Math.min((safePage + 1) * PAGE_SIZE, groups.length)} of {groups.length}
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={safePage === 0}
              aria-label="Previous page"
              className="rounded-md border p-1 hover:bg-muted/40 disabled:opacity-30 disabled:hover:bg-transparent"
            >
              <ChevronLeft className="size-3" />
            </button>
            <span className="px-1 tabular-nums">{safePage + 1} / {totalPages}</span>
            <button
              type="button"
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={safePage >= totalPages - 1}
              aria-label="Next page"
              className="rounded-md border p-1 hover:bg-muted/40 disabled:opacity-30 disabled:hover:bg-transparent"
            >
              <ChevronRight className="size-3" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

type CommitGroup = {
  key: string
  commitSha: string | null
  versionString: string
  branchName: string | null
  latestCreatedAt: string
  // Aggregated across every CV in the build cycle (net10, web, etc.),
  // deduped to one row per scanner (latest receipt wins on conflict).
  scannerSummary: ScanReceiptRow[]
}

function groupByCommit(builds: BuildReceipt[]): CommitGroup[] {
  const map = new Map<string, BuildReceipt[]>()
  for (const b of builds) {
    const key = b.commitSha ?? b.versionString
    const arr = map.get(key) ?? []
    arr.push(b)
    map.set(key, arr)
  }
  const groups: CommitGroup[] = []
  for (const [key, cvs] of map.entries()) {
    cvs.sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    const head = cvs[0]
    const byScanner = new Map<string, ScanReceiptRow>()
    for (const cv of cvs) {
      for (const r of cv.receipts) {
        const prev = byScanner.get(r.scanner)
        if (!prev || (r.completedAt ?? '') > (prev.completedAt ?? '')) byScanner.set(r.scanner, r)
      }
    }
    groups.push({
      key,
      commitSha: head.commitSha,
      versionString: head.versionString,
      branchName: head.branchName,
      latestCreatedAt: head.createdAt,
      scannerSummary: [...byScanner.values()].sort((a, b) => a.scanner.localeCompare(b.scanner)),
    })
  }
  return groups.sort((a, b) => b.latestCreatedAt.localeCompare(a.latestCreatedAt))
}

function CommitRow({ group }: { group: CommitGroup }) {
  const totalFindings = group.scannerSummary.reduce((s, r) => s + r.findingsCount, 0)
  const failed = group.scannerSummary.filter(r => r.status === 'Failed').length
  const succeeded = group.scannerSummary.filter(r => r.status === 'Succeeded').length
  const skipped = group.scannerSummary.filter(r => r.status === 'Skipped').length

  return (
    <li className="rounded-md border bg-card/60 p-2 text-xs">
      <div className="flex items-baseline justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-foreground">{group.commitSha?.slice(0, 7) ?? group.versionString}</span>
            {group.branchName && <span className="text-muted-foreground">· {group.branchName}</span>}
            <span className="text-muted-foreground">· {formatDt(group.latestCreatedAt)}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2 text-[11px] tabular-nums whitespace-nowrap">
          {failed > 0 && (
            <span className="inline-flex items-center gap-0.5 text-destructive">
              <XCircle className="size-3" /> {failed}
            </span>
          )}
          {succeeded > 0 && (
            <span className="inline-flex items-center gap-0.5 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-3" /> {succeeded}
            </span>
          )}
          {skipped > 0 && (
            <span className="inline-flex items-center gap-0.5 text-muted-foreground">
              <MinusCircle className="size-3" /> {skipped}
            </span>
          )}
          <span className="text-muted-foreground">{totalFindings} findings</span>
        </div>
      </div>
      {group.scannerSummary.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {group.scannerSummary.map(r => <ScannerChip key={r.scanner} r={r} />)}
        </div>
      )}
    </li>
  )
}

function ScannerChip({ r }: { r: ScanReceiptRow }) {
  const tone =
    r.status === 'Succeeded' ? 'border-emerald-500/40 text-emerald-700 dark:text-emerald-400' :
    r.status === 'Failed'    ? 'border-destructive/50 text-destructive' :
                               'border-border text-muted-foreground'
  return (
    <span
      title={`${r.scanner} · ${r.status}${r.toolVersion ? ` · v${r.toolVersion}` : ''}${r.completedAt ? `\n${formatDt(r.completedAt)}` : ''}`}
      className={`inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] tabular-nums ${tone}`}
    >
      {r.scanner}
      {r.findingsCount > 0 && <span>· {r.findingsCount}</span>}
    </span>
  )
}

function formatDt(iso: string) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: 'numeric', minute: '2-digit',
    })
  } catch { return iso }
}
