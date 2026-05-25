import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, Printer, ShieldCheck, ShieldAlert, ShieldQuestion, CircleSlash } from 'lucide-react'
import { fetchSsdfAttestation } from '@/lib/api'
import type { SsdfAttestation, SsdfPractice, SsdfPracticeStatus } from '@/lib/api'

// CISA SSDF attestation page. Single-screen layout intended to print
// clean (margins via the @page CSS in index.css fallback to default).
// Two affordances besides the read view:
//   - "Export JSON" downloads the raw doc for inclusion in a FedRAMP
//     package
//   - "Print / save PDF" hands off to the browser's native print flow
//
// Practice ordering follows SP 800-218 family order: PO → PS → PW →
// RV. Within each family the practice ids are pre-sorted by the
// backend.
export function AttestationView({
  projectId,
  onBack,
}: {
  projectId: string
  onBack: () => void
}) {
  const q = useQuery({
    queryKey: ['ssdf-attestation', projectId],
    queryFn: () => fetchSsdfAttestation(projectId),
  })

  const onExport = () => {
    if (!q.data) return
    const blob = new Blob([JSON.stringify(q.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ssdf-attestation-${q.data.project.name.replace(/\W+/g, '-')}-${q.data.generated.substring(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2 print:hidden">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-4" /> Back to project
        </button>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => window.print()}
            disabled={!q.data}
            className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted/40 disabled:opacity-50"
          >
            <Printer className="size-3.5" /> Print / save PDF
          </button>
          <button
            type="button"
            onClick={onExport}
            disabled={!q.data}
            className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted/40 disabled:opacity-50"
          >
            <Download className="size-3.5" /> Export JSON
          </button>
        </div>
      </div>

      {q.isLoading && <p className="text-sm text-muted-foreground">Loading attestation…</p>}
      {q.isError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load: {(q.error as Error).message}
        </p>
      )}

      {q.data && <AttestationBody doc={q.data} />}
    </div>
  )
}

function AttestationBody({ doc }: { doc: SsdfAttestation }) {
  // Group practices by family for the table-of-practices section.
  const families: Array<{ key: string; label: string; expand: string }> = [
    { key: 'PO', label: 'PO — Prepare the Organization', expand: 'Org-level capability & toolchain readiness' },
    { key: 'PS', label: 'PS — Protect the Software', expand: 'Integrity, distribution, SBOM provenance' },
    { key: 'PW', label: 'PW — Produce Well-Secured Software', expand: 'Design review, SAST, secrets, IaC, tests' },
    { key: 'RV', label: 'RV — Respond to Vulnerabilities', expand: 'CVE detection, triage, POA&M, VEX, disclosure' },
  ]

  return (
    <article className="space-y-6 print:space-y-4">
      {/* Cover header */}
      <header className="rounded-md border bg-card p-5 print:border-0 print:p-0">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
          CISA Secure Software Development Attestation · NIST SSDF (SP 800-218)
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">{doc.project.name}</h1>
        <p className="text-sm text-muted-foreground">
          Client: {doc.project.clientName || '—'}
        </p>
        <p className="mt-3 text-xs text-muted-foreground">
          Generated {formatDateTime(doc.generated)} · auto-populated from automated evidence;
          Manual practices require attestation by the software-producer's authorized
          signatory before submission.
        </p>
      </header>

      {/* Summary tile + build stamp */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="rounded-md border bg-card p-4">
          <h2 className="text-sm font-semibold">Attestation summary</h2>
          <p className="mt-1 text-xs text-muted-foreground">{doc.summary.headline}</p>
          <div className="mt-3 grid grid-cols-4 gap-2 text-center text-xs">
            <SummaryTile count={doc.summary.yes} label="Yes" tone="emerald" />
            <SummaryTile count={doc.summary.partial} label="Partial" tone="amber" />
            <SummaryTile count={doc.summary.no} label="No" tone="red" />
            <SummaryTile count={doc.summary.manual} label="Manual" tone="muted" />
          </div>
        </div>

        <div className="rounded-md border bg-card p-4">
          <h2 className="text-sm font-semibold">Build under attestation</h2>
          {doc.build ? (
            <dl className="mt-1 space-y-0.5 text-xs">
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Commit</dt>
                <dd className="font-mono">{doc.build.commitSha?.substring(0, 12) ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Version</dt>
                <dd className="font-mono">{doc.build.versionString}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Built</dt>
                <dd>{formatDateTime(doc.build.latestCreatedAt)}</dd>
              </div>
              {doc.risk && (
                <>
                  <div className="flex justify-between gap-2 pt-1">
                    <dt className="text-muted-foreground">Risk score</dt>
                    <dd>
                      <RiskScorePill score={doc.risk.score} band={doc.risk.band} />
                    </dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted-foreground">Policy</dt>
                    <dd className="text-right">{doc.risk.policyName}</dd>
                  </div>
                </>
              )}
            </dl>
          ) : (
            <p className="mt-1 text-xs text-muted-foreground">
              No canonical build for this project yet — attestation evidence is empty.
            </p>
          )}
        </div>
      </section>

      {/* Gates */}
      {doc.gates && doc.gates.enabled > 0 && (
        <section className="rounded-md border bg-card p-4">
          <h2 className="text-sm font-semibold">Acceptance gates</h2>
          <p className="text-[11px] text-muted-foreground">
            {doc.gates.passed} of {doc.gates.enabled} passed · {doc.gates.failed} failing
          </p>
          <ul className="mt-2 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {doc.gates.results.map(g => (
              <li key={g.key} className="flex items-center justify-between gap-2 rounded-md border bg-background/40 px-2.5 py-1.5 text-xs">
                <span className="flex items-center gap-1.5">
                  {g.passed
                    ? <span className="inline-block size-2 rounded-full bg-emerald-500" />
                    : <span className="inline-block size-2 rounded-full bg-destructive" />}
                  <code className="text-[11px]">{g.key}</code>
                </span>
                <span className="text-muted-foreground">{g.observed}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Practices */}
      <section className="space-y-4">
        {families.map(f => {
          const rows = doc.practices.filter(p => p.family === f.key)
          if (rows.length === 0) return null
          return (
            <div key={f.key} className="rounded-md border bg-card">
              <header className="border-b border-border bg-muted/30 px-4 py-2.5">
                <h3 className="text-sm font-semibold">{f.label}</h3>
                <p className="text-[11px] text-muted-foreground">{f.expand}</p>
              </header>
              <table className="w-full text-xs">
                <colgroup>
                  <col className="w-20" />
                  <col className="w-24" />
                  <col />
                </colgroup>
                <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-4 py-1.5">Practice</th>
                    <th className="px-4 py-1.5">Status</th>
                    <th className="px-4 py-1.5">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(p => (
                    <PracticeRow key={p.id} practice={p} />
                  ))}
                </tbody>
              </table>
            </div>
          )
        })}
      </section>

      {/* Signatory block (printable footer; not interactive) */}
      <footer className="rounded-md border border-dashed bg-card p-5 text-xs print:border-0 print:px-0">
        <p className="font-medium">Signatory attestation</p>
        <p className="mt-1 text-muted-foreground">
          The undersigned attests that the practices marked <strong>Manual</strong> have been
          performed in accordance with this project's documented procedures, and that the
          automated evidence above is accurate to the best of their knowledge.
        </p>
        <div className="mt-6 grid grid-cols-1 gap-6 sm:grid-cols-3">
          <SignatoryLine label="Name + title" />
          <SignatoryLine label="Signature" />
          <SignatoryLine label="Date" />
        </div>
      </footer>
    </article>
  )
}

function PracticeRow({ practice }: { practice: SsdfPractice }) {
  return (
    <tr className="border-t border-border align-top">
      <td className="px-4 py-2 font-mono text-[11px] font-medium">{practice.id}</td>
      <td className="px-4 py-2"><StatusBadge status={practice.status} /></td>
      <td className="px-4 py-2">
        <p className="font-medium text-foreground">{practice.label}</p>
        <p className="text-[11px] text-muted-foreground">{practice.intent}</p>
        <p className="mt-1 text-[11px] text-foreground/90">{practice.evidence}</p>
      </td>
    </tr>
  )
}

function StatusBadge({ status }: { status: SsdfPracticeStatus }) {
  const map: Record<SsdfPracticeStatus, { icon: typeof ShieldCheck; tone: string }> = {
    Yes: { icon: ShieldCheck, tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300' },
    Partial: { icon: ShieldQuestion, tone: 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300' },
    No: { icon: ShieldAlert, tone: 'bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-300' },
    Manual: { icon: CircleSlash, tone: 'bg-muted text-muted-foreground' },
  }
  const { icon: Icon, tone } = map[status]
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${tone}`}>
      <Icon className="size-3" />
      {status}
    </span>
  )
}

function SummaryTile({ count, label, tone }: { count: number; label: string; tone: string }) {
  const tones: Record<string, string> = {
    emerald: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300',
    amber: 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300',
    red: 'bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-300',
    muted: 'bg-muted text-muted-foreground',
  }
  return (
    <div className={`rounded-md py-2 ${tones[tone] ?? tones.muted}`}>
      <p className="text-lg font-bold tabular-nums">{count}</p>
      <p className="text-[10px] uppercase tracking-wider">{label}</p>
    </div>
  )
}

function RiskScorePill({ score, band }: { score: number; band: string }) {
  const bandTone: Record<string, string> = {
    green: 'text-emerald-700 dark:text-emerald-400',
    yellow: 'text-yellow-700 dark:text-yellow-400',
    orange: 'text-orange-700 dark:text-orange-400',
    red: 'text-red-700 dark:text-red-400',
  }
  return <span className={`tabular-nums font-medium ${bandTone[band] ?? ''}`}>{score.toFixed(1)} · {band}</span>
}

function SignatoryLine({ label }: { label: string }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="mt-6 border-b border-foreground/40" />
    </div>
  )
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}
