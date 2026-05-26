import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, ShieldCheck, ShieldAlert, ShieldQuestion, Wrench } from 'lucide-react'
import {
  fetchVexStatements, createVexStatement, retireVexStatement,
} from '@/lib/api'
import type { VexStatementStatus, VexJustification } from '@/lib/api'

// Renders the per-project VEX management panel inside the project
// settings dialog. Two responsibilities:
//   1. Show active statements (purl, advisory, disposition, why)
//      so an auditor can see the project's CVE-suppression posture
//      at a glance.
//   2. Author a new statement (the common "we already triaged this
//      CVE; not exploitable because <reason>" workflow).
//
// Deferred for later:
//   - SBOM-row badges (TFND-25 phase 3) — would need the SbomTable
//     to know which vulns are VEX-covered.
//   - CycloneDX-VEX bulk-ingest UI (backend endpoint exists; today
//     it's curl-only).
//   - Edit-in-place — for now, retire + recreate is the path. Keeps
//     the audit trail honest.
export function VexStatementsPanel({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const list = useQuery({
    queryKey: ['vex-statements', projectId],
    queryFn: () => fetchVexStatements(projectId, false),
  })

  const [draft, setDraft] = useState<DraftState | null>(null)

  const create = useMutation({
    mutationFn: () => createVexStatement(projectId, normalizeDraft(draft!)),
    onSuccess: () => {
      setDraft(null)
      // Invalidate the panel's own list AND aggregates — the
      // suppression flows through to the dashboard score and the
      // kevExposure gate; the user expects the change immediately.
      qc.invalidateQueries({ queryKey: ['vex-statements', projectId] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
      qc.invalidateQueries({ queryKey: ['build-evaluation', projectId] })
    },
  })

  const retire = useMutation({
    mutationFn: (id: string) => retireVexStatement(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vex-statements', projectId] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
      qc.invalidateQueries({ queryKey: ['build-evaluation', projectId] })
    },
  })

  return (
    <section className="space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">VEX statements</h3>
          <p className="text-[11px] text-muted-foreground">
            Document why a CVE in your SBOM isn't exploitable. <strong className="font-medium">Not affected</strong> and <strong className="font-medium">Fixed</strong> statements suppress the matching vuln from CVE counts and the CISA KEV gate. Required for federal audits (M-22-18, FedRAMP SBOM/VDR).
          </p>
        </div>
        {draft === null && (
          <button
            type="button"
            onClick={() => setDraft(makeBlankDraft())}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted/40"
          >
            <Plus className="size-3.5" /> Author statement
          </button>
        )}
      </div>

      {list.isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
      {list.data && list.data.length === 0 && draft === null && (
        <p className="rounded-md border border-dashed bg-card/40 px-3 py-3 text-xs text-muted-foreground">
          No active VEX statements for this project. Every CVE in the SBOM is scored at face value.
        </p>
      )}

      {list.data && list.data.length > 0 && (
        <ul className="space-y-2">
          {list.data.map(v => (
            <li key={v.id} className="rounded-md border bg-card/60 p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={v.status} />
                    <span className="font-mono text-xs">{v.advisoryId}</span>
                  </div>
                  <p className="break-all text-[12px] text-muted-foreground">
                    <span className="font-mono">{v.purl}</span>
                    {v.componentVersion && <span className="font-mono"> @ {v.componentVersion}</span>}
                  </p>
                  {v.justification && v.justification !== 'None' && (
                    <p className="text-[11px] text-muted-foreground">
                      Justification: <span className="text-foreground">{prettyJustification(v.justification)}</span>
                    </p>
                  )}
                  {v.impactStatement && (
                    <p className="whitespace-pre-line text-[12px] text-foreground/90">
                      {v.impactStatement}
                    </p>
                  )}
                  {v.responseReferenceUrl && (
                    <p className="text-[11px]">
                      <a
                        href={v.responseReferenceUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-blue-600 hover:underline dark:text-blue-400"
                      >
                        Reference ↗
                      </a>
                    </p>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => retire.mutate(v.id)}
                  disabled={retire.isPending}
                  title="Retire this statement (soft-delete; audit row preserved). The CVE will start counting again."
                  className="shrink-0 rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-destructive"
                >
                  <Trash2 className="size-4" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {draft !== null && (
        <VexDraftForm
          draft={draft}
          onChange={setDraft}
          onCancel={() => setDraft(null)}
          onSubmit={() => create.mutate()}
          submitting={create.isPending}
          error={(create.error as Error | null)?.message ?? null}
        />
      )}
    </section>
  )
}

// ---------------------------------------------------------------- form

type DraftState = {
  advisoryId: string
  purl: string
  componentVersion: string
  status: VexStatementStatus
  justification: VexJustification
  impactStatement: string
  responseReferenceUrl: string
}

function makeBlankDraft(): DraftState {
  return {
    advisoryId: '',
    purl: '',
    componentVersion: '',
    // NotAffected is the federally-interesting status — Affected is
    // documentation-only; UnderInvestigation doesn't suppress.
    status: 'NotAffected',
    justification: 'VulnerableCodeNotInExecutePath',
    impactStatement: '',
    responseReferenceUrl: '',
  }
}

function normalizeDraft(d: DraftState) {
  // The backend treats Justification=None as "no justification";
  // collapse the form's None selection to null so the wire payload
  // matches the spec.
  return {
    advisoryId: d.advisoryId.trim(),
    purl: d.purl.trim(),
    componentVersion: d.componentVersion.trim() || null,
    status: d.status,
    justification: d.justification === 'None' ? null : d.justification,
    impactStatement: d.impactStatement.trim() || null,
    responseReferenceUrl: d.responseReferenceUrl.trim() || null,
  }
}

function VexDraftForm({
  draft, onChange, onCancel, onSubmit, submitting, error,
}: {
  draft: DraftState
  onChange: (d: DraftState) => void
  onCancel: () => void
  onSubmit: () => void
  submitting: boolean
  error: string | null
}) {
  const set = <K extends keyof DraftState>(k: K, v: DraftState[K]) =>
    onChange({ ...draft, [k]: v })
  const justRequired = draft.status === 'NotAffected'
  const justInvalid = justRequired && draft.justification === 'None'
  const ready = draft.advisoryId.trim() && draft.purl.trim() && !justInvalid

  return (
    <div className="space-y-3 rounded-md border bg-card/60 p-3">
      <p className="text-xs font-medium">New VEX statement</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Advisory ID" hint="e.g. CVE-2021-44228">
          <input
            value={draft.advisoryId}
            onChange={(e) => set('advisoryId', e.target.value)}
            placeholder="CVE-2021-44228"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </Field>
        <Field label="Package URL" hint="bare or @version; bare matches every version in the SBOM">
          <input
            value={draft.purl}
            onChange={(e) => set('purl', e.target.value)}
            placeholder="pkg:nuget/Log4Net"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </Field>
        <Field label="Component version (optional)" hint="leave blank to apply to every version">
          <input
            value={draft.componentVersion}
            onChange={(e) => set('componentVersion', e.target.value)}
            placeholder="2.0.5"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </Field>
        <Field label="Disposition" hint="Not affected / Fixed suppress; Under investigation / Affected do not">
          <select
            value={draft.status}
            onChange={(e) => set('status', e.target.value as VexStatementStatus)}
            className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          >
            <option value="UnderInvestigation">Under investigation</option>
            <option value="Affected">Affected</option>
            <option value="NotAffected">Not affected</option>
            <option value="Fixed">Fixed</option>
          </select>
        </Field>
        <Field
          label="Justification"
          hint={justRequired ? 'Required for Not affected' : 'Optional'}
          className="sm:col-span-2"
        >
          <select
            value={draft.justification}
            onChange={(e) => set('justification', e.target.value as VexJustification)}
            className={`w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 ${
              justInvalid ? 'border-destructive focus:ring-destructive/40' : 'focus:ring-ring/40'
            }`}
          >
            <option value="None">— Select —</option>
            <option value="ComponentNotPresent">Component not present</option>
            <option value="VulnerableCodeNotPresent">Vulnerable code not present</option>
            <option value="VulnerableCodeNotInExecutePath">Vulnerable code not in execute path</option>
            <option value="VulnerableCodeCannotBeControlledByAdversary">Vulnerable code cannot be controlled by adversary</option>
            <option value="InlineMitigationsAlreadyExist">Inline mitigations already exist</option>
          </select>
        </Field>
        <Field label="Impact statement" hint="Free text — surfaces to auditors" className="sm:col-span-2">
          <textarea
            value={draft.impactStatement}
            onChange={(e) => set('impactStatement', e.target.value)}
            rows={3}
            placeholder="Affected sink uses log4net.Layout but never deserializes user input; JNDI lookups disabled at config level."
            className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </Field>
        <Field label="Reference URL (optional)" hint="Issue tracker, blog post, vendor advisory" className="sm:col-span-2">
          <input
            value={draft.responseReferenceUrl}
            onChange={(e) => set('responseReferenceUrl', e.target.value)}
            placeholder="https://github.com/example/repo/issues/123"
            className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
          />
        </Field>
      </div>

      {error && <p className="text-xs text-destructive">Save failed: {error}</p>}

      <div className="flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSubmit}
          disabled={!ready || submitting}
          className="rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background disabled:opacity-50"
        >
          {submitting ? 'Saving…' : 'Author'}
        </button>
      </div>
    </div>
  )
}

function Field({
  label, hint, className, children,
}: {
  label: string
  hint?: string
  className?: string
  children: React.ReactNode
}) {
  return (
    <div className={className}>
      <label className="block text-[11px] font-medium text-muted-foreground">{label}</label>
      {children}
      {hint && <p className="mt-0.5 text-[10px] text-muted-foreground/80">{hint}</p>}
    </div>
  )
}

// ---------------------------------------------------------------- helpers

function StatusBadge({ status }: { status: VexStatementStatus }) {
  // Icon + colour cue mirror the meaning at score time:
  //   - NotAffected: shield-check (positive — vuln subtracted)
  //   - Fixed: wrench (resolved upstream)
  //   - Affected: shield-alert (still counts; documented)
  //   - UnderInvestigation: shield-question (triage pending)
  const map: Record<VexStatementStatus, { icon: typeof ShieldCheck; label: string; tone: string }> = {
    NotAffected: { icon: ShieldCheck, label: 'Not affected', tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300' },
    Fixed: { icon: Wrench, label: 'Fixed', tone: 'bg-blue-100 text-blue-800 dark:bg-blue-950/40 dark:text-blue-300' },
    Affected: { icon: ShieldAlert, label: 'Affected', tone: 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300' },
    UnderInvestigation: { icon: ShieldQuestion, label: 'Under investigation', tone: 'bg-muted text-muted-foreground' },
  }
  const { icon: Icon, label, tone } = map[status]
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ${tone}`}>
      <Icon className="size-3" />
      {label}
    </span>
  )
}

function prettyJustification(j: VexJustification): string {
  switch (j) {
    case 'ComponentNotPresent': return 'Component not present'
    case 'VulnerableCodeNotPresent': return 'Vulnerable code not present'
    case 'VulnerableCodeNotInExecutePath': return 'Vulnerable code not in execute path'
    case 'VulnerableCodeCannotBeControlledByAdversary': return 'Cannot be controlled by adversary'
    case 'InlineMitigationsAlreadyExist': return 'Inline mitigations already exist'
    case 'None': return '—'
  }
}
