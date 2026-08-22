import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, Unlink, Pencil } from 'lucide-react'
import {
  fetchProjectPolicyAndGates, fetchRiskPolicies, assignProjectPolicy,
  forkProjectPolicy, updateProjectGates, fetchRiskPolicy,
} from '@/lib/api'
import type { ProjectGatesConfig, RiskPolicySummary } from '@/lib/api'
import { RiskPolicyEditor } from '@/components/RiskPolicyEditor'
import { VexStatementsPanel } from '@/components/VexStatementsPanel'
import { PoamItemsPanel } from '@/components/PoamItemsPanel'
import { VdpPanel } from '@/components/VdpPanel'

// Per-gate UI schema — keys must match GateKeys on the backend.
type GateField = { key: string; label: string; hint?: string; thresholdLabel?: string; thresholdStep?: number; thresholdDefault?: number }
const GATE_FIELDS: GateField[] = [
  { key: 'riskScoreRegression', label: 'Risk score regression',
    hint: 'Fail when this build\'s score is higher than the prior canonical build\'s by more than X points.',
    thresholdLabel: 'Max allowed delta (points)', thresholdStep: 0.5, thresholdDefault: 0 },
  { key: 'kevExposure', label: 'CISA KEV exposure',
    hint: 'Fail if the SBOM contains any CVE on the CISA Known Exploited Vulnerabilities catalog (M-22-09 / BOD 22-01). KEV-listed CVEs are confirmed exploited in the wild.' },
  { key: 'anyCves', label: 'Any open CVE',
    hint: 'Fail if the SBOM has any open vulnerability, regardless of severity.' },
  { key: 'criticalCves', label: 'Critical CVE',
    hint: 'Fail if any Critical-severity CVE is open in the SBOM.' },
  { key: 'highCves', label: 'High CVE',
    hint: 'Fail if any High-severity CVE is open in the SBOM.' },
  { key: 'criticalSast', label: 'Critical SAST finding',
    hint: 'Fail if any Critical-severity SAST finding is open (Roslyn / ReSharper / OpenGrep / CodeQL / ESLint). Note: only reachable for scanners that publish a security-severity (CVSS) score — SARIF levels alone top out at High, so prefer the High gate for most SAST tools.' },
  { key: 'highSast', label: 'High SAST finding',
    hint: 'Fail if any High-severity SAST finding is open. This is the gate that bites for scanners reporting through SARIF levels, whose most severe class is High.' },
  { key: 'criticalDast', label: 'Critical DAST finding',
    hint: 'Fail if any Critical-severity dynamic-scan finding is open (ZAP / Nuclei). ZAP reports through SARIF levels and tops out at High, so use the High gate for it.' },
  { key: 'highDast', label: 'High DAST finding',
    hint: 'Fail if any High-severity dynamic-scan finding is open. A ZAP-confirmed SQL injection lands here — this is the gate that catches it.' },
  { key: 'criticalIac', label: 'Critical IaC misconfig',
    hint: 'Fail if any Critical Trivy misconfiguration finding is open.' },
  { key: 'verifiedSecrets', label: 'Verified secret',
    hint: 'Fail if any TruffleHog-verified credential is present.' },
  { key: 'deniedLicenses', label: 'Denied license',
    hint: 'Fail if any component\'s license falls in the Denied tier.' },
  { key: 'testFailures', label: 'Test failures',
    hint: 'Fail if the latest TestRunReport has any failed cases.' },
  { key: 'coverageRegression', label: 'Coverage regression',
    hint: 'Fail when coverage drops from the prior canonical build by more than X percentage points.',
    thresholdLabel: 'Max allowed drop (pp)', thresholdStep: 0.5, thresholdDefault: 1 },
  { key: 'poamPastDue', label: 'POA&M past due',
    hint: 'Fail when more than X open POA&M items are past their scheduled completion date. Federal continuous monitoring (FedRAMP / NIST 800-53 CA-5) expects past-due weaknesses to be flagged explicitly.',
    thresholdLabel: 'Max past-due allowed', thresholdStep: 1, thresholdDefault: 0 },
]

export function ProjectSettingsDialog({
  projectId,
  projectName,
  onClose,
}: {
  projectId: string
  projectName: string
  onClose: () => void
}) {
  const qc = useQueryClient()
  const view = useQuery({
    queryKey: ['project-policy-gates', projectId],
    queryFn: () => fetchProjectPolicyAndGates(projectId),
  })
  const policies = useQuery({ queryKey: ['risk-policies'], queryFn: fetchRiskPolicies })

  // Local edit state for gates. Lazy-initialise once view loads.
  const [gates, setGates] = useState<ProjectGatesConfig | null>(null)
  useEffect(() => {
    if (view.data && gates === null) setGates(structuredClone(view.data.gates))
  }, [view.data, gates])

  // Editor-open state when the admin clicks "Edit policy" on the
  // project-owned (forked) policy.
  const [editingId, setEditingId] = useState<string | null>(null)
  const editingPolicy = useQuery({
    queryKey: ['risk-policy', editingId],
    queryFn: () => fetchRiskPolicy(editingId!),
    enabled: editingId !== null,
  })

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && editingId === null) onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose, editingId])

  const assign = useMutation({
    mutationFn: (policyId: string | null) => assignProjectPolicy(projectId, policyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-policy-gates', projectId] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
    },
  })
  const fork = useMutation({
    mutationFn: () => forkProjectPolicy(projectId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-policy-gates', projectId] })
      qc.invalidateQueries({ queryKey: ['risk-policies'] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
    },
  })
  const saveGates = useMutation({
    mutationFn: () => updateProjectGates(projectId, gates!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-policy-gates', projectId] })
    },
  })

  const updateGate = (key: string, patch: Partial<{ enabled: boolean; threshold: number | null }>) => {
    if (!gates) return
    const current = gates.gates[key] ?? { enabled: false }
    setGates({
      ...gates,
      gates: { ...gates.gates, [key]: { ...current, ...patch } },
    })
  }

  const inheritedSource = view.data?.effectiveFromClient ? 'client' : 'default'
  const onProjectOwnedPolicy = view.data?.effectiveFromProject === true

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 sm:p-8"
      role="dialog" aria-modal="true"
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-3xl rounded-md border bg-card shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 className="text-base font-semibold tracking-tight">
            Project settings — {projectName}
          </h2>
          <button onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground">
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-6 px-5 py-5 text-sm">
          {/* ---- Risk policy --------------------------------------- */}
          <section className="space-y-2">
            <div>
              <h3 className="text-sm font-semibold">Risk policy</h3>
              <p className="text-[11px] text-muted-foreground">
                Drives the project's risk score. Inherits from the client by default; override to tune just this project.
              </p>
            </div>

            {view.isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
            {view.data && (
              <div className="rounded-md border bg-card/60 p-3">
                <p className="text-sm">
                  <span className="font-medium">{view.data.effectivePolicyName}</span>
                  {!onProjectOwnedPolicy && (
                    <span className="ml-2 text-[11px] text-muted-foreground">
                      (inherited from {inheritedSource})
                    </span>
                  )}
                  {onProjectOwnedPolicy && (
                    <span className="ml-2 text-[11px] text-emerald-700 dark:text-emerald-400">
                      (project override)
                    </span>
                  )}
                </p>

                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {!onProjectOwnedPolicy && (
                    <button
                      type="button"
                      onClick={() => fork.mutate()}
                      disabled={fork.isPending}
                      title="Clone the current effective policy and assign the copy to this project so you can tune it independently."
                      className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted/40"
                    >
                      <Unlink className="size-3.5" />
                      {fork.isPending ? 'Disconnecting…' : 'Disconnect & customize'}
                    </button>
                  )}
                  {onProjectOwnedPolicy && (
                    <>
                      <button
                        type="button"
                        onClick={() => setEditingId(view.data.effectivePolicyId)}
                        className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted/40"
                      >
                        <Pencil className="size-3.5" />
                        Edit policy
                      </button>
                      <button
                        type="button"
                        onClick={() => assign.mutate(null)}
                        disabled={assign.isPending}
                        title="Drop the project override and inherit from the client / default again. The override policy row stays in the library."
                        className="rounded-md px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                      >
                        Revert to inherited
                      </button>
                    </>
                  )}
                  {/* Picker for selecting an existing policy by name. Independent
                      of fork — useful when several projects should share a
                      hand-crafted policy already in the library. */}
                  {policies.data && (
                    <select
                      value={view.data.assignedPolicyId ?? '__inherit__'}
                      onChange={(e) => assign.mutate(e.target.value === '__inherit__' ? null : e.target.value)}
                      disabled={assign.isPending}
                      className="rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
                    >
                      <option value="__inherit__">Inherit</option>
                      {(policies.data as RiskPolicySummary[]).map(p => (
                        <option key={p.id} value={p.id}>{p.name}{p.isDefault ? ' · default' : ''}</option>
                      ))}
                    </select>
                  )}
                </div>
              </div>
            )}
          </section>

          {/* ---- Gates --------------------------------------------- */}
          <section className="space-y-2">
            <div>
              <h3 className="text-sm font-semibold">Acceptance gates</h3>
              <p className="text-[11px] text-muted-foreground">
                Pass/fail blockers per build. Independent of the risk score — a gate failure says "don't merge", not "your score went up".
                Evaluation against builds lands with the per-build risk computation (TODO).
              </p>
            </div>

            {gates && (
              <div className="space-y-2">
                {GATE_FIELDS.map(f => {
                  const cfg = gates.gates[f.key] ?? { enabled: false }
                  const hasThreshold = f.thresholdLabel !== undefined
                  return (
                    <div key={f.key} className="rounded-md border border-border p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            id={`gate-${f.key}`}
                            checked={cfg.enabled}
                            onChange={(e) => updateGate(f.key, { enabled: e.target.checked })}
                            className="rounded"
                          />
                          <label htmlFor={`gate-${f.key}`} className="text-sm font-medium">{f.label}</label>
                        </div>
                        {hasThreshold && (
                          <div className="flex items-center gap-1.5 text-xs">
                            <span className="text-muted-foreground">{f.thresholdLabel}</span>
                            <input
                              type="number" step={f.thresholdStep ?? 1}
                              value={cfg.threshold ?? f.thresholdDefault ?? 0}
                              onChange={(e) => updateGate(f.key, { threshold: Number(e.target.value) })}
                              disabled={!cfg.enabled}
                              className="w-20 rounded-md border bg-background px-2 py-1 text-right tabular-nums disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ring/40"
                            />
                          </div>
                        )}
                      </div>
                      {f.hint && <p className="mt-1 text-[11px] text-muted-foreground">{f.hint}</p>}
                    </div>
                  )
                })}
              </div>
            )}

            {saveGates.isError && (
              <p className="text-xs text-destructive">Save failed: {(saveGates.error as Error)?.message}</p>
            )}
          </section>

          {/* ---- VEX statements ------------------------------------- */}
          <VexStatementsPanel projectId={projectId} />

          {/* ---- POA&M items ---------------------------------------- */}
          <PoamItemsPanel projectId={projectId} />

          {/* ---- Vulnerability disclosure --------------------------- */}
          <VdpPanel projectId={projectId} />
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            Close
          </button>
          <button
            type="button"
            onClick={() => saveGates.mutate()}
            disabled={!gates || saveGates.isPending}
            className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
          >
            {saveGates.isPending ? 'Saving gates…' : 'Save gates'}
          </button>
        </div>

        {editingId !== null && editingPolicy.data && (
          <RiskPolicyEditor
            policy={editingPolicy.data}
            onClose={() => setEditingId(null)}
          />
        )}
      </div>
    </div>
  )
}
