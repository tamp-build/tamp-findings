import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Trash2, Star, Copy } from 'lucide-react'
import {
  updateRiskPolicy, deleteRiskPolicy, setDefaultRiskPolicy, cloneRiskPolicy,
} from '@/lib/api'
import type { RiskPolicyFull, RiskPolicyConfig } from '@/lib/api'

// Canonical per-category UI schema. Drives the form: which weight keys
// the editor exposes, with friendly labels. Keys here are the same
// keys the scorer reads (RiskCategoryNames in domain). When the scorer
// gains a new category, add it here too so the editor surfaces it.
type WeightField = { key: string; label: string; step?: number }
type CategorySchema = { label: string; fields: WeightField[]; help?: string }

const CATEGORY_SCHEMA: Record<string, CategorySchema> = {
  cve: {
    label: 'Known CVEs',
    fields: [
      { key: 'critical', label: 'Critical', step: 0.05 },
      { key: 'high', label: 'High', step: 0.05 },
      { key: 'medium', label: 'Medium', step: 0.01 },
      { key: 'low', label: 'Low', step: 0.005 },
    ],
    help: 'sub-score = Σ count × weight (capped at 1)',
  },
  secrets: {
    label: 'Verified secrets',
    fields: [
      { key: 'verified', label: 'Verified (live cred)', step: 0.1 },
      { key: 'unverified', label: 'Unverified (pattern match)', step: 0.05 },
    ],
  },
  sastSevere: {
    label: 'SAST · critical + high',
    fields: [
      { key: 'critical', label: 'Critical', step: 0.05 },
      { key: 'high', label: 'High', step: 0.05 },
    ],
  },
  iacSevere: {
    label: 'IaC · critical + high (Trivy)',
    fields: [
      { key: 'critical', label: 'Critical', step: 0.05 },
      { key: 'high', label: 'High', step: 0.05 },
    ],
  },
  coverage: {
    label: 'Coverage gap',
    fields: [
      { key: 'targetPercent', label: 'Target coverage %', step: 1 },
      { key: 'unmeasuredScore', label: 'Score when unmeasured (0–1)', step: 0.1 },
    ],
    help: 'sub-score = max(0, (target − measured) / target)',
  },
  sbomStaleness: {
    label: 'SBOM staleness',
    fields: [
      { key: 'outdated', label: 'Outdated fraction weight', step: 0.1 },
      { key: 'stale', label: 'Stale (>180d) fraction weight', step: 0.1 },
    ],
  },
  tests: {
    label: 'Test failures',
    fields: [
      { key: 'failureMultiplier', label: 'Failure-rate multiplier', step: 0.5 },
      { key: 'anyFailureFloor', label: 'Any-failure floor (0–1)', step: 0.05 },
      { key: 'unmeasuredScore', label: 'Score when unmeasured (0–1)', step: 0.05 },
    ],
  },
  license: {
    label: 'License risk',
    fields: [
      { key: 'denied', label: 'Per-denied weight', step: 0.05 },
      { key: 'strongCopyleft', label: 'Per-strong-copyleft weight', step: 0.05 },
      { key: 'unknownPctMul', label: 'Unknown fraction weight', step: 0.05 },
    ],
  },
  sastLow: {
    label: 'SAST · medium + low',
    fields: [
      { key: 'medium', label: 'Per-medium weight', step: 0.001 },
      { key: 'low', label: 'Per-low weight', step: 0.0005 },
    ],
  },
  missingScanners: {
    label: 'Missing scanners',
    fields: [],
    help: 'Fraction of expected scanner classes (SAST/Secrets/IaC/SBOM/Coverage) that didn\'t run.',
  },
}

export function RiskPolicyEditor({
  policy,
  onClose,
}: {
  policy: RiskPolicyFull
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [name, setName] = useState(policy.name)
  const [description, setDescription] = useState(policy.description ?? '')
  const [config, setConfig] = useState<RiskPolicyConfig>(structuredClone(policy.config))

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const save = useMutation({
    mutationFn: () => updateRiskPolicy(policy.id, {
      name: name.trim(),
      description: description.trim() || null,
      config,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-policies'] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
      onClose()
    },
  })

  const clone = useMutation({
    mutationFn: () => cloneRiskPolicy(policy.id, `${policy.name} (copy)`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-policies'] })
      onClose()
    },
  })

  const remove = useMutation({
    mutationFn: () => deleteRiskPolicy(policy.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-policies'] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
      onClose()
    },
  })

  const makeDefault = useMutation({
    mutationFn: () => setDefaultRiskPolicy(policy.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-policies'] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
    },
  })

  // Sum of category maxes — surfaced so the admin sees if their config
  // exceeds 100 (the score auto-clamps but it's clearly miscalibrated).
  const totalMax = Object.values(config.categories).reduce((s, c) => s + (c.enabled ? c.max : 0), 0)

  const updateBand = (k: 'greenMax' | 'yellowMax' | 'orangeMax', v: number) =>
    setConfig({ ...config, bands: { ...config.bands, [k]: v } })

  const updateCategory = (key: string, patch: Partial<{ enabled: boolean; max: number }>) =>
    setConfig({
      ...config,
      categories: { ...config.categories, [key]: { ...config.categories[key], ...patch } },
    })

  const updateWeight = (catKey: string, wKey: string, v: number) =>
    setConfig({
      ...config,
      categories: {
        ...config.categories,
        [catKey]: {
          ...config.categories[catKey],
          weights: { ...config.categories[catKey].weights, [wKey]: v },
        },
      },
    })

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
          <div className="flex items-baseline gap-2">
            <h2 className="text-base font-semibold tracking-tight">Edit policy</h2>
            {policy.isDefault && <span className="text-[10px] uppercase tracking-wider text-emerald-700 dark:text-emerald-400">default</span>}
            {policy.isSeeded && <span className="text-[10px] uppercase tracking-wider text-muted-foreground">seeded</span>}
          </div>
          <button onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground">
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-6 px-5 py-5 text-sm">

          {/* Identity */}
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">Identity</h3>
            <Field label="Name">
              <input value={name} onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40" />
            </Field>
            <Field label="Description">
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2}
                className="w-full resize-y rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40" />
            </Field>
          </section>

          {/* Bands */}
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">Bands</h3>
            <p className="text-[11px] text-muted-foreground">
              0–green = Low, green–yellow = Moderate, yellow–orange = Elevated, orange–100 = High.
            </p>
            <div className="grid grid-cols-3 gap-2">
              <BandInput label="Green ≤" value={config.bands.greenMax} onChange={(v) => updateBand('greenMax', v)} />
              <BandInput label="Yellow ≤" value={config.bands.yellowMax} onChange={(v) => updateBand('yellowMax', v)} />
              <BandInput label="Orange ≤" value={config.bands.orangeMax} onChange={(v) => updateBand('orangeMax', v)} />
            </div>
          </section>

          {/* Categories */}
          <section className="space-y-3">
            <div className="flex items-baseline justify-between">
              <h3 className="text-sm font-semibold">Categories</h3>
              <p className={totalMax === 100 ? 'text-[11px] text-muted-foreground' : 'text-[11px] text-amber-600 dark:text-amber-400'}>
                Sum of max points: {totalMax} {totalMax !== 100 && '(scores auto-clamp to 100)'}
              </p>
            </div>
            {Object.entries(CATEGORY_SCHEMA).map(([key, schema]) => {
              const cat = config.categories[key]
              if (!cat) return null  // policy doesn't have this category (older schema version)
              return (
                <div key={key} className="rounded-md border border-border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={cat.enabled}
                        onChange={(e) => updateCategory(key, { enabled: e.target.checked })}
                        className="rounded"
                      />
                      <h4 className="text-sm font-medium">{schema.label}</h4>
                    </div>
                    <div className="flex items-center gap-1.5 text-xs">
                      <span className="text-muted-foreground">Max</span>
                      <input
                        type="number" min={0} max={100} step={1}
                        value={cat.max}
                        onChange={(e) => updateCategory(key, { max: Number(e.target.value) })}
                        disabled={!cat.enabled}
                        className="w-16 rounded-md border bg-background px-2 py-1 text-right text-sm disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ring/40"
                      />
                    </div>
                  </div>
                  {schema.help && <p className="mt-1 text-[11px] text-muted-foreground">{schema.help}</p>}
                  {schema.fields.length > 0 && (
                    <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {schema.fields.map((f) => (
                        <div key={f.key} className="flex items-center justify-between gap-2 text-xs">
                          <label className="text-muted-foreground">{f.label}</label>
                          <input
                            type="number" step={f.step ?? 0.01}
                            value={cat.weights[f.key] ?? 0}
                            onChange={(e) => updateWeight(key, f.key, Number(e.target.value))}
                            disabled={!cat.enabled}
                            className="w-24 rounded-md border bg-background px-2 py-1 text-right tabular-nums disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ring/40"
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </section>

          {save.isError && (
            <p className="text-xs text-destructive">Save failed: {(save.error as Error)?.message}</p>
          )}
          {remove.isError && (
            <p className="text-xs text-destructive">Delete failed: {(remove.error as Error)?.message}</p>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => clone.mutate()}
              disabled={clone.isPending}
              className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted/40"
            >
              <Copy className="size-3.5" /> Clone
            </button>
            {!policy.isDefault && (
              <button
                type="button"
                onClick={() => makeDefault.mutate()}
                disabled={makeDefault.isPending}
                className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted/40"
              >
                <Star className="size-3.5" /> Make default
              </button>
            )}
            {!policy.isDefault && (
              <button
                type="button"
                onClick={() => { if (confirm('Delete this policy?')) remove.mutate() }}
                disabled={remove.isPending}
                className="inline-flex items-center gap-1 rounded-md border border-destructive/40 bg-background px-3 py-1.5 text-sm text-destructive hover:bg-destructive/10"
              >
                <Trash2 className="size-3.5" /> Delete
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => save.mutate()}
              disabled={save.isPending}
              className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
            >
              {save.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label className="text-xs uppercase tracking-wide text-muted-foreground">{label}</label>
      {children}
    </div>
  )
}

function BandInput({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <div className="space-y-1">
      <label className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</label>
      <input
        type="number" min={0} max={100} step={1}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full rounded-md border bg-background px-2 py-1.5 text-right text-sm tabular-nums focus:outline-none focus:ring-2 focus:ring-ring/40"
      />
    </div>
  )
}
