import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus, Star } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { fetchRiskPolicies, fetchRiskPolicy } from '@/lib/api'
import type { RiskPolicySummary } from '@/lib/api'
import { RiskPolicyEditor } from '@/components/RiskPolicyEditor'

// Admin-only settings landing. Risk Policies is the first fleshed-out
// section; the rest stay placeholders for TFND-3 / TFND-4 follow-ups.
export function SettingsView() {
  const { user } = useAuth()
  if (!user?.isAdmin) {
    return (
      <div className="rounded-md border border-destructive/50 bg-card p-4 text-sm">
        <p className="font-medium">Admin only</p>
        <p className="text-muted-foreground">This area is restricted to admins.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
      <RiskPoliciesSection />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Placeholder title="User allowlist" body="Approve / revoke GitHub logins. Bootstrap admin is auto-approved." />
        <Placeholder title="Role assignments" body="Assign InfoSec Officer / Lead Dev / Architect at Client / Project / Component scope (TFND-3)." />
        <Placeholder title="Audit log" body="Recent suppression authoring, allowlist changes, role grants." />
      </div>
    </div>
  )
}

function RiskPoliciesSection() {
  const policies = useQuery({ queryKey: ['risk-policies'], queryFn: fetchRiskPolicies })
  const [editingId, setEditingId] = useState<string | null>(null)
  // Full record for the editor — loaded on demand so we always have the
  // freshest config blob, not just the summary fields.
  const editing = useQuery({
    queryKey: ['risk-policy', editingId],
    queryFn: () => fetchRiskPolicy(editingId!),
    enabled: editingId !== null,
  })

  const rows = policies.data ?? []

  return (
    <section className="rounded-md border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div>
          <h3 className="text-sm font-semibold">Risk policies</h3>
          <p className="text-[11px] text-muted-foreground">
            Define how scores roll up. Clients/Projects pick from this list; default applies when no override is set.
          </p>
        </div>
        {rows.length > 0 && (
          <button
            type="button"
            onClick={() => {
              const seed = rows.find(p => p.isSeeded) ?? rows[0]
              if (seed) setEditingId(seed.id)
            }}
            className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted/40"
            title="Open the seeded policy to clone-and-edit"
          >
            <Plus className="size-3.5" /> Clone from seed
          </button>
        )}
      </div>
      {policies.isLoading && <p className="px-4 py-3 text-xs text-muted-foreground">Loading…</p>}
      {rows.length === 0 && !policies.isLoading && (
        <p className="px-4 py-3 text-xs text-muted-foreground">No policies defined.</p>
      )}
      {rows.length > 0 && (
        <ul className="divide-y divide-border">
          {rows.map(p => <PolicyRow key={p.id} p={p} onEdit={() => setEditingId(p.id)} />)}
        </ul>
      )}

      {editingId !== null && editing.data && (
        <RiskPolicyEditor
          policy={editing.data}
          onClose={() => setEditingId(null)}
        />
      )}
    </section>
  )
}

function PolicyRow({ p, onEdit }: { p: RiskPolicySummary; onEdit: () => void }) {
  return (
    <li className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/30">
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <button
            type="button"
            onClick={onEdit}
            className="text-sm font-medium text-foreground hover:underline"
          >
            {p.name}
          </button>
          {p.isDefault && (
            <span className="inline-flex items-center gap-0.5 text-[10px] uppercase tracking-wider text-emerald-700 dark:text-emerald-400">
              <Star className="size-2.5" /> default
            </span>
          )}
          {p.isSeeded && (
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">seeded</span>
          )}
        </div>
        {p.description && <p className="truncate text-xs text-muted-foreground">{p.description}</p>}
      </div>
      <button
        type="button"
        onClick={onEdit}
        className="rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted/40"
      >
        Edit
      </button>
    </li>
  )
}

function Placeholder({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-md border bg-card p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-semibold">{title}</h3>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">todo</span>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{body}</p>
    </div>
  )
}

