import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { X, Copy, Check, Trash2 } from 'lucide-react'
import {
  fetchClientTokens, mintClientToken, revokeIngestToken,
  fetchRiskPolicies, fetchClients, assignClientPolicy,
} from '@/lib/api'
import type { IngestTokenListItem, MintedIngestToken, RiskPolicySummary } from '@/lib/api'

// Settings overlay shown from the per-client card's title-bar gear.
// Gated upstream by isAdmin (and eventually by per-project ownership via
// TFND-3 role assignments). All actions are TODO scaffolding — the
// backing endpoints land as separate tickets:
//   - PATCH /clients/{id}                  (rename / description)
//   - POST   /clients/{id}/tokens          (API token mint — TFND-4)
//   - GET / DELETE /clients/{id}/tokens
//   - Project role assignment endpoints   (TFND-3)
//   - Policy + gate endpoints              (TFND-10 / TFND-11 placeholders)
export function ClientSettingsDialog({
  clientId,
  clientName,
  onClose,
}: {
  clientId: string
  clientName: string
  onClose: () => void
}) {
  const [name, setName] = useState(clientName)
  const [description, setDescription] = useState('')

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 sm:p-8"
      role="dialog"
      aria-modal="true"
      aria-labelledby="client-settings-title"
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-2xl rounded-md border bg-card shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 id="client-settings-title" className="text-base font-semibold tracking-tight">
            Settings — {clientName}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-6 px-5 py-5 text-sm">
          {/* --- Identity ------------------------------------------------ */}
          <Section title="Identity">
            <Field label="Name" htmlFor="name">
              <input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </Field>
            <Field label="Description" htmlFor="description">
              <textarea
                id="description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                placeholder="Optional — visible to anyone with access to this project."
                className="w-full resize-y rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </Field>
            <p className="text-[11px] text-muted-foreground">
              Renaming and description editing land with{' '}
              <code className="rounded bg-muted px-1">PATCH /clients/{clientId}</code>{' '}— TODO.
            </p>
          </Section>

          {/* --- API tokens ---------------------------------------------- */}
          <Section title="API tokens" subtitle="cli_-prefixed bearer tokens authorize ingest for any project under this client. Use them from CI emitters and the MCP server.">
            <TokensPanel clientId={clientId} />
          </Section>

          {/* --- Access control ----------------------------------------- */}
          <Section title="Access control" subtitle="Assign InfoSec Officer / Lead Dev / Architect at this scope. Inherited downward (TFND-3).">
            <div className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-muted-foreground">
              Role assignments UI — TFND-3.
              <br />
              Roles: InfoSec Officer · Lead Dev · Architect.
            </div>
          </Section>

          {/* --- Risk policy -------------------------------------------- */}
          <Section title="Risk policy" subtitle="Which policy scores this client. Falls back to the system default when no override is set.">
            <RiskPolicyPanel clientId={clientId} />
          </Section>

          {/* --- Gates (placeholders) ----------------------------------- */}
          <Section title="Gates" subtitle="Branch-protection thresholds, suppression rules.">
            <div className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-muted-foreground">
              Commit / PR check-run gates — TFND-23.
            </div>
          </Section>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled
            className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background opacity-50"
            title="No mutating endpoints wired yet"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  )
}

function Section({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        {subtitle && <p className="text-[11px] text-muted-foreground">{subtitle}</p>}
      </div>
      <div className="space-y-2">{children}</div>
    </section>
  )
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label htmlFor={htmlFor} className="text-xs uppercase tracking-wide text-muted-foreground">{label}</label>
      {children}
    </div>
  )
}

function TokensPanel({ clientId }: { clientId: string }) {
  const qc = useQueryClient()
  const tokens = useQuery({
    queryKey: ['ingest-tokens', 'client', clientId],
    queryFn: () => fetchClientTokens(clientId),
  })
  const [showForm, setShowForm] = useState(false)
  const [newName, setNewName] = useState('')
  // Plaintext minted-once. Held in state until the user dismisses it; never
  // re-fetchable from the server.
  const [justMinted, setJustMinted] = useState<MintedIngestToken | null>(null)

  const mint = useMutation({
    mutationFn: () => mintClientToken(clientId, newName.trim()),
    onSuccess: (m) => {
      setJustMinted(m)
      setShowForm(false)
      setNewName('')
      qc.invalidateQueries({ queryKey: ['ingest-tokens', 'client', clientId] })
    },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => revokeIngestToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ingest-tokens', 'client', clientId] }),
  })

  const rows = tokens.data ?? []
  const live = rows.filter(t => t.revokedAt === null)
  const revoked = rows.filter(t => t.revokedAt !== null)

  return (
    <div className="space-y-3">
      {justMinted && (
        <MintedReveal token={justMinted} onDismiss={() => setJustMinted(null)} />
      )}

      {tokens.isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}

      {live.length === 0 && !tokens.isLoading && (
        <p className="text-xs text-muted-foreground">No tokens issued for this client yet.</p>
      )}

      {live.length > 0 && (
        <ul className="divide-y divide-border rounded-md border">
          {live.map(t => <TokenRow key={t.id} t={t} onRevoke={() => revoke.mutate(t.id)} />)}
        </ul>
      )}

      {revoked.length > 0 && (
        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">Revoked ({revoked.length})</summary>
          <ul className="mt-2 divide-y divide-border rounded-md border opacity-60">
            {revoked.map(t => <TokenRow key={t.id} t={t} onRevoke={() => {}} />)}
          </ul>
        </details>
      )}

      {showForm ? (
        <div className="flex items-center gap-2">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder='e.g. "ci · brewerybot"'
            className="flex-1 rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40"
            autoFocus
          />
          <button
            type="button"
            onClick={() => mint.mutate()}
            disabled={!newName.trim() || mint.isPending}
            className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
          >
            {mint.isPending ? 'Generating…' : 'Generate'}
          </button>
          <button
            type="button"
            onClick={() => { setShowForm(false); setNewName('') }}
            className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setShowForm(true)}
          className="rounded-md border bg-background px-3 py-1.5 text-sm font-medium hover:bg-muted/40"
        >
          Generate new token
        </button>
      )}

      {mint.isError && (
        <p className="text-xs text-destructive">Mint failed: {(mint.error as Error)?.message}</p>
      )}
    </div>
  )
}

function TokenRow({ t, onRevoke }: { t: IngestTokenListItem; onRevoke: () => void }) {
  const isRevoked = t.revokedAt !== null
  return (
    <li className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
      <div className="min-w-0 flex-1">
        <p className="truncate font-medium text-foreground">{t.name}</p>
        <p className="text-muted-foreground">
          {t.prefix}… · created {formatShort(t.createdAt)}
          {t.lastUsedAt && ` · last used ${formatShort(t.lastUsedAt)}`}
          {t.revokedAt && ` · revoked ${formatShort(t.revokedAt)}`}
        </p>
      </div>
      {!isRevoked && (
        <button
          type="button"
          onClick={onRevoke}
          title="Revoke token"
          aria-label={`Revoke ${t.name}`}
          className="rounded-md p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
        >
          <Trash2 className="size-3.5" />
        </button>
      )}
    </li>
  )
}

function MintedReveal({ token, onDismiss }: { token: MintedIngestToken; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(token.token)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard may be blocked (e.g. http on non-localhost). User can
      // still select-and-copy the displayed value.
    }
  }
  return (
    <div className="space-y-2 rounded-md border border-amber-500/50 bg-amber-500/5 p-3">
      <p className="text-xs font-medium text-amber-700 dark:text-amber-400">
        Copy this token now — it won't be shown again.
      </p>
      <div className="flex items-center gap-2">
        <code className="flex-1 truncate rounded-md border bg-background px-2 py-1.5 font-mono text-xs">
          {token.token}
        </code>
        <button
          type="button"
          onClick={copy}
          title="Copy to clipboard"
          className="rounded-md border bg-background p-1.5 hover:bg-muted/40"
        >
          {copied ? <Check className="size-3.5 text-emerald-600" /> : <Copy className="size-3.5" />}
        </button>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        className="text-xs text-muted-foreground hover:text-foreground"
      >
        Dismiss
      </button>
    </div>
  )
}

function formatShort(iso: string) {
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
  } catch {
    return iso
  }
}

function RiskPolicyPanel({ clientId }: { clientId: string }) {
  const qc = useQueryClient()
  // Need the assigned policy id from the client row; /api/clients
  // doesn't currently expose RiskPolicyId — query the list and find by
  // id. (Fine for now; if the list grows huge we'll switch to a
  // dedicated GET /clients/{id} that includes it.)
  const clients = useQuery({ queryKey: ['clients-detail'], queryFn: fetchClients })
  const policies = useQuery({ queryKey: ['risk-policies'], queryFn: fetchRiskPolicies })

  const assigned: string | null = clients.data?.find(c => c.id === clientId)?.riskPolicyId ?? null
  const defaultPolicy = policies.data?.find(p => p.isDefault) ?? null

  const assign = useMutation({
    mutationFn: (policyId: string | null) => assignClientPolicy(clientId, policyId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients-detail'] })
      // Aggregates depends on the effective policy — invalidate so the
      // risk badge re-renders with the new score.
      qc.invalidateQueries({ queryKey: ['aggregates'] })
    },
  })

  const onChange = (val: string) => {
    if (val === '__default__') assign.mutate(null)
    else assign.mutate(val)
  }

  if (policies.isLoading) return <p className="text-xs text-muted-foreground">Loading policies…</p>
  if (!policies.data || policies.data.length === 0) {
    return <p className="text-xs text-muted-foreground">No policies defined.</p>
  }

  return (
    <div className="space-y-2">
      <select
        value={assigned ?? '__default__'}
        onChange={(e) => onChange(e.target.value)}
        disabled={assign.isPending}
        className="w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40"
      >
        <option value="__default__">
          Use system default{defaultPolicy ? ` (${defaultPolicy.name})` : ''}
        </option>
        {(policies.data as RiskPolicySummary[]).map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}{p.isDefault ? ' · default' : ''}{p.isSeeded ? ' · seeded' : ''}
          </option>
        ))}
      </select>
      {assign.isError && (
        <p className="text-xs text-destructive">Assignment failed: {(assign.error as Error)?.message}</p>
      )}
      <p className="text-[11px] text-muted-foreground">
        Admins manage the policy library — Settings → Policies (coming soon).
        Edit a policy in place via <code className="rounded bg-muted px-1">PATCH /risk-policies/{'{id}'}</code> for now.
      </p>
    </div>
  )
}
