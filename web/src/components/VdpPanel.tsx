import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Megaphone, Save } from 'lucide-react'
import { fetchProjectVdp, updateProjectVdp } from '@/lib/api'

// Vulnerability Disclosure Policy metadata. Three free-text fields
// per project. RV.3.1 in the SSDF attestation reads these — set a
// PolicyUrl to flip from Manual/No → Yes; set just the contact email
// for Partial.
//
// Not gated as required by the schema — leaving any field blank just
// means that signal isn't surfaced in the attestation. Saved as a
// whole record via PUT so partial clears work without N PATCHes.
export function VdpPanel({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['project-vdp', projectId],
    queryFn: () => fetchProjectVdp(projectId),
  })
  const [draft, setDraft] = useState<{
    vdpPolicyUrl: string
    vdpContactEmail: string
    vdpReportingFormUrl: string
  } | null>(null)

  useEffect(() => {
    if (q.data && draft === null) {
      setDraft({
        vdpPolicyUrl: q.data.vdpPolicyUrl ?? '',
        vdpContactEmail: q.data.vdpContactEmail ?? '',
        vdpReportingFormUrl: q.data.vdpReportingFormUrl ?? '',
      })
    }
  }, [q.data, draft])

  const save = useMutation({
    mutationFn: () => updateProjectVdp(projectId, {
      vdpPolicyUrl: blank(draft!.vdpPolicyUrl),
      vdpContactEmail: blank(draft!.vdpContactEmail),
      vdpReportingFormUrl: blank(draft!.vdpReportingFormUrl),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-vdp', projectId] })
      qc.invalidateQueries({ queryKey: ['ssdf-attestation', projectId] })
    },
  })

  return (
    <section className="space-y-2">
      <div>
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <Megaphone className="size-3.5" />
          Vulnerability disclosure
        </h3>
        <p className="text-[11px] text-muted-foreground">
          CISA BOD 20-01 + NIST SSDF RV.3.1. Setting a policy URL flips the SSDF attestation's RV.3.1 line to <strong className="text-foreground">Yes</strong>; setting only the contact email yields <strong className="text-foreground">Partial</strong>.
        </p>
      </div>

      {q.isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
      {draft && (
        <div className="space-y-2 rounded-md border bg-card/60 p-3">
          <Field label="Policy URL" hint="Public page describing your VDP / coordinated disclosure process">
            <input
              value={draft.vdpPolicyUrl}
              onChange={(e) => setDraft({ ...draft, vdpPolicyUrl: e.target.value })}
              placeholder="https://example.gov/.well-known/security.txt"
              className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
            />
          </Field>
          <Field label="Contact email" hint="security@... — minimum BOD 20-01 requirement">
            <input
              type="email"
              value={draft.vdpContactEmail}
              onChange={(e) => setDraft({ ...draft, vdpContactEmail: e.target.value })}
              placeholder="security@example.gov"
              className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
            />
          </Field>
          <Field label="Reporting form URL" hint="Optional — triage form, HackerOne, Bugcrowd, etc.">
            <input
              value={draft.vdpReportingFormUrl}
              onChange={(e) => setDraft({ ...draft, vdpReportingFormUrl: e.target.value })}
              placeholder="https://hackerone.com/example"
              className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
            />
          </Field>

          {save.isError && (
            <p className="text-xs text-destructive">Save failed: {(save.error as Error).message}</p>
          )}

          <div className="flex items-center justify-end">
            <button
              type="button"
              onClick={() => save.mutate()}
              disabled={save.isPending}
              className="inline-flex items-center gap-1 rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background disabled:opacity-50"
            >
              <Save className="size-3.5" />
              {save.isPending ? 'Saving…' : 'Save VDP'}
            </button>
          </div>
        </div>
      )}
    </section>
  )
}

function Field({
  label, hint, children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <label className="block text-[11px] font-medium text-muted-foreground">{label}</label>
      {children}
      {hint && <p className="mt-0.5 text-[10px] text-muted-foreground/80">{hint}</p>}
    </div>
  )
}

function blank(s: string): string | null {
  const t = s.trim()
  return t.length === 0 ? null : t
}
