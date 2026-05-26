import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'
import {
  fetchClients, fetchProjects,
  createClient, createProject, createComponent,
} from '@/lib/api'

// One dialog, three creates. The hierarchy nodes are tight enough
// (name + optional parent + optional kind/description) that a single
// shared shape keeps the surface tidy. Each mode renders only the
// fields that node type needs:
//   client     — name
//   project    — name + clientId (parent picker)
//   component  — name + projectId (parent picker) + kind
//
// Mutation invalidates the query keys the rest of the UI watches so a
// new node shows up in the Overview / ClientPage / AddMenu pickers
// without a hard refresh.
export type CreateHierarchyNodeKind = 'client' | 'project' | 'component'

export function CreateHierarchyNodeDialog({
  kind,
  onClose,
  onCreated,
}: {
  kind: CreateHierarchyNodeKind
  onClose: () => void
  // Fires after a successful create so the caller can navigate or
  // surface a success toast. Receives the new row's id.
  onCreated?: (id: string) => void
}) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [parentId, setParentId] = useState('')
  const [description, setDescription] = useState('')
  const [componentKind, setComponentKind] = useState('')

  // Parent picker data — only loaded when the dialog actually needs it.
  const clients = useQuery({
    queryKey: ['clients'],
    queryFn: fetchClients,
    enabled: kind === 'project',
  })
  const projects = useQuery({
    queryKey: ['projects', null],
    queryFn: () => fetchProjects(),
    enabled: kind === 'component',
  })

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const submit = useMutation({
    mutationFn: async () => {
      const n = name.trim()
      if (kind === 'client') {
        return await createClient(n)
      }
      if (kind === 'project') {
        return await createProject({
          name: n,
          clientId: parentId,
          description: description.trim() || null,
        })
      }
      return await createComponent({
        name: n,
        projectId: parentId,
        kind: componentKind.trim() || null,
      })
    },
    onSuccess: (row) => {
      // Invalidate every list the new node could appear in. Hierarchy
      // is small enough that broad invalidation is the right call.
      qc.invalidateQueries({ queryKey: ['clients'] })
      qc.invalidateQueries({ queryKey: ['projects'] })
      qc.invalidateQueries({ queryKey: ['components'] })
      qc.invalidateQueries({ queryKey: ['aggregates'] })
      onCreated?.(row.id)
      onClose()
    },
  })

  const ready =
    name.trim().length > 0 &&
    (kind === 'client' || parentId !== '')

  const title = kind === 'client' ? 'New client'
              : kind === 'project' ? 'New project'
              : 'New component'

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 sm:p-8"
      role="dialog" aria-modal="true"
      onClick={onClose}
    >
      <div
        className="my-16 w-full max-w-md rounded-md border bg-card shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 className="text-base font-semibold tracking-tight">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="rounded-md p-1 text-muted-foreground hover:bg-muted/40 hover:text-foreground">
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-3 px-5 py-4 text-sm">
          {kind === 'project' && (
            <Field label="Client">
              <select
                value={parentId}
                onChange={(e) => setParentId(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
              >
                <option value="">— Select client —</option>
                {clients.data?.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
            </Field>
          )}

          {kind === 'component' && (
            <Field label="Project">
              <select
                value={parentId}
                onChange={(e) => setParentId(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
              >
                <option value="">— Select project —</option>
                {projects.data?.map(p => (
                  <option key={p.id} value={p.id}>{p.clientName} · {p.name}</option>
                ))}
              </select>
            </Field>
          )}

          <Field
            label="Name"
            hint={
              kind === 'client'   ? 'e.g. "BrewingCoder", "Acme Corp"' :
              kind === 'project'  ? 'e.g. "tamp.findings", "checkout-service"' :
                                    'e.g. "api", "web", "worker"'
            }
          >
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring/40"
            />
          </Field>

          {kind === 'project' && (
            <Field label="Description (optional)">
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </Field>
          )}

          {kind === 'component' && (
            <Field label="Kind (optional)" hint="solution / library / service / spa / function / …">
              <input
                value={componentKind}
                onChange={(e) => setComponentKind(e.target.value)}
                placeholder="solution"
                className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </Field>
          )}

          {submit.isError && (
            <p className="text-xs text-destructive">
              {(submit.error as Error).message || 'Create failed'}
            </p>
          )}
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
            onClick={() => submit.mutate()}
            disabled={!ready || submit.isPending}
            className="rounded-md bg-foreground px-3 py-1.5 text-sm font-medium text-background disabled:opacity-50"
          >
            {submit.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Field({
  label, hint, children,
}: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[11px] font-medium text-muted-foreground">{label}</label>
      {children}
      {hint && <p className="mt-0.5 text-[10px] text-muted-foreground/80">{hint}</p>}
    </div>
  )
}
