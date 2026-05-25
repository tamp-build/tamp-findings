import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ClipboardList, Plus, Trash2, AlertTriangle, CheckCircle2, ShieldCheck, Pause, Pencil, Save, XCircle,
} from 'lucide-react'
import {
  fetchPoamItems, createPoamItem, updatePoamItem, cancelPoamItem,
} from '@/lib/api'
import type {
  PoamItem, PoamStatus, CreatePoamItemRequest, UpdatePoamItemRequest, Severity,
} from '@/lib/api'

// Plan of Action & Milestones — the federal companion to VEX. VEX
// explains "this CVE isn't reachable so we won't patch"; POA&M
// documents "this weakness IS real, here's our plan and target
// date." Auditors (AO, FedRAMP PMO) expect a POA&M for any open
// weakness that survives a build with no closing remediation.
//
// Panel responsibilities:
//   1. Surface live items so the project owner can see exposure
//      at a glance — past-due rows highlight in red.
//   2. Allow authoring of new items linked to one or more
//      Findings/Vulnerabilities (today: free-text Guid list — wire
//      a picker later).
//   3. Allow inline edit of status / due-date / mitigation plan —
//      unlike VEX, POA&M items have a lifecycle, so edit-in-place
//      is the natural workflow.
//   4. Cancel (soft-close) entries opened in error.
export function PoamItemsPanel({ projectId }: { projectId: string }) {
  const qc = useQueryClient()
  const [showClosed, setShowClosed] = useState(false)
  const list = useQuery({
    queryKey: ['poam-items', projectId, showClosed],
    queryFn: () => fetchPoamItems(projectId, { includeClosed: showClosed }),
  })

  const [draft, setDraft] = useState<DraftState | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: () => createPoamItem(projectId, draftToCreate(draft!)),
    onSuccess: () => {
      setDraft(null)
      invalidateAll(qc, projectId)
    },
  })

  const update = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: UpdatePoamItemRequest }) => updatePoamItem(id, patch),
    onSuccess: () => {
      setEditingId(null)
      invalidateAll(qc, projectId)
    },
  })

  const cancel = useMutation({
    mutationFn: (id: string) => cancelPoamItem(id),
    onSuccess: () => invalidateAll(qc, projectId),
  })

  const liveCount = list.data?.filter(p => p.closedAt === null).length ?? 0
  const pastDueCount = list.data?.filter(p => p.isPastDue).length ?? 0

  return (
    <section className="space-y-2">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">POA&amp;M items</h3>
          <p className="text-[11px] text-muted-foreground">
            Plan of Action &amp; Milestones — document known weaknesses with a target close date. NIST SP 800-53 CA-5 / FedRAMP continuous monitoring. The <code className="rounded bg-muted px-1 text-[10px]">poamPastDue</code> gate fails the build when any item slips its due date.
          </p>
        </div>
        {draft === null && (
          <button
            type="button"
            onClick={() => setDraft(makeBlankDraft())}
            className="inline-flex shrink-0 items-center gap-1 rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted/40"
          >
            <Plus className="size-3.5" /> Open entry
          </button>
        )}
      </div>

      {/* Status strip */}
      <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
        <span>{liveCount} live</span>
        {pastDueCount > 0 && (
          <span className="inline-flex items-center gap-1 text-destructive">
            <AlertTriangle className="size-3" /> {pastDueCount} past due
          </span>
        )}
        <label className="ml-auto inline-flex items-center gap-1.5">
          <input
            type="checkbox"
            checked={showClosed}
            onChange={(e) => setShowClosed(e.target.checked)}
            className="rounded"
          />
          <span>Show closed</span>
        </label>
      </div>

      {list.isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
      {list.data && list.data.length === 0 && draft === null && (
        <p className="rounded-md border border-dashed bg-card/40 px-3 py-3 text-xs text-muted-foreground">
          No POA&amp;M entries. Open one when an auditor or scanner identifies a weakness you can't close before the build ships.
        </p>
      )}

      {list.data && list.data.length > 0 && (
        <ul className="space-y-2">
          {list.data.map(p => editingId === p.id
            ? (
              <EditRow
                key={p.id}
                item={p}
                onCancel={() => setEditingId(null)}
                onSave={(patch) => update.mutate({ id: p.id, patch })}
                submitting={update.isPending}
                error={(update.error as Error | null)?.message ?? null}
              />
            )
            : (
              <ItemRow
                key={p.id}
                item={p}
                onEdit={() => setEditingId(p.id)}
                onCancelEntry={() => cancel.mutate(p.id)}
                cancelling={cancel.isPending}
              />
            ))}
        </ul>
      )}

      {draft !== null && (
        <DraftForm
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

// ---------------------------------------------------------------- list row

function ItemRow({
  item, onEdit, onCancelEntry, cancelling,
}: {
  item: PoamItem
  onEdit: () => void
  onCancelEntry: () => void
  cancelling: boolean
}) {
  const tone = item.isPastDue ? 'border-destructive/70 bg-destructive/5' : 'bg-card/60'
  return (
    <li className={`rounded-md border p-3 ${tone}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={item.status} />
            <SeverityBadge severity={item.severity} />
            <span className="truncate text-sm font-medium">{item.title}</span>
          </div>
          <p className="whitespace-pre-line text-[12px] text-foreground/90">{item.weaknessDescription}</p>
          {item.mitigationPlan && (
            <p className="text-[12px] text-muted-foreground">
              <span className="font-medium text-foreground/80">Plan:</span> {item.mitigationPlan}
            </p>
          )}
          {item.resourcesRequired && (
            <p className="text-[11px] text-muted-foreground">
              <span className="font-medium">Resources:</span> {item.resourcesRequired}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
            {item.scheduledCompletionDate && (
              <span className={item.isPastDue ? 'font-medium text-destructive' : ''}>
                Due {formatDate(item.scheduledCompletionDate)}
                {item.isPastDue && ` · ${daysAgo(item.scheduledCompletionDate)}d overdue`}
              </span>
            )}
            {!item.scheduledCompletionDate && item.closedAt === null && (
              <span className="italic">unscheduled</span>
            )}
            {item.actualCompletionDate && (
              <span>Closed {formatDate(item.actualCompletionDate)}</span>
            )}
            {item.linkedFindingIds.length > 0 && (
              <span>{item.linkedFindingIds.length} linked finding{item.linkedFindingIds.length === 1 ? '' : 's'}</span>
            )}
            {item.referenceUrl && (
              <a
                href={item.referenceUrl}
                target="_blank"
                rel="noreferrer noopener"
                className="text-blue-600 hover:underline dark:text-blue-400"
              >Reference ↗</a>
            )}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            onClick={onEdit}
            title="Edit entry"
            className="rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
          >
            <Pencil className="size-4" />
          </button>
          {item.closedAt === null && (
            <button
              type="button"
              onClick={onCancelEntry}
              disabled={cancelling}
              title="Cancel this entry (soft-close; audit trail preserved). Prefer Edit → Status=Completed for actual remediation."
              className="rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-destructive disabled:opacity-50"
            >
              <Trash2 className="size-4" />
            </button>
          )}
        </div>
      </div>
    </li>
  )
}

// ---------------------------------------------------------------- inline edit

function EditRow({
  item, onCancel, onSave, submitting, error,
}: {
  item: PoamItem
  onCancel: () => void
  onSave: (patch: UpdatePoamItemRequest) => void
  submitting: boolean
  error: string | null
}) {
  const [draft, setDraft] = useState<DraftState>({
    title: item.title,
    weaknessDescription: item.weaknessDescription,
    mitigationPlan: item.mitigationPlan ?? '',
    resourcesRequired: item.resourcesRequired ?? '',
    severity: item.severity,
    status: item.status,
    scheduledCompletionDate: dateOnly(item.scheduledCompletionDate) ?? '',
    linkedFindingIds: item.linkedFindingIds.join(', '),
    referenceUrl: item.referenceUrl ?? '',
  })

  return (
    <li className="space-y-3 rounded-md border bg-card/80 p-3">
      <p className="text-xs font-medium">Edit entry</p>
      <FormBody draft={draft} onChange={setDraft} />
      {error && <p className="text-xs text-destructive">Save failed: {error}</p>}
      <div className="flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted/40 hover:text-foreground"
        >
          <XCircle className="size-3.5" /> Cancel
        </button>
        <button
          type="button"
          onClick={() => onSave(draftToUpdate(draft))}
          disabled={submitting}
          className="inline-flex items-center gap-1 rounded-md bg-foreground px-3 py-1.5 text-xs font-medium text-background disabled:opacity-50"
        >
          <Save className="size-3.5" />
          {submitting ? 'Saving…' : 'Save'}
        </button>
      </div>
    </li>
  )
}

// ---------------------------------------------------------------- new-entry form

function DraftForm({
  draft, onChange, onCancel, onSubmit, submitting, error,
}: {
  draft: DraftState
  onChange: (d: DraftState) => void
  onCancel: () => void
  onSubmit: () => void
  submitting: boolean
  error: string | null
}) {
  const ready = draft.title.trim() && draft.weaknessDescription.trim()
  return (
    <div className="space-y-3 rounded-md border bg-card/60 p-3">
      <p className="text-xs font-medium">Open POA&amp;M entry</p>
      <FormBody draft={draft} onChange={onChange} />
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
          {submitting ? 'Saving…' : 'Open entry'}
        </button>
      </div>
    </div>
  )
}

function FormBody({
  draft, onChange,
}: {
  draft: DraftState
  onChange: (d: DraftState) => void
}) {
  const set = <K extends keyof DraftState>(k: K, v: DraftState[K]) =>
    onChange({ ...draft, [k]: v })
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <Field label="Title" className="sm:col-span-2" hint="One-line summary auditors will scan first">
        <input
          value={draft.title}
          onChange={(e) => set('title', e.target.value)}
          placeholder="Upgrade Log4Net past 2.0.5"
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Weakness description" className="sm:col-span-2" hint="Describe the weakness as an AO would read it">
        <textarea
          value={draft.weaknessDescription}
          onChange={(e) => set('weaknessDescription', e.target.value)}
          rows={3}
          placeholder="Application bundles log4net 2.0.5; vulnerable to CVE-2021-44228 (Log4Shell) under JNDI lookups."
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Mitigation plan" className="sm:col-span-2" hint="What will close the weakness?">
        <textarea
          value={draft.mitigationPlan}
          onChange={(e) => set('mitigationPlan', e.target.value)}
          rows={2}
          placeholder="Upgrade to log4net 3.x in Q3 release; ETA YYYY-MM-DD."
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Resources required" className="sm:col-span-2" hint="Staffing / budget / external dependencies">
        <input
          value={draft.resourcesRequired}
          onChange={(e) => set('resourcesRequired', e.target.value)}
          placeholder="1 dev-week; coordinate with Vendor X for compat testing"
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Severity">
        <select
          value={draft.severity}
          onChange={(e) => set('severity', e.target.value as Severity)}
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        >
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
      </Field>
      <Field label="Status">
        <select
          value={draft.status}
          onChange={(e) => set('status', e.target.value as PoamStatus)}
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        >
          <option value="Open">Open</option>
          <option value="InProgress">In progress</option>
          <option value="Completed">Completed</option>
          <option value="RiskAccepted">Risk accepted (AO)</option>
          <option value="Cancelled">Cancelled</option>
        </select>
      </Field>
      <Field label="Scheduled completion" hint="When the team committed to close with the AO">
        <input
          type="date"
          value={draft.scheduledCompletionDate}
          onChange={(e) => set('scheduledCompletionDate', e.target.value)}
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Reference URL" hint="Ticket / memo / vendor advisory">
        <input
          value={draft.referenceUrl}
          onChange={(e) => set('referenceUrl', e.target.value)}
          placeholder="https://issues.example.com/browse/PROJ-123"
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
      <Field label="Linked finding IDs (Guids, comma-separated)" className="sm:col-span-2" hint="Optional — Finding / Vulnerability ids that motivated the entry">
        <input
          value={draft.linkedFindingIds}
          onChange={(e) => set('linkedFindingIds', e.target.value)}
          placeholder="3fa85f64-5717-4562-b3fc-2c963f66afa6, ..."
          className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-[11px] focus:outline-none focus:ring-2 focus:ring-ring/40"
        />
      </Field>
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

// ---------------------------------------------------------------- badges

function StatusBadge({ status }: { status: PoamStatus }) {
  const map: Record<PoamStatus, { icon: typeof CheckCircle2; label: string; tone: string }> = {
    Open: { icon: ClipboardList, label: 'Open', tone: 'bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300' },
    InProgress: { icon: Pause, label: 'In progress', tone: 'bg-blue-100 text-blue-800 dark:bg-blue-950/40 dark:text-blue-300' },
    Completed: { icon: CheckCircle2, label: 'Completed', tone: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300' },
    RiskAccepted: { icon: ShieldCheck, label: 'Risk accepted', tone: 'bg-purple-100 text-purple-800 dark:bg-purple-950/40 dark:text-purple-300' },
    Cancelled: { icon: XCircle, label: 'Cancelled', tone: 'bg-muted text-muted-foreground' },
  }
  const { icon: Icon, label, tone } = map[status]
  return (
    <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-medium ${tone}`}>
      <Icon className="size-3" />
      {label}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  // Same colour scale used elsewhere in the dashboard so eyes don't
  // have to retrain.
  const tones: Record<Severity, string> = {
    Critical: 'bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-300',
    High: 'bg-orange-100 text-orange-800 dark:bg-orange-950/40 dark:text-orange-300',
    Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950/40 dark:text-yellow-300',
    Low: 'bg-sky-100 text-sky-800 dark:bg-sky-950/40 dark:text-sky-300',
    Info: 'bg-muted text-muted-foreground',
  }
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium ${tones[severity]}`}>
      {severity}
    </span>
  )
}

// ---------------------------------------------------------------- helpers

type DraftState = {
  title: string
  weaknessDescription: string
  mitigationPlan: string
  resourcesRequired: string
  severity: Severity
  status: PoamStatus
  scheduledCompletionDate: string   // yyyy-mm-dd; '' means unscheduled
  linkedFindingIds: string          // comma-separated Guid list
  referenceUrl: string
}

function makeBlankDraft(): DraftState {
  return {
    title: '',
    weaknessDescription: '',
    mitigationPlan: '',
    resourcesRequired: '',
    severity: 'High',
    status: 'Open',
    scheduledCompletionDate: '',
    linkedFindingIds: '',
    referenceUrl: '',
  }
}

function draftToCreate(d: DraftState): CreatePoamItemRequest {
  return {
    title: d.title.trim(),
    weaknessDescription: d.weaknessDescription.trim(),
    mitigationPlan: blankToNull(d.mitigationPlan),
    resourcesRequired: blankToNull(d.resourcesRequired),
    severity: d.severity,
    status: d.status,
    scheduledCompletionDate: dateToIso(d.scheduledCompletionDate),
    linkedFindingIds: parseGuidList(d.linkedFindingIds),
    referenceUrl: blankToNull(d.referenceUrl),
  }
}

function draftToUpdate(d: DraftState): UpdatePoamItemRequest {
  return {
    title: d.title.trim(),
    weaknessDescription: d.weaknessDescription.trim(),
    mitigationPlan: blankToNull(d.mitigationPlan),
    resourcesRequired: blankToNull(d.resourcesRequired),
    severity: d.severity,
    status: d.status,
    scheduledCompletionDate: dateToIso(d.scheduledCompletionDate),
    linkedFindingIds: parseGuidList(d.linkedFindingIds),
    referenceUrl: blankToNull(d.referenceUrl),
  }
}

function blankToNull(s: string): string | null {
  const t = s.trim()
  return t.length === 0 ? null : t
}

// yyyy-mm-dd → ISO UTC midnight (backend reads DateTimeOffset).
// Empty string → null.
function dateToIso(d: string): string | null {
  if (!d) return null
  return new Date(d + 'T00:00:00Z').toISOString()
}

function dateOnly(iso: string | null): string | null {
  if (!iso) return null
  return iso.substring(0, 10)
}

function parseGuidList(s: string): string[] {
  return s.split(/[,\s]+/).map(x => x.trim()).filter(x => x.length > 0)
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

function daysAgo(iso: string): number {
  const due = new Date(iso).getTime()
  return Math.floor((Date.now() - due) / (1000 * 60 * 60 * 24))
}

function invalidateAll(qc: ReturnType<typeof useQueryClient>, projectId: string) {
  qc.invalidateQueries({ queryKey: ['poam-items', projectId] })
  qc.invalidateQueries({ queryKey: ['aggregates'] })
  qc.invalidateQueries({ queryKey: ['build-evaluation', projectId] })
}
