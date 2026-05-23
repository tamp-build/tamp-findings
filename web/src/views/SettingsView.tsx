import { useAuth } from '@/lib/auth'

// Admin-only settings landing. Real surface lands as TFND-3 (RBAC role
// assignment) + TFND-19 (suppression authoring gate) flesh out: user
// allowlist + approval, role assignments at Client/Project/Component,
// project-role inheritance review, audit log.
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
    <div className="space-y-4">
      <h2 className="text-2xl font-semibold tracking-tight">Settings</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <SettingsCard title="User allowlist" body="Approve / revoke GitHub logins. Bootstrap admin is auto-approved." todo />
        <SettingsCard title="Role assignments" body="Assign InfoSec Officer / Lead Dev / Architect at Client / Project / Component scope (TFND-3)." todo />
        <SettingsCard title="API tokens" body="Mint per-user bearer tokens for CI emitters and the MCP server (TFND-4 follow-up)." todo />
        <SettingsCard title="Audit log" body="Recent suppression authoring, allowlist changes, role grants." todo />
      </div>
    </div>
  )
}

function SettingsCard({ title, body, todo }: { title: string; body: string; todo?: boolean }) {
  return (
    <div className="rounded-md border bg-card p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-semibold">{title}</h3>
        {todo && <span className="text-[10px] uppercase tracking-wider text-muted-foreground">todo</span>}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{body}</p>
    </div>
  )
}
