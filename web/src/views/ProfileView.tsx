import { useAuth } from '@/lib/auth'

// Placeholder profile page. Hooks: future per-user prefs, API token
// issuance (TFND-4 bearer tokens), per-user audit log.
export function ProfileView() {
  const { user } = useAuth()
  if (!user) return null

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center gap-4">
        {user.avatarUrl && (
          <img
            src={user.avatarUrl}
            alt=""
            className="size-16 rounded-full border border-border"
            referrerPolicy="no-referrer"
          />
        )}
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">
            {user.displayName || user.login}
          </h2>
          <p className="text-sm text-muted-foreground">@{user.login}</p>
        </div>
      </div>

      <dl className="grid grid-cols-1 gap-3 rounded-md border bg-card p-4 text-sm sm:grid-cols-[8rem_minmax(0,1fr)]">
        <dt className="text-muted-foreground">Email</dt>
        <dd>{user.email ?? <span className="text-muted-foreground">—</span>}</dd>

        <dt className="text-muted-foreground">GitHub login</dt>
        <dd className="font-mono">{user.login}</dd>

        <dt className="text-muted-foreground">Role</dt>
        <dd>{user.isAdmin ? 'Admin' : 'Member'}</dd>
      </dl>

      <p className="text-xs text-muted-foreground">
        Per-user API tokens, role-assignment review, and notification
        preferences land here as TFND-3 / TFND-4 bearer tokens advance.
      </p>
    </div>
  )
}
