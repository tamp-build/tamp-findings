import { useAuth } from '@/lib/auth'

export function SignInView() {
  const { signIn } = useAuth()

  // The OAuth handler redirects denied users to /?error=not_approved. Read
  // it once on mount; no need to keep it reactive.
  const error = new URLSearchParams(window.location.search).get('error')
  const errorMsg = error === 'not_approved'
    ? 'Your GitHub login is not on the tamp.findings allowlist. Ask an admin to approve it before signing in again.'
    : error
      ? 'Sign-in failed. Try again, or ask an admin if the problem persists.'
      : null

  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-6 rounded-lg border bg-card p-8 shadow-sm">
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">tamp.findings</h1>
          <p className="text-sm text-muted-foreground">
            Sign in to view findings, components, and coverage.
          </p>
        </div>

        {errorMsg && (
          <div className="rounded-md border border-destructive/50 bg-destructive/5 p-3 text-sm text-destructive">
            {errorMsg}
          </div>
        )}

        <button
          type="button"
          onClick={() => signIn('/')}
          className="flex w-full items-center justify-center gap-2 rounded-md bg-foreground px-4 py-2.5 text-sm font-medium text-background hover:bg-foreground/90 transition-colors"
        >
          <GitHubMark />
          Sign in with GitHub
        </button>

        <p className="text-xs text-muted-foreground">
          Access is restricted to approved logins. First sign-in by an
          unapproved GitHub user is rejected.
        </p>
      </div>
    </div>
  )
}

function GitHubMark() {
  return (
    <svg viewBox="0 0 16 16" className="size-5" aria-hidden="true" fill="currentColor">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2 .37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  )
}
