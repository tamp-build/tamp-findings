import { useEffect, useState } from 'react'
import { Activity, AlertCircle, CheckCircle2 } from 'lucide-react'
import { cn } from '@/lib/utils'

type HealthState =
  | { kind: 'loading' }
  | { kind: 'ok'; service: string }
  | { kind: 'error'; message: string }

function App() {
  const [health, setHealth] = useState<HealthState>({ kind: 'loading' })

  useEffect(() => {
    const ctrl = new AbortController()
    fetch('/api/health', { signal: ctrl.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const body = (await r.json()) as { status: string; service: string }
        setHealth({ kind: 'ok', service: body.service })
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return
        setHealth({
          kind: 'error',
          message: e instanceof Error ? e.message : String(e),
        })
      })
    return () => ctrl.abort()
  }, [])

  return (
    <main className="min-h-svh bg-background text-foreground">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-12">
          <h1 className="text-3xl font-semibold tracking-tight">
            tamp.findings
          </h1>
          <p className="mt-2 text-muted-foreground">
            Findings hub for tamp-built software — POC scaffold
          </p>
        </header>

        <section
          className={cn(
            'rounded-lg border bg-card p-6',
            health.kind === 'error' && 'border-destructive/50',
          )}
        >
          <div className="flex items-start gap-4">
            <StatusIcon state={health} />
            <div className="flex-1">
              <h2 className="text-lg font-medium">API health</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {health.kind === 'loading' && 'Probing /api/health…'}
                {health.kind === 'ok' && (
                  <>
                    Service <code className="font-mono">{health.service}</code> is
                    responding.
                  </>
                )}
                {health.kind === 'error' && (
                  <>
                    Could not reach the API: <code className="font-mono">{health.message}</code>.
                    Is <code className="font-mono">dotnet run</code> up on port 5080?
                  </>
                )}
              </p>
            </div>
          </div>
        </section>

        <footer className="mt-16 text-xs text-muted-foreground">
          Tracking: YouTrack <code className="font-mono">TFND</code> · Stack: .NET 10 · React 19 · shadcn/ui · Postgres
        </footer>
      </div>
    </main>
  )
}

function StatusIcon({ state }: { state: HealthState }) {
  if (state.kind === 'loading') {
    return <Activity className="size-6 animate-pulse text-muted-foreground" />
  }
  if (state.kind === 'ok') {
    return <CheckCircle2 className="size-6 text-emerald-500" />
  }
  return <AlertCircle className="size-6 text-destructive" />
}

export default App
