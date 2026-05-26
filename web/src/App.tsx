import { useEffect, useRef, useState } from 'react'
import { Search, LogOut, Settings, Plus, ChevronDown } from 'lucide-react'
import type { ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import { FindingsView } from '@/views/FindingsView'
import { ComponentsView } from '@/views/ComponentsView'
import { OverviewView } from '@/views/OverviewView'
import { DrillBreadcrumb } from '@/components/DrillBreadcrumb'
import { ClientPageView } from '@/views/ClientPageView'
import { ProjectPageView } from '@/views/ProjectPageView'
import { CoverageView } from '@/views/CoverageView'
import { TestsView } from '@/views/TestsView'
import { SignInView } from '@/views/SignInView'
import { ProfileView } from '@/views/ProfileView'
import { SettingsView } from '@/views/SettingsView'
import { AttestationView } from '@/views/AttestationView'
import { CreateHierarchyNodeDialog, type CreateHierarchyNodeKind } from '@/components/CreateHierarchyNodeDialog'
import { AuthProvider, useAuth, type AuthUser } from '@/lib/auth'

type Tab = 'overview' | 'client' | 'project'
  | 'findings' | 'components' | 'coverage' | 'tests'
  | 'attestation'
  | 'profile' | 'settings'

// Cross-tab presets — set by Overview row/donut clicks, consumed once
// by the destination view's effect that seeds its local filter state.
// A simple `nonce` counter forces the effect to re-fire even when the
// payload happens to match the previous one.
export type FindingsPreset = {
  nonce: number
  scanners?: ScannerKind[]
  severities?: Severity[]
  statuses?: FindingStatus[]
  // TFND-18: drill from Overview's "Top rules" filters to a single ruleId.
  ruleId?: string
}
export type ComponentsPreset = {
  nonce: number
  sbomStatus?: SbomHealthStatus
  license?: string
}

function App() {
  return (
    <AuthProvider>
      <AuthGate />
    </AuthProvider>
  )
}

function AuthGate() {
  const { status } = useAuth()
  if (status === 'loading') {
    return (
      <div className="flex min-h-svh items-center justify-center text-sm text-muted-foreground">
        Loading…
      </div>
    )
  }
  if (status === 'anon') return <SignInView />
  return <Dashboard />
}

function Dashboard() {
  const { user, signOut } = useAuth()
  const [tab, setTab] = useState<Tab>('overview')
  const [search, setSearch] = useState('')
  const [findingsPreset, setFindingsPreset] = useState<FindingsPreset>({ nonce: 0 })
  const [componentsPreset, setComponentsPreset] = useState<ComponentsPreset>({ nonce: 0 })
  // Scope state for the client/project pages. Cleared when the user
  // navigates back to overview via the brand link or a breadcrumb.
  const [scopeClientId, setScopeClientId] = useState<string | null>(null)
  const [scopeProjectId, setScopeProjectId] = useState<string | null>(null)

  const goToOverview = () => { setTab('overview'); setSearch(''); setScopeClientId(null); setScopeProjectId(null) }
  const goToClient = (clientId: string) => { setScopeClientId(clientId); setTab('client'); setSearch('') }
  const goToProject = (projectId: string) => { setScopeProjectId(projectId); setTab('project'); setSearch('') }
  const goToFindings = (preset: Omit<FindingsPreset, 'nonce'>) => {
    setFindingsPreset(p => ({ nonce: p.nonce + 1, ...preset }))
    setSearch('')
    setTab('findings')
  }
  const goToComponents = (preset: Omit<ComponentsPreset, 'nonce'> = {}) => {
    setComponentsPreset(p => ({ nonce: p.nonce + 1, ...preset }))
    setSearch('')
    setTab('components')
  }

  return (
    <div className="min-h-svh bg-background text-foreground">
      <header className="sticky top-0 z-20 border-b border-border bg-card/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-2 px-3 py-2 sm:gap-4 sm:px-4 sm:py-4">
          {/* Brand doubles as "home" — clicking returns to Overview from a
              drilled view (Findings/Components/Coverage/Tests are reached
              by clicking ring segments or rows, not by top-nav tabs). */}
          <button
            type="button"
            onClick={goToOverview}
            className="text-base font-semibold tracking-tight hover:text-foreground/80 sm:text-xl"
          >
            tamp.findings
          </button>
          {tab === 'findings' && (
            <div className="relative w-full sm:ml-auto sm:w-72 sm:mr-3">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search rule or title…"
                className="w-full rounded-md border bg-background py-2 pl-8 pr-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </div>
          )}
          <div className={tab === 'findings' ? "flex items-center gap-1" : "ml-auto flex items-center gap-1"}>
            <AddMenu />
            {user?.isAdmin && (
              <button
                type="button"
                onClick={() => setTab('settings')}
                title="Settings"
                className="rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
              >
                <Settings className="size-4" />
              </button>
            )}
            <UserAvatarButton user={user} onClick={() => setTab('profile')} />
            <button
              type="button"
              onClick={signOut}
              title="Sign out"
              className="rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            >
              <LogOut className="size-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-3 py-3 sm:px-4 sm:py-6">
        {tab === 'overview' && <OverviewView onSelectClient={goToClient} />}
        {tab === 'client' && scopeClientId && (
          <ClientPageView
            clientId={scopeClientId}
            onBack={goToOverview}
            onSelectProject={goToProject}
          />
        )}
        {tab === 'project' && scopeProjectId && (
          <ProjectPageView
            projectId={scopeProjectId}
            onBack={() => scopeClientId ? setTab('client') : goToOverview()}
            onBackToOverview={goToOverview}
            onDrillToFindings={goToFindings}
            onDrillToComponents={goToComponents}
            onDrillToCoverage={() => setTab('coverage')}
            onDrillToAttestation={() => setTab('attestation')}
          />
        )}
        {(tab === 'findings' || tab === 'components' || tab === 'coverage' || tab === 'tests') && scopeProjectId && (
          <DrillBreadcrumb
            clientId={scopeClientId}
            projectId={scopeProjectId}
            currentLabel={
              tab === 'findings'   ? 'Findings' :
              tab === 'components' ? 'SBOM components' :
              tab === 'coverage'   ? 'Coverage' :
              'Tests'
            }
            onSelectOverview={goToOverview}
            onSelectClient={goToClient}
            onSelectProject={goToProject}
          />
        )}
        {tab === 'findings' && <FindingsView search={search} preset={findingsPreset} />}
        {tab === 'components' && <ComponentsView preset={componentsPreset} />}
        {tab === 'coverage' && <CoverageView />}
        {tab === 'tests' && <TestsView />}
        {tab === 'attestation' && scopeProjectId && (
          <AttestationView
            projectId={scopeProjectId}
            onBack={() => setTab('project')}
          />
        )}
        {tab === 'profile' && <ProfileView />}
        {tab === 'settings' && <SettingsView />}
      </div>
    </div>
  )
}

function UserAvatarButton({ user, onClick }: { user: AuthUser | null; onClick: () => void }) {
  if (!user) return null
  // Tooltip stays as native `title` — newlines render as separate lines
  // in every major browser's native bubble. Good enough until we wire a
  // proper tooltip component for the rest of the app.
  const tooltipLines = [
    user.displayName || user.login,
    user.email,
    user.isAdmin ? 'admin' : null,
  ].filter(Boolean) as string[]
  return (
    <button
      type="button"
      onClick={onClick}
      title={tooltipLines.join('\n')}
      className="rounded-full transition-opacity hover:opacity-80"
    >
      {user.avatarUrl ? (
        <img
          src={user.avatarUrl}
          alt=""
          className="size-7 rounded-full border border-border"
          referrerPolicy="no-referrer"
        />
      ) : (
        <div className="flex size-7 items-center justify-center rounded-full border border-border bg-muted text-xs font-semibold uppercase">
          {(user.login[0] ?? '?').toUpperCase()}
        </div>
      )}
    </button>
  )
}

function AddMenu() {
  const [open, setOpen] = useState(false)
  const [dialog, setDialog] = useState<CreateHierarchyNodeKind | null>(null)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onMouseDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onMouseDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const items: { label: string; kind: CreateHierarchyNodeKind }[] = [
    { label: 'New client',    kind: 'client'    },
    { label: 'New project',   kind: 'project'   },
    { label: 'New component', kind: 'component' },
  ]

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        title="Create new"
        className="flex items-center gap-0.5 rounded-md p-1.5 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
      >
        <Plus className="size-4" />
        <ChevronDown className="size-3" />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-44 rounded-md border bg-card py-1 shadow-md">
          {items.map(it => (
            <button
              key={it.label}
              type="button"
              onClick={() => { setOpen(false); setDialog(it.kind) }}
              className="block w-full px-3 py-1.5 text-left text-sm hover:bg-muted/40"
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
      {dialog && (
        <CreateHierarchyNodeDialog
          kind={dialog}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  )
}

export default App
