import { useState } from 'react'
import { Search } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ScannerKind, Severity, FindingStatus, SbomHealthStatus } from '@/lib/api'
import { FindingsView } from '@/views/FindingsView'
import { ComponentsView } from '@/views/ComponentsView'
import { OverviewView } from '@/views/OverviewView'
import { CoverageView } from '@/views/CoverageView'
import { TestsView } from '@/views/TestsView'

type Tab = 'overview' | 'findings' | 'components' | 'coverage' | 'tests'

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
  const [tab, setTab] = useState<Tab>('overview')
  const [search, setSearch] = useState('')
  const [findingsPreset, setFindingsPreset] = useState<FindingsPreset>({ nonce: 0 })
  const [componentsPreset, setComponentsPreset] = useState<ComponentsPreset>({ nonce: 0 })

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
          <h1 className="text-base font-semibold tracking-tight sm:text-xl">tamp.findings</h1>
          {/* Mobile: tabs scroll horizontally instead of wrapping to a second
              row; the sticky header stays one row tall. sm+ keeps the
              flex-wrap fallback for narrow desktop windows. */}
          <nav className="-mx-1 flex flex-nowrap items-center gap-1 overflow-x-auto px-1 sm:flex-wrap sm:overflow-visible">
            <TabButton active={tab === 'overview'} onClick={() => { setTab('overview'); setSearch('') }}>
              Overview
            </TabButton>
            <TabButton active={tab === 'findings'} onClick={() => { setTab('findings'); setSearch('') }}>
              Findings
            </TabButton>
            <TabButton active={tab === 'components'} onClick={() => { setTab('components'); setSearch('') }}>
              Components
            </TabButton>
            <TabButton active={tab === 'coverage'} onClick={() => { setTab('coverage'); setSearch('') }}>
              Coverage
            </TabButton>
            <TabButton active={tab === 'tests'} onClick={() => { setTab('tests'); setSearch('') }}>
              Tests
            </TabButton>
          </nav>
          {tab === 'findings' && (
            <div className="relative w-full sm:ml-auto sm:w-72">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search rule or title…"
                className="w-full rounded-md border bg-background py-2 pl-8 pr-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring/40"
              />
            </div>
          )}
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-3 py-3 sm:px-4 sm:py-6">
        {tab === 'overview' && <OverviewView onDrillToFindings={goToFindings} onDrillToComponents={goToComponents} onDrillToCoverage={() => setTab('coverage')} />}
        {tab === 'findings' && <FindingsView search={search} preset={findingsPreset} />}
        {tab === 'components' && <ComponentsView preset={componentsPreset} />}
        {tab === 'coverage' && <CoverageView />}
        {tab === 'tests' && <TestsView />}
      </div>
    </div>
  )
}

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
        active ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground hover:bg-muted/40',
      )}
    >
      {children}
    </button>
  )
}

export default App
