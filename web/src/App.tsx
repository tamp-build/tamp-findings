import { useState } from 'react'
import { Search } from 'lucide-react'
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
          {/* Brand doubles as "home" — clicking returns to Overview from a
              drilled view (Findings/Components/Coverage/Tests are reached
              by clicking ring segments or rows, not by top-nav tabs). */}
          <button
            type="button"
            onClick={() => { setTab('overview'); setSearch('') }}
            className="text-base font-semibold tracking-tight hover:text-foreground/80 sm:text-xl"
          >
            tamp.findings
          </button>
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

export default App
