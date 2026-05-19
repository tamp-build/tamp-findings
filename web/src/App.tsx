import { useState } from 'react'
import { Search } from 'lucide-react'
import { cn } from '@/lib/utils'
import { FindingsView } from '@/views/FindingsView'
import { ComponentsView } from '@/views/ComponentsView'

type Tab = 'findings' | 'components'

function App() {
  const [tab, setTab] = useState<Tab>('findings')
  const [search, setSearch] = useState('')

  return (
    <div className="min-h-svh bg-background text-foreground">
      <header className="border-b border-border bg-card/50">
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-6 py-4">
          <h1 className="text-xl font-semibold tracking-tight">tamp.findings</h1>
          <nav className="flex items-center gap-1">
            <TabButton active={tab === 'findings'} onClick={() => { setTab('findings'); setSearch('') }}>
              Findings
            </TabButton>
            <TabButton active={tab === 'components'} onClick={() => { setTab('components'); setSearch('') }}>
              Components
            </TabButton>
          </nav>
          {tab === 'findings' && (
            <div className="relative ml-auto w-72">
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

      <div className="mx-auto max-w-7xl px-6 py-6">
        {tab === 'findings' ? <FindingsView search={search} /> : <ComponentsView />}
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
