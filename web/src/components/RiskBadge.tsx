import { useState, useRef, useEffect } from 'react'
import type { RiskScore, RiskBand } from '@/lib/api'
import { cn } from '@/lib/utils'

// Canonical human label per category key — order is presentation order
// in the popover. Keys must match the scorer's RiskCategoryNames.
const CATEGORY_LABELS: Record<string, string> = {
  cve: 'Known CVEs',
  secrets: 'Verified secrets',
  sastSevere: 'SAST · critical + high',
  iacSevere: 'IaC · critical + high',
  coverage: 'Coverage gap',
  sbomStaleness: 'SBOM staleness',
  tests: 'Test failures',
  license: 'License risk',
  sastLow: 'SAST · medium + low',
  missingScanners: 'Missing scanners',
}

const BAND_STYLES: Record<RiskBand, { dot: string; text: string; ring: string }> = {
  green:  { dot: 'bg-emerald-500', text: 'text-emerald-700 dark:text-emerald-400', ring: 'ring-emerald-500/40' },
  yellow: { dot: 'bg-amber-500',   text: 'text-amber-700  dark:text-amber-400',   ring: 'ring-amber-500/40' },
  orange: { dot: 'bg-orange-500',  text: 'text-orange-700 dark:text-orange-400',  ring: 'ring-orange-500/40' },
  red:    { dot: 'bg-red-600',     text: 'text-red-700    dark:text-red-400',     ring: 'ring-red-600/40' },
}

const BAND_LABELS: Record<RiskBand, string> = {
  green: 'Low Risk',
  yellow: 'Moderate Risk',
  orange: 'Elevated Risk',
  red: 'High Risk',
}

export function RiskBadge({ risk }: { risk: RiskScore | null }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  if (risk === null) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-dashed border-border px-2 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
        Not yet scored
      </span>
    )
  }

  const style = BAND_STYLES[risk.band]
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full border bg-card px-2 py-0.5 text-xs font-semibold ring-1 ring-inset',
          style.ring, style.text,
        )}
        title={`${BAND_LABELS[risk.band]} · ${risk.policyName}`}
      >
        <span className={cn('inline-block size-2 rounded-full', style.dot)} />
        {risk.score.toFixed(1)}%
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-1 w-80 rounded-md border bg-card p-3 shadow-md">
          <div className="mb-2 flex items-baseline justify-between">
            <p className="text-sm font-semibold">{BAND_LABELS[risk.band]}</p>
            <p className="text-xs text-muted-foreground">{risk.policyName}</p>
          </div>
          <table className="w-full text-xs">
            <tbody>
              {risk.breakdown
                .filter(b => b.enabled)
                .sort((a, b) => b.contribution - a.contribution)
                .map(b => (
                <tr key={b.key} className="border-t border-border first:border-t-0">
                  <td className="py-1 text-muted-foreground">{CATEGORY_LABELS[b.key] ?? b.key}</td>
                  <td className="py-1 text-right tabular-nums">
                    {b.contribution.toFixed(2)}
                    <span className="text-muted-foreground"> / {b.max}</span>
                  </td>
                </tr>
              ))}
              <tr className="border-t border-border font-semibold">
                <td className="py-1.5">Total</td>
                <td className="py-1.5 text-right tabular-nums">{risk.score.toFixed(1)}%</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
