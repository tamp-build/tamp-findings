import { describe, it, expect } from 'vitest'
import { coverageTierColor, aggregateSastCounts, tierForLicense } from './RingChart'
import type { ScannerDetail } from '@/lib/api'

// Pure-function tests for the helpers powering the Overview rings.
// These don't render React; they just exercise the math/lookup so the
// coverage data flowing through tamp.findings has signal.

describe('coverageTierColor', () => {
  it('returns green for ≥80%', () => {
    expect(coverageTierColor(80)).toBe('#22c55e')
    expect(coverageTierColor(95)).toBe('#22c55e')
    expect(coverageTierColor(100)).toBe('#22c55e')
  })
  it('returns amber for 60..80%', () => {
    expect(coverageTierColor(60)).toBe('#f59e0b')
    expect(coverageTierColor(75)).toBe('#f59e0b')
    expect(coverageTierColor(79.9)).toBe('#f59e0b')
  })
  it('returns red below 60%', () => {
    expect(coverageTierColor(59.9)).toBe('#dc2626')
    expect(coverageTierColor(30)).toBe('#dc2626')
    expect(coverageTierColor(0)).toBe('#dc2626')
  })
})

describe('tierForLicense', () => {
  it('classifies common permissive SPDX ids', () => {
    expect(tierForLicense('MIT')).toBe('permissive')
    expect(tierForLicense('Apache-2.0')).toBe('permissive')
    expect(tierForLicense('BSD-3-Clause')).toBe('permissive')
    expect(tierForLicense('ISC')).toBe('permissive')
  })
  it('classifies weak copyleft (MPL/LGPL-2.1/EPL)', () => {
    expect(tierForLicense('MPL-2.0')).toBe('weakCopyleft')
    expect(tierForLicense('LGPL-2.1-or-later')).toBe('weakCopyleft')
    expect(tierForLicense('EPL-2.0')).toBe('weakCopyleft')
  })
  it('classifies strong copyleft (GPL-2.0, LGPL-3.0)', () => {
    expect(tierForLicense('GPL-2.0')).toBe('strongCopyleft')
    expect(tierForLicense('LGPL-3.0-only')).toBe('strongCopyleft')
  })
  it('classifies denied (GPL-3.0, AGPL, SSPL)', () => {
    expect(tierForLicense('GPL-3.0')).toBe('denied')
    expect(tierForLicense('AGPL-3.0-or-later')).toBe('denied')
    expect(tierForLicense('SSPL-1.0')).toBe('denied')
  })
  it('marks unknown for blank or "(unknown)"', () => {
    expect(tierForLicense('')).toBe('unknown')
    expect(tierForLicense('(unknown)')).toBe('unknown')
    expect(tierForLicense('SomeProprietary-1.0')).toBe('unknown')
  })
  it('composite expressions take the loosest atom', () => {
    // MIT (permissive) OR GPL-3.0 (denied) → permissive
    expect(tierForLicense('MIT OR GPL-3.0')).toBe('permissive')
    // GPL-2.0 (strong) AND MPL-2.0 (weak) → weak is looser
    expect(tierForLicense('GPL-2.0 AND MPL-2.0')).toBe('weakCopyleft')
  })
})

describe('aggregateSastCounts', () => {
  const sd = (
    scanner: string,
    open: Partial<{ critical: number; high: number; medium: number; low: number; info: number }> = {},
    closed = 0,
  ): ScannerDetail => {
    const o = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...open }
    const total = o.critical + o.high + o.medium + o.low + o.info
    return { scanner, open: { ...o, total }, closed, suppressed: 0, accepted: 0 }
  }

  it('returns null on empty list', () => {
    expect(aggregateSastCounts([])).toBeNull()
  })
  it('sums severities across every SAST scanner', () => {
    const agg = aggregateSastCounts([
      sd('ReSharper', { medium: 200, low: 180 }),
      sd('Roslyn',    { medium: 7,   low: 14 }),
      sd('OpenGrep',  {}),
    ])
    expect(agg?.scanner).toBe('Code Quality')
    expect(agg?.open.medium).toBe(207)
    expect(agg?.open.low).toBe(194)
    expect(agg?.open.total).toBe(207 + 194)
  })
  it('ignores non-SAST scanners (TruffleHog, Trivy, etc.)', () => {
    const agg = aggregateSastCounts([
      sd('Roslyn',     { high: 3 }),
      sd('TruffleHog', { critical: 99 }),
      sd('Trivy',      { high: 99 }),
    ])
    expect(agg?.open.high).toBe(3)
    expect(agg?.open.critical).toBe(0)
  })
  it('returns null when SAST scanners exist but all are empty', () => {
    expect(aggregateSastCounts([sd('Roslyn', {}), sd('OpenGrep', {})])).toBeNull()
  })
  it('rolls up lifecycle (closed/suppressed/accepted) across SAST scanners', () => {
    const agg = aggregateSastCounts([
      sd('Roslyn',    { medium: 5 }, 10),
      sd('ReSharper', { medium: 1 }, 3),
    ])
    expect(agg?.closed).toBe(13)
  })
})
