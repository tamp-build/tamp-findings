import { describe, it, expect } from 'vitest'
import { coverageTierColor, pickPrimaryScanner, tierForLicense } from './RingChart'
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

describe('pickPrimaryScanner', () => {
  const empty = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }
  const sd = (scanner: string, total: number): ScannerDetail => ({
    scanner,
    open: { ...empty, total },
    closed: 0,
    suppressed: 0,
    accepted: 0,
  })

  it('returns null on empty list', () => {
    expect(pickPrimaryScanner([])).toBeNull()
  })
  it('prefers OpenGrep over Roslyn when both have findings', () => {
    const result = pickPrimaryScanner([sd('Roslyn', 5), sd('OpenGrep', 3)])
    expect(result?.scanner).toBe('OpenGrep')
  })
  it('falls back to Roslyn when OpenGrep has 0 findings', () => {
    const result = pickPrimaryScanner([sd('OpenGrep', 0), sd('Roslyn', 5)])
    expect(result?.scanner).toBe('Roslyn')
  })
  it('picks any nonzero scanner before zero ones outside the preference list', () => {
    const result = pickPrimaryScanner([sd('Trivy', 7), sd('TruffleHog', 0)])
    expect(result?.scanner).toBe('Trivy')
  })
  it('returns the first detail when nothing has findings', () => {
    const result = pickPrimaryScanner([sd('OpenGrep', 0), sd('Roslyn', 0)])
    // pickPrimaryScanner ends with `?? details[0] ?? null` so the first one wins
    expect(result?.scanner).toBe('OpenGrep')
  })
})
