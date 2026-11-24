import { describe, expect, it } from 'vitest'
import { inspectorRows, type ScannerResult } from './inspectors'
import type { ScannerInfo } from './system'

const counts = (critical: number) => ({ critical, high: 0, moderate: 0, low: 0 })

const configured: ScannerInfo[] = [
  { name: 'trivy', enabled: true, healthy: true, version: '0.58.1' },
  { name: 'grype', enabled: true, healthy: false, version: '' },
  { name: 'govulncheck', enabled: true, healthy: true, version: '1.1.4' },
  { name: 'pip-audit', enabled: false, healthy: null, version: '' },
]

describe('inspectorRows', () => {
  it('lists reporting scanners first, with their counts and the configured version', () => {
    const results: ScannerResult[] = [{ name: 'trivy', findings: 1, severity_counts: counts(1) }]
    const [first] = inspectorRows('npm', results, configured)
    expect(first).toMatchObject({ name: 'trivy', status: 'reported', version: '0.58.1', findings: 1, health: 'healthy' })
    expect(first.counts?.critical).toBe(1)
  })

  it('explains each scanner that did not report', () => {
    const rows = inspectorRows('npm', [{ name: 'trivy', findings: 0, severity_counts: counts(0) }], configured)
    const status = Object.fromEntries(rows.map((r) => [r.name, r.status]))
    expect(status).toEqual({
      trivy: 'reported',
      grype: 'no-result',
      govulncheck: 'not-applicable',
      'pip-audit': 'off',
    })
  })

  it('flags a reporting scanner that is now unhealthy', () => {
    const rows = inspectorRows('npm', [{ name: 'grype', findings: 0, severity_counts: counts(0) }], configured)
    expect(rows[0].health).toBe('down')
  })

  it('keeps a reported scanner that is no longer configured', () => {
    const rows = inspectorRows('npm', [{ name: 'retired', findings: 2, severity_counts: counts(2) }], configured)
    expect(rows[0]).toMatchObject({ name: 'retired', health: null, version: '' })
  })
})
