import { describe, expect, it } from 'vitest'
import { verdictBanner } from './verdictBanner'
import type { PackageReport } from './report'

function report(over: Partial<PackageReport>): PackageReport {
  return {
    scanned: true,
    status: 'vulnerable',
    vulnerabilities: [],
    vulnerability_count: 0,
    scanners: [],
    decision: { verdict: 'cleared', blocked: false, reason: '', bypass: null },
    ...over,
  }
}

const vuln = (id: string, severity: string, extra: object = {}) => ({
  id,
  severity,
  title: '',
  description: '',
  references: [],
  fixed_in: '',
  bypassed: false,
  ...extra,
})

describe('verdictBanner', () => {
  it('names the blocking advisory, its severity, the policy and the fix', () => {
    const banner = verdictBanner(
      report({
        vulnerabilities: [vuln('CVE-2021-44906', 'CRITICAL', { fixed_in: '1.2.6' }), vuln('CVE-2022-0001', 'LOW')],
        decision: { verdict: 'held', blocked: true, reason: 'Package has 1 CRITICAL vulnerabilities (threshold: 0)', bypass: null },
      }),
      'Blocks any CRITICAL.',
      true,
    )
    expect(banner.type).toBe('danger')
    expect(banner.title).toBe('Held: CVE-2021-44906 is CRITICAL')
    expect(banner.body).toContain('1 critical finding. Policy holds any critical finding.')
    expect(banner.body).not.toContain('threshold')
    expect(banner.body).toContain('403')
    expect(banner.body).toContain('Fixed in v1.2.6')
  })

  it('summarises many blockers and ignores bypassed ones', () => {
    const vulns = ['A', 'B', 'C', 'D', 'E'].map((id) => vuln(id, 'critical'))
    vulns.push(vuln('Z', 'critical', { bypassed: true }))
    const banner = verdictBanner(report({ vulnerabilities: vulns, decision: { verdict: 'held', blocked: true, reason: '', bypass: null } }), '', true)
    expect(banner.title).toBe('Held: A, B, C and 2 more are CRITICAL')
  })

  it('falls back to the reason when no finding explains the hold', () => {
    const banner = verdictBanner(
      report({ decision: { verdict: 'held', blocked: true, reason: 'scan failed - fail closed', bypass: null } }),
      'Blocks any CRITICAL.',
      true,
    )
    expect(banner.title).toBe('Held: scan failed - fail closed')
  })

  it('says who bypassed a package and when it expires', () => {
    const banner = verdictBanner(
      report({
        decision: {
          verdict: 'bypassed',
          blocked: false,
          reason: '',
          bypass: {
            id: 'b1',
            type: 'package',
            target: 'npm/x@1',
            reason: 'Vendored fix',
            created_by: 'a.khan',
            created_at: '2026-11-01T00:00:00Z',
            expires_at: '2026-12-01T00:00:00Z',
          },
        },
      }),
      '',
      true,
    )
    expect(banner.type).toBe('note')
    expect(banner.title).toBe('Bypassed: Vendored fix')
    expect(banner.body).toContain('a.khan')
    expect(banner.body).toContain('package bypass')
  })

  it('reports an unscanned package by the fail-closed rule', () => {
    const base = report({ scanned: false, decision: { verdict: 'pending', blocked: false, reason: '', bypass: null } })
    expect(verdictBanner(base, '', true).body).toContain('held until one does')
    expect(verdictBanner(base, '', false).body).not.toContain('held')
  })

  it('counts findings that stay under the policy', () => {
    expect(verdictBanner(report({ vulnerability_count: 2 }), '', true).body).toContain('2 findings below the block policy')
    expect(verdictBanner(report({}), '', true).body).toContain('reported nothing')
  })
})
