import { describe, expect, it } from 'vitest'
import { humanReason, plural } from './reason'

describe('plural', () => {
  it.each([
    [0, '0 findings'],
    [1, '1 finding'],
    [2, '2 findings'],
  ])('%i', (n, want) => expect(plural(n, 'finding')).toBe(want))
})

describe('humanReason', () => {
  it('rewrites a zero threshold as "any"', () => {
    expect(humanReason('Package has 1 CRITICAL vulnerabilities (threshold: 0)')).toBe('1 critical finding. Policy holds any critical finding.')
  })

  it('states a count threshold and pluralises both numbers', () => {
    expect(humanReason('Package has 5 HIGH vulnerabilities (threshold: 3)')).toBe('5 high findings. Policy holds more than 3 high findings.')
    expect(humanReason('Package has 2 LOW vulnerabilities (threshold: 1)')).toBe('2 low findings. Policy holds more than 1 low finding.')
  })

  it('rewrites a severity-floor reason', () => {
    expect(humanReason('Package has HIGH or CRITICAL vulnerabilities')).toBe('Has a high or critical finding. Policy holds a finding at that level.')
    expect(humanReason('Package has MODERATE, HIGH, or CRITICAL vulnerabilities')).toBe(
      'Has a moderate, high or critical finding. Policy holds a finding at that level.',
    )
  })

  it('passes an unknown or empty reason through', () => {
    expect(humanReason('scan failed - fail closed')).toBe('scan failed - fail closed')
    expect(humanReason(undefined)).toBe('')
  })
})
