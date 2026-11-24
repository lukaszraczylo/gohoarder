import { describe, expect, it } from 'vitest'
import { verdictOf, VERDICT_LABELS } from './verdict'

describe('verdictOf', () => {
  it.each([
    ['the server verdict when present', { scanned: true, status: 'vulnerable', verdict: 'bypassed', isBlocked: false }, 'bypassed'],
    ['held for a blocked package from an older server', { scanned: true, status: 'vulnerable', isBlocked: true }, 'held'],
    ['cleared for a scanned package from an older server', { scanned: true, status: 'clean' }, 'cleared'],
    ['pending for an unscanned package', { scanned: false, status: 'pending' }, 'pending'],
  ] as const)('%s', (_name, vulnerabilities, want) => {
    expect(verdictOf({ vulnerabilities: { ...vulnerabilities } })).toBe(want)
  })

  it('is unscanned when the server sends no scan block, as with scanning off', () => {
    expect(verdictOf({})).toBe('unscanned')
  })
})

describe('VERDICT_LABELS', () => {
  it('uses the checkpoint vocabulary', () => {
    expect(VERDICT_LABELS).toMatchObject({ cleared: 'Cleared', held: 'Held', bypassed: 'Bypassed', pending: 'Awaiting scan' })
  })
})
