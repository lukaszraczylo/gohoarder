import { describe, expect, it } from 'vitest'
import { describePolicy, scannerState, type SystemInfo } from './system'

function security(over: Partial<SystemInfo['security']>): SystemInfo['security'] {
  return {
    enabled: true,
    fail_closed: true,
    scan_on_download: true,
    block_on_severity: 'none',
    block_thresholds: { critical: -1, high: -1, moderate: -1, low: -1 },
    scan_wait_timeout: 30,
    scanners: [],
    rescan: { interval: 0, active_window: 0, concurrency: 1, on_access: false },
    ...over,
  }
}

describe('describePolicy', () => {
  it('names a critical-only threshold policy', () => {
    const policy = describePolicy(security({ block_thresholds: { critical: 0, high: -1, moderate: -1, low: -1 } }))
    expect(policy).toBe('Blocks any CRITICAL.')
  })

  it('states a count threshold', () => {
    const policy = describePolicy(security({ block_thresholds: { critical: 0, high: 3, moderate: -1, low: -1 } }))
    expect(policy).toBe('Blocks any CRITICAL, more than 3 HIGH.')
  })

  it('expands the block-on-severity floor to every level at or above it', () => {
    expect(describePolicy(security({ block_on_severity: 'high' }))).toBe('Blocks any CRITICAL or HIGH.')
  })

  it('does not repeat a level the thresholds already cover', () => {
    const policy = describePolicy(security({ block_on_severity: 'critical', block_thresholds: { critical: 0, high: -1, moderate: -1, low: -1 } }))
    expect(policy).toBe('Blocks any CRITICAL.')
  })

  it('says so when nothing blocks and when scanning is off', () => {
    expect(describePolicy(security({}))).toBe('No severity blocks a package.')
    expect(describePolicy(security({ enabled: false }))).toBe('Scanning is off. Every package is served.')
  })
})

describe('scannerState', () => {
  it('maps config and probe to a state', () => {
    expect(scannerState({ name: 'a', enabled: false, healthy: null, version: '' })).toBe('off')
    expect(scannerState({ name: 'a', enabled: true, healthy: false, version: '' })).toBe('down')
    expect(scannerState({ name: 'a', enabled: true, healthy: true, version: '' })).toBe('healthy')
  })
})
