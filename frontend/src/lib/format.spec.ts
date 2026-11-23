import { describe, expect, it } from 'vitest'
import { formatDuration } from './format'

describe('formatDuration', () => {
  it.each([
    [604800, '7 days'],
    [86400, '1 day'],
    [129600, '36 hours'],
    [3600, '1 hour'],
    [5400, '90 minutes'],
    [60, '1 minute'],
  ])('formats %i seconds as %s', (seconds, expected) => {
    expect(formatDuration(seconds)).toBe(expected)
  })
})
