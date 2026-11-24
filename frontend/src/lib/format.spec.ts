import { describe, expect, it } from 'vitest'
import { formatApproxDuration, formatDuration } from './format'

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

describe('formatApproxDuration', () => {
  it.each([
    [0, '1 second'],
    [40, '40 seconds'],
    [59.4, '59 seconds'],
    [60, '1 minute'],
    [750, '13 minutes'],
    [7199, '120 minutes'],
    [7200, '2 hours'],
    [36000, '10 hours'],
  ])('%d seconds reads %s', (seconds, expected) => {
    expect(formatApproxDuration(seconds)).toBe(expected)
  })
})
