import type { VulnerabilityCounts } from '@/stores/packages'

export type SeverityTone = 'danger' | 'warning' | 'info' | 'neutral'

export const SEVERITY_TONES: Record<string, SeverityTone> = {
  critical: 'danger',
  high: 'warning',
  moderate: 'info',
  medium: 'info',
  low: 'neutral',
}

export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  medium: 2,
  low: 1,
}

export const SEVERITY_LEVELS = ['critical', 'high', 'moderate', 'low'] as const
export type SeverityLevel = (typeof SEVERITY_LEVELS)[number]

export const NO_VULNERABILITIES: VulnerabilityCounts = { critical: 0, high: 0, moderate: 0, low: 0 }

export function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? 0
}

export function formatSeverityName(severity: string): string {
  const lower = severity.toLowerCase()
  return lower.charAt(0).toUpperCase() + lower.slice(1)
}
