import type { SeverityLevel } from '@/lib/severity'

export type TrendPeriod = '30day' | '90day' | '1year'

export const TREND_PERIODS: { value: TrendPeriod; label: string }[] = [
  { value: '30day', label: '30 days' },
  { value: '90day', label: '90 days' },
  { value: '1year', label: '1 year' },
]

export const DEFAULT_TREND_PERIOD: TrendPeriod = '30day'

/** One UTC day. A null count is unknown (no scan history yet), not zero. */
export interface TrendPoint {
  date: string
  total_packages: number
  total_size: number
  vulnerable_packages: number | null
  critical: number | null
  high: number | null
  moderate: number | null
  low: number | null
  blocked: number | null
}

export interface TrendResponse {
  period: TrendPeriod
  from: string
  to: string
  /** First day in the window with vulnerability data; null when the window has none. */
  vulnerability_history_start: string | null
  points: TrendPoint[]
}

/** Chart tone of each severity line, from the LineChart tone set. */
export const SEVERITY_LINE_TONES: Record<SeverityLevel, 'danger' | 'warning' | 'info' | 'muted'> = {
  critical: 'danger',
  high: 'warning',
  moderate: 'info',
  low: 'muted',
}

/** "2026-11-23" as "23 Nov", read in UTC so the label never shifts a day with the viewer's zone. */
export function formatTrendDate(iso: string, withYear = false): string {
  const date = new Date(`${iso}T00:00:00Z`)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'short',
    year: withYear ? 'numeric' : undefined,
    timeZone: 'UTC',
  })
}

/** Chart values of one count; unknown days become NaN, which breaks the line instead of drawing zero. */
export function trendValues(points: readonly TrendPoint[], key: keyof Omit<TrendPoint, 'date'>): number[] {
  return points.map((p) => p[key] ?? Number.NaN)
}

/** True when some day in the window has no vulnerability data. */
export function hasUnknownVulnerabilityDays(points: readonly TrendPoint[]): boolean {
  return points.some((p) => p.vulnerable_packages === null)
}
