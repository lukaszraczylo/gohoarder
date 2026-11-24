import type { Package } from '@/stores/packages'

/** The customs-desk outcome of a package; `unscanned` is a server with scanning off. */
export type Verdict = 'cleared' | 'held' | 'bypassed' | 'pending' | 'unscanned'

export const VERDICT_LABELS: Record<Verdict, string> = {
  cleared: 'Cleared',
  held: 'Held',
  bypassed: 'Bypassed',
  pending: 'Awaiting scan',
  unscanned: 'Not scanned',
}

export const VERDICT_TONES: Record<Verdict, 'success' | 'danger' | 'info' | 'warning' | 'neutral'> = {
  cleared: 'success',
  held: 'danger',
  bypassed: 'info',
  pending: 'warning',
  unscanned: 'neutral',
}

/** Text colour of a verdict's icon; the label is always shown beside it. */
export const VERDICT_TEXT: Record<Verdict, string> = {
  cleared: 'text-success',
  held: 'text-destructive',
  bypassed: 'text-info',
  pending: 'text-warning',
  unscanned: 'text-muted-foreground',
}

/** One sentence per verdict, for tooltips and headings. */
export const VERDICT_MEANINGS: Record<Verdict, string> = {
  cleared: 'Scanned and under the block policy. Served to clients.',
  held: 'At or over the block policy. Clients get a 403.',
  bypassed: 'An admin bypass applies. Served to clients.',
  pending: 'No scan result yet.',
  unscanned: 'Security scanning is off.',
}

export const VERDICT_OPTIONS = (['cleared', 'held', 'bypassed', 'pending'] as const).map((value) => ({
  value,
  label: VERDICT_LABELS[value],
}))

/** Sort order for a verdict column: worst first. */
export const VERDICT_RANK: Record<Verdict, number> = { held: 4, pending: 3, bypassed: 2, cleared: 1, unscanned: 0 }

export function verdictOf(pkg: Pick<Package, 'vulnerabilities'>): Verdict {
  const info = pkg.vulnerabilities
  if (!info) return 'unscanned'
  if (info.verdict) return info.verdict
  if (info.isBlocked) return 'held'
  return info.scanned ? 'cleared' : 'pending'
}
