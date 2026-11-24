import type { Package } from '@/stores/packages'

const LEVELS = ['critical', 'high', 'moderate', 'low'] as const

function verdictOf(p: Package): string {
  return p.vulnerabilities?.verdict ?? (p.vulnerabilities?.isBlocked ? 'held' : p.vulnerabilities?.scanned ? 'cleared' : 'pending')
}

function count(p: Package, level: (typeof LEVELS)[number]): number {
  return p.vulnerabilities?.counts?.[level] ?? 0
}

/** A stand-in for GET /api/packages?layout=rows, so views can be tested against the real query contract. */
export function serveRows(url: string, all: readonly Package[]) {
  const params = new URL(url, 'http://test').searchParams
  const q = (params.get('q') ?? '').toLowerCase()
  const registry = params.get('registry')
  const verdict = params.get('verdict')
  const severities = (params.get('severity') ?? '').split(',').filter(Boolean)
  const page = Number(params.get('page') ?? 1)
  const pageSize = Number(params.get('page_size') ?? 25)

  const base = all.filter(
    (p) =>
      (!registry || p.registry === registry) &&
      (!q || [p.name, p.version, p.release_version ?? ''].some((f) => f.toLowerCase().includes(q))),
  )
  const counts = {
    verdicts: { cleared: 0, held: 0, bypassed: 0, pending: 0 } as Record<string, number>,
    severity_packages: { critical: 0, high: 0, moderate: 0, low: 0 } as Record<string, number>,
    severity_findings: { critical: 0, high: 0, moderate: 0, low: 0 } as Record<string, number>,
    vulnerable_allowed: 0,
  }
  for (const p of base) {
    counts.verdicts[verdictOf(p)]++
    if (verdictOf(p) === 'cleared' && (p.vulnerabilities?.total ?? 0) > 0) counts.vulnerable_allowed++
    for (const level of LEVELS) {
      if (count(p, level) > 0) counts.severity_packages[level]++
      counts.severity_findings[level] += count(p, level)
    }
  }

  const matched = base
    .filter((p) => !verdict || verdictOf(p) === verdict)
    .filter((p) => severities.length === 0 || severities.some((s) => count(p, s as (typeof LEVELS)[number]) > 0))
  const sort = params.get('sort')
  if (sort === 'risk') {
    matched.sort((a, b) => {
      for (const level of LEVELS) if (count(a, level) !== count(b, level)) return count(b, level) - count(a, level)
      return 0
    })
  }
  return {
    packages: matched.slice((page - 1) * pageSize, page * pageSize),
    total: matched.length,
    page,
    page_size: pageSize,
    counts,
  }
}
