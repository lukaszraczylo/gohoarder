import { scannerState, type ScannerInfo, type ScannerState } from '@/lib/system'
import type { VulnerabilityCounts } from '@/stores/packages'

/** One entry of the `scanners` array on a package's vulnerability response. */
export interface ScannerResult {
  name: string
  findings: number
  severity_counts: VulnerabilityCounts
}

/** Ecosystem-specific scanners only inspect their own registry (mirrors the server's shouldRunScanner). */
const REGISTRY_SCANNERS: Record<string, string> = { govulncheck: 'go', 'npm-audit': 'npm', 'pip-audit': 'pypi' }

export type InspectorStatus = 'reported' | 'no-result' | 'not-applicable' | 'off'

export interface InspectorRow {
  name: string
  version: string
  status: InspectorStatus
  health: ScannerState | null
  counts: VulnerabilityCounts | null
  findings: number | null
}

export const INSPECTOR_STATUS_LABELS: Record<InspectorStatus, string> = {
  reported: 'Reported',
  'no-result': 'No result',
  'not-applicable': 'Not applicable',
  off: 'Off',
}

/**
 * Scanner by severity for one package: every scanner that reported, then each configured scanner that did not,
 * with the reason it is absent where the registry explains it.
 */
export function inspectorRows(
  registry: string,
  results: readonly ScannerResult[],
  configured: readonly ScannerInfo[],
): InspectorRow[] {
  const byName = new Map(configured.map((s) => [s.name, s]))
  const rows: InspectorRow[] = results.map((r) => {
    const info = byName.get(r.name)
    return {
      name: r.name,
      version: info?.version ?? '',
      status: 'reported',
      health: info ? scannerState(info) : null,
      counts: r.severity_counts,
      findings: r.findings,
    }
  })
  const reported = new Set(results.map((r) => r.name))
  for (const info of configured) {
    if (reported.has(info.name)) continue
    const own = REGISTRY_SCANNERS[info.name]
    const status: InspectorStatus = !info.enabled ? 'off' : own && own !== registry ? 'not-applicable' : 'no-result'
    rows.push({ name: info.name, version: info.version, status, health: scannerState(info), counts: null, findings: null })
  }
  return rows
}
