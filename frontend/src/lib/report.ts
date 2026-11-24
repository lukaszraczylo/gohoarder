import type { ScannerResult } from '@/lib/inspectors'
import type { AppliedBypass, ApiVerdict, VulnerabilityCounts } from '@/stores/packages'

export interface VulnerabilityEntry {
  id: string
  severity: string
  title: string
  description: string
  references: string[]
  fixed_in: string
  detected_by?: string[]
  aliases?: string[]
  bypassed: boolean
  bypass?: { id: string; reason: string; created_by: string; expires_at: string }
}

/** Response of GET /api/packages/{registry}/{name}/{version}/vulnerabilities. */
export interface PackageReport {
  package?: { release_version?: string }
  scanned: boolean
  scanner?: string
  scanned_at?: string
  status: string
  message?: string
  vulnerabilities: VulnerabilityEntry[]
  vulnerability_count: number
  severity_counts?: VulnerabilityCounts
  bypassed_count?: number
  scanners: ScannerResult[]
  decision: { verdict: ApiVerdict; blocked: boolean; reason: string; bypass: AppliedBypass | null }
}
