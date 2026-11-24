import { ref } from 'vue'
import axios from 'axios'

export interface ScannerInfo {
  name: string
  enabled: boolean
  /** Null while the scanner is off or has not been probed. */
  healthy: boolean | null
  version: string
}

/** Response of GET /api/system. Durations are seconds; a negative threshold means unlimited. */
export interface SystemInfo {
  version: string
  security: {
    enabled: boolean
    fail_closed: boolean
    scan_on_download: boolean
    block_on_severity: string
    block_thresholds: { critical: number; high: number; moderate: number; low: number }
    scan_wait_timeout: number
    scanners: ScannerInfo[]
    rescan: { interval: number; active_window: number; concurrency: number; on_access: boolean }
  }
  upstreams: Record<string, string>
  cache: { max_size: number; idle_ttl: number; default_ttl: number }
  prewarming: { enabled: boolean; interval: number; top_packages: number }
}

export type ScannerState = 'healthy' | 'down' | 'off'

export function scannerState(scanner: ScannerInfo): ScannerState {
  if (!scanner.enabled) return 'off'
  return scanner.healthy === false ? 'down' : 'healthy'
}

const SEVERITY_NAMES = { critical: 'CRITICAL', high: 'HIGH', moderate: 'MODERATE', low: 'LOW' } as const
const SEVERITY_ORDER = ['critical', 'high', 'moderate', 'low'] as const

/** The block policy in words, from the threshold counts and the block-on-severity floor. */
export function describePolicy(security: SystemInfo['security']): string {
  if (!security.enabled) return 'Scanning is off. Every package is served.'
  const parts: string[] = []
  for (const level of SEVERITY_ORDER) {
    const limit = security.block_thresholds[level]
    if (limit < 0) continue
    parts.push(limit === 0 ? `any ${SEVERITY_NAMES[level]}` : `more than ${limit} ${SEVERITY_NAMES[level]}`)
  }
  const floor = security.block_on_severity.toLowerCase() as keyof typeof SEVERITY_NAMES
  if (floor in SEVERITY_NAMES) {
    const covered = SEVERITY_ORDER.slice(0, SEVERITY_ORDER.indexOf(floor) + 1).map((l) => SEVERITY_NAMES[l])
    parts.push(`any ${covered.join(' or ')}`)
  }
  return parts.length === 0 ? 'No severity blocks a package.' : `Blocks ${[...new Set(parts)].join(', ')}.`
}

const info = ref<SystemInfo | null>(null)
const error = ref<string | null>(null)
let inflight: Promise<void> | null = null

/** Shared GET /api/system state; concurrent callers share one request. */
export function useSystem() {
  function load(force = false): Promise<void> {
    if (info.value && !force) return Promise.resolve()
    inflight ??= axios
      .get<SystemInfo>('/api/system')
      .then((res) => {
        info.value = res.data
        error.value = null
      })
      .catch((err: unknown) => {
        error.value = err instanceof Error ? err.message : 'Could not load system settings'
      })
      .finally(() => {
        inflight = null
      })
    return inflight
  }
  return { info, error, load }
}

/** Test hook: forgets the cached response. */
export function __resetSystem(): void {
  info.value = null
  error.value = null
  inflight = null
}
