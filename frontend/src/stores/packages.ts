import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

export interface VulnerabilityCounts {
  critical: number
  high: number
  moderate: number
  low: number
}

/** What the proxy did with a package; absent on servers that predate verdicts. */
export type ApiVerdict = 'cleared' | 'held' | 'bypassed' | 'pending'

/** The admin bypass that applied to a package. */
export interface AppliedBypass {
  id: string
  type: 'cve' | 'package'
  target: string
  reason: string
  created_by: string
  created_at: string
  expires_at: string
}

export interface VulnerabilityInfo {
  scanned: boolean
  status: 'clean' | 'vulnerable' | 'pending' | 'not_scanned'
  counts?: VulnerabilityCounts
  total?: number
  scannedAt?: string // ISO 8601 timestamp
  isBlocked?: boolean // Whether download is blocked due to vulnerability thresholds
  verdict?: ApiVerdict
  /** Why the package is held. */
  reason?: string
  bypass?: AppliedBypass
}

export interface Package {
  id: string
  registry: string
  name: string
  version: string
  release_version?: string
  size: number
  checksum_sha256?: string
  cached_at: string
  last_accessed: string
  download_count: number
  vulnerabilities?: VulnerabilityInfo
}

export interface Stats {
  registry: string
  total_packages: number
  total_size: number
  max_cache_size: number
  total_downloads: number
  scanned_packages: number
  vulnerable_packages: number
  blocked_packages: number
  bypassed_packages?: number
  /** Seconds a cached item can go unrequested before cleanup removes it; 0 means never. */
  idle_ttl?: number
}

export const usePackageStore = defineStore('packages', () => {
  const stats = ref<Stats | null>(null)
  const registries = ref<Record<string, any>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Requests overlap, so loading stays on until the last one settles.
  let inFlight = 0
  function begin() {
    inFlight++
    loading.value = true
    error.value = null
  }
  function settle() {
    inFlight = Math.max(inFlight - 1, 0)
    if (inFlight === 0) loading.value = false
  }

  async function fetchStats(registry = '') {
    begin()
    try {
      const url = registry ? `/api/stats?registry=${registry}` : '/api/stats'
      const response = await axios.get(url)
      // Only update stats if we got valid data
      if (response.data && response.data.stats) {
        stats.value = response.data.stats
        registries.value = response.data.registries || {}
      } else {
        console.warn('Unexpected stats response format:', response.data)
        error.value = 'Unexpected stats response format from server'
      }
    } catch (err: any) {
      console.error('Failed to fetch stats:', err)
      error.value = err.message
      // Don't clear stats on error - keep showing the cached data
    } finally {
      settle()
    }
  }

  /** Deletes one version; the caller reloads whichever list it shows. */
  async function deletePackage(registry: string, name: string, version: string) {
    begin()
    try {
      await axios.delete(`/api/packages/${registry}/${name}/${version}`)
    } catch (err: any) {
      error.value = err.message
    } finally {
      settle()
    }
  }

  return {
    stats,
    registries,
    loading,
    error,
    fetchStats,
    deletePackage,
  }
})
