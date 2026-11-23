import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

export interface VulnerabilityCounts {
  critical: number
  high: number
  moderate: number
  low: number
}

export interface VulnerabilityInfo {
  scanned: boolean
  status: 'clean' | 'vulnerable' | 'pending' | 'not_scanned'
  counts?: VulnerabilityCounts
  total?: number
  scannedAt?: string // ISO 8601 timestamp
  isBlocked?: boolean // Whether download is blocked due to vulnerability thresholds
}

export interface Package {
  id: string
  registry: string
  name: string
  version: string
  release_version?: string
  size: number
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
  /** Seconds a cached item can go unrequested before cleanup removes it; 0 means never. */
  idle_ttl?: number
}

export type PackageSort = 'name' | 'cached_at' | 'downloads' | 'size'

export interface PackagePageParams {
  page: number
  pageSize: number
  /** Empty or 'all' means every registry. */
  registry?: string
  /** Case-insensitive match on name, version or release version. */
  q?: string
  sort?: PackageSort
  order?: 'asc' | 'desc'
}

/** One page of package groups: every version row of each group, in group order. */
export interface PackagePage {
  packages: Package[]
  totalGroups: number
  page: number
  pageSize: number
}

/** Rows shown under "Recent packages". */
export const RECENT_PACKAGES = 10

function distinctGroups(rows: Package[]): number {
  return new Set(rows.map((p) => `${p.registry}\u0000${p.name}`)).size
}

export const usePackageStore = defineStore('packages', () => {
  const packages = ref<Package[]>([])
  const packagePage = ref<PackagePage>({ packages: [], totalGroups: 0, page: 1, pageSize: 25 })
  const recentPackages = ref<Package[]>([])
  const stats = ref<Stats | null>(null)
  const registries = ref<Record<string, any>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)

  // Requests overlap (stats next to the recent list, a new search before the last answer),
  // so loading stays on until the last one settles.
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
  let pageRequest = 0

  /**
   * Every package, unpaginated. Only views that filter on scan results need it.
   * `severity` keeps the packages whose latest scan has a vulnerability of any listed severity.
   */
  async function fetchPackages(options: { severity?: readonly string[] } = {}) {
    begin()
    try {
      const query = options.severity?.length ? `?severity=${options.severity.join(',')}` : ''
      const response = await axios.get(`/api/packages${query}`)
      // Only update packages if we got valid data
      if (response.data && Array.isArray(response.data.packages)) {
        packages.value = response.data.packages
      } else {
        console.warn('Unexpected API response format:', response.data)
        error.value = 'Unexpected response format from server'
      }
    } catch (err: any) {
      console.error('Failed to fetch packages:', err)
      error.value = err.message
      // Don't clear packages on error - keep showing the cached data
    } finally {
      settle()
    }
  }

  async function fetchPackagePage(params: PackagePageParams) {
    const request = ++pageRequest
    begin()
    try {
      const query = new URLSearchParams({ page: String(params.page), page_size: String(params.pageSize) })
      if (params.registry && params.registry !== 'all') query.set('registry', params.registry)
      if (params.q?.trim()) query.set('q', params.q.trim())
      if (params.sort) query.set('sort', params.sort)
      if (params.order) query.set('order', params.order)
      const response = await axios.get(`/api/packages?${query.toString()}`)
      // A newer request is on its way; its answer must win.
      if (request !== pageRequest) return
      const data = response.data
      if (data && Array.isArray(data.packages)) {
        packagePage.value = {
          packages: data.packages,
          totalGroups: Number.isFinite(data.total_groups) ? data.total_groups : distinctGroups(data.packages),
          page: params.page,
          pageSize: params.pageSize,
        }
      } else {
        console.warn('Unexpected API response format:', data)
        error.value = 'Unexpected response format from server'
      }
    } catch (err: any) {
      if (request !== pageRequest) return
      console.error('Failed to fetch packages:', err)
      error.value = err.message
    } finally {
      settle()
    }
  }

  async function fetchRecentPackages() {
    begin()
    try {
      const response = await axios.get(
        `/api/packages?page=1&page_size=${RECENT_PACKAGES}&sort=cached_at&order=desc`,
      )
      if (response.data && Array.isArray(response.data.packages)) {
        // The page holds whole groups, so the newest rows are in there but not in order.
        recentPackages.value = [...response.data.packages]
          .sort((a: Package, b: Package) => new Date(b.cached_at).getTime() - new Date(a.cached_at).getTime())
          .slice(0, RECENT_PACKAGES)
      } else {
        console.warn('Unexpected API response format:', response.data)
        error.value = 'Unexpected response format from server'
      }
    } catch (err: any) {
      console.error('Failed to fetch recent packages:', err)
      error.value = err.message
    } finally {
      settle()
    }
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
    packages,
    packagePage,
    recentPackages,
    stats,
    registries,
    loading,
    error,
    fetchPackages,
    fetchPackagePage,
    fetchRecentPackages,
    fetchStats,
    deletePackage,
  }
})
