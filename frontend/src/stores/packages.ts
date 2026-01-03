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
  total_downloads: number
  scanned_packages: number
  vulnerable_packages: number
}

export const usePackageStore = defineStore('packages', () => {
  const packages = ref<Package[]>([])
  const stats = ref<Stats | null>(null)
  const registries = ref<Record<string, any>>({})
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function fetchPackages() {
    loading.value = true
    error.value = null
    try {
      const response = await axios.get('/api/packages')
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
      loading.value = false
    }
  }

  async function fetchStats(registry = '') {
    loading.value = true
    error.value = null
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
      loading.value = false
    }
  }

  async function deletePackage(registry: string, name: string, version: string) {
    loading.value = true
    error.value = null
    try {
      await axios.delete(`/api/packages/${registry}/${name}/${version}`)
      await fetchPackages()
    } catch (err: any) {
      error.value = err.message
    } finally {
      loading.value = false
    }
  }

  return {
    packages,
    stats,
    registries,
    loading,
    error,
    fetchPackages,
    fetchStats,
    deletePackage,
  }
})
