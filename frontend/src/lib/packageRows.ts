import { ref, type Ref } from 'vue'
import axios from 'axios'
import type { ApiVerdict, Package } from '@/stores/packages'

export type RowSort = 'name' | 'version' | 'registry' | 'size' | 'downloads' | 'last_accessed' | 'last_scanned' | 'risk'

export interface RowQuery {
  q?: string
  registry?: string
  verdict?: ApiVerdict
  severity?: readonly string[]
  sort?: RowSort
  order?: 'asc' | 'desc'
  page: number
  pageSize: number
}

type Tally = Record<'critical' | 'high' | 'moderate' | 'low', number>

/** Counts over the registry and search matches, before the verdict and severity filters. */
export interface RowCounts {
  verdicts: Record<ApiVerdict, number>
  severity_packages: Tally
  severity_findings: Tally
  vulnerable_allowed: number
}

export interface RowsResponse {
  packages: Package[]
  total: number
  page: number
  page_size: number
  counts: RowCounts
}

export const EMPTY_COUNTS: RowCounts = {
  verdicts: { cleared: 0, held: 0, bypassed: 0, pending: 0 },
  severity_packages: { critical: 0, high: 0, moderate: 0, low: 0 },
  severity_findings: { critical: 0, high: 0, moderate: 0, low: 0 },
  vulnerable_allowed: 0,
}

/** URL of one page of package rows; empty filters are left out. */
export function rowsUrl(query: RowQuery): string {
  const params = new URLSearchParams({ layout: 'rows', page: String(query.page), page_size: String(query.pageSize) })
  if (query.q?.trim()) params.set('q', query.q.trim())
  if (query.registry) params.set('registry', query.registry)
  if (query.verdict) params.set('verdict', query.verdict)
  if (query.severity?.length) params.set('severity', query.severity.join(','))
  if (query.sort) params.set('sort', query.sort)
  if (query.sort && query.order) params.set('order', query.order)
  return `/api/packages?${params.toString()}`
}

export interface PackageRows {
  rows: Ref<Package[]>
  total: Ref<number>
  counts: Ref<RowCounts>
  loading: Ref<boolean>
  error: Ref<string | null>
  load: (query: RowQuery) => Promise<void>
}

/** One page of rows from the server. An answer to an older request is dropped, so the last query wins. */
export function usePackageRows(): PackageRows {
  const rows = ref<Package[]>([])
  const total = ref(0)
  const counts = ref<RowCounts>(EMPTY_COUNTS)
  const loading = ref(false)
  const error = ref<string | null>(null)
  let latest = 0

  async function load(query: RowQuery) {
    const request = ++latest
    loading.value = true
    error.value = null
    try {
      const { data } = await axios.get(rowsUrl(query))
      if (request !== latest) return
      if (!data || !Array.isArray(data.packages)) {
        error.value = 'Unexpected response format from server'
        return
      }
      rows.value = data.packages
      total.value = Number.isFinite(data.total) ? data.total : data.packages.length
      counts.value = data.counts ?? EMPTY_COUNTS
    } catch (err) {
      if (request !== latest) return
      error.value = err instanceof Error ? err.message : 'Failed to load packages'
    } finally {
      if (request === latest) loading.value = false
    }
  }

  return { rows, total, counts, loading, error, load }
}
