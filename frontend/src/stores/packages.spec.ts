import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { usePackageStore, RECENT_PACKAGES, type Package } from './packages'

vi.mock('axios')

function pkg(id: number, cachedAt: string, over: Partial<Package> = {}): Package {
  return {
    id: String(id),
    registry: 'npm',
    name: `p${id}`,
    version: '1.0.0',
    size: 1,
    cached_at: cachedAt,
    last_accessed: cachedAt,
    download_count: 0,
    ...over,
  }
}

describe('package store paging', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.mocked(axios.get).mockReset()
  })
  afterEach(() => vi.restoreAllMocks())

  it('sends page, page_size, registry and q; skips the all-registries and empty values', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { packages: [], total_groups: 0 } })
    const store = usePackageStore()

    await store.fetchPackagePage({ page: 2, pageSize: 25, registry: 'pypi', q: ' six ' })
    await store.fetchPackagePage({ page: 1, pageSize: 25, registry: 'all', q: '' })

    expect(vi.mocked(axios.get).mock.calls.map((c) => c[0])).toEqual([
      '/api/packages?page=2&page_size=25&registry=pypi&q=six',
      '/api/packages?page=1&page_size=25',
    ])
  })

  it('keeps the server group count, and counts groups itself when the server sends none', async () => {
    const store = usePackageStore()
    vi.mocked(axios.get).mockResolvedValueOnce({ data: { packages: [pkg(1, '2026-01-01T00:00:00Z')], total_groups: 80 } })
    await store.fetchPackagePage({ page: 3, pageSize: 25 })
    expect(store.packagePage).toMatchObject({ totalGroups: 80, page: 3, pageSize: 25 })

    vi.mocked(axios.get).mockResolvedValueOnce({
      data: { packages: [pkg(1, '2026-01-01T00:00:00Z'), pkg(1, '2026-01-02T00:00:00Z', { version: '2.0.0' })] },
    })
    await store.fetchPackagePage({ page: 1, pageSize: 25 })
    expect(store.packagePage.totalGroups).toBe(1)
  })

  it('drops the answer of a request a newer one has replaced', async () => {
    const store = usePackageStore()
    let release: (v: unknown) => void = () => {}
    vi.mocked(axios.get)
      .mockImplementationOnce(() => new Promise((resolve) => { release = resolve }))
      .mockResolvedValueOnce({ data: { packages: [pkg(2, '2026-01-01T00:00:00Z')], total_groups: 1 } })

    const slow = store.fetchPackagePage({ page: 1, pageSize: 25, q: 'old' })
    await store.fetchPackagePage({ page: 1, pageSize: 25, q: 'new' })
    release({ data: { packages: [pkg(1, '2026-01-01T00:00:00Z')], total_groups: 1 } })
    await slow

    expect(store.packagePage.packages.map((p) => p.id)).toEqual(['2'])
    expect(store.loading).toBe(false)
  })

  it('reports a failed page request and leaves the last page in place', async () => {
    const store = usePackageStore()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(axios.get).mockResolvedValueOnce({ data: { packages: [pkg(1, '2026-01-01T00:00:00Z')], total_groups: 1 } })
    await store.fetchPackagePage({ page: 1, pageSize: 25 })
    vi.mocked(axios.get).mockRejectedValueOnce(new Error('502'))
    await store.fetchPackagePage({ page: 1, pageSize: 25 })

    expect(store.error).toBe('502')
    expect(store.packagePage.packages).toHaveLength(1)
    expect(store.loading).toBe(false)
  })

  it('recent packages: small page sorted by cached_at, newest ten rows, newest first', async () => {
    const rows = Array.from({ length: 14 }, (_, i) => pkg(i, `2026-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`))
    vi.mocked(axios.get).mockResolvedValue({ data: { packages: rows, total_groups: 14 } })
    const store = usePackageStore()

    await store.fetchRecentPackages()

    expect(vi.mocked(axios.get)).toHaveBeenCalledWith(`/api/packages?page=1&page_size=${RECENT_PACKAGES}&sort=cached_at&order=desc`)
    expect(store.recentPackages).toHaveLength(RECENT_PACKAGES)
    expect(store.recentPackages[0].id).toBe('13')
    expect(store.recentPackages[9].id).toBe('4')
  })

  it('loading stays on until the last overlapping request settles', async () => {
    const store = usePackageStore()
    const releases: Array<(v: unknown) => void> = []
    vi.mocked(axios.get).mockImplementation(() => new Promise((resolve) => releases.push(resolve)))

    const stats = store.fetchStats()
    const recent = store.fetchRecentPackages()
    expect(store.loading).toBe(true)
    releases[0]({ data: { stats: { total_packages: 1 }, registries: {} } })
    await stats
    expect(store.loading).toBe(true)
    releases[1]({ data: { packages: [] } })
    await recent
    expect(store.loading).toBe(false)
  })

  it('delete removes one version and leaves reloading to the caller', async () => {
    vi.mocked(axios.delete).mockResolvedValue({})
    const store = usePackageStore()
    await store.deletePackage('npm', 'left-pad', '1.0.0')
    expect(vi.mocked(axios.delete)).toHaveBeenCalledWith('/api/packages/npm/left-pad/1.0.0')
    expect(vi.mocked(axios.get)).not.toHaveBeenCalled()
  })
})
