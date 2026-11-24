import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { usePackageStore } from './packages'

vi.mock('axios')

describe('package store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.mocked(axios.get).mockReset()
  })
  afterEach(() => vi.restoreAllMocks())

  it('loads the stats of one registry', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { stats: { total_packages: 3 }, registries: { npm: {} } } })
    const store = usePackageStore()

    await store.fetchStats('npm')

    expect(vi.mocked(axios.get)).toHaveBeenCalledWith('/api/stats?registry=npm')
    expect(store.stats?.total_packages).toBe(3)
    expect(store.registries).toEqual({ npm: {} })
  })

  it('keeps the last stats and reports the error when a request fails', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: { stats: { total_packages: 3 }, registries: {} } })
    const store = usePackageStore()
    await store.fetchStats()

    vi.mocked(axios.get).mockRejectedValueOnce(new Error('boom'))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await store.fetchStats()

    expect(store.stats?.total_packages).toBe(3)
    expect(store.error).toBe('boom')
    expect(store.loading).toBe(false)
  })

  it('loading stays on until the last overlapping request settles', async () => {
    const store = usePackageStore()
    const releases: Array<(v: unknown) => void> = []
    vi.mocked(axios.get).mockImplementation(() => new Promise((resolve) => releases.push(resolve)))

    const first = store.fetchStats()
    const second = store.fetchStats('pypi')
    expect(store.loading).toBe(true)
    releases[0]({ data: { stats: { total_packages: 1 }, registries: {} } })
    await first
    expect(store.loading).toBe(true)
    releases[1]({ data: { stats: { total_packages: 2 }, registries: {} } })
    await second
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
