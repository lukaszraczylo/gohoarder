import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import Overview from './Overview.vue'
import { usePackageStore } from '../stores/packages'
import { useRealtimeStore, __resetRealtimeSingleton } from '../stores/realtime'
import { __resetSystem } from '@/lib/system'
import { REGISTRIES, STATS, SYSTEM, TIMESERIES, TOP_PACKAGES } from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  __resetRealtimeSingleton()
  __resetSystem()
  vi.mocked(axios.get).mockImplementation(async (url: string) => {
    if (url.startsWith('/api/system')) return { data: SYSTEM } as never
    if (url.startsWith('/api/analytics/')) return { data: TOP_PACKAGES } as never
    if (url.startsWith('/api/stats/timeseries')) return { data: TIMESERIES } as never
    return { data: { stats: STATS, registries: REGISTRIES } } as never
  })
})

afterEach(() => {
  restore?.()
  restore = undefined
  vi.restoreAllMocks()
})

async function open() {
  const router = await createTestRouter('/')
  const pinia = createPinia()
  setActivePinia(pinia)
  vi.spyOn(useRealtimeStore(), 'connect').mockImplementation(() => {})
  const mounted = await mountStrict(Overview, { global: { plugins: [pinia, router] } })
  restore = mounted.restore
  await flushPromises()
  return mounted
}

describe('Overview', () => {
  it('counts each verdict from the stats', async () => {
    const { wrapper, problems } = await open()
    expect(problems).toEqual([])
    const count = (verdict: string) => wrapper.get(`[data-verdict="${verdict}"]`).text()
    // 4 cached, 3 scanned, 1 held, 1 bypassed.
    expect(count('cleared')).toMatch(/Cleared\s*1/)
    expect(count('held')).toMatch(/Held\s*1/)
    expect(count('bypassed')).toMatch(/Bypassed\s*1/)
    expect(count('pending')).toMatch(/Awaiting scan\s*1/)
  })

  it('links each verdict to the page that lists it', async () => {
    const { wrapper } = await open()
    const href = (verdict: string) => wrapper.get(`[data-verdict="${verdict}"]`).attributes('href')
    expect(href('held')).toBe('/security?tab=held')
    expect(href('bypassed')).toBe('/security?tab=bypassed')
    expect(href('pending')).toBe('/packages?verdict=pending')
  })

  it('never shows a hit rate or evictions, which the server does not track', async () => {
    const { wrapper } = await open()
    expect(wrapper.text()).not.toMatch(/hit rate|evict/i)
  })

  it('lets a live stats frame override polled counters without losing the rest', async () => {
    const { wrapper } = await open()
    useRealtimeStore().lastStats = { blocked_packages: 5 }
    await flushPromises()
    expect(wrapper.get('[data-verdict="held"]').text()).toMatch(/Held\s*5/)
    expect(wrapper.get('[data-verdict="bypassed"]').text()).toMatch(/Bypassed\s*1/)
  })

  it('shows loading while statistics are in flight', async () => {
    const router = await createTestRouter('/')
    const pinia = createPinia()
    setActivePinia(pinia)
    usePackageStore().loading = true
    vi.spyOn(usePackageStore(), 'fetchStats').mockResolvedValue()
    vi.spyOn(useRealtimeStore(), 'connect').mockImplementation(() => {})
    const mounted = await mountStrict(Overview, { global: { plugins: [pinia, router] } })
    restore = mounted.restore
    expect(mounted.wrapper.text()).toContain('Loading statistics...')
  })
})
