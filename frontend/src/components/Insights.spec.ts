import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import Insights from './Insights.vue'
import { REGISTRIES, STATS, TIMESERIES, TREND } from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

let restore: (() => void) | undefined

afterEach(() => {
  restore?.()
  restore = undefined
  vi.restoreAllMocks()
})

async function open(stats = STATS, timeseries: unknown = TIMESERIES) {
  vi.mocked(axios.get).mockImplementation(async (url: string) => {
    if (url.startsWith('/api/stats/timeseries')) return { data: timeseries } as never
    if (url.startsWith('/api/stats/trend')) return { data: TREND } as never
    return { data: { stats, registries: REGISTRIES } } as never
  })
  const router = await createTestRouter('/stats')
  const pinia = createPinia()
  setActivePinia(pinia)
  const mounted = await mountStrict(Insights, { global: { plugins: [pinia, router] } })
  restore = mounted.restore
  await flushPromises()
  return mounted
}

beforeEach(() => setActivePinia(createPinia()))

describe('Insights', () => {
  it('lists packages and downloads per registry', async () => {
    const { wrapper, problems } = await open()
    expect(problems).toEqual([])
    const table = wrapper.get('[data-testid="registry-breakdown"] table')
    expect(table.text()).toContain('npm280')
    expect(table.text()).toContain('go110')
    expect(table.text()).toContain('pypi130')
  })

  it('reports scan coverage and the four outcomes', async () => {
    const { wrapper } = await open()
    const coverage = wrapper.get('[data-testid="scan-coverage"]').text()
    expect(coverage).toContain('3 of 4')
    for (const word of ['Cleared', 'Held', 'Bypassed', 'Awaiting scan']) expect(coverage).toContain(word)
  })

  it('shades a day when there were downloads', async () => {
    const { wrapper } = await open()
    expect(wrapper.get('[data-testid="daily-downloads"]').find('[role="img"]').exists()).toBe(true)
  })

  it('does not draw an empty heatmap for a month with no downloads', async () => {
    const quiet = { ...TIMESERIES, data_points: TIMESERIES.data_points.map((p) => ({ ...p, value: 0 })) }
    const { wrapper } = await open(STATS, quiet)
    expect(wrapper.get('[data-testid="daily-downloads"]').text()).toContain('No downloads yet')
  })

  it('never shows a hit rate or evictions, which the server does not track', async () => {
    const { wrapper } = await open()
    expect(wrapper.text()).not.toMatch(/hit rate|evict/i)
  })
})
