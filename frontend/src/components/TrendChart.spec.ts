import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import TrendChart from './TrendChart.vue'
import { TREND } from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'
import { formatTrendDate, trendValues } from '@/lib/trend'

vi.mock('axios')

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  vi.mocked(axios.get).mockReset()
  vi.mocked(axios.get).mockResolvedValue({ data: TREND })
})

afterEach(() => {
  restore?.()
  restore = undefined
  vi.restoreAllMocks()
})

async function open(props: Record<string, unknown> = {}) {
  const router = await createTestRouter('/stats')
  const mounted = await mountStrict(TrendChart, { props, global: { plugins: [router] } })
  restore = mounted.restore
  await flushPromises()
  return mounted
}

type Wrapper = Awaited<ReturnType<typeof open>>['wrapper']
const charts = (w: Wrapper) => w.findAll('svg[role="img"]')
const requested = () => vi.mocked(axios.get).mock.calls.map((c) => c[0])

describe('TrendChart', () => {
  it('requests the 30 day trend and draws both charts with accessible names', async () => {
    const { wrapper, problems } = await open()

    expect(problems).toEqual([])
    expect(requested()).toEqual(['/api/stats/trend?period=30day'])
    const labels = charts(wrapper).map((c) => c.attributes('aria-label'))
    expect(labels).toHaveLength(2)
    expect(labels[0]).toContain('Cached packages per day, from 3 on 2 Jan 2026 to 4 on 4 Jan 2026')
    expect(labels[1]).toContain('Vulnerable packages per day, from 1 on 3 Jan 2026 to 2 on 4 Jan 2026')
  })

  it('offers every value as text through the chart data table', async () => {
    const { wrapper } = await open()
    const tables = wrapper.findAll('table')

    expect(tables.length).toBeGreaterThanOrEqual(2)
    expect(tables[0]!.text()).toContain('Cached packages')
    expect(tables[0]!.text()).toContain('4')
  })

  it('refetches when the period changes', async () => {
    const { wrapper } = await open()
    const ninety = wrapper.findAll('[role="radio"]').find((r) => r.text() === '90 days')!

    await ninety.trigger('click')
    await flushPromises()

    expect(requested()).toEqual(['/api/stats/trend?period=30day', '/api/stats/trend?period=90day'])
  })

  it('draws the vulnerable total first and adds a line for each severity that is switched on', async () => {
    const { wrapper } = await open()
    const vulnerable = () => charts(wrapper)[1]!.attributes('aria-label')
    expect(vulnerable()).not.toContain('lines for')

    const critical = wrapper.findAll('button[aria-pressed]').find((b) => b.text() === 'Critical')!
    expect(critical.attributes('aria-pressed')).toBe('false')
    await critical.trigger('click')
    await flushPromises()

    expect(critical.attributes('aria-pressed')).toBe('true')
    expect(vulnerable()).toContain('with lines for critical')
    expect(wrapper.text()).toContain('Critical (highest severity)')

    await critical.trigger('click')
    await flushPromises()
    expect(vulnerable()).not.toContain('lines for')
  })

  it('offers all four severities as toggle buttons', async () => {
    const { wrapper } = await open()
    const names = wrapper.findAll('button[aria-pressed]').map((b) => b.text())
    expect(names).toEqual(['Critical', 'High', 'Moderate', 'Low'])
  })

  it('says plainly when vulnerability history starts after the first day', async () => {
    const { wrapper } = await open()
    expect(wrapper.get('[data-testid="trend-vulnerability-note"]').text()).toBe('Vulnerability history starts 3 Jan 2026.')
  })

  it('shows no note when every day has vulnerability data', async () => {
    const full = { ...TREND, vulnerability_history_start: TREND.points[0]!.date }
    vi.mocked(axios.get).mockResolvedValue({ data: full })
    const { wrapper } = await open()
    expect(wrapper.find('[data-testid="trend-vulnerability-note"]').exists()).toBe(false)
  })

  it('shows an empty state instead of the vulnerable chart while no scan data exists', async () => {
    const noScans = {
      ...TREND,
      vulnerability_history_start: null,
      points: TREND.points.map((p) => ({ ...p, vulnerable_packages: null, critical: null, high: null, moderate: null, low: null })),
    }
    vi.mocked(axios.get).mockResolvedValue({ data: noScans })
    const { wrapper, problems } = await open()

    expect(problems).toEqual([])
    expect(charts(wrapper)).toHaveLength(1)
    expect(wrapper.get('[data-slot="empty-state"]').text()).toContain('Vulnerability history has not started')
    expect(wrapper.get('[data-testid="trend-vulnerability-note"]').text()).toContain('has not started in this period')
  })

  it('shows an empty state when the server holds no snapshots', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { ...TREND, vulnerability_history_start: null, points: [] } })
    const { wrapper } = await open()

    expect(wrapper.get('[data-slot="empty-state"]').text()).toContain('No history yet')
    expect(charts(wrapper)).toHaveLength(0)
  })

  it('shows a loading state until the first answer arrives', async () => {
    let resolve!: (value: unknown) => void
    vi.mocked(axios.get).mockReturnValue(new Promise((r) => (resolve = r)) as never)
    const { wrapper } = await open()

    expect(wrapper.text()).toContain('Loading package history...')
    resolve({ data: TREND })
    await flushPromises()
    expect(wrapper.text()).not.toContain('Loading package history...')
    expect(charts(wrapper)).toHaveLength(2)
  })

  it('shows the error with a retry that fetches again', async () => {
    vi.mocked(axios.get).mockRejectedValueOnce(new Error('Request failed with status code 502'))
    const { wrapper, problems } = await open()

    expect(problems).toEqual([])
    const state = wrapper.get('[data-slot="error-state"]')
    expect(state.text()).toContain('502')
    expect(charts(wrapper)).toHaveLength(0)

    await state.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-slot="error-state"]').exists()).toBe(false)
    expect(charts(wrapper)).toHaveLength(2)
    expect(requested()).toHaveLength(2)
  })

  it('rejects a body without points as an error, not an empty chart', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { stats: {} } })
    const { wrapper } = await open()
    expect(wrapper.get('[data-slot="error-state"]').text()).toContain('Unexpected response format')
  })

  it('ignores an answer that a newer request has replaced', async () => {
    const answers: Array<(v: unknown) => void> = []
    vi.mocked(axios.get).mockImplementation(() => new Promise((r) => answers.push(r)) as never)
    const { wrapper } = await open()
    await wrapper.findAll('[role="radio"]').find((r) => r.text() === '1 year')!.trigger('click')
    await flushPromises()

    answers[1]!({ data: { ...TREND, period: '1year', points: [TREND.points[2]] } })
    await flushPromises()
    answers[0]!({ data: TREND })
    await flushPromises()

    expect(wrapper.get('svg[role="img"]').attributes('aria-label')).toContain('from 4 on 4 Jan 2026 to 4 on 4 Jan 2026')
  })

  describe('compact', () => {
    it('always asks for 30 days, draws one chart and links to the full history', async () => {
      const { wrapper, problems } = await open({ compact: true })

      expect(problems).toEqual([])
      expect(requested()).toEqual(['/api/stats/trend?period=30day'])
      expect(charts(wrapper)).toHaveLength(1)
      expect(wrapper.find('[role="radiogroup"]').exists()).toBe(false)
      expect(wrapper.find('button[aria-pressed]').exists()).toBe(false)
      expect(wrapper.get('a[href="/stats"]').text()).toBe('Open the full history')
      expect(wrapper.get('[data-testid="trend-compact-vulnerable"]').text()).toBe('2 vulnerable packages on 4 Jan 2026.')
    })

    it('says so when the latest day has no vulnerability data', async () => {
      const last = { ...TREND.points[2]!, vulnerable_packages: null }
      vi.mocked(axios.get).mockResolvedValue({ data: { ...TREND, points: [TREND.points[0]!, last] } })
      const { wrapper } = await open({ compact: true })
      expect(wrapper.get('[data-testid="trend-compact-vulnerable"]').text()).toBe('Vulnerability history has not started yet.')
    })
  })
})

describe('trend helpers', () => {
  it('formats a UTC date without shifting it with the viewer zone', () => {
    expect(formatTrendDate('2026-11-23')).toBe('23 Nov')
    expect(formatTrendDate('2026-01-01', true)).toBe('1 Jan 2026')
    expect(formatTrendDate('not-a-date')).toBe('not-a-date')
  })

  it('turns unknown counts into gaps, never zeros', () => {
    const values = trendValues(TREND.points, 'vulnerable_packages')
    expect(values[0]).toBeNaN()
    expect(values.slice(1)).toEqual([1, 2])
  })
})
