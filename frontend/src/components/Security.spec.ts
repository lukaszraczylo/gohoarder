import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import VulnerablePackages from './VulnerablePackages.vue'
import type { Package, VulnerabilityCounts } from '@/stores/packages'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

function vulnerable(name: string, counts: Partial<VulnerabilityCounts>): Package {
  const full = { critical: 0, high: 0, moderate: 0, low: 0, ...counts }
  return {
    id: name,
    registry: 'npm',
    name,
    version: '1.0.0',
    size: 1024,
    cached_at: '2026-01-03T10:00:00Z',
    last_accessed: '2026-01-03T10:00:00Z',
    download_count: 1,
    vulnerabilities: {
      scanned: true,
      status: 'vulnerable',
      counts: full,
      total: full.critical + full.high + full.moderate + full.low,
      scannedAt: '2026-01-03T10:05:00Z',
      isBlocked: false,
    },
  }
}

const ALL_SEVERITIES = 'critical,high,moderate,low'
const FIXTURE: Package[] = [
  vulnerable('alpha-critical', { critical: 1 }),
  vulnerable('bravo-high', { high: 2 }),
  vulnerable('charlie-moderate', { moderate: 1 }),
  vulnerable('delta-mixed', { critical: 1, moderate: 3 }),
]
const NAMES = FIXTURE.map((p) => p.name)

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  vi.mocked(axios.get).mockResolvedValue({ data: { packages: FIXTURE } })
})

afterEach(() => {
  restore?.()
  restore = undefined
  vi.restoreAllMocks()
})

async function open(path = '/vulnerable-packages') {
  const router = await createTestRouter(path)
  const pinia = createPinia()
  setActivePinia(pinia)
  const mounted = await mountStrict(VulnerablePackages, { global: { plugins: [pinia, router] } })
  restore = mounted.restore
  await flushPromises()
  return { ...mounted, router }
}

type Wrapper = Awaited<ReturnType<typeof open>>['wrapper']

const tile = (wrapper: Wrapper, severity: string) => wrapper.get(`button[data-severity="${severity}"]`)
const shown = (wrapper: Wrapper) => NAMES.filter((name) => wrapper.text().includes(name))
const pressed = (wrapper: Wrapper) =>
  wrapper.findAll('button[data-severity]').map((b) => b.attributes('aria-pressed'))
const clearButtons = (wrapper: Wrapper) => wrapper.findAll('button').filter((b) => b.text() === 'Clear filters')

describe('VulnerablePackages severity filter', () => {
  it('starts unfiltered: every vulnerable package, no tile pressed, no clear control', async () => {
    const { wrapper, problems, router } = await open()

    expect(problems).toEqual([])
    expect(shown(wrapper)).toEqual(NAMES)
    expect(pressed(wrapper)).toEqual(['false', 'false', 'false', 'false'])
    expect(wrapper.text()).not.toContain('Filter on')
    expect(clearButtons(wrapper)).toHaveLength(0)
    expect(router.currentRoute.value.query.severity).toBeUndefined()
  })

  it('asks the server for vulnerable packages only', async () => {
    await open()
    expect(axios.get).toHaveBeenCalledWith(`/api/packages?severity=${ALL_SEVERITIES}`)
  })

  it('renders the four tiles as keyboard-operable buttons in severity order', async () => {
    const { wrapper } = await open()
    const tiles = wrapper.findAll('button[data-severity]')

    expect(tiles.map((t) => t.attributes('data-severity'))).toEqual(['critical', 'high', 'moderate', 'low'])
    for (const t of tiles) {
      expect(t.element.tagName).toBe('BUTTON')
      expect(t.attributes('type')).toBe('button')
      expect(t.attributes('tabindex')).not.toBe('-1')
      expect(t.attributes('aria-pressed')).toBeDefined()
    }
  })

  it('one click filters to that severity and shows the state in text, not colour alone', async () => {
    const { wrapper, router } = await open()

    await tile(wrapper, 'high').trigger('click')
    await flushPromises()

    expect(shown(wrapper)).toEqual(['bravo-high'])
    expect(pressed(wrapper)).toEqual(['false', 'true', 'false', 'false'])
    expect(tile(wrapper, 'high').text()).toContain('Filter on')
    expect(tile(wrapper, 'critical').text()).not.toContain('Filter on')
    expect(wrapper.get('[data-testid="filter-bar"]').text()).toContain('Showing packages with high vulnerabilities.')
    expect(clearButtons(wrapper)).toHaveLength(1)
    expect(router.currentRoute.value.query.severity).toBe('high')
  })

  it('keeps the tile counts of the whole list while a filter is on', async () => {
    const { wrapper } = await open()
    const before = tile(wrapper, 'critical').text()

    await tile(wrapper, 'high').trigger('click')
    await flushPromises()

    expect(tile(wrapper, 'critical').text()).toBe(before)
    expect(tile(wrapper, 'critical').text()).toContain('2 packages')
  })

  it('selects several severities with OR semantics', async () => {
    const { wrapper, router } = await open()

    await tile(wrapper, 'critical').trigger('click')
    await flushPromises()
    expect(shown(wrapper)).toEqual(['alpha-critical', 'delta-mixed'])

    await tile(wrapper, 'high').trigger('click')
    await flushPromises()
    expect(shown(wrapper)).toEqual(['alpha-critical', 'bravo-high', 'delta-mixed'])
    expect(pressed(wrapper)).toEqual(['true', 'true', 'false', 'false'])
    expect(router.currentRoute.value.query.severity).toBe('critical,high')
    expect(wrapper.get('[data-testid="filter-bar"]').text()).toContain('critical or high')
  })

  it('a second click toggles the filter off and removes the query', async () => {
    const { wrapper, router } = await open()

    await tile(wrapper, 'moderate').trigger('click')
    await flushPromises()
    expect(shown(wrapper)).toEqual(['charlie-moderate', 'delta-mixed'])

    await tile(wrapper, 'moderate').trigger('click')
    await flushPromises()
    expect(shown(wrapper)).toEqual(NAMES)
    expect(pressed(wrapper)).toEqual(['false', 'false', 'false', 'false'])
    expect(clearButtons(wrapper)).toHaveLength(0)
    expect(router.currentRoute.value.query.severity).toBeUndefined()
  })

  it('Clear filters resets every selected severity at once', async () => {
    const { wrapper, router } = await open()
    await tile(wrapper, 'critical').trigger('click')
    await tile(wrapper, 'high').trigger('click')
    await flushPromises()

    await clearButtons(wrapper)[0]!.trigger('click')
    await flushPromises()

    expect(shown(wrapper)).toEqual(NAMES)
    expect(pressed(wrapper)).toEqual(['false', 'false', 'false', 'false'])
    expect(router.currentRoute.value.query.severity).toBeUndefined()
  })

  it('restores the filter from the URL, as after a reload or a shared link', async () => {
    const { wrapper } = await open('/vulnerable-packages?severity=high,critical')

    expect(shown(wrapper)).toEqual(['alpha-critical', 'bravo-high', 'delta-mixed'])
    expect(pressed(wrapper)).toEqual(['true', 'true', 'false', 'false'])
    expect(clearButtons(wrapper)).toHaveLength(1)
  })

  it('ignores unknown severities in the URL and keeps the other query parameters', async () => {
    const { wrapper, router } = await open('/vulnerable-packages?severity=bogus&ref=mail')
    expect(shown(wrapper)).toEqual(NAMES)
    expect(clearButtons(wrapper)).toHaveLength(0)

    await tile(wrapper, 'low').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query).toEqual({ ref: 'mail', severity: 'low' })
  })

  it('shows a library empty state with a clear control when no package matches', async () => {
    const { wrapper, router } = await open('/vulnerable-packages?severity=low')

    const empty = wrapper.get('[data-slot="empty-state"]')
    expect(empty.text()).toContain('No packages match the filter')
    expect(shown(wrapper)).toEqual([])
    // The tiles stay so the filter can be changed without leaving the page.
    expect(pressed(wrapper)).toEqual(['false', 'false', 'false', 'true'])

    await empty.findAll('button').find((b) => b.text() === 'Clear filters')!.trigger('click')
    await flushPromises()

    expect(shown(wrapper)).toEqual(NAMES)
    expect(wrapper.find('[data-slot="empty-state"]').exists()).toBe(false)
    expect(router.currentRoute.value.query.severity).toBeUndefined()
  })

  it('keeps the success state when nothing is vulnerable, filter or not', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { packages: [] } })
    const { wrapper } = await open('/vulnerable-packages?severity=critical')

    expect(wrapper.text()).toContain('No vulnerable packages')
    expect(wrapper.find('button[data-severity]').exists()).toBe(false)
  })

  it('still narrows to blocked packages on the blocked route', async () => {
    const blocked = vulnerable('echo-blocked', { critical: 1 })
    blocked.vulnerabilities!.isBlocked = true
    vi.mocked(axios.get).mockResolvedValue({ data: { packages: [...FIXTURE, blocked] } })
    const { wrapper } = await open('/blocked-packages?severity=critical')

    expect(wrapper.text()).toContain('echo-blocked')
    expect(wrapper.text()).not.toContain('alpha-critical')
  })
})
