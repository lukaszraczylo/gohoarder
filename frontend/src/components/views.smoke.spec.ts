import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import App from '@/App.vue'
import Dashboard from './Dashboard.vue'
import PackageList from './PackageList.vue'
import PackageDetails from './PackageDetails.vue'
import VulnerablePackages from './VulnerablePackages.vue'
import BypassManagementPanel from './BypassManagementPanel.vue'
import Stats from './Stats.vue'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import { __resetRealtimeSingleton, useRealtimeStore } from '@/stores/realtime'
import { usePackageStore } from '@/stores/packages'
import { BYPASSES, PACKAGES, REGISTRIES, STATS, TIMESERIES, VULNERABILITY_REPORT } from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

const API_KEY_STORAGE = 'admin_api_key'

function respond(url: string) {
  if (url.startsWith('/api/stats/timeseries')) return { data: TIMESERIES }
  if (url.startsWith('/api/stats')) return { data: { stats: STATS, registries: REGISTRIES } }
  if (url.endsWith('/vulnerabilities')) return { data: VULNERABILITY_REPORT }
  if (url.startsWith('/api/admin/bypasses')) return { data: { bypasses: BYPASSES } }
  if (url.startsWith('/api/packages')) return { data: { packages: PACKAGES } }
  throw new Error(`unexpected request: ${url}`)
}

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  __resetRealtimeSingleton()
  vi.mocked(axios.get).mockImplementation(async (url: string) => respond(url) as never)
  localStorage.setItem(API_KEY_STORAGE, 'test-key')
})

afterEach(() => {
  restore?.()
  restore = undefined
  localStorage.clear()
  vi.restoreAllMocks()
})

async function smoke(component: Parameters<typeof mountStrict>[0], path: string, props: Record<string, unknown> = {}) {
  const router = await createTestRouter(path)
  const pinia = createPinia()
  setActivePinia(pinia)
  vi.spyOn(useRealtimeStore(), 'connect').mockImplementation(() => {})
  const mounted = await mountStrict(component, { props, global: { plugins: [pinia, router] } })
  restore = mounted.restore
  return mounted
}

describe('view smoke tests (strict mode throw, fixture data)', () => {
  it('Dashboard renders the tiles, chart, feed and recent packages', async () => {
    const router = await createTestRouter('/')
    const pinia = createPinia()
    setActivePinia(pinia)
    const rt = useRealtimeStore()
    vi.spyOn(rt, 'connect').mockImplementation(() => {})
    rt.events = [{ type: 'package_cached', payload: { name: 'left-pad', version: '1.3.0', registry: 'npm' }, timestamp: Date.now() }]
    const { wrapper, problems, restore: r } = await mountStrict(Dashboard, { global: { plugins: [pinia, router] } })
    restore = r
    await flushPromises()

    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Dashboard')
    expect(wrapper.text()).toContain('Total packages')
    expect(wrapper.find('[data-testid="ws-event-feed"]').text()).toContain('left-pad')
    expect(wrapper.find('[role="img"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Recent packages')
    expect(wrapper.text()).toContain('github.com/example/module')
  })

  it('PackageList groups fixture packages and shows severity words', async () => {
    const { wrapper, problems } = await smoke(PackageList, '/packages')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Packages')
    expect(wrapper.text()).toContain('left-pad')
    expect(wrapper.text()).toContain('2 versions')
    expect(wrapper.text()).toContain('requests')

    const trigger = wrapper.findAll('button').find((b) => b.text().includes('left-pad'))
    await trigger!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Critical: 1')
    expect(wrapper.text()).toContain('Blocked')
  })

  it('PackageDetails renders the report, severity table and expanded row', async () => {
    const { wrapper, problems } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0')
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push('/package/npm/left-pad/1.3.0')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('left-pad')
    expect(wrapper.text()).toContain('Security scan summary')
    expect(wrapper.text()).toContain('trivy')

    // Most severe first: CRITICAL, HIGH, then LOW.
    const ids = wrapper.findAll('tbody td.font-mono').map((td) => td.text().replace('CVE ID', ''))
    expect(ids.slice(0, 3)).toEqual(['CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0001'])

    await wrapper.find('button[aria-label^="Show details for CVE-2026-0002"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Bypass active')
    expect(wrapper.text()).toContain('No fix available')
  })

  it('VulnerablePackages lists the vulnerable fixture packages', async () => {
    const { wrapper, problems } = await smoke(VulnerablePackages, '/vulnerable-packages')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Vulnerable packages')
    expect(wrapper.text()).toContain('left-pad')
    expect(wrapper.text()).not.toContain('requests')
    expect(wrapper.text()).toContain('Critical')
  })

  it('VulnerablePackages on the blocked route keeps only blocked packages', async () => {
    const { wrapper, problems } = await smoke(VulnerablePackages, '/blocked-packages')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Blocked packages')
    expect(wrapper.text()).toContain('1 vulnerable version')
  })

  it('BypassManagementPanel lists bypasses and opens the create dialog', async () => {
    const { wrapper, problems } = await smoke(BypassManagementPanel, '/admin/bypasses')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('CVE bypass management')
    expect(wrapper.text()).toContain('CVE-2026-0002')
    expect(wrapper.text()).toContain('Expired')

    const create = wrapper.findAll('button').find((b) => b.text() === 'Create bypass')
    await create!.trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('Create a temporary bypass for a CVE or package.')
    expect(document.body.querySelector('textarea')).not.toBeNull()
  })

  it('Stats renders totals, the storage tile and the registry table', async () => {
    const { wrapper, problems } = await smoke(Stats, '/stats')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Statistics')
    expect(wrapper.text()).toContain('5 GB / 10 GB')
    expect(wrapper.text()).toContain('50.0% used')
    expect(wrapper.text()).toContain('Go modules')
    expect(wrapper.find('[role="progressbar"]').exists()).toBe(true)
  })

  it('VulnerabilityBadge prints the severity word for every tone', async () => {
    const { wrapper, problems } = await smoke(VulnerabilityBadge, '/', {
      scanned: true,
      status: 'vulnerable',
      counts: { critical: 1, high: 2, moderate: 3, low: 4 },
      total: 10,
      isBlocked: true,
    })
    expect(problems).toEqual([])
    const text = wrapper.text()
    for (const word of ['Blocked', 'Critical: 1', 'High: 2', 'Moderate: 3', 'Low: 4']) expect(text).toContain(word)
    const tones = wrapper.findAll('[data-slot="status-badge"]').map((b) => b.attributes('data-tone'))
    expect(tones).toEqual(['danger', 'danger', 'warning', 'info', 'neutral'])
  })

  it('App renders one banner, one main, a skip link first and the five sections', async () => {
    const { wrapper, problems } = await smoke(App, '/')
    expect(problems).toEqual([])
    expect(document.body.querySelectorAll('header').length).toBe(1)
    expect(document.body.querySelectorAll('main').length).toBe(1)
    const first = document.body.querySelector<HTMLElement>('a[href], button')
    expect(first?.getAttribute('href')).toBe('#main-content')
    const nav = wrapper.find('nav[aria-label="Sections"]')
    expect(nav.findAll('a').map((a) => a.text())).toEqual(['Dashboard', 'Packages', 'Vulnerable', 'Bypasses', 'Stats'])
    expect(document.documentElement.getAttribute('data-style')).toBe('workbench')
  })

  it('PackageList still fetches through the store on mount', async () => {
    await smoke(PackageList, '/packages')
    expect(usePackageStore().packages.length).toBe(PACKAGES.length)
  })
})
