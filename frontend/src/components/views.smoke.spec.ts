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

  it('BypassManagementPanel asks for the admin key in a dialog, not a native prompt', async () => {
    localStorage.clear()
    const prompt = vi.spyOn(window, 'prompt')
    const { wrapper, problems } = await smoke(BypassManagementPanel, '/admin/bypasses')
    await flushPromises()
    expect(problems).toEqual([])
    expect(prompt).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter your admin API key to manage bypasses.')

    const input = document.body.querySelector<HTMLInputElement>('input[type="password"]')
    expect(input).not.toBeNull()
    input!.value = 'secret-key'
    input!.dispatchEvent(new Event('input', { bubbles: true }))
    await flushPromises()
    document.body.querySelector<HTMLFormElement>('input[type="password"]')!.form!.requestSubmit()
    await flushPromises()

    expect(localStorage.getItem('admin_api_key')).toBe('secret-key')
    expect(vi.mocked(axios.get)).toHaveBeenCalledWith(
      expect.stringContaining('/api/admin/bypasses'),
      expect.objectContaining({ headers: { Authorization: 'Bearer secret-key' } }),
    )
    expect(wrapper.text()).toContain('CVE-2026-0002')
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
    // A page's own <header> inside <main> is not a banner landmark.
    expect(document.body.querySelectorAll('header:not(main header)').length).toBe(1)
    expect(document.body.querySelectorAll('main').length).toBe(1)
    const first = document.body.querySelector<HTMLElement>('a[href], button')
    expect(first?.getAttribute('href')).toBe('#main-content')
    const nav = wrapper.find('nav[aria-label="Sections"]')
    expect(nav.findAll('a').map((a) => a.text())).toEqual(['Dashboard', 'Packages', 'Vulnerable', 'Bypasses', 'Stats'])
    expect(document.documentElement.getAttribute('data-style')).toBe('workbench')
    // Brand column and sidebar items share one left edge: 6 spacing units each.
    expect(document.body.querySelector('header')?.className).toContain('[&>div]:px-6')
    expect(nav.classes()).toContain('p-3')
  })

  it('PackageList still fetches through the store on mount', async () => {
    await smoke(PackageList, '/packages')
    expect(usePackageStore().packages.length).toBe(PACKAGES.length)
  })
})

describe('PyPI rows show the release version, not the file name', () => {
  const FILE = 'six-1.17.0-py2.py3-none-any.whl'
  const SIX = {
    id: 'pypi-six',
    registry: 'pypi',
    name: 'six',
    version: FILE,
    release_version: '1.17.0',
    size: 1,
    cached_at: '2026-02-01T10:00:00Z',
    last_accessed: '2026-02-01T10:00:00Z',
    download_count: 1,
    vulnerabilities: {
      scanned: true,
      status: 'vulnerable',
      counts: { critical: 1, high: 0, moderate: 0, low: 0 },
      total: 1,
      scannedAt: '2026-02-01T10:05:00Z',
      isBlocked: false,
    },
  }

  beforeEach(() => {
    vi.mocked(axios.get).mockImplementation(async (url: string) => {
      if (url.endsWith('/vulnerabilities')) {
        return { data: { ...VULNERABILITY_REPORT, package: { release_version: '1.17.0' } } } as never
      }
      if (url.startsWith('/api/packages')) return { data: { packages: [SIX] } } as never
      return respond(url) as never
    })
  })

  it('Dashboard recent packages', async () => {
    const { wrapper } = await smoke(Dashboard, '/')
    await flushPromises()
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })

  it('Dashboard activity feed', async () => {
    const router = await createTestRouter('/')
    const pinia = createPinia()
    setActivePinia(pinia)
    const rt = useRealtimeStore()
    vi.spyOn(rt, 'connect').mockImplementation(() => {})
    rt.events = [{ type: 'package_cached', payload: { name: 'six', version: FILE, release_version: '1.17.0', registry: 'pypi' }, timestamp: Date.now() }]
    const { wrapper, restore: r } = await mountStrict(Dashboard, { global: { plugins: [pinia, router] } })
    restore = r
    await flushPromises()
    const feed = wrapper.find('[data-testid="ws-event-feed"]').text()
    expect(feed).toContain('six@1.17.0')
    expect(feed).not.toContain('whl')
  })

  it('VulnerablePackages version column', async () => {
    const { wrapper } = await smoke(VulnerablePackages, '/vulnerable-packages')
    await flushPromises()
    await wrapper.find('button[aria-expanded]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })

  it('PackageDetails header badge', async () => {
    const { wrapper } = await smoke(PackageDetails, `/package/pypi/six/${FILE}`)
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push(`/package/pypi/six/${FILE}`)
    await flushPromises()
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })

  it('PackageDetails falls back to the route version without a release version', async () => {
    vi.mocked(axios.get).mockImplementation(async (url: string) => respond(url) as never)
    const { wrapper } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0')
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push('/package/npm/left-pad/1.3.0')
    await flushPromises()
    expect(wrapper.text()).toContain('v1.3.0')
  })

  it('bypass form tells PyPI users to use the release version', async () => {
    const { wrapper } = await smoke(BypassManagementPanel, '/admin/bypasses')
    await wrapper.findAll('button').find((b) => b.text() === 'Create bypass')!.trigger('click')
    await flushPromises()
    const pkg = Array.from(document.body.querySelectorAll<HTMLElement>('button, [role="radio"]')).find((e) => e.textContent?.trim() === 'Package bypass')
    pkg!.click()
    await flushPromises()
    expect(document.body.textContent).toContain('pypi/six@1.17.0')
  })
})
