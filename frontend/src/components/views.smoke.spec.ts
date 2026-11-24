import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import App from '@/App.vue'
import Overview from './Overview.vue'
import PackageList from './PackageList.vue'
import PackageDetails from './PackageDetails.vue'
import Security from './Security.vue'
import BypassManagementPanel from './BypassManagementPanel.vue'
import Insights from './Insights.vue'
import System from './System.vue'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import { __resetSystem } from '@/lib/system'
import { serveRows } from '@/test/rowsServer'
import { __resetRealtimeSingleton, useRealtimeStore } from '@/stores/realtime'
import {
  BYPASSES,
  PACKAGES,
  PACKAGE_ANALYTICS,
  REGISTRIES,
  STATS,
  SYSTEM,
  TIMESERIES,
  TOP_PACKAGES,
  TREND,
  VULNERABILITY_REPORT,
} from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

const API_KEY_STORAGE = 'admin_api_key'

function respond(url: string) {
  if (url.startsWith('/api/system')) return { data: SYSTEM }
  if (url.startsWith('/api/analytics/package/')) return { data: PACKAGE_ANALYTICS }
  if (url.startsWith('/api/analytics/')) return { data: TOP_PACKAGES }
  if (url.startsWith('/api/stats/timeseries')) return { data: TIMESERIES }
  if (url.startsWith('/api/stats/trend')) return { data: TREND }
  if (url.startsWith('/api/stats')) return { data: { stats: STATS, registries: REGISTRIES } }
  if (url.endsWith('/vulnerabilities')) return { data: VULNERABILITY_REPORT }
  if (url.startsWith('/api/admin/bypasses')) return { data: { bypasses: BYPASSES } }
  if (url.includes('layout=rows')) return { data: serveRows(url, PACKAGES) }
  const single = /^\/api\/packages\/([^/]+)\/(.+)\/([^/?]+)$/.exec(url)
  if (single) {
    const row = PACKAGES.find((p) => p.registry === single[1] && p.name === single[2] && p.version === single[3])
    if (!row) throw Object.assign(new Error('not found'), { response: { status: 404 } })
    return { data: row }
  }
  if (url.startsWith('/api/packages')) return { data: { packages: PACKAGES } }
  throw new Error(`unexpected request: ${url}`)
}

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  __resetRealtimeSingleton()
  __resetSystem()
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
  it('Overview renders the verdict strip, policy, capacity, trend, rankings, inspectors and feed', async () => {
    const router = await createTestRouter('/')
    const pinia = createPinia()
    setActivePinia(pinia)
    const rt = useRealtimeStore()
    vi.spyOn(rt, 'connect').mockImplementation(() => {})
    rt.events = [{ type: 'package_cached', payload: { name: 'left-pad', version: '1.3.0', registry: 'npm' }, timestamp: Date.now() }]
    const { wrapper, problems, restore: r } = await mountStrict(Overview, { global: { plugins: [pinia, router] } })
    restore = r
    await flushPromises()

    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Overview')

    const strip = wrapper.find('[data-testid="verdict-strip"]').text()
    for (const word of ['Cleared', 'Held', 'Bypassed', 'Awaiting scan']) expect(strip).toContain(word)
    // 3 scanned, 1 held, 1 bypassed: 1 cleared; 4 cached, 3 scanned: 1 awaiting.
    expect(wrapper.find('[data-verdict="cleared"]').text()).toContain('1')
    expect(wrapper.find('[data-verdict="held"]').attributes('href')).toBe('/security?tab=held')

    expect(wrapper.find('[data-testid="policy-line"]').text()).toContain('Blocks any CRITICAL.')
    expect(wrapper.find('[data-testid="policy-line"]').text()).toContain('Fail-closed')
    expect(wrapper.find('[data-testid="cache-capacity"]').text()).toContain('5 GB of 10 GB')
    expect(wrapper.find('[data-testid="download-trend"] [role="img"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="top-packages"]').text()).toContain('npm · left-pad')
    expect(wrapper.find('[data-testid="scanner-health"]').text()).toContain('grype')
    expect(wrapper.find('[data-testid="scanner-health"]').text()).toContain('Unavailable')
    expect(wrapper.find('[data-testid="ws-event-feed"]').text()).toContain('left-pad')
  })

  it('PackageList shows a verdict for each row and filters by it', async () => {
    const { wrapper, problems } = await smoke(PackageList, '/packages')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Packages')
    expect(wrapper.find('[data-testid="package-count"]').text()).toContain('1–4 of 4')
    const text = wrapper.text()
    for (const word of ['left-pad', 'requests', 'github.com/example/module', 'Held', 'Cleared', 'Bypassed', 'Awaiting scan']) {
      expect(text).toContain(word)
    }
  })

  it('PackageList seeds the verdict filter from the URL', async () => {
    const { wrapper, problems } = await smoke(PackageList, '/packages?verdict=held')
    expect(problems).toEqual([])
    expect(wrapper.find('[data-testid="package-count"]').text()).toContain('1–1 of 1')
    expect(wrapper.text()).toContain('left-pad')
    expect(wrapper.text()).not.toContain('requests')
  })

  it('PackageList opens a quick view with a link to the full page', async () => {
    const { wrapper, problems } = await smoke(PackageList, '/packages?verdict=held')
    await wrapper.find('tbody tr').trigger('click')
    await flushPromises()
    expect(problems).toEqual([])
    const sheet = document.body.querySelector('[data-slot="sheet-content"]')
    expect(sheet?.textContent).toContain('1 critical finding. Policy holds any critical finding.')
    expect(sheet?.querySelector('a[href^="/package/npm/left-pad/1.3.0"]')).not.toBeNull()
  })

  it('PackageDetails explains the verdict and lists findings most severe first', async () => {
    const { wrapper, problems } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0')
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push('/package/npm/left-pad/1.3.0')
    await flushPromises()
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('left-pad')

    const banner = wrapper.find('[data-testid="verdict-banner"]').text()
    expect(banner).toContain('Held: CVE-2026-0003 is HIGH')
    expect(banner).toContain('1 critical finding. Policy holds any critical finding.')

    const meta = wrapper.find('[data-testid="package-meta"]').text()
    expect(meta).toContain('2 KB')
    expect(meta).toContain('https://registry.npmjs.org')
    expect(meta).toContain('Removed after 30 days without a request')

    const ids = wrapper.findAll('tbody td.font-mono').map((td) => td.text().replace('Advisory', ''))
    expect(ids.slice(0, 3)).toEqual(['CVE-2026-0002', 'CVE-2026-0003', 'CVE-2026-0001'])

    await wrapper.find('button[aria-label^="Show details for CVE-2026-0002"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Bypass active')
    expect(wrapper.text()).toContain('No fix available')
  })

  it('PackageDetails reads its own row, not the grouped package list', async () => {
    const { wrapper, problems } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0')
    expect(problems).toEqual([])
    const urls = vi.mocked(axios.get).mock.calls.map((c) => String(c[0]))
    expect(urls).toContain('/api/packages/npm/left-pad/1.3.0')
    expect(urls.filter((u) => u.startsWith('/api/packages?'))).toEqual([])
    expect(wrapper.text()).toContain('2 KB')
  })

  it('PackageDetails Inspectors tab shows one row per scanner', async () => {
    const { wrapper, problems } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0?tab=inspectors')
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push('/package/npm/left-pad/1.3.0?tab=inspectors')
    await flushPromises()
    expect(problems).toEqual([])
    const panel = wrapper.find('[role="tabpanel"]:not([hidden])')
    const text = panel.text()
    for (const word of ['trivy', 'osv', 'grype', 'govulncheck', 'v0.58.1', 'No result', 'Off']) expect(text).toContain(word)
  })

  it('PackageDetails Downloads tab reads the per-package analytics', async () => {
    const { wrapper, problems } = await smoke(PackageDetails, '/package/npm/left-pad/1.3.0?tab=downloads')
    const router = (wrapper.vm as unknown as { $router: Awaited<ReturnType<typeof createTestRouter>> }).$router
    await router.push('/package/npm/left-pad/1.3.0?tab=downloads')
    await flushPromises()
    expect(problems).toEqual([])
    expect(vi.mocked(axios.get)).toHaveBeenCalledWith('/api/analytics/package/npm/left-pad')
    expect(wrapper.text()).toContain('80 KB')
  })

  it('Security splits packages by what the policy did', async () => {
    const { wrapper, problems } = await smoke(Security, '/security')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Security')
    const triggers = wrapper.findAll('[role="tab"]').map((t) => t.text())
    expect(triggers).toEqual(['Held (1)', 'Vulnerable but allowed (1)', 'Bypassed (1)'])
    expect(wrapper.text()).toContain('left-pad')
    expect(wrapper.text()).toContain('1 critical finding. Policy holds any critical finding.')
  })

  it('Security opens on the tab named in the URL', async () => {
    const { wrapper, problems } = await smoke(Security, '/security?tab=bypassed')
    expect(problems).toEqual([])
    const selected = wrapper.findAll('[role="tab"]').find((t) => t.attributes('aria-selected') === 'true')
    expect(selected?.text()).toBe('Bypassed (1)')
    expect(wrapper.text()).toContain('a.khan')
  })

  it('BypassManagementPanel lists bypasses and opens the create dialog', async () => {
    const { wrapper, problems } = await smoke(BypassManagementPanel, '/admin/bypasses')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Bypasses')
    expect(wrapper.text()).toContain('CVE-2026-0002')
    expect(wrapper.text()).toContain('Expired')

    const create = wrapper.findAll('button').find((b) => b.text() === 'Create bypass')
    await create!.trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('Create a temporary bypass for a CVE or package.')
    expect(document.body.querySelector('textarea')).not.toBeNull()
  })

  it('BypassManagementPanel opens the form prefilled from a package page link', async () => {
    const { problems } = await smoke(BypassManagementPanel, '/admin/bypasses?type=package&target=npm/left-pad@1.3.0')
    await flushPromises()
    expect(problems).toEqual([])
    const input = Array.from(document.body.querySelectorAll<HTMLInputElement>('input')).find((i) => i.value === 'npm/left-pad@1.3.0')
    expect(input).toBeDefined()
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

  it('Insights renders the registry breakdown, scan coverage and daily downloads', async () => {
    const { wrapper, problems } = await smoke(Insights, '/stats')
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('Insights')
    const breakdown = wrapper.find('[data-testid="registry-breakdown"]').text()
    for (const word of ['npm', 'pypi', 'go', '2 GB']) expect(breakdown).toContain(word)
    expect(wrapper.find('[data-testid="scan-coverage"]').text()).toContain('3 of 4')
    expect(wrapper.find('[data-testid="daily-downloads"] [role="img"]').exists()).toBe(true)
  })

  it('System shows the policy, scanners, rescans, cache, pre-warming and build version', async () => {
    const { wrapper, problems } = await smoke(System, '/admin/system')
    await flushPromises()
    expect(problems).toEqual([])
    expect(wrapper.find('h1').text()).toBe('System')
    expect(wrapper.find('[data-testid="build-version"]').text()).toBe('v1.8.0')
    expect(wrapper.find('[data-testid="policy-list"]').text()).toContain('Blocks any CRITICAL.')
    expect(wrapper.find('[data-testid="policy-list"]').text()).toContain('Fail-closed')
    expect(wrapper.find('[data-testid="rescan-list"]').text()).toContain('1 day')
    expect(wrapper.find('[data-testid="cache-list"]').text()).toContain('10 GB')
    expect(wrapper.text()).toContain('v0.58.1')
    expect(wrapper.find('[data-testid="prewarming"] button').text()).toContain('Run a cycle now')
  })

  it('System starts a pre-warming cycle with the admin key', async () => {
    vi.mocked(axios.post).mockResolvedValue({ data: {} })
    const { wrapper } = await smoke(System, '/admin/system')
    await flushPromises()
    await wrapper.find('[data-testid="prewarming"] button').trigger('click')
    await flushPromises()
    expect(vi.mocked(axios.post)).toHaveBeenCalledWith(
      '/api/admin/prewarming/trigger',
      null,
      expect.objectContaining({ headers: { Authorization: 'Bearer test-key' } }),
    )
  })

  it('System asks for the key before it triggers anything', async () => {
    localStorage.clear()
    const { wrapper } = await smoke(System, '/admin/system')
    await flushPromises()
    await wrapper.find('[data-testid="prewarming"] button').trigger('click')
    await flushPromises()
    expect(vi.mocked(axios.post)).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter your admin API key to start a pre-warming cycle.')
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

  it('App renders one banner, one main, a skip link first and the sections', async () => {
    const { wrapper, problems } = await smoke(App, '/')
    expect(problems).toEqual([])
    // A page's own <header> inside <main> is not a banner landmark.
    expect(document.body.querySelectorAll('header:not(main header)').length).toBe(1)
    expect(document.body.querySelectorAll('main').length).toBe(1)
    const first = document.body.querySelector<HTMLElement>('a[href], button')
    expect(first?.getAttribute('href')).toBe('#main-content')
    const nav = wrapper.find('nav[aria-label="Sections"]')
    expect(nav.findAll('a').map((a) => a.text())).toEqual(['Overview', 'Packages', 'Security', 'Insights', 'Bypasses', 'System'])
    expect(document.documentElement.getAttribute('data-style')).toBe('workbench')
    // Brand column and sidebar items share one left edge: 6 spacing units each.
    expect(document.body.querySelector('header')?.className).toContain('[&>div]:px-6')
    expect(nav.classes()).toContain('p-3')
  })

  it('PackageList asks for one page of rows on mount', async () => {
    await smoke(PackageList, '/packages')
    await flushPromises()
    expect(vi.mocked(axios.get)).toHaveBeenCalledWith(expect.stringContaining('/api/packages?layout=rows'))
  })
})

describe('old URLs land on the new pages', () => {
  it.each([
    ['/vulnerable-packages', '/security', 'allowed'],
    ['/blocked-packages', '/security', 'held'],
  ])('%s redirects to %s with tab %s', async (from, path, tab) => {
    const router = await createTestRouter(from)
    expect(router.currentRoute.value.path).toBe(path)
    expect(router.currentRoute.value.query.tab).toBe(tab)
  })

  it('keeps the severity filter of the old link', async () => {
    const router = await createTestRouter('/vulnerable-packages?severity=critical')
    expect(router.currentRoute.value.query).toEqual({ severity: 'critical', tab: 'allowed' })
  })

  it('/packages/npm still seeds the registry filter', async () => {
    const { wrapper } = await smoke(PackageList, '/packages/npm', { registry: 'npm' })
    expect(wrapper.find('[data-testid="package-count"]').text()).toContain('1–2 of 2')
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
      if (url.includes('layout=rows')) return { data: serveRows(url, [SIX as never]) } as never
      if (url === `/api/packages/pypi/six/${FILE}`) return { data: SIX } as never
      if (url.startsWith('/api/packages')) return { data: { packages: [SIX] } } as never
      return respond(url) as never
    })
  })

  it('PackageList version column', async () => {
    const { wrapper } = await smoke(PackageList, '/packages')
    await flushPromises()
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })

  it('Overview activity feed', async () => {
    const router = await createTestRouter('/')
    const pinia = createPinia()
    setActivePinia(pinia)
    const rt = useRealtimeStore()
    vi.spyOn(rt, 'connect').mockImplementation(() => {})
    rt.events = [{ type: 'package_cached', payload: { name: 'six', version: FILE, release_version: '1.17.0', registry: 'pypi' }, timestamp: Date.now() }]
    const { wrapper, restore: r } = await mountStrict(Overview, { global: { plugins: [pinia, router] } })
    restore = r
    await flushPromises()
    const feed = wrapper.find('[data-testid="ws-event-feed"]').text()
    expect(feed).toContain('six@1.17.0')
    expect(feed).not.toContain('whl')
  })

  it('Security version column', async () => {
    const { wrapper } = await smoke(Security, '/security?tab=allowed')
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
