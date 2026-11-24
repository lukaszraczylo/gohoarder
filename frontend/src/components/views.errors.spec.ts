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
import { __resetSystem } from '@/lib/system'
import { __resetRealtimeSingleton, useRealtimeStore } from '@/stores/realtime'
import { mountStrict } from '@/test/mountStrict'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

const FAILURE = Object.assign(new Error('Request failed with status code 502'), {
  response: { status: 502, data: {} },
})

// What each view must not say when the request failed: an empty state would tell the operator there is nothing to see.
const EMPTY_TEXT: Record<string, string> = {
  Overview: 'Quiet at the desk',
  PackageList: 'No packages cached yet',
  Security: 'Nothing is held',
  Insights: 'No registry data yet',
  BypassManagementPanel: 'No bypasses found',
}

const CASES: Array<[string, Parameters<typeof mountStrict>[0], string]> = [
  ['Overview', Overview, '/'],
  ['PackageList', PackageList, '/packages'],
  ['PackageDetails', PackageDetails, '/package/npm/left-pad/1.3.0'],
  ['Security', Security, '/security'],
  ['BypassManagementPanel', BypassManagementPanel, '/admin/bypasses'],
  ['Insights', Insights, '/stats'],
  ['System', System, '/admin/system'],
]

let restore: (() => void) | undefined

beforeEach(() => {
  setActivePinia(createPinia())
  __resetRealtimeSingleton()
  __resetSystem()
  vi.mocked(axios.get).mockRejectedValue(FAILURE)
  localStorage.setItem('admin_api_key', 'test-key')
})

afterEach(() => {
  restore?.()
  restore = undefined
  localStorage.clear()
  vi.restoreAllMocks()
})

describe('an API failure renders ErrorState, never an empty state', () => {
  it.each(CASES)('%s', async (name, component, path) => {
    const router = await createTestRouter(path)
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.spyOn(useRealtimeStore(), 'connect').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const mounted = await mountStrict(component, { global: { plugins: [pinia, router] } })
    restore = mounted.restore
    await flushPromises()

    const state = mounted.wrapper.find('[data-slot="error-state"]')
    expect(state.exists()).toBe(true)
    expect(state.text()).toContain('502')
    expect(state.find('button').text()).toMatch(/try again/i)
    expect(mounted.wrapper.find('[data-slot="empty-state"]').exists()).toBe(false)
    if (EMPTY_TEXT[name]) expect(mounted.wrapper.text()).not.toContain(EMPTY_TEXT[name])
  })

  it('retry fetches again and clears the error when the backend is back', async () => {
    const router = await createTestRouter('/security')
    const pinia = createPinia()
    setActivePinia(pinia)
    const mounted = await mountStrict(Security, { global: { plugins: [pinia, router] } })
    restore = mounted.restore
    vi.mocked(axios.get).mockResolvedValue({ data: { packages: [] } })
    await mounted.wrapper.find('[data-slot="error-state"] button').trigger('click')
    await flushPromises()
    expect(mounted.wrapper.find('[data-slot="error-state"]').exists()).toBe(false)
    expect(mounted.wrapper.text()).toContain('Nothing is held')
  })
})

describe('unknown routes', () => {
  it('render NotFound with a link to the dashboard', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: {} })
    const router = await createTestRouter('/vulnerable')
    const pinia = createPinia()
    setActivePinia(pinia)
    vi.spyOn(useRealtimeStore(), 'connect').mockImplementation(() => {})
    const mounted = await mountStrict(App, { global: { plugins: [pinia, router] } })
    restore = mounted.restore
    await flushPromises()

    expect(mounted.problems).toEqual([])
    const main = mounted.wrapper.find('main')
    expect(main.find('h1').text()).toBe('Page not found')
    expect(main.find('[data-slot="empty-state"]').text()).toContain('/vulnerable')
    const link = main.find('a[href="/"]')
    expect(link.text()).toMatch(/overview|dashboard/i)
  })
})
