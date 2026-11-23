import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createMemoryHistory, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import PackageList from './PackageList.vue'
import { usePackageStore } from '../stores/packages'

type Row = ReturnType<typeof usePackageStore>['packagePage']['packages'][number]

// A page as the server sends it: whole groups, flattened to rows.
function setRows(store: ReturnType<typeof usePackageStore>, packages: Row[]) {
  const groups = new Set(packages.map((p) => `${p.registry}:${p.name}`))
  store.packagePage = { packages, totalGroups: groups.size, page: 1, pageSize: 25 }
}

const Stub = defineComponent({ render: () => h('div') })

function createTestRouter(): Router {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'dashboard', component: Stub },
      { path: '/packages/:registry?', name: 'packages', component: Stub, props: true },
      {
        path: '/package/:registry/:name+/:version',
        name: 'package-details',
        component: Stub,
        props: true,
      },
    ],
  })
}

async function mountWithRouter() {
  const router = createTestRouter()
  router.push('/packages')
  await router.isReady()
  return mount(PackageList, {
    global: {
      plugins: [router],
    },
  })
}

describe('PackageList.vue', () => {
  beforeEach(() => {
    // Create a fresh pinia instance before each test
    setActivePinia(createPinia())
    // Prevent real network calls from store actions on mount
    const store = usePackageStore()
    vi.spyOn(store, 'fetchPackagePage').mockResolvedValue()
  })

  it('renders package list component', async () => {
    const wrapper = await mountWithRouter()
    expect(wrapper.find('h1').text()).toBe('Packages')
  })

  it('displays loading state when loading', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = true
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Loading packages...')
  })

  it('displays error message when error occurs', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.error = 'Failed to fetch packages'
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Failed to fetch packages')
  })

  it('displays empty state when no packages', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    setRows(store, [])
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('No packages cached yet')
  })

  it('displays package accordion when packages exist', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    setRows(store, [
      {
        id: '1',
        registry: 'npm',
        name: 'test-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 10,
      },
    ])
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('test-package')
    expect(wrapper.text()).toContain('1 version')
  })

  it('asks the server for the first page on mount', async () => {
    const store = usePackageStore()
    // beforeEach already spied with mockResolvedValue; reuse that spy
    const fetchSpy = store.fetchPackagePage as ReturnType<typeof vi.spyOn>
    fetchSpy.mockClear()

    await mountWithRouter()

    expect(fetchSpy).toHaveBeenCalled()
  })

  it('groups packages and displays version counts', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    setRows(store, [
      {
        id: '1',
        registry: 'npm',
        name: 'test-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 10,
      },
      {
        id: '2',
        registry: 'npm',
        name: 'test-package',
        version: '2.0.0',
        size: 2048,
        cached_at: '2025-01-02T00:00:00Z',
        last_accessed: '2025-01-02T00:00:00Z',
        download_count: 20,
      },
    ])
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('test-package')
    expect(wrapper.text()).toContain('2 versions')
  })

  it('formats bytes correctly', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    setRows(store, [
      {
        id: '1',
        registry: 'npm',
        name: 'test-package',
        version: '1.0.0',
        size: 1048576, // 1 MB
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 10,
      },
    ])
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('1 MB')
  })

  it('prints every registry as a badge with its name', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    setRows(store, [
      {
        id: '3',
        registry: 'go',
        name: 'go-module',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 3,
      },
      {
        id: '1',
        registry: 'npm',
        name: 'npm-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 10,
      },
      {
        id: '2',
        registry: 'pypi',
        name: 'python-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 5,
      },
    ])
    await wrapper.vm.$nextTick()

    // Verify that all registry badges are displayed
    // The server sends groups in name order: go-module, npm-package, python-package
    expect(wrapper.text()).toContain('npm')
    expect(wrapper.text()).toContain('pypi')
    expect(wrapper.text()).toContain('go')

    // Each registry is printed as text in an outline badge, never as colour alone.
    const badges = wrapper.findAll('[data-slot="badge"]').map((badge) => badge.text())
    expect(badges).toEqual(['go', 'npm', 'pypi'])
  })

  it('shows the release version for a PyPI file row, not the file name', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    setRows(store, [
      {
        id: '1',
        registry: 'pypi',
        name: 'six',
        version: 'six-1.17.0-py2.py3-none-any.whl',
        release_version: '1.17.0',
        size: 1,
        cached_at: '2026-11-23T00:00:00Z',
        last_accessed: '2026-11-23T00:00:00Z',
        download_count: 0,
      },
    ])
    await wrapper.vm.$nextTick()
    await wrapper.find('button[aria-expanded]').trigger('click')
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })

  describe('server-side paging, search and registry filter', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })
    afterEach(() => {
      vi.useRealTimers()
    })

    it('debounces the search box into one request with q and page 1', async () => {
      const wrapper = await mountWithRouter()
      const store = usePackageStore()
      const fetchSpy = store.fetchPackagePage as ReturnType<typeof vi.spyOn>
      fetchSpy.mockClear()

      const input = wrapper.find('input[type="search"], input')
      await input.setValue('l')
      await input.setValue('le')
      await input.setValue('left')
      expect(fetchSpy).not.toHaveBeenCalled()

      await vi.advanceTimersByTimeAsync(300)
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(fetchSpy).toHaveBeenCalledWith({ page: 1, pageSize: 25, registry: 'all', q: 'left' })
    })

    it('sends the registry of the route with every request', async () => {
      const router = createTestRouter()
      router.push('/packages/pypi')
      await router.isReady()
      const store = usePackageStore()
      const fetchSpy = store.fetchPackagePage as ReturnType<typeof vi.spyOn>
      fetchSpy.mockClear()
      mount(PackageList, { props: { registry: 'pypi' }, global: { plugins: [router] } })
      expect(fetchSpy).toHaveBeenCalledWith({ page: 1, pageSize: 25, registry: 'pypi', q: '' })
    })

    it('pages through the server, not the loaded rows', async () => {
      const wrapper = await mountWithRouter()
      const store = usePackageStore()
      store.loading = false
      store.packagePage = {
        packages: [
          { id: '1', registry: 'npm', name: 'a', version: '1', size: 1, cached_at: '2025-01-01T00:00:00Z', last_accessed: '2025-01-01T00:00:00Z', download_count: 0 },
        ],
        totalGroups: 60,
        page: 1,
        pageSize: 25,
      }
      await wrapper.vm.$nextTick()
      expect(wrapper.text()).toContain('Page 1 of 3 (60 total packages)')

      const fetchSpy = store.fetchPackagePage as ReturnType<typeof vi.spyOn>
      fetchSpy.mockClear()
      window.scrollTo = vi.fn() as unknown as typeof window.scrollTo
      const next = wrapper.findAll('button').find((b) => /next/i.test(b.attributes('aria-label') ?? b.text()))
      await next!.trigger('click')
      expect(fetchSpy).toHaveBeenCalledWith({ page: 2, pageSize: 25, registry: 'all', q: '' })
    })

    it('says no packages match when a filter empties the page', async () => {
      const wrapper = await mountWithRouter()
      const store = usePackageStore()
      store.loading = false
      setRows(store, [])
      await wrapper.find('input').setValue('zzz')
      await vi.advanceTimersByTimeAsync(300)
      expect(wrapper.text()).toContain('No packages match')
      expect(wrapper.text()).not.toContain('No packages cached yet')
    })
  })
})
