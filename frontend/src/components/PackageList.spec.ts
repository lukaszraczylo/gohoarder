import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createMemoryHistory, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'
import PackageList from './PackageList.vue'
import { usePackageStore } from '../stores/packages'

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
    vi.spyOn(store, 'fetchPackages').mockResolvedValue()
  })

  it('renders package list component', async () => {
    const wrapper = await mountWithRouter()
    expect(wrapper.find('h2').text()).toBe('Packages')
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
    store.packages = []
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('No packages cached yet')
  })

  it('displays package accordion when packages exist', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    store.packages = [
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
    ]
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('test-package')
    expect(wrapper.text()).toContain('1 version')
  })

  it('calls fetchPackages on mount', async () => {
    const store = usePackageStore()
    // beforeEach already spied with mockResolvedValue; reuse that spy
    const fetchSpy = store.fetchPackages as ReturnType<typeof vi.spyOn>
    fetchSpy.mockClear()

    await mountWithRouter()

    expect(fetchSpy).toHaveBeenCalled()
  })

  it('groups packages and displays version counts', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    store.packages = [
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
    ]
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('test-package')
    expect(wrapper.text()).toContain('2 versions')
  })

  it('formats bytes correctly', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    store.packages = [
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
    ]
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('1 MB')
  })

  it('applies correct registry badge classes', async () => {
    const wrapper = await mountWithRouter()
    const store = usePackageStore()

    store.loading = false
    store.packages = [
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
    ]
    await wrapper.vm.$nextTick()

    // Verify that all registry badges are displayed
    // Packages are grouped and sorted alphabetically, so order is: go-module, npm-package, python-package
    expect(wrapper.text()).toContain('npm')
    expect(wrapper.text()).toContain('pypi')
    expect(wrapper.text()).toContain('go')

    // Verify badge component is used with correct classes
    // (matches getRegistryBadgeClass in src/composables/useBadgeStyles.ts)
    const html = wrapper.html()
    expect(html).toContain('bg-red-100') // npm badge
    expect(html).toContain('bg-blue-100') // pypi badge
    expect(html).toContain('bg-cyan-100') // go badge
  })
})
