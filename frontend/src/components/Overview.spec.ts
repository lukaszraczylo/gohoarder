import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount as mountWith } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Dashboard from './Dashboard.vue'
import { usePackageStore } from '../stores/packages'
import { useRealtimeStore, __resetRealtimeSingleton } from '../stores/realtime'
import { createTestRouter } from '@/test/router'

describe('Dashboard.vue', () => {
  let router: Awaited<ReturnType<typeof createTestRouter>>
  const mount = (component: typeof Dashboard) => mountWith(component, { global: { plugins: [router] } })

  beforeEach(async () => {
    router = await createTestRouter('/')
    setActivePinia(createPinia())
    __resetRealtimeSingleton()
    // Mock the fetch functions to prevent actual API calls
    const store = usePackageStore()
    vi.spyOn(store, 'fetchStats').mockResolvedValue()
    vi.spyOn(store, 'fetchRecentPackages').mockResolvedValue()
  })

  it('renders dashboard component', () => {
    const wrapper = mount(Dashboard)
    expect(wrapper.find('h1').text()).toBe('Dashboard')
  })

  it('displays error message when error occurs', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.error = 'Failed to load dashboard'
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Failed to load dashboard')
  })

  it('displays loading state when loading', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = true
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Loading statistics...')
  })

  it('displays overview stats cards', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 2,
      total_size: 3072,
      max_cache_size: 10737418240,
      total_downloads: 30,
      scanned_packages: 2,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Total packages')
    expect(wrapper.text()).toContain('Total size')
    expect(wrapper.text()).toContain('Total downloads')
  })

  it('displays total packages from stats', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 0,
      max_cache_size: 10737418240,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('100')
  })

  it('displays total downloads from stats', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 0,
      total_size: 0,
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('500')
  })

  it('displays total size from stats', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 0,
      total_size: 1048576, // 1 MB
      max_cache_size: 10737418240,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('1 MB')
  })

  it('displays recent packages section', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.recentPackages = [
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

    expect(wrapper.text()).toContain('Recent packages')
  })

  it('lists recent packages in the order the store holds them, newest first', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.recentPackages = [
      {
        id: '2',
        registry: 'npm',
        name: 'new-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-02T00:00:00Z',
        last_accessed: '2025-01-02T00:00:00Z',
        download_count: 5,
      },
      {
        id: '1',
        registry: 'npm',
        name: 'old-package',
        version: '1.0.0',
        size: 1024,
        cached_at: '2025-01-01T00:00:00Z',
        last_accessed: '2025-01-01T00:00:00Z',
        download_count: 10,
      },
    ]
    await wrapper.vm.$nextTick()

    const recentPackagesSection = wrapper.text().split('Recent packages')[1]

    // The store sorts by cached_at; the view keeps that order
    expect(recentPackagesSection.indexOf('new-package')).toBeLessThan(
      recentPackagesSection.indexOf('old-package')
    )
  })

  it('handles empty packages array', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.recentPackages = []
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('0')
    expect(wrapper.text()).toContain('0 B')
  })

  it('renders realtime lastStats over polled stats when present', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()
    const rt = useRealtimeStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 10,
      total_size: 1024,
      max_cache_size: 10737418240,
      total_downloads: 5,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    rt.lastStats = {
      total_packages: 999,
      total_size: 2048,
      total_downloads: 777,
      scanned_packages: 0,
    }
    await wrapper.vm.$nextTick()

    // Realtime values should be visible (override polled values).
    expect(wrapper.text()).toContain('999')
    expect(wrapper.text()).toContain('777')
  })

  it('shows a neutral "Live updates paused" badge while the socket is down', async () => {
    const wrapper = mount(Dashboard)
    const badge = wrapper.find('[data-testid="ws-live-indicator"]')
    expect(badge.text()).toBe('Live updates paused')
    expect(badge.text()).not.toMatch(/offline/i)
    expect(badge.attributes('data-tone')).toBe('neutral')
  })

  it('shows a "Live" badge once the socket is connected', async () => {
    const wrapper = mount(Dashboard)
    useRealtimeStore().connected = true
    await wrapper.vm.$nextTick()
    const badge = wrapper.find('[data-testid="ws-live-indicator"]')
    expect(badge.text()).toBe('Live')
    expect(badge.attributes('data-tone')).toBe('success')
  })
})
