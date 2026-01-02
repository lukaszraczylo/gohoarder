import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Dashboard from './Dashboard.vue'
import { usePackageStore } from '../stores/packages'

describe('Dashboard.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    // Mock the fetch functions to prevent actual API calls
    const store = usePackageStore()
    vi.spyOn(store, 'fetchStats').mockResolvedValue()
    vi.spyOn(store, 'fetchPackages').mockResolvedValue()
  })

  it('renders dashboard component', () => {
    const wrapper = mount(Dashboard)
    expect(wrapper.find('h2').text()).toBe('Dashboard')
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
      total_downloads: 30,
      scanned_packages: 2,
      vulnerable_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Total Packages')
    expect(wrapper.text()).toContain('Total Size')
    expect(wrapper.text()).toContain('Total Downloads')
  })

  it('displays total packages from stats', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 0,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
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
      total_downloads: 500,
      scanned_packages: 0,
      vulnerable_packages: 0,
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
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('1 MB')
  })

  it('displays recent packages section', async () => {
    const wrapper = mount(Dashboard)
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

    expect(wrapper.text()).toContain('Recent Packages')
  })

  it('shows recent packages sorted by cached_at', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.packages = [
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
    ]
    await wrapper.vm.$nextTick()

    const recentPackagesSection = wrapper.text().split('Recent Packages')[1]

    // new-package should appear before old-package since it's more recent
    expect(recentPackagesSection.indexOf('new-package')).toBeLessThan(
      recentPackagesSection.indexOf('old-package')
    )
  })

  it('limits recent packages to 10 items', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.packages = Array.from({ length: 15 }, (_, i) => ({
      id: `${i}`,
      registry: 'npm',
      name: `package${i}`,
      version: '1.0.0',
      size: 1024,
      cached_at: `2025-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
      last_accessed: `2025-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
      download_count: i,
    }))
    await wrapper.vm.$nextTick()

    const recentSection = wrapper.text().split('Recent Packages')[1]
    // Count how many "package" strings appear (each package has the word "package" in its name)
    const packageCount = (recentSection.match(/package\d+/g) || []).length
    expect(packageCount).toBeLessThanOrEqual(10)
  })

  it('handles empty packages array', async () => {
    const wrapper = mount(Dashboard)
    const store = usePackageStore()

    store.loading = false
    store.packages = []
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('0')
    expect(wrapper.text()).toContain('0 B')
  })
})
