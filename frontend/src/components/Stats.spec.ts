import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Stats from './Stats.vue'
import { usePackageStore } from '../stores/packages'

describe('Stats.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('renders stats component', () => {
    const wrapper = mount(Stats)
    expect(wrapper.find('h2').text()).toBe('Statistics')
  })

  it('displays loading state when loading', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = true
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Loading statistics...')
  })

  it('displays error message when error occurs', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.error = 'Failed to fetch statistics'
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Failed to fetch statistics')
  })

  it('displays overall statistics', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824, // 1 GB
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Overall Statistics')
    expect(wrapper.text()).toContain('100')
    expect(wrapper.text()).toContain('500')
  })

  it('displays security scanning statistics', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Security Scanning')
    expect(wrapper.text()).toContain('Scanned Packages')
    expect(wrapper.text()).toContain('Vulnerable Packages')
  })

  it('displays registry breakdown', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
    }
    store.registries = {
      npm: {
        count: 50,
        size: 536870912, // 512 MB
        downloads: 300,
      },
      pypi: {
        count: 30,
        size: 322122547, // ~307 MB
        downloads: 150,
      },
      go: {
        count: 20,
        size: 214748365, // ~205 MB
        downloads: 50,
      },
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Registry Breakdown')
    expect(wrapper.text()).toContain('NPM Registry')
    expect(wrapper.text()).toContain('PyPI Registry')
    expect(wrapper.text()).toContain('Go Modules')
    expect(wrapper.text()).toContain('50 packages')
    expect(wrapper.text()).toContain('30 packages')
    expect(wrapper.text()).toContain('20 packages')
  })

  it('formats bytes correctly in overall stats', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824, // 1 GB
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('1 GB')
  })

  it('calls fetchStats on mount', () => {
    const store = usePackageStore()
    const fetchSpy = vi.spyOn(store, 'fetchStats')

    mount(Stats)

    expect(fetchSpy).toHaveBeenCalled()
  })

  it('displays correct icon colors for different registries', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 3,
      total_size: 0,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
    }
    store.registries = {
      npm: { count: 1, size: 0, downloads: 0 },
      pypi: { count: 1, size: 0, downloads: 0 },
      go: { count: 1, size: 0, downloads: 0 },
    }
    await wrapper.vm.$nextTick()

    const containers = wrapper.findAll('.rounded-full')
    expect(containers[0].classes()).toContain('bg-red-100') // npm
    expect(containers[1].classes()).toContain('bg-blue-100') // pypi
    expect(containers[2].classes()).toContain('bg-cyan-100') // go
  })

  it('handles empty registries data', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 0,
      total_size: 0,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
    }
    store.registries = {}
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Registry Breakdown')
    // Should have no registry items
    const registryItems = wrapper.findAll('.bg-gray-50')
    expect(registryItems.length).toBe(3) // Only the overall stats cards
  })
})
