import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount as mountWith } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Stats from './Stats.vue'
import { createTestRouter } from '@/test/router'
import { usePackageStore } from '../stores/packages'

describe('Stats.vue', () => {
  let router: Awaited<ReturnType<typeof createTestRouter>>
  const mount = (component: typeof Stats) => mountWith(component, { global: { plugins: [router] } })

  beforeEach(async () => {
    setActivePinia(createPinia())
    router = await createTestRouter('/stats')
  })

  it('renders stats component', () => {
    const wrapper = mount(Stats)
    expect(wrapper.find('h1').text()).toBe('Statistics')
  })

  it('displays loading state when loading', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = true
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Loading statistics...')
  })

  it('displays error message when error occurs', async () => {
    const store = usePackageStore()
    vi.spyOn(store, 'fetchStats').mockResolvedValue()
    const wrapper = mount(Stats)

    store.loading = false
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
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Overall statistics')
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
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
      blocked_packages: 0,
    }
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Security scanning')
    expect(wrapper.text()).toContain('Scanned packages')
    expect(wrapper.text()).toContain('Vulnerable packages')
  })

  it('displays registry breakdown', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824,
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
      blocked_packages: 0,
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

    expect(wrapper.text()).toContain('Registry breakdown')
    expect(wrapper.text()).toContain('npm')
    expect(wrapper.text()).toContain('PyPI')
    expect(wrapper.text()).toContain('Go modules')
    // The cards layout prefixes each cell with its column label.
    const packageCounts = wrapper
      .findAll('tbody tr')
      .map((row) => row.findAll('td')[0].text().replace(/^Packages/, ''))
    expect(packageCounts).toEqual(['50', '30', '20'])
  })

  it('formats bytes correctly in overall stats', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824, // 1 GB
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
      blocked_packages: 0,
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

  it('lists the registries in the order the API reports them', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 3,
      total_size: 0,
      max_cache_size: 10737418240,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    store.registries = {
      npm: { count: 1, size: 0, downloads: 0 },
      pypi: { count: 1, size: 0, downloads: 0 },
      go: { count: 1, size: 0, downloads: 0 },
    }
    await wrapper.vm.$nextTick()

    const labels = wrapper.findAll('tbody th').map((cell) => cell.text().replace(/^Registry/, ''))
    expect(labels).toEqual(['npm', 'PyPI', 'Go modules'])
  })

  it('handles empty registries data', async () => {
    const wrapper = mount(Stats)
    const store = usePackageStore()

    store.loading = false
    store.stats = {
      registry: '',
      total_packages: 0,
      total_size: 0,
      max_cache_size: 10737418240,
      total_downloads: 0,
      scanned_packages: 0,
      vulnerable_packages: 0,
      blocked_packages: 0,
    }
    store.registries = {}
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Registry breakdown')
    expect(wrapper.findAll('tbody th')).toHaveLength(0)
    expect(wrapper.text()).toContain('No registries reported')
  })

  describe('idle eviction note', () => {
    const baseStats = {
      registry: '',
      total_packages: 100,
      total_size: 1073741824,
      max_cache_size: 10737418240,
      total_downloads: 500,
      scanned_packages: 90,
      vulnerable_packages: 5,
      blocked_packages: 0,
    }

    async function render(idleTtl?: number) {
      const wrapper = mount(Stats)
      const store = usePackageStore()
      store.loading = false
      store.stats = idleTtl === undefined ? { ...baseStats } : { ...baseStats, idle_ttl: idleTtl }
      await wrapper.vm.$nextTick()
      return wrapper
    }

    it.each([
      [604800, 'Cached items not requested for 7 days are removed.'],
      [86400, 'Cached items not requested for 1 day are removed.'],
      [129600, 'Cached items not requested for 36 hours are removed.'],
      [5400, 'Cached items not requested for 90 minutes are removed.'],
    ])('shows the window for idle_ttl=%i', async (seconds, sentence) => {
      const wrapper = await render(seconds)
      expect(wrapper.text()).toContain(sentence)
    })

    it('hides the note when idle eviction is off', async () => {
      const wrapper = await render(0)
      expect(wrapper.text()).not.toContain('not requested')
    })

    it('hides the note when the API sends no idle_ttl', async () => {
      const wrapper = await render()
      expect(wrapper.text()).not.toContain('not requested')
    })
  })
})
