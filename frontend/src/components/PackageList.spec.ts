import { describe, it, expect, beforeEach, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import PackageList from './PackageList.vue'
import { usePackageStore, type Package } from '../stores/packages'
import { PACKAGES } from '@/test/fixtures'
import { createTestRouter } from '@/test/router'

async function open(path = '/packages', rows: Package[] = PACKAGES) {
  const router = await createTestRouter(path)
  const pinia = createPinia()
  setActivePinia(pinia)
  const store = usePackageStore()
  vi.spyOn(store, 'fetchPackages').mockImplementation(async () => {
    store.packages = rows
  })
  const wrapper = mount(PackageList, { props: { registry: router.currentRoute.value.params.registry as string | undefined }, global: { plugins: [pinia, router] } })
  await flushPromises()
  return { wrapper, store, router }
}

describe('PackageList.vue', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('renders the page heading', async () => {
    const { wrapper } = await open()
    expect(wrapper.find('h1').text()).toBe('Packages')
  })

  it('loads every package once on mount', async () => {
    const { store } = await open()
    expect(store.fetchPackages).toHaveBeenCalledTimes(1)
  })

  it('displays loading state while the first load runs', async () => {
    const { wrapper, store } = await open('/packages', [])
    store.loading = true
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Loading packages...')
  })

  it('displays the error message when the load fails', async () => {
    const { wrapper, store } = await open('/packages', [])
    store.error = 'Failed to fetch packages'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Failed to fetch packages')
  })

  it('displays an empty state when nothing is cached', async () => {
    const { wrapper } = await open('/packages', [])
    expect(wrapper.text()).toContain('No packages cached yet')
  })

  it('shows one row per version with its size, downloads and verdict word', async () => {
    const { wrapper } = await open()
    expect(wrapper.findAll('tbody tr')).toHaveLength(PACKAGES.length)
    const text = wrapper.text()
    expect(text).toContain('2 KB')
    expect(text).toContain('Held')
    expect(text).toContain('Awaiting scan')
  })

  it('narrows rows with the search box and says when nothing matches', async () => {
    const { wrapper } = await open()
    const input = wrapper.get('input[type="search"], input[aria-label="Search packages"]')
    await input.setValue('requests')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)

    await input.setValue('nothing-like-this')
    expect(wrapper.text()).toContain('No packages match')
  })

  it('writes the search to the URL so a reload restores it', async () => {
    const { wrapper, router } = await open()
    await wrapper.get('input[aria-label="Search packages"]').setValue('left')
    await flushPromises()
    expect(router.currentRoute.value.query.q).toBe('left')
  })

  it('treats the registry path segment as a registry filter', async () => {
    const { wrapper } = await open('/packages/pypi')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    expect(wrapper.text()).toContain('requests')
  })

  it('shows the release version of a PyPI file row, not the file name', async () => {
    const six = { ...PACKAGES[2], version: 'six-1.17.0-py2.py3-none-any.whl', release_version: '1.17.0' }
    const { wrapper } = await open('/packages', [six])
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })
})
