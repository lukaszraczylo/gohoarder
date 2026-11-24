import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises, mount } from '@vue/test-utils'
import PackageList from './PackageList.vue'
import type { Package } from '../stores/packages'
import { PACKAGES } from '@/test/fixtures'
import { serveRows } from '@/test/rowsServer'
import { createTestRouter } from '@/test/router'

vi.mock('axios')

const lastUrl = () => new URL(String(vi.mocked(axios.get).mock.calls[vi.mocked(axios.get).mock.calls.length - 1]![0]), 'http://x').searchParams

function serve(rows: Package[]) {
  vi.mocked(axios.get).mockImplementation(async (url: string) => ({ data: serveRows(url, rows) }) as never)
}

async function open(path = '/packages', rows: Package[] = PACKAGES) {
  serve(rows)
  const router = await createTestRouter(path)
  const pinia = createPinia()
  setActivePinia(pinia)
  const wrapper = mount(PackageList, { props: { registry: router.currentRoute.value.params.registry as string | undefined }, global: { plugins: [pinia, router] } })
  await flushPromises()
  return { wrapper, router }
}

describe('PackageList.vue', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('renders the page heading', async () => {
    const { wrapper } = await open()
    expect(wrapper.find('h1').text()).toBe('Packages')
  })

  it('asks the server for the first page of rows, not for every package', async () => {
    await open()
    const calls = vi.mocked(axios.get).mock.calls.filter((c) => String(c[0]).startsWith('/api/packages'))
    expect(calls).toHaveLength(1)
    expect(Object.fromEntries(lastUrl())).toEqual({ layout: 'rows', page: '1', page_size: '25' })
  })

  it('displays the error message when the load fails', async () => {
    vi.mocked(axios.get).mockRejectedValue(new Error('Failed to fetch packages'))
    const router = await createTestRouter('/packages')
    const wrapper = mount(PackageList, { global: { plugins: [createPinia(), router] } })
    await flushPromises()
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

  it('debounces the search box into one request', async () => {
    const { wrapper } = await open()
    vi.mocked(axios.get).mockClear()
    const input = wrapper.get('input[aria-label="Search packages"]')

    await input.setValue('r')
    await input.setValue('re')
    await input.setValue('requests')
    await vi.advanceTimersByTimeAsync(100)
    expect(axios.get).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(400)
    await flushPromises()
    expect(axios.get).toHaveBeenCalledTimes(1)
    expect(lastUrl().get('q')).toBe('requests')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
  })

  it('says nothing matches when the server returns no rows for a search', async () => {
    const { wrapper } = await open()
    await wrapper.get('input[aria-label="Search packages"]').setValue('nothing-like-this')
    await vi.advanceTimersByTimeAsync(400)
    await flushPromises()
    expect(wrapper.text()).toContain('No packages match')
  })

  it('writes the search to the URL so a reload restores it', async () => {
    const { wrapper, router } = await open()
    await wrapper.get('input[aria-label="Search packages"]').setValue('left')
    await vi.advanceTimersByTimeAsync(400)
    await flushPromises()
    expect(router.currentRoute.value.query.q).toBe('left')
  })

  it('treats the registry path segment as a registry filter sent to the server', async () => {
    const { wrapper } = await open('/packages/pypi')
    expect(lastUrl().get('registry')).toBe('pypi')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    expect(wrapper.text()).toContain('requests')
  })

  it('sends the verdict from the URL', async () => {
    const { wrapper } = await open('/packages?verdict=held')
    expect(lastUrl().get('verdict')).toBe('held')
    expect(wrapper.get('[data-testid="package-count"]').text()).toContain('1 of 1 package version')
  })

  it('pages through the server and shows the range', async () => {
    const many = Array.from({ length: 60 }, (_, i) => ({ ...PACKAGES[0]!, id: `p${i}`, name: `pkg-${String(i).padStart(2, '0')}` }))
    const { wrapper } = await open('/packages', many)
    expect(wrapper.findAll('tbody tr')).toHaveLength(25)
    expect(wrapper.get('[data-testid="package-count"]').text()).toContain('1–25 of 60 package versions')

    await wrapper.get('nav[aria-label="Package pages"] button[aria-label*="ext"]').trigger('click')
    await flushPromises()
    expect(lastUrl().get('page')).toBe('2')
    expect(wrapper.get('[data-testid="package-count"]').text()).toContain('26–50 of 60')
  })

  it('sends a column sort to the server and returns to page 1', async () => {
    const { wrapper } = await open()
    await wrapper.get('thead button[aria-label*="Size"], thead th button').trigger('click')
    await flushPromises()
    expect(lastUrl().get('page')).toBe('1')
    expect(lastUrl().get('sort')).not.toBeNull()
  })

  it('shows the release version of a PyPI file row, not the file name', async () => {
    const six = { ...PACKAGES[2], version: 'six-1.17.0-py2.py3-none-any.whl', release_version: '1.17.0' } as Package
    const { wrapper } = await open('/packages', [six])
    expect(wrapper.text()).toContain('v1.17.0')
    expect(wrapper.text()).not.toContain('py2.py3-none-any.whl')
  })
})
