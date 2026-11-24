import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import TopPackages from './TopPackages.vue'
import { mountStrict } from '@/test/mountStrict'

vi.mock('axios')

let restore: (() => void) | undefined

const row = (registry: string, name: string, download_count: number) => ({ registry, name, version: '1.0.0', download_count })

function serve(rows: unknown[], trending: unknown[] = []) {
  vi.mocked(axios.get).mockImplementation(async (url: string) => {
    if (url.startsWith('/api/analytics/trending')) return { data: { packages: trending } } as never
    if (url.startsWith('/api/packages?layout=rows')) return { data: { packages: rows } } as never
    throw new Error(`unexpected request: ${url}`)
  })
}

async function open() {
  const mounted = await mountStrict(TopPackages)
  restore = mounted.restore
  await flushPromises()
  return mounted.wrapper
}

beforeEach(() => {
  vi.mocked(axios.get).mockReset()
})
afterEach(() => {
  restore?.()
  restore = undefined
})

describe('TopPackages', () => {
  it('ranks packages by the stored download counts, so a restart does not empty it', async () => {
    serve([row('npm', 'left-pad', 12), row('npm', 'left-pad', 5), row('pypi', 'six', 9)])
    const wrapper = await open()

    const text = wrapper.get('[data-testid="top-packages"]').text()
    expect(text).toContain('npm · left-pad')
    expect(text).toContain('pypi · six')
    expect(text).not.toContain('No downloads yet')
    expect(vi.mocked(axios.get)).toHaveBeenCalledWith('/api/packages?layout=rows&sort=downloads&order=desc&page=1&page_size=200')
    expect(vi.mocked(axios.get)).not.toHaveBeenCalledWith(expect.stringContaining('/api/analytics/top'))
  })

  it('adds the versions of a package and orders by the sum', async () => {
    serve([row('npm', 'a', 10), row('npm', 'b', 15), row('npm', 'a', 9)])
    const wrapper = await open()
    const labels = wrapper.findAll('[data-testid="top-packages"] li').map((li) => li.text())
    expect(labels[0]).toContain('npm · a')
    expect(labels[1]).toContain('npm · b')
  })

  it('counts a Go module once, by its zip, and not its .mod and .info files', async () => {
    serve([
      row('go', 'github.com/google/uuid/@v/v1.6.0.zip', 4),
      row('go', 'github.com/google/uuid/@v/v1.6.0.mod', 4),
      row('go', 'github.com/google/uuid/@v/v1.6.0.info', 4),
    ])
    const wrapper = await open()
    const entries = wrapper.findAll('[data-testid="top-packages"] li')
    expect(entries).toHaveLength(1)
    expect(entries[0].text()).toContain('go · github.com/google/uuid')
    expect(entries[0].text()).toContain('4')
    expect(entries[0].text()).not.toContain('12')
  })

  it('says so when no package has a download', async () => {
    serve([row('npm', 'left-pad', 0)])
    const wrapper = await open()
    expect(wrapper.get('[data-testid="top-packages"]').text()).toContain('No downloads yet')
  })

  it('shows the change against the previous 7 days for trending packages', async () => {
    serve([], [
      { Registry: 'npm', Name: 'left-pad', Downloads: 9, RecentDownloads: 9, PreviousDownloads: 4 },
      { Registry: 'npm', Name: 'six', Downloads: 3, RecentDownloads: 3, PreviousDownloads: 8 },
    ])
    const wrapper = await open()
    const rows = wrapper.findAll('[data-testid="top-packages"] li').map((li) => li.text())
    const pad = rows.find((r) => r.includes('left-pad'))
    const six = rows.find((r) => r.includes('six'))
    expect(pad).toMatch(/\+5/)
    expect(six).toMatch(/[-−]5/)
  })

  it('names where each ranking comes from', async () => {
    serve([row('npm', 'left-pad', 3)])
    const wrapper = await open()
    const text = wrapper.get('[data-testid="top-packages"]').text()
    expect(text).toContain('The counts survive restarts.')
    expect(text).toContain('the change from the 7 days before')
    expect(text).not.toContain('restarts with the server')
  })
})
