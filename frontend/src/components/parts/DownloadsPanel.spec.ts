import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import DownloadsPanel from './DownloadsPanel.vue'
import { PACKAGE_ANALYTICS } from '@/test/fixtures'
import { mountStrict } from '@/test/mountStrict'

vi.mock('axios')

let restore: (() => void) | undefined

async function open(props: { registry: string; name: string; downloadCount: number }) {
  const mounted = await mountStrict(DownloadsPanel, { props })
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

describe('DownloadsPanel', () => {
  it('shows the stored count even when analytics have no record since the restart', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { package: null } })
    const wrapper = await open({ registry: 'npm', name: 'left-pad', downloadCount: 12 })

    expect(wrapper.text()).toContain('12')
    expect(wrapper.text()).toContain('No downloads since the last restart')
    expect(wrapper.text()).not.toContain('Could not load')
  })

  it('adds the in-memory totals and labels them as since the restart', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: PACKAGE_ANALYTICS })
    const wrapper = await open({ registry: 'npm', name: 'left-pad', downloadCount: 12 })

    expect(wrapper.text()).toContain('kept across restarts')
    expect(wrapper.text()).toContain('2 versions since the last restart')
    expect(wrapper.text()).toContain('80 KB')
  })

  it('asks for a Go module by its path, with no cache-file suffix', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: { package: null } })
    await open({ registry: 'go', name: 'github.com/google/uuid/@v/v1.6.0.zip', downloadCount: 2 })

    expect(vi.mocked(axios.get)).toHaveBeenCalledWith('/api/analytics/package/go/github.com/google/uuid')
  })

  it('reports a failed request', async () => {
    vi.mocked(axios.get).mockRejectedValue(new Error('boom'))
    const wrapper = await open({ registry: 'npm', name: 'left-pad', downloadCount: 1 })
    expect(wrapper.text()).toContain('Could not load download history')
  })
})
