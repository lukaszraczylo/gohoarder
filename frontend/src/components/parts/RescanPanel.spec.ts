import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import axios from 'axios'
import { flushPromises } from '@vue/test-utils'
import RescanPanel from './RescanPanel.vue'
import { mountStrict } from '@/test/mountStrict'

vi.mock('axios')

const idle = { enabled: true, running: false, scope: '', queued: 0, done: 0, failed: 0 }
const running = { enabled: true, running: true, scope: 'vulnerable', queued: 10, done: 3, failed: 1, elapsed_seconds: 40, eta_seconds: 60 }
let estimate: unknown
const finished = { ...running, running: false, done: 9 }

let restore: (() => void) | undefined
let statuses: Array<typeof idle | typeof running>

beforeEach(() => {
  localStorage.setItem('admin_api_key', 'test-key')
  statuses = [idle]
  estimate = { vulnerable: { artifacts: 12, seconds: 30 }, all: { artifacts: 1200, seconds: 6000 }, avg_scan_seconds: 10, concurrency: 2 }
  vi.mocked(axios.get).mockReset()
  vi.mocked(axios.post).mockReset()
  vi.mocked(axios.get).mockImplementation(async (url: string) => {
    if (url === '/api/admin/rescan/status') return { data: statuses.length > 1 ? statuses.shift() : statuses[0] } as never
    if (url === '/api/admin/rescan/estimate') return { data: estimate } as never
    throw new Error(`unexpected request: ${url}`)
  })
})
afterEach(() => {
  restore?.()
  restore = undefined
  localStorage.clear()
  vi.useRealTimers()
})

async function open(props = { enabled: true, concurrency: 2 }) {
  const pinia = createPinia()
  setActivePinia(pinia)
  const mounted = await mountStrict(RescanPanel, { props, global: { plugins: [pinia] } })
  restore = mounted.restore
  await flushPromises()
  return mounted.wrapper
}

const body = () => document.body.textContent ?? ''
function dialogButton(label: string): HTMLButtonElement {
  const btn = [...document.body.querySelectorAll('[role="alertdialog"] button, [role="dialog"] button')].find((b) => b.textContent?.trim() === label)
  if (!btn) throw new Error(`no button "${label}"`)
  return btn as HTMLButtonElement
}

describe('RescanPanel', () => {
  it('starts a vulnerable rescan with the admin key and shows progress', async () => {
    vi.mocked(axios.post).mockResolvedValue({ data: { queued: 10, scope: 'vulnerable' } })
    statuses = [idle, running]
    const wrapper = await open()

    await wrapper.get('[data-testid="rescan-vulnerable"]').trigger('click')
    await flushPromises()

    expect(vi.mocked(axios.post)).toHaveBeenCalledWith('/api/admin/rescan', { scope: 'vulnerable' }, { headers: { Authorization: 'Bearer test-key' } })
    expect(wrapper.get('[data-testid="rescan-counts"]').text()).toContain('3 scanned, 1 failed, of 10 queued')
    expect(wrapper.get('[data-testid="rescan-vulnerable"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="rescan-note"]').text()).toContain('A rescan is running')
  })

  it('asks before rescanning everything and says how long it takes', async () => {
    vi.mocked(axios.post).mockResolvedValue({ data: { queued: 1200, scope: 'all' } })
    const wrapper = await open()

    await wrapper.get('[data-testid="rescan-all"]').trigger('click')
    await flushPromises()
    expect(vi.mocked(axios.post)).not.toHaveBeenCalled()
    expect(body()).toContain('re-runs all scanners on every cached artifact')
    expect(body()).toContain('1,200 artifacts, 2 at a time and 10.0 seconds each on recent scans: roughly 100 minutes')
    expect(vi.mocked(axios.get)).toHaveBeenCalledWith('/api/admin/rescan/estimate', { headers: { Authorization: 'Bearer test-key' } })

    dialogButton('Rescan everything').click()
    await flushPromises()
    expect(vi.mocked(axios.post)).toHaveBeenCalledWith('/api/admin/rescan', { scope: 'all' }, expect.anything())
  })

  it('does not invent an estimate before any scan was timed', async () => {
    estimate = { vulnerable: { artifacts: 1, seconds: null }, all: { artifacts: 7, seconds: null }, avg_scan_seconds: 0, concurrency: 2 }
    const wrapper = await open()
    await wrapper.get('[data-testid="rescan-all"]').trigger('click')
    await flushPromises()
    expect(body()).toContain('No scan has been timed yet, so there is no estimate.')
    expect(body()).not.toContain('roughly')
  })

  it('shows the live rate and the time left while a rescan runs', async () => {
    statuses = [running]
    const wrapper = await open()
    // 4 processed in 40 s is 6 a minute; the server says 60 s remain.
    expect(wrapper.get('[data-testid="rescan-live"]').text()).toBe('6.0 artifacts a minute. About 1 minute left.')
  })

  it('polls until the rescan finishes and then stops', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(axios.post).mockResolvedValue({ data: { queued: 10, scope: 'vulnerable' } })
    statuses = [idle, running, running, finished]
    const wrapper = await open()

    await wrapper.get('[data-testid="rescan-vulnerable"]').trigger('click')
    await flushPromises()
    const statusCalls = () => vi.mocked(axios.get).mock.calls.filter(([url]) => url === '/api/admin/rescan/status').length

    await vi.advanceTimersByTimeAsync(2100)
    await vi.advanceTimersByTimeAsync(2100)
    await flushPromises()
    expect(wrapper.get('[data-testid="rescan-counts"]').text()).toContain('Finished.')
    const settled = statusCalls()
    await vi.advanceTimersByTimeAsync(10000)
    expect(statusCalls()).toBe(settled)
  })

  it('shows the running rescan when the server answers 409', async () => {
    vi.mocked(axios.post).mockRejectedValue({ response: { status: 409 } })
    statuses = [idle, running]
    const wrapper = await open()

    await wrapper.get('[data-testid="rescan-vulnerable"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="rescan-counts"]').text()).toContain('3 scanned')
  })

  it('is disabled and explains why when scanning is off', async () => {
    const wrapper = await open({ enabled: false, concurrency: 2 })
    expect(wrapper.get('[data-testid="rescan-vulnerable"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="rescan-all"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="rescan-note"]').text()).toContain('Security scanning is off')
    expect(vi.mocked(axios.get)).not.toHaveBeenCalled()
  })

  it('asks for the admin key before it posts anything', async () => {
    localStorage.clear()
    const wrapper = await open()
    await wrapper.get('[data-testid="rescan-vulnerable"]').trigger('click')
    await flushPromises()
    expect(vi.mocked(axios.post)).not.toHaveBeenCalled()
    expect(body()).toContain('Enter your admin API key to start a rescan.')
  })

  it('asks for the admin key before it sizes a full rescan', async () => {
    localStorage.clear()
    const wrapper = await open()
    await wrapper.get('[data-testid="rescan-all"]').trigger('click')
    await flushPromises()
    expect(vi.mocked(axios.get)).not.toHaveBeenCalledWith('/api/admin/rescan/estimate', expect.anything())
    expect(body()).toContain('Enter your admin API key to start a rescan.')
  })

  it('forgets a key the server refuses', async () => {
    vi.mocked(axios.post).mockRejectedValue({ response: { status: 403 } })
    const wrapper = await open()
    await wrapper.get('[data-testid="rescan-vulnerable"]').trigger('click')
    await flushPromises()
    expect(localStorage.getItem('admin_api_key')).toBeNull()
  })
})
