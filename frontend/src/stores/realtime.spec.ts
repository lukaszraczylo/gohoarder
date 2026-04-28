import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useRealtimeStore, __resetRealtimeSingleton } from './realtime'
import type { RealtimeEvent } from '@/lib/ws'

function makeEvent(
  type: RealtimeEvent['type'],
  payload: Record<string, unknown> = {},
  timestamp = Date.now(),
): RealtimeEvent {
  return { type, payload, timestamp }
}

describe('useRealtimeStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    __resetRealtimeSingleton()
  })

  it('appends events on ingest', () => {
    const store = useRealtimeStore()
    store.ingest(makeEvent('package_cached', { name: 'a' }))
    store.ingest(makeEvent('package_deleted', { name: 'b' }))
    expect(store.events).toHaveLength(2)
    expect(store.events[0].type).toBe('package_cached')
  })

  it('caps events at 100 with FIFO eviction', () => {
    const store = useRealtimeStore()
    for (let i = 0; i < 150; i += 1) {
      store.ingest(makeEvent('package_cached', { i }))
    }
    expect(store.events).toHaveLength(100)
    // First event should be index 50 (0..49 dropped)
    expect((store.events[0].payload as { i: number }).i).toBe(50)
    expect((store.events[99].payload as { i: number }).i).toBe(149)
  })

  it('updates lastStats only on stats_update events', () => {
    const store = useRealtimeStore()
    expect(store.lastStats).toBeNull()
    store.ingest(makeEvent('package_cached', { name: 'x' }))
    expect(store.lastStats).toBeNull()
    store.ingest(
      makeEvent('stats_update', {
        total_packages: 42,
        total_size: 1024,
      }),
    )
    expect(store.lastStats).toMatchObject({ total_packages: 42, total_size: 1024 })
  })

  it('exposes filtered computed slices', () => {
    const store = useRealtimeStore()
    store.ingest(makeEvent('package_cached'))
    store.ingest(makeEvent('package_downloaded'))
    store.ingest(makeEvent('scan_complete'))
    store.ingest(makeEvent('stats_update'))
    expect(store.recentCacheActivity).toHaveLength(2)
    expect(store.recentScans).toHaveLength(1)
  })
})
