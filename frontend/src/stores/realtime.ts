import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { WSClient, type EventType, type RealtimeEvent } from '@/lib/ws'

const EVENTS_CAP = 100

export interface RealtimeStats {
  registry?: string
  total_packages?: number
  total_size?: number
  max_cache_size?: number
  total_downloads?: number
  scanned_packages?: number
  vulnerable_packages?: number
  blocked_packages?: number
  [key: string]: unknown
}

let singletonClient: WSClient | null = null

function getClient(url?: string): WSClient {
  if (!singletonClient) {
    singletonClient = new WSClient(url)
  }
  return singletonClient
}

// Test-only reset hook. Avoids leaking a singleton across tests.
export function __resetRealtimeSingleton(): void {
  if (singletonClient) {
    singletonClient.close()
  }
  singletonClient = null
}

export const useRealtimeStore = defineStore('realtime', () => {
  const connected = ref(false)
  const events = ref<RealtimeEvent[]>([])
  const lastStats = ref<RealtimeStats | null>(null)
  const unsubscribers = ref<Array<() => void>>([])

  const recentCacheActivity = computed(() =>
    events.value.filter(
      (e) => e.type === 'package_cached' || e.type === 'package_downloaded',
    ),
  )

  const recentScans = computed(() =>
    events.value.filter((e) => e.type === 'scan_complete'),
  )

  function appendEvent(event: RealtimeEvent): void {
    events.value.push(event)
    if (events.value.length > EVENTS_CAP) {
      events.value.splice(0, events.value.length - EVENTS_CAP)
    }
    if (event.type === 'stats_update') {
      lastStats.value = event.payload as RealtimeStats
    }
  }

  function ingest(event: RealtimeEvent): void {
    appendEvent(event)
  }

  function connect(url?: string): void {
    // Bail in SSR / non-browser test environments where there is no
    // WebSocket constructor. Keeps Dashboard.spec.ts (which mounts the
    // component without a WS stub) from leaking timers.
    const hasWS =
      typeof globalThis !== 'undefined' &&
      typeof (globalThis as { WebSocket?: unknown }).WebSocket !== 'undefined'
    if (!hasWS) return

    const client = getClient(url)
    if (unsubscribers.value.length === 0) {
      const types: EventType[] = [
        'package_cached',
        'package_deleted',
        'package_downloaded',
        'scan_complete',
        'stats_update',
      ]
      for (const t of types) {
        unsubscribers.value.push(client.on(t, ingest))
      }
      // Poll connected status — WSClient does not yet emit connection events;
      // a 1s tick is acceptable here and avoids tight coupling.
      const tick = setInterval(() => {
        connected.value = client.connected
      }, 1_000)
      unsubscribers.value.push(() => clearInterval(tick))
    }
    client.connect()
    // Reflect the current state immediately so tests/UX don't wait a tick.
    connected.value = client.connected
  }

  function disconnect(): void {
    for (const off of unsubscribers.value) off()
    unsubscribers.value = []
    if (singletonClient) {
      singletonClient.close()
    }
    connected.value = false
  }

  return {
    connected,
    events,
    lastStats,
    recentCacheActivity,
    recentScans,
    connect,
    disconnect,
    ingest,
  }
})
