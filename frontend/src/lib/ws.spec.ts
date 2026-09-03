import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { WSClient, __wsInternals, type RealtimeEvent } from './ws'

/**
 * Minimal WebSocket stub mimicking the parts of the browser API the WSClient
 * touches: readyState, onopen, onmessage, onclose, onerror, send, close.
 */
class StubWebSocket {
  static OPEN = 1
  static CLOSED = 3
  static instances: StubWebSocket[] = []

  url: string
  readyState = 0
  sent: string[] = []
  onopen: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    StubWebSocket.instances.push(this)
  }

  // Test helpers
  open(): void {
    this.readyState = StubWebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  receive(data: unknown): void {
    const text = typeof data === 'string' ? data : JSON.stringify(data)
    this.onmessage?.({ data: text } as MessageEvent)
  }

  triggerClose(): void {
    this.readyState = StubWebSocket.CLOSED
    this.onclose?.({} as CloseEvent)
  }

  // Real API
  send(payload: string): void {
    this.sent.push(payload)
  }

  close(): void {
    this.readyState = StubWebSocket.CLOSED
    this.onclose?.({} as CloseEvent)
  }
}

const originalWebSocket = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket

beforeEach(() => {
  StubWebSocket.instances = []
  ;(globalThis as unknown as { WebSocket: unknown }).WebSocket = StubWebSocket
})

afterEach(() => {
  ;(globalThis as unknown as { WebSocket: unknown }).WebSocket = originalWebSocket
  vi.useRealTimers()
})

describe('parseEvent', () => {
  it('normalizes backend envelope (data + RFC3339 timestamp)', () => {
    const evt = __wsInternals.parseEvent(
      JSON.stringify({
        type: 'package_cached',
        timestamp: '2026-04-28T12:00:00Z',
        data: { name: 'lodash', version: '4.17.21', registry: 'npm' },
      }),
    )
    expect(evt).not.toBeNull()
    expect(evt!.type).toBe('package_cached')
    expect(evt!.payload).toMatchObject({ name: 'lodash' })
    expect(evt!.timestamp).toBe(Date.parse('2026-04-28T12:00:00Z'))
  })

  it('drops malformed JSON', () => {
    expect(__wsInternals.parseEvent('not-json{{')).toBeNull()
  })

  it('drops unknown event types (e.g. control frames)', () => {
    expect(
      __wsInternals.parseEvent(JSON.stringify({ type: 'pong' })),
    ).toBeNull()
  })

  it('accepts numeric timestamp', () => {
    const evt = __wsInternals.parseEvent(
      JSON.stringify({ type: 'stats_update', timestamp: 1234567890, data: {} }),
    )
    expect(evt!.timestamp).toBe(1234567890)
  })
})

describe('WSClient', () => {
  it('connects and dispatches typed events to subscribers', () => {
    const client = new WSClient('ws://test/ws')
    const received: RealtimeEvent[] = []
    client.on('package_cached', (e) => received.push(e))
    client.connect()

    const sock = StubWebSocket.instances[0]
    expect(sock).toBeDefined()
    sock.open()
    sock.receive({
      type: 'package_cached',
      timestamp: '2026-04-28T00:00:00Z',
      data: { name: 'foo' },
    })

    expect(received).toHaveLength(1)
    expect(received[0].type).toBe('package_cached')
    expect(received[0].payload.name).toBe('foo')
    client.close()
  })

  it('forwards events to wildcard subscribers', () => {
    const client = new WSClient('ws://test/ws')
    const seen: string[] = []
    client.on('*', (e) => seen.push(e.type))
    client.connect()
    const sock = StubWebSocket.instances[0]
    sock.open()
    sock.receive({ type: 'scan_complete', data: {} })
    sock.receive({ type: 'package_deleted', data: {} })
    expect(seen).toEqual(['scan_complete', 'package_deleted'])
    client.close()
  })

  it('unsubscribe stops further dispatches', () => {
    const client = new WSClient('ws://test/ws')
    let count = 0
    const off = client.on('package_cached', () => {
      count += 1
    })
    client.connect()
    const sock = StubWebSocket.instances[0]
    sock.open()
    sock.receive({ type: 'package_cached', data: {} })
    expect(count).toBe(1)
    off()
    sock.receive({ type: 'package_cached', data: {} })
    expect(count).toBe(1)
    client.close()
  })

  it('auto-reconnects with backoff after unexpected close', () => {
    vi.useFakeTimers()
    const client = new WSClient('ws://test/ws')
    client.connect()
    const first = StubWebSocket.instances[0]
    first.open()
    first.triggerClose()

    // First reconnect happens after RECONNECT_BASE_MS (1s).
    vi.advanceTimersByTime(__wsInternals.RECONNECT_BASE_MS)
    expect(StubWebSocket.instances.length).toBe(2)

    // Second drop -> next backoff is 2s.
    StubWebSocket.instances[1].open()
    StubWebSocket.instances[1].triggerClose()
    vi.advanceTimersByTime(__wsInternals.RECONNECT_BASE_MS * 2)
    expect(StubWebSocket.instances.length).toBe(3)

    client.close()
  })

  it('does not reconnect after explicit close', () => {
    vi.useFakeTimers()
    const client = new WSClient('ws://test/ws')
    client.connect()
    const sock = StubWebSocket.instances[0]
    sock.open()
    client.close()
    vi.advanceTimersByTime(60_000)
    expect(StubWebSocket.instances.length).toBe(1)
  })

  it('emits heartbeat ping every 25s', () => {
    vi.useFakeTimers()
    const client = new WSClient('ws://test/ws')
    client.connect()
    const sock = StubWebSocket.instances[0]
    sock.open()
    expect(sock.sent).toHaveLength(0)
    vi.advanceTimersByTime(__wsInternals.HEARTBEAT_INTERVAL_MS)
    expect(sock.sent).toHaveLength(1)
    expect(JSON.parse(sock.sent[0])).toEqual({ action: 'ping' })
    vi.advanceTimersByTime(__wsInternals.HEARTBEAT_INTERVAL_MS)
    expect(sock.sent).toHaveLength(2)
    client.close()
  })

  it('queues outbound messages while disconnected and flushes on open', () => {
    const client = new WSClient('ws://test/ws')
    client.send({ action: 'subscribe', data: ['package_cached'] })
    client.connect()
    const sock = StubWebSocket.instances[0]
    expect(sock.sent).toHaveLength(0)
    sock.open()
    expect(sock.sent).toHaveLength(1)
    expect(JSON.parse(sock.sent[0])).toMatchObject({ action: 'subscribe' })
    client.close()
  })

  it('drops malformed inbound JSON without throwing', () => {
    const client = new WSClient('ws://test/ws')
    let count = 0
    client.on('*', () => {
      count += 1
    })
    client.connect()
    const sock = StubWebSocket.instances[0]
    sock.open()
    sock.receive('not-json{{{')
    sock.receive({ type: 'unknown_type', data: {} })
    expect(count).toBe(0)
    client.close()
  })
})
