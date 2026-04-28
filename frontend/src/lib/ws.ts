/**
 * Lightweight WebSocket client with auto-reconnect, heartbeat, and pub/sub.
 *
 * Backend (pkg/websocket/server.go) emits envelopes shaped like:
 *   { "type": "package_cached", "timestamp": "2026-04-28T12:34:56Z", "data": {...} }
 *
 * We normalize this into RealtimeEvent { type, payload, timestamp(number ms) }.
 */

export type EventType =
  | 'package_deleted'
  | 'package_cached'
  | 'package_downloaded'
  | 'scan_complete'
  | 'stats_update'

export interface RealtimeEvent {
  type: EventType
  payload: Record<string, unknown>
  timestamp: number
}

type WildcardListener = '*'
type ListenerKey = EventType | WildcardListener
type Listener = (e: RealtimeEvent) => void

const KNOWN_EVENT_TYPES: ReadonlySet<string> = new Set<EventType>([
  'package_deleted',
  'package_cached',
  'package_downloaded',
  'scan_complete',
  'stats_update',
])

const RECONNECT_BASE_MS = 1_000
const RECONNECT_MAX_MS = 30_000
const HEARTBEAT_INTERVAL_MS = 25_000
const RECONNECT_QUEUE_CAP = 50

interface OutboundMessage {
  action: string
  data?: unknown
}

function defaultUrl(): string {
  if (typeof window === 'undefined' || !window.location) {
    return 'ws://localhost/ws'
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}/ws`
}

function isKnownEventType(value: unknown): value is EventType {
  return typeof value === 'string' && KNOWN_EVENT_TYPES.has(value)
}

function coerceTimestamp(raw: unknown): number {
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    return raw
  }
  if (typeof raw === 'string') {
    const parsed = Date.parse(raw)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now()
}

function parseEvent(text: string): RealtimeEvent | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object') return null
  const obj = parsed as Record<string, unknown>

  // Server may also emit `{ type: "pong" }` style control frames; ignore those.
  if (!isKnownEventType(obj.type)) return null

  const payloadSource = obj.payload ?? obj.data
  const payload =
    payloadSource && typeof payloadSource === 'object'
      ? (payloadSource as Record<string, unknown>)
      : {}

  return {
    type: obj.type,
    payload,
    timestamp: coerceTimestamp(obj.timestamp),
  }
}

export class WSClient {
  readonly url: string
  private socket: WebSocket | null = null
  private listeners: Map<ListenerKey, Set<Listener>> = new Map()
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectAttempts = 0
  private explicitlyClosed = false
  private outboundQueue: OutboundMessage[] = []
  private _connected = false

  constructor(url?: string) {
    this.url = url ?? defaultUrl()
  }

  get connected(): boolean {
    return this._connected
  }

  connect(): void {
    this.explicitlyClosed = false
    this.openSocket()
  }

  close(): void {
    this.explicitlyClosed = true
    this.clearReconnect()
    this.stopHeartbeat()
    this._connected = false
    if (this.socket) {
      try {
        this.socket.close()
      } catch {
        /* swallow */
      }
      this.socket = null
    }
  }

  on(type: ListenerKey, cb: Listener): () => void {
    let bucket = this.listeners.get(type)
    if (!bucket) {
      bucket = new Set()
      this.listeners.set(type, bucket)
    }
    bucket.add(cb)
    return () => {
      const current = this.listeners.get(type)
      if (!current) return
      current.delete(cb)
      if (current.size === 0) this.listeners.delete(type)
    }
  }

  /**
   * Send a message. If not connected, queue (capped) and flush on open.
   */
  send(msg: OutboundMessage): void {
    if (this.socket && this._connected && this.socket.readyState === 1) {
      try {
        this.socket.send(JSON.stringify(msg))
        return
      } catch {
        /* fall through to queue */
      }
    }
    if (this.outboundQueue.length >= RECONNECT_QUEUE_CAP) {
      this.outboundQueue.shift()
    }
    this.outboundQueue.push(msg)
  }

  private openSocket(): void {
    const Ctor: typeof WebSocket | undefined =
      typeof WebSocket !== 'undefined'
        ? WebSocket
        : (globalThis as unknown as { WebSocket?: typeof WebSocket }).WebSocket
    if (!Ctor) {
      // No WebSocket available (e.g. SSR); silently bail.
      return
    }

    let socket: WebSocket
    try {
      socket = new Ctor(this.url)
    } catch {
      this.scheduleReconnect()
      return
    }
    this.socket = socket

    socket.onopen = () => {
      this._connected = true
      this.reconnectAttempts = 0
      this.startHeartbeat()
      this.flushQueue()
    }

    socket.onmessage = (ev: MessageEvent) => {
      const data = ev.data
      if (typeof data !== 'string') return
      const evt = parseEvent(data)
      if (!evt) return
      this.dispatch(evt)
    }

    socket.onerror = () => {
      // onclose handles reconnect; nothing to do here.
    }

    socket.onclose = () => {
      this._connected = false
      this.stopHeartbeat()
      this.socket = null
      if (!this.explicitlyClosed) {
        this.scheduleReconnect()
      }
    }
  }

  private dispatch(event: RealtimeEvent): void {
    const exact = this.listeners.get(event.type)
    if (exact) {
      for (const cb of exact) {
        try {
          cb(event)
        } catch (err) {
          console.error('[ws] listener error', err)
        }
      }
    }
    const wild = this.listeners.get('*')
    if (wild) {
      for (const cb of wild) {
        try {
          cb(event)
        } catch (err) {
          console.error('[ws] listener error', err)
        }
      }
    }
  }

  private flushQueue(): void {
    if (!this.socket || !this._connected) return
    const queued = this.outboundQueue.splice(0)
    for (const msg of queued) {
      try {
        this.socket.send(JSON.stringify(msg))
      } catch {
        // requeue and bail
        this.outboundQueue.unshift(msg)
        return
      }
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(() => {
      if (this.socket && this._connected) {
        try {
          this.socket.send(JSON.stringify({ action: 'ping' }))
        } catch {
          /* swallow; reconnect path will handle */
        }
      }
    }, HEARTBEAT_INTERVAL_MS)
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  private scheduleReconnect(): void {
    if (this.explicitlyClosed) return
    this.clearReconnect()
    const delay = Math.min(
      RECONNECT_MAX_MS,
      RECONNECT_BASE_MS * 2 ** this.reconnectAttempts,
    )
    this.reconnectAttempts += 1
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.openSocket()
    }, delay)
  }

  private clearReconnect(): void {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }
}

// Test-only helpers — exported under a namespace so production code does not
// reach into reconnect math accidentally.
export const __wsInternals = {
  RECONNECT_BASE_MS,
  RECONNECT_MAX_MS,
  HEARTBEAT_INTERVAL_MS,
  parseEvent,
  defaultUrl,
}
