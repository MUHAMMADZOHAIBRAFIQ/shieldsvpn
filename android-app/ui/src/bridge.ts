/**
 * The message bridge between this UI and the Kotlin app (MainActivity).
 *
 * Inside the app, androidx.webkit injects `window.ShieldsBridge` only for our own origin
 * (https://appassets.androidplatform.net).  Messages are JSON strings in both directions:
 *
 *   UI  -> app : { type: 'ready' | 'connect' | 'disconnect' | 'importProfile' | 'removeProfile' | 'openPortal' }
 *   app -> UI  : { type: 'state', state } | { type: 'traffic', rx, tx, at } | { type: 'notice', ... }
 *                | { type: 'insets', top, bottom, left, right }
 *
 * The UI never sees keys or certificates: the app sends display data only.
 */

export type Phase =
  | 'disconnected'
  | 'preparing'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'error'
  | 'disconnecting'

export interface Profile {
  account: string
  server: string
  serverName: string
  tunnelAddress: string
  /** Certificate expiry, Unix seconds. */
  expires: number
  fullTunnel: boolean
  encryption: string
  portalUrl: string
  /** Signature algorithm of the client certificate, e.g. ML-DSA-65. */
  keyAlg?: string
}

export interface VpnState {
  phase: Phase
  /** A session is running in the VPN service (the button means "Disconnect"). */
  active: boolean
  message: string
  server: string
  endpoint: string
  tunnelAddress: string
  encryption: string
  keyAlg: string
  routes: string[]
  dns: string[]
  fullTunnel: boolean
  /** When the tunnel first came up, Unix milliseconds; 0 when not connected. */
  connectedSince: number
  importing: boolean
  /** Android's VPN consent has not been given yet (the system will ask on Connect). */
  permissionNeeded: boolean
  /** Android always-on VPN for this app; null = unknown (only the running service can read it). */
  alwaysOn: boolean | null
  /** Android "Block connections without VPN" (the system kill switch); null = unknown. */
  lockdown: boolean | null
  profile: Profile | null
}

export interface Traffic {
  /** Bytes received from the tunnel (download). */
  rx: number
  /** Bytes sent into the tunnel (upload). */
  tx: number
  /** Sample time, Unix milliseconds. */
  at: number
}

export interface Notice {
  kind: 'ok' | 'error'
  title: string
  text: string
}

export interface Insets {
  top: number
  bottom: number
  left: number
  right: number
}

export type Inbound =
  | { type: 'state'; state: VpnState }
  | ({ type: 'traffic' } & Traffic)
  | ({ type: 'notice' } & Notice)
  | ({ type: 'insets' } & Insets)

export type Outbound = {
  type: 'ready' | 'connect' | 'disconnect' | 'importProfile' | 'removeProfile' | 'openPortal' | 'openVpnSettings'
}

export interface Bridge {
  readonly native: boolean
  send(msg: Outbound): void
  subscribe(listener: (msg: Inbound) => void): () => void
}

export const initialState: VpnState = {
  phase: 'disconnected',
  active: false,
  message: '',
  server: '',
  endpoint: '',
  tunnelAddress: '',
  encryption: '',
  keyAlg: '',
  routes: [],
  dns: [],
  fullTunnel: false,
  connectedSince: 0,
  importing: false,
  permissionNeeded: false,
  alwaysOn: null,
  lockdown: null,
  profile: null,
}

/** The object androidx.webkit's addWebMessageListener injects (a subset of the MessagePort API). */
export interface NativePort {
  postMessage(data: string): void
  onmessage: ((event: { data: unknown }) => void) | null
}

const PHASES: readonly Phase[] = [
  'disconnected', 'preparing', 'connecting', 'connected', 'reconnecting', 'error', 'disconnecting',
]

/** Parses one inbound message; anything malformed is dropped instead of crashing the UI. */
export function parseInbound(data: unknown): Inbound | null {
  if (typeof data !== 'string') return null
  let msg: unknown
  try {
    msg = JSON.parse(data)
  } catch {
    return null
  }
  if (typeof msg !== 'object' || msg === null || !('type' in msg)) return null
  const m = msg as Record<string, unknown>
  switch (m.type) {
    case 'state': {
      const s = { ...initialState, ...(m.state as Partial<VpnState>) }
      if (!PHASES.includes(s.phase)) return null
      const tri = (v: unknown) => (v === true || v === false ? v : null)
      s.alwaysOn = tri(s.alwaysOn)
      s.lockdown = tri(s.lockdown)
      return { type: 'state', state: s }
    }
    case 'traffic':
      return typeof m.rx === 'number' && typeof m.tx === 'number' && typeof m.at === 'number'
        ? { type: 'traffic', rx: m.rx, tx: m.tx, at: m.at }
        : null
    case 'notice':
      return (m.kind === 'ok' || m.kind === 'error') && typeof m.text === 'string'
        ? { type: 'notice', kind: m.kind, title: String(m.title ?? ''), text: m.text }
        : null
    case 'insets':
      return {
        type: 'insets',
        top: Number(m.top) || 0,
        bottom: Number(m.bottom) || 0,
        left: Number(m.left) || 0,
        right: Number(m.right) || 0,
      }
    default:
      return null
  }
}

export function nativeBridge(port: NativePort): Bridge {
  const listeners = new Set<(msg: Inbound) => void>()
  port.onmessage = (event) => {
    const msg = parseInbound(event.data)
    if (msg) listeners.forEach((l) => l(msg))
  }
  return {
    native: true,
    send: (msg) => port.postMessage(JSON.stringify(msg)),
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
  }
}
