/**
 * A stand-in for the Android app, used when the UI runs in a normal browser (`npm run dev`).
 * It walks through the same states the real VpnService reports, so the UI can be designed and
 * checked without a phone.  Never used inside the app.
 */
import { type Bridge, type Inbound, type Outbound, type VpnState, initialState } from './bridge'

const demoProfile = {
  account: 'alice',
  server: 'vpn.example.com:51820',
  serverName: 'vpn.example.com',
  tunnelAddress: '10.66.0.2/32',
  expires: Math.floor(Date.now() / 1000) + 76 * 86400,
  fullTunnel: false,
  encryption: 'ML-KEM-768 + X25519 · ChaCha20-Poly1305',
  portalUrl: 'https://vpn.example.com/',
}

export function mockBridge(): Bridge {
  const listeners = new Set<(msg: Inbound) => void>()
  let state: VpnState = { ...initialState, profile: demoProfile, permissionNeeded: true }
  let rx = 0
  let tx = 0
  let timers: number[] = []

  const emit = (msg: Inbound) => listeners.forEach((l) => l(msg))
  const set = (patch: Partial<VpnState>) => {
    state = { ...state, ...patch }
    emit({ type: 'state', state })
  }
  const later = (ms: number, fn: () => void) => timers.push(window.setTimeout(fn, ms))
  const clear = () => {
    timers.forEach((t) => window.clearTimeout(t))
    timers = []
  }

  const connect = () => {
    clear()
    set({ phase: 'preparing', active: true, message: '' })
    later(700, () => set({ phase: 'connecting', server: 'vpn.example.com', endpoint: '203.0.113.10:51820' }))
    later(1900, () => {
      set({
        phase: 'connected',
        permissionNeeded: false,
        tunnelAddress: '10.66.0.2/24',
        encryption: 'ML-KEM-768 + X25519 · ChaCha20-Poly1305',
        keyAlg: 'ML-DSA-65',
        routes: ['10.66.0.0/24'],
        dns: ['10.66.0.1'],
        connectedSince: Date.now(),
      })
      const tick = () => {
        rx += 20_000 + Math.random() * 180_000
        tx += 4_000 + Math.random() * 30_000
        emit({ type: 'traffic', rx: Math.round(rx), tx: Math.round(tx), at: Date.now() })
        timers.push(window.setTimeout(tick, 1000))
      }
      tick()
    })
  }

  const handle = (msg: Outbound) => {
    switch (msg.type) {
      case 'ready':
        emit({ type: 'state', state })
        break
      case 'connect':
        connect()
        break
      case 'disconnect':
        clear()
        set({ phase: 'disconnecting' })
        later(400, () => {
          rx = tx = 0
          set({ ...initialState, profile: state.profile })
        })
        break
      case 'importProfile':
        set({ importing: true })
        later(900, () => {
          set({ importing: false, profile: demoProfile })
          emit({ type: 'notice', kind: 'ok', title: 'Profile installed', text: 'Profile for alice installed.' })
        })
        break
      case 'removeProfile':
        set({ ...initialState, profile: null })
        break
      case 'openPortal':
        window.open(state.profile?.portalUrl ?? '#', '_blank', 'noopener')
        break
      case 'openVpnSettings':
        set({ alwaysOn: true, lockdown: !state.lockdown }) // demo only: pretend the user toggled it
        break
    }
  }

  return {
    native: false,
    send: (msg) => window.setTimeout(() => handle(msg), 0),
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
  }
}
