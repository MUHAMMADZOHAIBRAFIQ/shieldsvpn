/**
 * A stand-in for the Android app, used when the UI runs in a normal browser (`npm run dev`).
 * It walks through the same states the real VpnService reports, so the UI can be designed and
 * checked without a phone.  Never used inside the app.
 */
import { type Account, type Bridge, type Inbound, type Outbound, type VpnState, initialState, noAccount } from './bridge'

const demoProfile = {
  account: 'alice',
  server: 'vpn.example.com:51820',
  serverName: 'vpn.example.com',
  tunnelAddress: '10.66.0.2/32',
  expires: Math.floor(Date.now() / 1000) + 76 * 86400,
  fullTunnel: false,
  encryption: 'ML-KEM-768 + X25519 · ChaCha20-Poly1305',
  portalUrl: 'https://vpn.example.com/',
  enrolled: true,
}

export function mockBridge(): Bridge {
  const listeners = new Set<(msg: Inbound) => void>()
  // `npm run dev` + ?fresh: a first start of a portal build (no profile yet; the first tap registers the phone).
  const fresh = new URLSearchParams(window.location.search).has('fresh')
  let state: VpnState = { ...initialState, profile: fresh ? null : demoProfile, permissionNeeded: true }
  let rx = 0
  let tx = 0
  let timers: number[] = []
  let account: Account = {
    ...noAccount, available: true, portal: true, privacy: true, known: true, at: Date.now(), freeSecondsLeft: 4 * 60,
    canConnect: true, rewardsLeft: 15, accounts: true, ads: true, payments: true, priceLabel: 'USD 4.99 / month',
    prices: [
      { period: 'week', name: 'Weekly', label: 'USD 1.99 / week' },
      { period: 'month', name: 'Monthly', label: 'USD 4.99 / month' },
      { period: 'year', name: 'Yearly', label: 'USD 39.99 / year' },
    ],
  }

  const emit = (msg: Inbound) => listeners.forEach((l) => l(msg))
  const set = (patch: Partial<VpnState>) => {
    state = { ...state, ...patch }
    emit({ type: 'state', state })
  }
  const later = (ms: number, fn: () => void) => timers.push(window.setTimeout(fn, ms))
  const setAccount = (patch: Partial<Account>) => {
    account = { ...account, ...patch }
    emit({ type: 'account', account })
  }
  const busyThen = (ms: number, fn: () => void) => {
    setAccount({ busy: true })
    window.setTimeout(() => {
      setAccount({ busy: false })
      fn()
    }, ms)
  }
  const ok = (op: string) => emit({ type: 'accountResult', op, ok: true, code: '', message: '' })
  const left = () => Math.max(0, account.freeSecondsLeft - Math.floor((Date.now() - account.at) / 1000))
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
        emit({ type: 'account', account })
        emit({ type: 'terms', accepted: !fresh, version: '2026-10-31' })   // a fresh install asks first
        break
      case 'acceptTerms':
        emit({ type: 'terms', accepted: true, version: msg.version })
        break
      case 'declineTerms':
        emit({ type: 'notice', kind: 'error', title: 'Declined', text: 'The app closes when you decline.' })
        break
      case 'watchAd':
        busyThen(1500, () => {
          setAccount({ freeSecondsLeft: left() + account.freeMinutes * 60, at: Date.now(), rewardsLeft: account.rewardsLeft - 1 })
          emit({ type: 'notice', kind: 'ok', title: 'Free time', text: `You have ${account.freeMinutes} more minutes.` })
        })
        break
      case 'signIn':
      case 'verifyEmail':
        busyThen(700, () => {
          setAccount({ signedIn: true, email: msg.type === 'signIn' ? msg.login : msg.email })
          ok(msg.type)
        })
        break
      case 'signUp':
      case 'forgotPassword':
      case 'resetPassword':
        busyThen(700, () => ok(msg.type))
        break
      case 'signOut':
        setAccount({ signedIn: false, email: '', plan: 'free', proUntil: null })
        break
      case 'goPro':
        if (!account.signedIn) {
          emit({ type: 'accountResult', op: 'goPro', ok: false, code: 'sign_in_required',
            message: 'Pro is tied to your account: sign in or create one first.' })
        } else {
          busyThen(1200, () => setAccount({ plan: 'premium', proUntil: Math.floor(Date.now() / 1000) + 30 * 86400 }))
        }
        break
      case 'manageSubscription':
      case 'refreshAccount':
      case 'openPrivacy':
        break
      case 'deleteAccount':
        busyThen(700, () => {
          setAccount({ signedIn: false, email: '', plan: 'free', proUntil: null })
          ok('deleteAccount')
        })
        break
      case 'connect':
        if (state.profile) connect()
        else busyThen(900, () => {   // a portal build registers the phone on the first tap
          set({ profile: demoProfile })
          connect()
        })
        break
      case 'overlay':
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
