/**
 * The message bridge between this UI and the Kotlin app (MainActivity).
 *
 * Inside the app, androidx.webkit injects `window.ShieldsBridge` only for our own origin
 * (https://appassets.androidplatform.net).  Messages are JSON strings in both directions:
 *
 *   UI  -> app : { type: 'ready' | 'connect' | 'disconnect' | 'importProfile' | 'removeProfile' | 'openPortal' }
 *                | account commands: 'watchAd', 'signIn' {login, password, code}, 'signUp' {email, password},
 *                  'verifyEmail' {email, code}, 'forgotPassword' {login}, 'resetPassword' {login, code, password},
 *                  'signOut', 'goPro' {period}, 'manageSubscription', 'refreshAccount',
 *                  'deleteAccount' {password, code}, 'openPrivacy'
 *                | { type: 'overlay', open }  (a menu or sheet is open: Android's Back closes it instead of the app)
 *                | { type: 'acceptTerms', version } | { type: 'declineTerms' }  (the User Agreement, terms.ts)
 *   app -> UI  : { type: 'state', state } | { type: 'traffic', rx, tx, at } | { type: 'notice', ... }
 *                | { type: 'insets', top, bottom, left, right }
 *                | { type: 'account', account } | { type: 'accountResult', op, ok, code, message }
 *                | { type: 'back' }  (Back was pressed while an overlay was open)
 *                | { type: 'terms', accepted, version }  (whether this installation accepted the User Agreement)
 *
 * The UI never sees keys, certificates or tokens: the app sends display data only.  (What the user types into
 * the sign-in forms goes the other way, to the app, which sends it to the portal over TLS.)
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
  /** Registered by the app itself (Free with ads / Pro) rather than imported from a ZIP file. */
  enrolled?: boolean
}

export type Period = 'week' | 'month' | 'year'

/** One Pro plan on sale, as priced by the administrator. */
export interface PriceOption {
  period: Period
  /** "Weekly", "Monthly", "Yearly". */
  name: string
  /** e.g. "USD 4.99 / month". */
  label: string
}

/** The plan card: Free time from ads, or Pro through a signed-in account. */
export interface Account {
  /** This app talks to a portal and the profile is its own registration (else no plan card). */
  available: boolean
  /** This build registers itself with a portal (first start needs no profile file). */
  portal: boolean
  /** Profile files may be imported (not in the Play Store build, which only registers itself). */
  imports: boolean
  /** A privacy-policy link exists (required in the Play Store build). */
  privacy: boolean
  /** A request to the portal is running. */
  busy: boolean
  /** The portal has answered at least once. */
  known: boolean
  /** When freeSecondsLeft was measured, Unix ms (the UI counts down from here). */
  at: number
  plan: 'free' | 'premium'
  freeSecondsLeft: number
  /** End of the paid Pro period, Unix seconds; null = no end date. */
  proUntil: number | null
  signedIn: boolean
  email: string
  canConnect: boolean
  reason: string
  rewardsLeft: number
  /** Seconds until the next ad for free time may start, measured at `at` (ads may follow each other). */
  nextAdIn: number
  freeMinutes: number
  /** The portal allows sign-in / sign-up from the app. */
  accounts: boolean
  /** Rewarded ads are on. */
  ads: boolean
  /** Pro can be bought. */
  payments: boolean
  priceLabel: string
  /** Pro plans on sale (weekly / monthly / yearly); empty = the portal's single default plan. */
  prices: PriceOption[]
}

export interface AccountResult {
  op: string
  ok: boolean
  code: string
  message: string
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
  | { type: 'account'; account: Account }
  | ({ type: 'accountResult' } & AccountResult)
  | { type: 'back' }
  | { type: 'terms'; accepted: boolean; version: string }

export type Outbound =
  | {
      type: 'ready' | 'connect' | 'disconnect' | 'importProfile' | 'removeProfile' | 'openPortal' | 'openVpnSettings'
        | 'watchAd' | 'signOut' | 'manageSubscription' | 'refreshAccount' | 'openPrivacy'
    }
  | { type: 'goPro'; period: Period | '' }
  | { type: 'overlay'; open: boolean }
  | { type: 'acceptTerms'; version: string }
  | { type: 'declineTerms' }
  | { type: 'deleteAccount'; password: string; code: string }
  | { type: 'signIn'; login: string; password: string; code: string }
  | { type: 'signUp'; email: string; password: string }
  | { type: 'verifyEmail'; email: string; code: string }
  | { type: 'forgotPassword'; login: string }
  | { type: 'resetPassword'; login: string; code: string; password: string }

export const noAccount: Account = {
  available: false,
  portal: false,
  imports: true,
  privacy: false,
  busy: false,
  known: false,
  at: 0,
  plan: 'free',
  freeSecondsLeft: 0,
  proUntil: null,
  signedIn: false,
  email: '',
  canConnect: false,
  reason: '',
  rewardsLeft: 0,
  nextAdIn: 0,
  freeMinutes: 30,
  accounts: false,
  ads: false,
  payments: false,
  priceLabel: '',
  prices: [],
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
    case 'account':
      return typeof m.account === 'object' && m.account !== null
        ? { type: 'account', account: parseAccount(m.account as Record<string, unknown>) }
        : null
    case 'accountResult':
      return typeof m.op === 'string' && typeof m.ok === 'boolean'
        ? { type: 'accountResult', op: m.op, ok: m.ok, code: String(m.code ?? ''), message: String(m.message ?? '') }
        : null
    case 'back':
      return { type: 'back' }
    case 'terms':
      return typeof m.accepted === 'boolean' && typeof m.version === 'string' && m.version.length <= 32
        ? { type: 'terms', accepted: m.accepted, version: m.version }
        : null
    default:
      return null
  }
}

/** Field by field, with safe defaults: a malformed value never reaches the screen. */
function parseAccount(a: Record<string, unknown>): Account {
  const num = (v: unknown, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : d)
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  return {
    available: a.available === true,
    portal: a.portal === true,
    imports: a.imports !== false,
    privacy: a.privacy === true,
    busy: a.busy === true,
    known: a.known === true,
    at: num(a.at),
    plan: a.plan === 'premium' ? 'premium' : 'free',
    freeSecondsLeft: Math.max(0, num(a.freeSecondsLeft)),
    proUntil: typeof a.proUntil === 'number' ? a.proUntil : null,
    signedIn: a.signedIn === true,
    email: str(a.email),
    canConnect: a.canConnect === true,
    reason: str(a.reason),
    rewardsLeft: num(a.rewardsLeft),
    nextAdIn: Math.max(0, num(a.nextAdIn)),
    freeMinutes: num(a.freeMinutes, 30),
    accounts: a.accounts === true,
    ads: a.ads === true,
    payments: a.payments === true,
    priceLabel: str(a.priceLabel),
    prices: parsePrices(a.prices),
  }
}

const PERIODS: readonly Period[] = ['week', 'month', 'year']

/** Known periods only, once each; anything else is dropped. */
function parsePrices(v: unknown): PriceOption[] {
  if (!Array.isArray(v)) return []
  const out: PriceOption[] = []
  for (const item of v) {
    if (typeof item !== 'object' || item === null) continue
    const p = item as Record<string, unknown>
    const period = p.period as Period
    if (!PERIODS.includes(period) || out.some((o) => o.period === period)) continue
    out.push({ period, name: typeof p.name === 'string' ? p.name : '', label: typeof p.label === 'string' ? p.label : '' })
  }
  return out
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
