import type { ReactNode } from 'react'
import type { Profile, VpnState } from './bridge'
import {
  daysLeft,
  encryptionParts,
  formatBytes,
  formatDate,
  formatDuration,
  formatRate,
  phaseInfo,
  subtitle,
} from './format'
import {
  IconAlert,
  IconClock,
  IconDown,
  IconExternal,
  IconGlobe,
  IconId,
  IconImport,
  IconLock,
  IconPin,
  IconRoute,
  IconServer,
  IconTrash,
  IconUp,
  ShieldLogo,
} from './icons'
import { PowerButton } from './PowerButton'

export interface TrafficView {
  down: number
  up: number
  downRate: number
  upRate: number
  /** Recent download / upload rates (bytes/s), oldest first, for the sparklines. */
  downHistory: number[]
  upHistory: number[]
}

export interface ScreenProps {
  state: VpnState
  traffic: TrafficView
  now: number
  onPower: () => void
  onImport: () => void
  onRemove: () => void
  onOpenPortal: () => void
  onOpenVpnSettings: () => void
  /** True when running in a browser against the simulated bridge (npm run dev): numbers are not real. */
  demo?: boolean
}

/** The whole app screen, as a pure function of the state (unit-tested with renderToString). */
export function Screen(props: ScreenProps) {
  const { state, traffic, now, onPower, onImport, onRemove, onOpenPortal, onOpenVpnSettings, demo } = props
  const info = phaseInfo(state.phase)
  const profile = state.profile
  const live = state.phase === 'connected' || (state.phase === 'reconnecting' && state.tunnelAddress !== '')
  const buttonLabel = state.active ? 'Disconnect' : profile ? 'Connect' : 'Import a profile'

  return (
    <div className={`app tone-${info.tone}`}>
      <div className="backdrop" aria-hidden="true" />
      <header className="top">
        <div className="brand">
          <ShieldLogo size={30} />
          <span>
            Shields<b>VPN</b>
          </span>
        </div>
        <span className={`pill pill--${info.tone}`}>
          <i className="pill__dot" aria-hidden="true" />
          {info.label}
        </span>
      </header>

      <main>
        {demo && (
          <div className="demo" role="note">
            Demo mode: simulated connection and traffic (not a real VPN).
          </div>
        )}
        <section className="hero">
          <PowerButton
            tone={info.tone}
            busy={info.busy}
            label={buttonLabel}
            disabled={state.phase === 'disconnecting' || state.importing}
            onPress={onPower}
          />
          <h1 aria-live="polite">{info.label}</h1>
          <p className="sub">{subtitle(state.phase, state.active, profile !== null, state.importing)}</p>
          {state.phase === 'connected' && state.connectedSince > 0 && (
            <div className="timer" aria-label="Connected for">
              <IconClock />
              {formatDuration(now - state.connectedSince)}
            </div>
          )}
          {state.permissionNeeded && profile && !state.active && (
            <p className="hint">The first time you connect, Android asks you to allow ShieldsVPN to set up a VPN.</p>
          )}
        </section>

        {state.phase === 'error' && state.message && (
          <div className="alert" role="alert">
            <IconAlert />
            <span>{state.message}</span>
          </div>
        )}

        {profile ? (
          <>
            <section className="traffic" aria-label="Traffic">
              <TrafficCard icon={<IconDown />} label="Download" total={traffic.down} rate={traffic.downRate}
                active={live} history={traffic.downHistory} />
              <TrafficCard icon={<IconUp />} label="Upload" total={traffic.up} rate={traffic.upRate}
                active={live} history={traffic.upHistory} variant="up" />
            </section>
            <Details state={state} profile={profile} live={live} />
            <KillSwitch state={state} onOpenVpnSettings={onOpenVpnSettings} />
            <ProfileCard profile={profile} now={now} locked={state.active || state.importing}
              onImport={onImport} onRemove={onRemove} onOpenPortal={onOpenPortal} />
          </>
        ) : (
          <EmptyState importing={state.importing} onImport={onImport} />
        )}
      </main>

      <footer className="foot">
        <span>ML-KEM</span>
        <span>ML-DSA</span>
        <span>SLH-DSA</span>
        <span>post-quantum</span>
      </footer>
    </div>
  )
}

function TrafficCard(props: {
  icon: ReactNode
  label: string
  total: number
  rate: number
  active: boolean
  history: number[]
  variant?: 'up'
}) {
  return (
    <div className={`card stat${props.variant ? ' stat--up' : ''}${props.active ? '' : ' stat--idle'}`}>
      <div className="stat__head">
        <span className="stat__icon">{props.icon}</span>
        {props.label}
      </div>
      <div className="stat__rate">{props.active ? formatRate(props.rate) : '—'}</div>
      <div className="stat__total">{formatBytes(props.total)} total</div>
      <Sparkline values={props.active ? props.history : []} />
    </div>
  )
}

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <svg className="spark" viewBox="0 0 100 24" aria-hidden="true" />
  const max = Math.max(...values, 1)
  const step = 100 / (values.length - 1)
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(22 - (v / max) * 20).toFixed(1)}`).join(' ')
  return (
    <svg className="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={`0,24 ${points} 100,24`} className="spark__area" />
      <polyline points={points} className="spark__line" />
    </svg>
  )
}

function Row({ icon, label, children }: { icon: ReactNode; label: string; children: ReactNode }) {
  return (
    <div className="row">
      <span className="row__icon">{icon}</span>
      <span className="row__label">{label}</span>
      <span className="row__value">{children}</span>
    </div>
  )
}

function Details({ state, profile, live }: { state: VpnState; profile: Profile; live: boolean }) {
  const parts = encryptionParts(state.encryption || profile.encryption)
  const full = live ? state.fullTunnel : profile.fullTunnel
  return (
    <section className="card details" aria-label="Connection details">
      <h2>Connection</h2>
      <Row icon={<IconServer />} label="Server">
        <span>{state.server || profile.serverName}</span>
        <small>{state.endpoint || profile.server}</small>
      </Row>
      <Row icon={<IconPin />} label="Tunnel IP">
        <span className="mono">{live ? state.tunnelAddress : profile.tunnelAddress.split('/')[0]}</span>
        {!live && <small>assigned when you connect</small>}
      </Row>
      <Row icon={<IconLock />} label="Encryption">
        <span className="chips">
          {parts.map((p) => (
            <i key={p} className="chip">{p}</i>
          ))}
        </span>
      </Row>
      <Row icon={<IconId />} label="Identity">
        <span>{state.keyAlg || profile.keyAlg || 'ML-DSA'} certificate</span>
      </Row>
      <Row icon={<IconRoute />} label="Routing">
        <span>{full ? 'All traffic' : 'Split tunnel'}</span>
        <small>{full ? 'full tunnel; IPv6 blocked unless the tunnel has it' : live ? state.routes.join(', ') : 'networks set by the server'}</small>
      </Row>
      {live && (
        <Row icon={<IconGlobe />} label="DNS">
          <span className="mono">{state.dns.length ? state.dns.join(', ') : 'device default'}</span>
        </Row>
      )}
    </section>
  )
}

/**
 * Android -- not this app -- can block every connection while the tunnel is down ("Block connections without
 * VPN" with always-on VPN).  Show what the running service reported, and never claim protection it cannot see.
 */
function KillSwitch({ state, onOpenVpnSettings }: { state: VpnState; onOpenVpnSettings: () => void }) {
  let tone: 'ok' | 'warn' | 'off'
  let text: string
  if (state.lockdown === true) {
    tone = 'ok'
    text = 'On. Android blocks all traffic whenever the VPN is not connected.'
  } else if (state.alwaysOn === true) {
    tone = 'warn'
    text = 'Always-on is set, but traffic is not blocked while the tunnel is down.'
  } else if (state.lockdown === false) {
    tone = 'warn'
    text = 'Off. While the VPN is disconnected or starting, apps use your normal connection.'
  } else {
    tone = 'off'
    text = 'Set in Android: turn on "Always-on VPN" and "Block connections without VPN" for ShieldsVPN.'
  }
  const label = tone === 'ok' ? 'On' : tone === 'warn' ? 'Off' : 'Android setting'
  return (
    <section className="card killswitch" aria-label="Kill switch">
      <div className="killswitch__head">
        <h2>Kill switch</h2>
        <span className={`tag tag--${tone}`}>{label}</span>
      </div>
      <p className="note">{text}</p>
      <div className="actions">
        <button type="button" className="btn btn--ghost" onClick={onOpenVpnSettings}>
          <IconExternal /> Android VPN settings
        </button>
      </div>
    </section>
  )
}

function ProfileCard(props: {
  profile: Profile
  now: number
  locked: boolean
  onImport: () => void
  onRemove: () => void
  onOpenPortal: () => void
}) {
  const { profile, now, locked } = props
  const days = daysLeft(profile.expires, now)
  const validity = days < 0 ? 'expired' : days === 0 ? 'expires today' : `${days} day${days === 1 ? '' : 's'} left`
  const tone = days < 0 ? 'error' : days < 14 ? 'warn' : 'ok'
  return (
    <section className="card profile" aria-label="Profile">
      <div className="profile__head">
        <span className="avatar" aria-hidden="true">{profile.account.slice(0, 1).toUpperCase()}</span>
        <div>
          <div className="profile__name">{profile.account}</div>
          <div className="profile__server">{profile.serverName}</div>
        </div>
      </div>
      <div className={`validity validity--${tone}`}>
        Valid until {formatDate(profile.expires)} · {validity}
      </div>
      {locked && <p className="note">Disconnect to change the profile.</p>}
      <div className="actions">
        <button type="button" className="btn btn--ghost" disabled={locked} onClick={props.onImport}>
          <IconImport /> Replace
        </button>
        {profile.portalUrl && (
          <button type="button" className="btn btn--ghost" onClick={props.onOpenPortal}>
            <IconExternal /> Portal
          </button>
        )}
        <button type="button" className="btn btn--danger" disabled={locked} onClick={props.onRemove}>
          <IconTrash /> Remove
        </button>
      </div>
    </section>
  )
}

function EmptyState({ importing, onImport }: { importing: boolean; onImport: () => void }) {
  return (
    <section className="card empty" aria-label="Set up">
      <h2>Set up ShieldsVPN</h2>
      <ol className="steps">
        <li>
          <b>Sign in</b> to your ShieldsVPN portal.
        </li>
        <li>
          <b>Download</b> your VPN profile (a .zip file).
        </li>
        <li>
          <b>Import</b> it here. Your private key stays on this phone, encrypted by the Android Keystore.
        </li>
      </ol>
      <button type="button" className="btn btn--primary btn--wide" disabled={importing} onClick={onImport}>
        <IconImport /> {importing ? 'Checking…' : 'Import profile'}
      </button>
    </section>
  )
}
