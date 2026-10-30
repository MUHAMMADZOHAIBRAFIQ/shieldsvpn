import type { ReactNode } from 'react'
import type { Account } from './bridge'
import { formatDate } from './format'
import {
  IconClose,
  IconCrown,
  IconDoc,
  IconImport,
  IconLogout,
  IconPlay,
  IconShieldCheck,
  IconTrash,
  IconUser,
  ShieldLogo,
} from './icons'

export type ProAction = 'signUp' | 'choose' | 'manage' | 'none'

export interface ProEntry {
  title: string
  detail: string
  action: ProAction
  /** Pro is already on (the entry is a status, not an offer). */
  active: boolean
}

/**
 * The "Sign up for Pro" entry at the top of the menu, as a pure function of the account (unit-tested).
 * Pro is tied to an account, so a signed-out user is sent to sign-up first; a signed-in one picks a plan.
 */
export function proEntry(a: Account, hasProfile: boolean): ProEntry {
  const offer = (detail: string, action: ProAction): ProEntry => ({ title: 'Sign up for Pro', detail, action, active: false })
  if (a.plan === 'premium' && a.known) {
    const until = a.proUntil ? `Active until ${formatDate(a.proUntil)}` : 'Active'
    return { title: 'ShieldsVPN Pro', detail: until, action: a.payments ? 'manage' : 'none', active: true }
  }
  if (!a.available) {
    if (!a.portal) return offer('Not available in this version of the app', 'none')   // profile-file builds
    if (!hasProfile) return offer(a.busy ? 'Setting up this phone…' : 'Tap Connect once to set up this phone', 'none')
    return offer('Not available with an imported profile', 'none')
  }
  if (!a.known) return offer(a.busy ? 'Checking your plan…' : 'Waiting for the server', 'none')
  if (!a.accounts) return offer('Coming soon', 'none')
  // Prices come shortest period first (week, month, year): "from" the first one.
  const price = a.prices.length ? a.prices[0].label : a.priceLabel
  const detail = price ? `No ads · unlimited time · from ${price}` : 'No ads · unlimited time'
  if (!a.signedIn) return offer(detail, 'signUp')
  if (!a.payments) return offer('Payments are not available yet', 'none')
  return offer(detail, 'choose')
}

export interface MenuProps {
  account: Account
  hasProfile: boolean
  /** Profile files may be imported (direct builds; the Play build only registers itself). */
  imports: boolean
  locked: boolean
  onClose: () => void
  onPro: (action: ProAction) => void
  onWatchAd: () => void
  onSignIn: () => void
  onSignOut: () => void
  onDeleteAccount: () => void
  onImport: () => void
  onVpnSettings: () => void
  onPrivacy: () => void
  /** Shows the User Agreement (read only). */
  onTerms?: () => void
}

/** The side menu behind the ☰ button: Pro first, then the account, the Android settings and the policies. */
export function Menu(props: MenuProps) {
  const { account: a } = props
  const pro = proEntry(a, props.hasProfile)
  const free = a.available && a.known && a.plan !== 'premium'
  const run = (fn: () => void) => () => {
    props.onClose()
    fn()
  }
  return (
    <div className="scrim scrim--side" onClick={props.onClose}>
      <nav className="drawer" aria-label="Menu" onClick={(e) => e.stopPropagation()}>
        <div className="drawer__head">
          <ShieldLogo size={36} />
          <div className="drawer__title">
            <b>
              Shields<span>VPN</span>
            </b>
            <small>{a.signedIn ? a.email : a.plan === 'premium' && a.known ? 'Pro plan' : 'Free plan · no account needed'}</small>
          </div>
          <button type="button" className="iconbtn iconbtn--small" aria-label="Close menu" onClick={props.onClose}>
            <IconClose />
          </button>
        </div>

        <button type="button" className={`pro-card${pro.active ? ' pro-card--active' : ''}`}
          disabled={pro.action === 'none' || a.busy} onClick={run(() => props.onPro(pro.action))}>
          <span className="pro-card__title">
            <IconCrown />
            {pro.title}
          </span>
          <span className="pro-card__detail">{pro.detail}</span>
          {pro.action === 'manage' && <span className="pro-card__cta">Manage subscription</span>}
        </button>

        {free && a.ads && a.rewardsLeft > 0 && (
          <MenuItem icon={<IconPlay />} label={`Get ${a.freeMinutes} free minutes`} detail="Watch a short ad"
            disabled={a.busy} onClick={run(props.onWatchAd)} />
        )}

        {a.available && a.known && a.accounts && (
          <section className="menu__section" aria-label="Account">
            <h3>Account</h3>
            {a.signedIn ? (
              <>
                <MenuItem icon={<IconLogout />} label="Sign out" detail={a.email} disabled={a.busy}
                  onClick={run(props.onSignOut)} />
                <MenuItem icon={<IconTrash />} label="Delete account" danger disabled={a.busy}
                  onClick={run(props.onDeleteAccount)} />
              </>
            ) : (
              <MenuItem icon={<IconUser />} label="Sign in" detail="Already have Pro? Sign in here" disabled={a.busy}
                onClick={run(props.onSignIn)} />
            )}
          </section>
        )}

        <section className="menu__section" aria-label="Settings">
          <h3>Settings</h3>
          <MenuItem icon={<IconShieldCheck />} label="Kill switch" detail="Android VPN settings"
            onClick={run(props.onVpnSettings)} />
          {props.imports && (
            <MenuItem icon={<IconImport />} label="Import a profile file" detail="From your ShieldsVPN portal"
              disabled={props.locked} onClick={run(props.onImport)} />
          )}
        </section>

        <section className="menu__section" aria-label="About">
          <h3>About</h3>
          {props.onTerms && <MenuItem icon={<IconDoc />} label="User agreement" onClick={run(props.onTerms)} />}
          {a.privacy && <MenuItem icon={<IconDoc />} label="Privacy policy" onClick={run(props.onPrivacy)} />}
        </section>

        <div className="drawer__foot">
          <span>ML-KEM</span>
          <span>ML-DSA</span>
          <span>SLH-DSA</span>
        </div>
      </nav>
    </div>
  )
}

function MenuItem(props: {
  icon: ReactNode
  label: string
  detail?: string
  danger?: boolean
  disabled?: boolean
  onClick: () => void
}) {
  return (
    <button type="button" className={`menu__item${props.danger ? ' menu__item--danger' : ''}`} disabled={props.disabled}
      onClick={props.onClick}>
      <span className="menu__icon">{props.icon}</span>
      <span className="menu__text">
        {props.label}
        {props.detail && <small>{props.detail}</small>}
      </span>
    </button>
  )
}
