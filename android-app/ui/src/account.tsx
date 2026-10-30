import { type FormEvent, useEffect, useRef, useState } from 'react'
import type { Account, AccountResult, Outbound, Period, PriceOption } from './bridge'
import { formatDate, formatDuration } from './format'
import { IconClock, IconCrown, IconExternal, IconTick } from './icons'

/** Free seconds left at `now`, counted down from when the app measured them. */
export function freeLeft(a: Account, now: number): number {
  return Math.max(0, a.freeSecondsLeft - Math.floor(Math.max(0, now - a.at) / 1000))
}

/**
 * The plan card (Free with ads, or Pro).  Pure: renders from the account state the app sends.
 * Free: a countdown, "Watch an ad" for more time, and Go Pro.  When the administrator sells several plans (weekly /
 * monthly / yearly) Go Pro opens the plan sheet (ProSheet) through [onChoosePlan]; without that, one button per plan.
 * Pro: unlimited, until the paid period ends.
 */
export function PlanCard(props: {
  account: Account
  now: number
  onWatchAd: () => void
  onGoPro: (period: Period | '') => void
  onChoosePlan?: () => void
  onSignIn: () => void
  onSignOut: () => void
  onManage: () => void
  onDeleteAccount?: () => void
}) {
  const { account: a, now } = props
  const pro = a.plan === 'premium'
  const left = freeLeft(a, now)
  const several = !pro && a.accounts && a.payments && a.prices.length > 1
  const sheet = several && props.onChoosePlan !== undefined
  const choosePlan = several && !sheet
  const single = a.prices.length === 1 ? a.prices[0] : null
  return (
    <section className={`card plan${pro ? ' plan--pro' : ''}`} aria-label="Your plan">
      <div className="plan__head">
        <h2>{pro ? 'ShieldsVPN Pro' : 'Free plan'}</h2>
        <span className={`tag ${pro ? 'tag--ok' : left > 0 ? 'tag--warn' : 'tag--off'}`}>
          {pro ? 'Unlimited' : left > 0 ? 'Time left' : 'No time left'}
        </span>
      </div>
      {!a.known ? (
        <p className="note">{a.busy ? 'Checking your plan…' : 'Your plan will show here once the server answers.'}</p>
      ) : pro ? (
        <p className="plan__line">
          No ads and unlimited time.
          {a.proUntil ? ` Paid until ${formatDate(a.proUntil)}.` : ''}
        </p>
      ) : (
        <>
          <div className="plan__timer" aria-label="Free time left">
            <IconClock />
            <span className="mono">{formatDuration(left * 1000)}</span>
          </div>
          {a.ads && (
            <button type="button" className="btn btn--primary btn--wide" disabled={a.busy || a.rewardsLeft <= 0}
              onClick={props.onWatchAd}>
              {a.busy ? 'Please wait…' : `Watch an ad · +${a.freeMinutes} min`}
            </button>
          )}
          {a.ads && a.rewardsLeft <= 0 && <p className="note">You used today's free sessions. Come back tomorrow, or go Pro.</p>}
          {!a.ads && <p className="note">Free time from ads is not available right now.</p>}
        </>
      )}
      {a.known && choosePlan && (
        <div className="plan__options" aria-label="Pro plans">
          {a.prices.map((p) => (
            <button key={p.period} type="button" className="btn btn--pro" disabled={a.busy}
              onClick={() => props.onGoPro(p.period)}>
              Go Pro · {p.label}
            </button>
          ))}
        </div>
      )}
      {a.known && (
        <div className="actions">
          {sheet && (
            <button type="button" className="btn btn--pro" disabled={a.busy} onClick={props.onChoosePlan}>
              Go Pro · from {a.prices[0].label}
            </button>
          )}
          {!pro && a.accounts && !several && (
            <button type="button" className="btn btn--pro" disabled={a.busy}
              onClick={() => props.onGoPro(single ? single.period : '')}>
              Go Pro{single ? ` · ${single.label}` : a.priceLabel ? ` · ${a.priceLabel}` : ''}
            </button>
          )}
          {pro && a.payments && (
            <button type="button" className="btn btn--ghost" disabled={a.busy} onClick={props.onManage}>
              <IconExternal /> Manage subscription
            </button>
          )}
          {a.accounts && !a.signedIn && (
            <button type="button" className="btn btn--ghost" disabled={a.busy} onClick={props.onSignIn}>Sign in</button>
          )}
          {a.signedIn && (
            <button type="button" className="btn btn--ghost" disabled={a.busy} onClick={props.onSignOut}>Sign out</button>
          )}
        </div>
      )}
      {a.signedIn && <p className="note">Signed in as {a.email}.</p>}
      {a.signedIn && props.onDeleteAccount && (
        <div className="actions">
          <button type="button" className="link link--danger" disabled={a.busy} onClick={props.onDeleteAccount}>
            Delete account
          </button>
        </div>
      )}
    </section>
  )
}

/** The plan the Pro sheet selects first: monthly when on sale, else the first one. */
export function defaultPeriod(prices: PriceOption[]): Period | '' {
  return (prices.find((p) => p.period === 'month') ?? prices[0])?.period ?? ''
}

/**
 * Choose a Pro plan (weekly / monthly / yearly, as the administrator priced them), then pay: in the browser
 * (Paddle) or in Google Play's own sheet (Play Store build).  Opened from the menu's "Sign up for Pro".
 */
export function ProSheet(props: {
  account: Account
  onChoose: (period: Period | '') => void
  onClose: () => void
}) {
  const { account: a } = props
  const [period, setPeriod] = useState<Period | ''>(() => defaultPeriod(a.prices))
  const chosen = a.prices.find((p) => p.period === period)
  const price = chosen ? chosen.label : a.priceLabel
  return (
    <div className="scrim" onClick={props.onClose}>
      <div className="sheet pro-sheet" role="dialog" aria-modal="true" aria-labelledby="pro-title"
        onClick={(e) => e.stopPropagation()}>
        <span className="pro-sheet__badge"><IconCrown /></span>
        <h2 id="pro-title">ShieldsVPN Pro</h2>
        <ul className="perks">
          <li><IconTick /> No ads</li>
          <li><IconTick /> Unlimited VPN time, no countdown</li>
          <li><IconTick /> Cancel anytime</li>
        </ul>
        {a.prices.length > 1 && (
          <div className="choices" role="radiogroup" aria-label="Pro plans">
            {a.prices.map((p) => (
              <button key={p.period} type="button" role="radio" aria-checked={p.period === period}
                className="choice" onClick={() => setPeriod(p.period)}>
                <span>
                  <b>{p.name || p.period}</b>
                  <small>{p.label}</small>
                </span>
                <i className="choice__dot" aria-hidden="true" />
              </button>
            ))}
          </div>
        )}
        <button type="button" className="btn btn--pro btn--wide pro-sheet__go" disabled={a.busy || !a.payments}
          onClick={() => props.onChoose(period)}>
          {a.busy ? 'Please wait…' : price ? `Continue · ${price}` : 'Continue'}
        </button>
        <div className="form__links">
          <button type="button" className="link" onClick={props.onClose}>Not now</button>
        </div>
      </div>
    </div>
  )
}

export type SheetMode = 'signIn' | 'signUp' | 'verify' | 'forgot' | 'reset' | 'delete'

const TITLES: Record<SheetMode, string> = {
  signIn: 'Sign in',
  signUp: 'Create your account',
  verify: 'Check your email',
  forgot: 'Forgot your password?',
  reset: 'Choose a new password',
  delete: 'Delete your account',
}

const DELETE_NOTE = 'This permanently deletes your ShieldsVPN account: email, password and plan. This phone stays ' +
  'on the Free plan. Deleting the account does not cancel a subscription: cancel it first with Manage subscription.'

/**
 * Sign in / create an account / verify the email / reset the password.  Pro needs an account; Free does not.
 * The forms only send what the user typed to the app; each step's outcome comes back as an accountResult.
 */
export function AccountSheet(props: {
  initial: SheetMode
  note: string
  busy: boolean
  result: AccountResult | null
  send: (msg: Outbound) => void
  onClose: () => void
}) {
  const [mode, setMode] = useState<SheetMode>(props.initial)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needCode, setNeedCode] = useState(false)
  const [message, setMessage] = useState(props.initial === 'delete' ? DELETE_NOTE : props.note)
  const [error, setError] = useState('')
  const handled = useRef<AccountResult | null>(props.result)   // a result from before the sheet opened is old
  const { result, onClose } = props

  useEffect(() => {
    if (!result || handled.current === result) return   // each answer is handled once, not on every keystroke
    handled.current = result
    setError('')
    if (result.ok) {
      switch (result.op) {
        case 'signIn':
        case 'verifyEmail':
        case 'deleteAccount':
          onClose()
          return
        case 'signUp':
          setMode('verify')
          setCode('')
          setMessage(`We sent a 6-digit code to ${email}. It expires in 10 minutes.`)
          return
        case 'forgotPassword':
          setMode('reset')
          setCode('')
          setPassword('')
          setMessage('If an account matches, a 6-digit code is on its way to its email address.')
          return
        case 'resetPassword':
          setMode('signIn')
          setPassword('')
          setMessage('Your password was changed. Sign in with the new one.')
          return
      }
      return
    }
    if ((result.op === 'signIn' || result.op === 'deleteAccount') && result.code === 'totp_required') {
      setNeedCode(true)
      setMessage('Enter the 6-digit code from your authenticator app.')
      return
    }
    if (result.op === 'signIn' && result.code === 'unverified') {
      setMode('verify')
      setMessage('Verify your email first: enter the code we sent you.')
      return
    }
    setError(result.message || 'Something went wrong. Try again.')
  }, [result, email, onClose])

  const go = (next: SheetMode) => {
    setMode(next)
    setError('')
    setMessage('')
    setCode('')
    setNeedCode(false)
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setError('')
    switch (mode) {
      case 'signIn':
        props.send({ type: 'signIn', login: email.trim(), password, code: code.trim() })
        break
      case 'signUp':
        if (password.length < 10) {
          setError('Use at least 10 characters.')
          return
        }
        props.send({ type: 'signUp', email: email.trim(), password })
        break
      case 'verify':
        props.send({ type: 'verifyEmail', email: email.trim(), code: code.trim() })
        break
      case 'forgot':
        props.send({ type: 'forgotPassword', login: email.trim() })
        break
      case 'reset':
        props.send({ type: 'resetPassword', login: email.trim(), code: code.trim(), password })
        break
      case 'delete':
        props.send({ type: 'deleteAccount', password, code: code.trim() })
        break
    }
  }

  const showEmail = mode !== 'verify' && mode !== 'reset' && mode !== 'delete'
  const showPassword = mode === 'signIn' || mode === 'signUp' || mode === 'reset' || mode === 'delete'
  const showCode = mode === 'verify' || mode === 'reset' || ((mode === 'signIn' || mode === 'delete') && needCode)
  const action = { signIn: 'Sign in', signUp: 'Create account', verify: 'Verify', forgot: 'Email me a code',
    reset: 'Change password', delete: 'Delete my account' }[mode]

  return (
    <div className="scrim" onClick={onClose}>
      <form className="sheet form" role="dialog" aria-modal="true" aria-labelledby="account-title" onSubmit={submit}
        onClick={(e) => e.stopPropagation()}>
        <h2 id="account-title">{TITLES[mode]}</h2>
        {message && <p className="form__note">{message}</p>}
        {showEmail && (
          <label>
            Email
            <input type="email" autoComplete="email" inputMode="email" required maxLength={254} value={email}
              onChange={(e) => setEmail(e.target.value)} />
          </label>
        )}
        {showPassword && (
          <label>
            {mode === 'signIn' || mode === 'delete' ? 'Password' : 'New password'}
            <input type="password" required maxLength={128} minLength={mode === 'signIn' || mode === 'delete' ? 1 : 10}
              value={password} autoComplete={mode === 'signIn' || mode === 'delete' ? 'current-password' : 'new-password'}
              onChange={(e) => setPassword(e.target.value)} />
          </label>
        )}
        {showCode && (
          <label>
            {mode === 'signIn' || mode === 'delete' ? 'Authenticator code' : 'Code from the email'}
            <input inputMode="numeric" autoComplete="one-time-code" required maxLength={7} pattern="[0-9 ]{6,7}" value={code}
              onChange={(e) => setCode(e.target.value)} />
          </label>
        )}
        {error && <p className="form__error" role="alert">{error}</p>}
        <button type="submit" className={`btn ${mode === 'delete' ? 'btn--dangerfill' : 'btn--primary'} btn--wide`}
          disabled={props.busy}>
          {props.busy ? 'Please wait…' : action}
        </button>
        <div className="form__links">
          {mode === 'delete' && <button type="button" className="link" onClick={onClose}>Keep my account</button>}
          {mode === 'signIn' && (
            <>
              <button type="button" className="link" onClick={() => go('signUp')}>Create an account</button>
              <button type="button" className="link" onClick={() => go('forgot')}>Forgot password?</button>
            </>
          )}
          {mode !== 'signIn' && mode !== 'delete' && (
            <button type="button" className="link" onClick={() => go('signIn')}>Back to sign in</button>
          )}
          {mode !== 'delete' && <button type="button" className="link" onClick={onClose}>Cancel</button>}
        </div>
      </form>
    </div>
  )
}
