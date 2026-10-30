import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { ProSheet, defaultPeriod } from './account'
import { type Account, type PriceOption, noAccount } from './bridge'
import { Menu, proEntry } from './menu'

const noop = () => {}
const prices: PriceOption[] = [
  { period: 'week', name: 'Weekly', label: 'USD 1.99 / week' },
  { period: 'month', name: 'Monthly', label: 'USD 4.99 / month' },
  { period: 'year', name: 'Yearly', label: 'USD 39.99 / year' },
]
const free: Account = {
  ...noAccount, available: true, portal: true, known: true, accounts: true, ads: true, payments: true, rewardsLeft: 4,
  prices,
}

function menu(account: Account, extra: { hasProfile?: boolean; imports?: boolean } = {}): string {
  return renderToStaticMarkup(
    <Menu account={account} hasProfile={extra.hasProfile ?? true} imports={extra.imports ?? false} locked={false}
      onClose={noop} onPro={noop} onWatchAd={noop} onSignIn={noop} onSignOut={noop} onDeleteAccount={noop}
      onImport={noop} onVpnSettings={noop} onPrivacy={noop} />,
  )
}

describe('proEntry', () => {
  it('sends a signed-out Free user to sign-up first, a signed-in one to the plans', () => {
    expect(proEntry(free, true)).toEqual({ title: 'Sign up for Pro', action: 'signUp', active: false,
      detail: 'No ads · unlimited time · from USD 1.99 / week' })
    expect(proEntry({ ...free, signedIn: true }, true).action).toBe('choose')
    expect(proEntry({ ...free, signedIn: true, payments: false }, true))
      .toMatchObject({ action: 'none', detail: 'Payments are not available yet' })
  })

  it('is a status, not an offer, for Pro', () => {
    const pro = { ...free, plan: 'premium' as const, signedIn: true, proUntil: Date.UTC(2027, 0, 15) / 1000 }
    expect(proEntry(pro, true)).toMatchObject({ title: 'ShieldsVPN Pro', action: 'manage', active: true })
    expect(proEntry(pro, true).detail).toMatch(/^Active until /)
    expect(proEntry({ ...pro, proUntil: null, payments: false }, true)).toMatchObject({ detail: 'Active', action: 'none' })
  })

  it('cannot be bought before the phone is registered, with an imported profile or while switched off', () => {
    expect(proEntry({ ...noAccount, portal: true }, false))
      .toMatchObject({ action: 'none', detail: 'Tap Connect once to set up this phone' })
    expect(proEntry({ ...noAccount, portal: true, busy: true }, false).detail).toBe('Setting up this phone…')
    expect(proEntry({ ...free, available: false }, true).detail).toBe('Not available with an imported profile')
    expect(proEntry({ ...free, known: false }, true).action).toBe('none')
    expect(proEntry({ ...free, accounts: false }, true)).toMatchObject({ action: 'none', detail: 'Coming soon' })
  })
})

describe('Menu', () => {
  it('leads with Sign up for Pro, then account and settings', () => {
    const html = menu({ ...free, privacy: true }, { imports: true })
    expect(html).toContain('aria-label="Menu"')
    expect(html.indexOf('Sign up for Pro')).toBeLessThan(html.indexOf('Kill switch'))
    expect(html).toContain('Get 30 free minutes')
    expect(html).toContain('Sign in')
    expect(html).toContain('Import a profile file')
    expect(html).toContain('Privacy policy')
    expect(html).toContain('aria-label="Close menu"')
    expect(html).not.toContain('Delete account')
  })

  it('shows the signed-in account and hides what does not apply', () => {
    const html = menu({ ...free, signedIn: true, email: 'sam@example.com', ads: false })
    expect(html).toContain('sam@example.com')
    expect(html).toContain('Sign out')
    expect(html).toContain('Delete account')
    expect(html).not.toContain('free minutes') // no ads on this portal
    expect(html).not.toContain('Import a profile file') // Play build
    expect(html).not.toContain('Privacy policy')
    expect(menu({ ...free, accounts: false })).not.toContain('Sign in') // app sign-in switched off
  })

  it('escapes what the portal sends', () => {
    const html = menu({ ...free, signedIn: true, email: '<b>x</b>@example.com' })
    expect(html).toContain('&lt;b&gt;x&lt;/b&gt;@example.com')
  })
})

describe('ProSheet', () => {
  it('offers each plan with the monthly one selected first', () => {
    expect(defaultPeriod(prices)).toBe('month')
    expect(defaultPeriod([prices[2]])).toBe('year')
    expect(defaultPeriod([])).toBe('')
    const html = renderToStaticMarkup(<ProSheet account={{ ...free, signedIn: true }} onChoose={noop} onClose={noop} />)
    expect(html).toContain('role="radiogroup"')
    expect(html.match(/role="radio"/g)).toHaveLength(3)
    expect(html).toMatch(/aria-checked="true"[^>]*><span><b>Monthly<\/b>/)
    expect(html).toContain('Continue · USD 4.99 / month')
    expect(html).not.toContain('blocking') // Play's VPN policy: no ad-blocking claims
  })

  it('falls back to the single default price, and cannot pay while payments are off', () => {
    const one = renderToStaticMarkup(
      <ProSheet account={{ ...free, prices: [], priceLabel: 'PKR 500 / month' }} onChoose={noop} onClose={noop} />)
    expect(one).not.toContain('radiogroup')
    expect(one).toContain('Continue · PKR 500 / month')
    const off = renderToStaticMarkup(<ProSheet account={{ ...free, payments: false }} onChoose={noop} onClose={noop} />)
    expect(off).toMatch(/<button[^>]*disabled=""[^>]*>Continue/)
  })
})
