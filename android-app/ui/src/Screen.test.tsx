import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { type Account, type Phase, type Profile, type VpnState, initialState, noAccount } from './bridge'
import { freeLeft } from './account'
import { Screen, type TrafficView } from './Screen'

const NOW = Date.UTC(2026, 9, 17, 12)
const profile: Profile = {
  account: 'android',
  server: '10.0.2.2:51888',
  serverName: 'vpn.e2e.test',
  tunnelAddress: '10.123.0.2/32',
  expires: NOW / 1000 + 90 * 86400,
  fullTunnel: false,
  encryption: 'ML-KEM-768 + X25519 · ChaCha20-Poly1305',
  portalUrl: 'https://127.0.0.1:8899/',
}
const traffic: TrafficView = { down: 3 * 1024 * 1024, up: 512 * 1024, downRate: 2048, upRate: 512, downHistory: [0, 1024, 2048], upHistory: [0, 256, 512] }
const noop = () => {}

function render(state: Partial<VpnState>, t: TrafficView = traffic, demo = false, account?: Account): string {
  return renderToStaticMarkup(
    <Screen state={{ ...initialState, ...state }} traffic={t} now={NOW} onPower={noop} onImport={noop} onRemove={noop}
      onOpenPortal={noop} onOpenVpnSettings={noop} demo={demo} account={account} />,
  )
}

const free: Account = {
  ...noAccount, available: true, portal: true, known: true, at: NOW - 10_000, freeSecondsLeft: 1810, canConnect: true,
  rewardsLeft: 3, accounts: true, ads: true, priceLabel: 'PKR 500 / month',
}

describe('Screen', () => {
  it('guides a first-time user to import a profile', () => {
    const html = render({ profile: null })
    expect(html).toContain('Set up ShieldsVPN')
    expect(html).toContain('Import profile')
    expect(html).toContain('aria-label="Import a profile"')
    expect(html).not.toContain('aria-label="Traffic"') // no traffic cards without a profile
  })

  it('renders every phase with its label and tone', () => {
    const cases: [Phase, string, string][] = [
      ['disconnected', 'Disconnected', 'tone-off'],
      ['preparing', 'Preparing VPN', 'tone-busy'],
      ['connecting', 'Connecting', 'tone-busy'],
      ['connected', 'Connected', 'tone-on'],
      ['reconnecting', 'Reconnecting', 'tone-busy'],
      ['error', 'Error', 'tone-error'],
      ['disconnecting', 'Disconnecting', 'tone-busy'],
    ]
    for (const [phase, label, tone] of cases) {
      const html = render({ phase, profile, active: phase !== 'disconnected' })
      expect(html).toContain(`<h1 aria-live="polite">${label}</h1>`)
      expect(html).toContain(tone)
    }
  })

  it('shows the live tunnel when connected', () => {
    const html = render({
      phase: 'connected', active: true, profile, server: 'vpn.e2e.test', endpoint: '10.0.2.2:51888',
      tunnelAddress: '10.123.0.2/24', encryption: profile.encryption, keyAlg: 'ML-DSA-65',
      routes: ['10.123.0.0/24'], dns: ['9.9.9.9'], connectedSince: NOW - 3_725_000,
    })
    expect(html).toContain('10.123.0.2/24')
    expect(html).toContain('01:02:05') // connected-for timer
    expect(html).toContain('<i class="chip">ML-KEM-768</i>')
    expect(html).toContain('ML-DSA-65 certificate')
    expect(html).toContain('10.123.0.0/24')
    expect(html).toContain('9.9.9.9')
    expect(html).toContain('2.0 KB/s') // download rate
    expect(html).toContain('3.0 MB total')
    expect(html).toContain('aria-label="Disconnect"')
    expect(html).toContain('Disconnect to change the profile.') // profile actions locked while active
  })

  it('keeps connection details collapsed until the user opens them', () => {
    const html = render({ phase: 'connected', active: true, profile, endpoint: '10.0.2.2:51888', tunnelAddress: '10.123.0.2/24' })
    expect(html).toContain('<details class="card details" aria-label="Connection details"><summary>')
    expect(html).not.toMatch(/<details[^>]*\sopen/)
  })

  it('shows the error message, escaped', () => {
    const html = render({ phase: 'error', active: false, profile, message: '<img src=x onerror=alert(1)> rejected' })
    expect(html).toContain('role="alert"')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt; rejected')
    expect(html).not.toContain('<img')
    expect(html).toContain('Tap to try again.')
  })

  it('warns before the certificate expires', () => {
    expect(render({ profile: { ...profile, expires: NOW / 1000 + 5 * 86400 + 60 } })).toContain('validity--warn')
    expect(render({ profile: { ...profile, expires: NOW / 1000 - 60 } })).toContain('expired')
    expect(render({ profile })).toContain('90 days left')
  })

  it('reports the Android kill switch honestly', () => {
    expect(render({ profile, lockdown: true, alwaysOn: true })).toContain('Android blocks all traffic')
    expect(render({ profile, lockdown: false, alwaysOn: true })).toContain('not blocked while the tunnel is down')
    expect(render({ profile, lockdown: false, alwaysOn: false })).toContain('apps use your normal connection')
    const unknown = render({ profile })
    expect(unknown).toContain('Android setting')
    expect(unknown).not.toContain('Android blocks all traffic') // never claims protection it cannot see
  })

  it('labels the simulated browser preview', () => {
    expect(render({ profile }, traffic, true)).toContain('Demo mode')
    expect(render({ profile })).not.toContain('Demo mode')
  })

  it('shows the permission hint only before Android consent exists', () => {
    expect(render({ profile, permissionNeeded: true })).toContain('Android asks you to allow')
    expect(render({ profile, permissionNeeded: false })).not.toContain('Android asks you to allow')
  })

  it('shows the Free plan with a countdown, an ad button and Go Pro', () => {
    const html = render({ profile: { ...profile, enrolled: true } }, traffic, false, free)
    expect(html).toContain('Free plan')
    expect(html).toContain('00:30:00') // 1810 s measured 10 s ago
    expect(html).toContain('Watch an ad · +30 min')
    expect(html).toContain('Go Pro · PKR 500 / month')
    expect(html).toContain('Sign in')
    expect(html).toContain('This phone') // the d-xxxx device name is never shown
    expect(html).not.toContain(profile.account)
    const used = render({ profile }, traffic, false, { ...free, rewardsLeft: 0, freeSecondsLeft: 0 })
    expect(used).toContain('No time left')
    expect(used).toContain('free sessions')
    expect(render({ profile }, traffic, false, { ...free, ads: false })).toContain('not available right now')
  })

  it('offers each Pro plan the administrator priced', () => {
    const prices = [
      { period: 'week' as const, name: 'Weekly', label: 'USD 1.99 / week' },
      { period: 'month' as const, name: 'Monthly', label: 'USD 4.99 / month' },
      { period: 'year' as const, name: 'Yearly', label: 'USD 39.99 / year' },
    ]
    const html = render({ profile }, traffic, false, { ...free, payments: true, prices })
    expect(html).toContain('aria-label="Pro plans"')
    for (const p of prices) expect(html).toContain(`Go Pro · ${p.label}`)
    expect(html).not.toContain('PKR 500') // the single-price button is replaced
    const one = render({ profile }, traffic, false, { ...free, payments: true, prices: [prices[1]] })
    expect(one).toContain('Go Pro · USD 4.99 / month')
    expect(one).not.toContain('aria-label="Pro plans"')
    // In the app, several plans collapse into one button that opens the plan sheet (ProSheet).
    const sheet = renderToStaticMarkup(
      <Screen state={{ ...initialState, profile }} traffic={traffic} now={NOW} onPower={noop} onImport={noop}
        onRemove={noop} onOpenPortal={noop} onOpenVpnSettings={noop} account={{ ...free, payments: true, prices }}
        onChoosePlan={noop} />,
    )
    expect(sheet).toContain('Go Pro · from USD 1.99 / week')
    expect(sheet).not.toContain('aria-label="Pro plans"')
    expect(sheet.match(/Go Pro/g)).toHaveLength(1)
  })

  it('Play Store build: no profile files, deletion and privacy links', () => {
    const play = { ...free, imports: false, privacy: true }
    const html = render({ profile: { ...profile, enrolled: true } }, traffic, false, play)
    expect(html).not.toContain('Replace')
    expect(html).toContain('Privacy policy')
    expect(render({ profile: null }, traffic, false, { ...noAccount, portal: true, imports: false }))
      .not.toContain('Import a profile file')
    expect(render({ profile }, traffic, false, free)).toContain('Replace') // direct builds keep the ZIP import
    expect(html).not.toContain('Delete account') // only when signed in
    const signedIn = renderToStaticMarkup(
      <Screen state={{ ...initialState, profile }} traffic={traffic} now={NOW} onPower={noop} onImport={noop}
        onRemove={noop} onOpenPortal={noop} onOpenVpnSettings={noop} account={{ ...play, signedIn: true }}
        onDeleteAccount={noop} />,
    )
    expect(signedIn).toContain('Delete account')
  })

  it('shows Pro without ads or timers', () => {
    const pro = { ...free, plan: 'premium' as const, proUntil: NOW / 1000 + 30 * 86400, signedIn: true,
      email: 'sam@example.com', payments: true }
    const html = render({ profile }, traffic, false, pro)
    expect(html).toContain('ShieldsVPN Pro')
    expect(html).toContain('Unlimited')
    expect(html).toContain('Manage subscription')
    expect(html).toContain('Signed in as sam@example.com')
    expect(html).not.toContain('Watch an ad')
    expect(html).not.toContain('Go Pro')
    expect(html).not.toContain('blocking') // Play's VPN policy: no ad-blocking claims
  })

  it('hides the plan card for imported profiles; portal builds connect with one tap, no file', () => {
    expect(render({ profile }, traffic, false, { ...free, available: false })).not.toContain('Free plan')
    const setup = render({ profile: null }, traffic, false, { ...noAccount, portal: true })
    expect(setup).toContain('aria-label="Connect"')
    expect(setup).toContain('Tap to connect. No account needed.')
    expect(setup).not.toContain('aria-label="Set up"') // no setup card: the power button is all it takes
    expect(setup).not.toContain('Import')
    const busy = render({ profile: null }, traffic, false, { ...noAccount, portal: true, busy: true })
    expect(busy).toContain('Setting up this phone')
    expect(busy).toContain('power--busy')
    expect(render({ profile: null })).toContain('Import profile') // no portal: the old ZIP flow
  })

  it('has a menu button in the header', () => {
    expect(render({ profile })).toContain('aria-label="Open menu"')
    expect(render({ profile: null })).toContain('aria-label="Open menu"')
  })

  it('says before the tap that Connect plays a short ad when the free time is used up', () => {
    const empty = { ...free, freeSecondsLeft: 0 }
    const html = render({ profile: { ...profile, enrolled: true } }, traffic, false, empty)
    expect(html).toContain('A short ad gives you 30 free minutes')
    expect(html).toContain('Short ad · +30 min free')
    expect(render({ profile }, traffic, false, free)).not.toContain('Short ad') // time left: connects directly
    expect(render({ profile }, traffic, false, { ...empty, rewardsLeft: 0 })).not.toContain('Short ad')
    expect(render({ profile }, traffic, false, { ...empty, ads: false })).not.toContain('Short ad')
    expect(render({ profile }, traffic, false, { ...empty, plan: 'premium' })).not.toContain('Short ad')
    expect(render({ profile, phase: 'connected', active: true }, traffic, false, empty)).not.toContain('Short ad')
  })

  it('counts free time down from when it was measured', () => {
    expect(freeLeft({ ...free, at: 1000, freeSecondsLeft: 60 }, 31_000)).toBe(30)
    expect(freeLeft({ ...free, at: 1000, freeSecondsLeft: 60 }, 500_000)).toBe(0)
    expect(freeLeft({ ...free, at: 5000, freeSecondsLeft: 60 }, 1000)).toBe(60) // clock went back: never adds time
  })
})
