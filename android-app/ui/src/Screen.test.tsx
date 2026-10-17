import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { type Phase, type Profile, type VpnState, initialState } from './bridge'
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

function render(state: Partial<VpnState>, t: TrafficView = traffic, demo = false): string {
  return renderToStaticMarkup(
    <Screen state={{ ...initialState, ...state }} traffic={t} now={NOW} onPower={noop} onImport={noop} onRemove={noop}
      onOpenPortal={noop} onOpenVpnSettings={noop} demo={demo} />,
  )
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
})
