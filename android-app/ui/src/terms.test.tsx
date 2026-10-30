import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import termsPage from '../../../public/terms.html?raw'
import { Agreement } from './agreement'
import { parseInbound } from './bridge'
import { CONTACT_EMAIL, DEVELOPER, TERMS_HEADLINE, TERMS_SECTIONS, termsText } from './terms'

const noop = () => {}
const squash = (s: string) => s.replace(/\s+/g, ' ').trim()

/** The visible text of an HTML page: inline tags (links, bold) dropped, block tags as spaces, entities decoded. */
function pageText(html: string): string {
  return squash(html.replace(/<style[\s\S]*?<\/style>/g, ' ').replace(/<\/?(a|strong)\b[^>]*>/g, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>'))
}

describe('User Agreement', () => {
  it('starts with the two bold lines the developer asked for', () => {
    const html = renderToStaticMarkup(<Agreement mode="accept" onAccept={noop} onDecline={noop} />)
    const headline = html.indexOf('agreement__headline')
    expect(headline).toBeGreaterThan(0)
    expect(headline).toBeLessThan(html.indexOf(TERMS_SECTIONS[0].title))
    for (const line of TERMS_HEADLINE) expect(html).toContain(`<strong>${line}</strong>`)
    expect(TERMS_HEADLINE[0]).toContain('Allah Almighty')
    expect(html).toContain('Agree and continue')
    expect(html).toContain('Decline')
    expect(html).toContain(DEVELOPER)
  })

  it('has every section, the contact and no unfilled placeholder', () => {
    expect(TERMS_SECTIONS).toHaveLength(20)
    const all = termsText().join('\n')
    expect(all).toContain(CONTACT_EMAIL)
    expect(all).not.toMatch(/\[[A-Z][A-Z _]+\]/)
    expect(all).not.toMatch(/blocking/i) // Play's VPN policy: no ad-blocking claims
  })

  it('read mode only closes', () => {
    const html = renderToStaticMarkup(<Agreement mode="read" onClose={noop} />)
    expect(html).toContain('>Close</button>')
    expect(html).not.toContain('agreement__agree') // no accept or decline buttons
    expect(html).not.toContain('>Decline</button>')
  })

  it('the website publishes exactly the same agreement', () => {
    const page = pageText(termsPage)
    for (const sentence of termsText()) expect(page).toContain(squash(sentence))
  })

  it('parses the terms message and rejects malformed ones', () => {
    expect(parseInbound(JSON.stringify({ type: 'terms', accepted: false, version: '2026-10-30' })))
      .toEqual({ type: 'terms', accepted: false, version: '2026-10-30' })
    for (const bad of [{ accepted: 'no', version: 'v' }, { accepted: true }, { accepted: true, version: 'x'.repeat(40) }]) {
      expect(parseInbound(JSON.stringify({ type: 'terms', ...bad }))).toBeNull()
    }
  })
})
