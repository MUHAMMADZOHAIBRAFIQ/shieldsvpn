import { describe, expect, it } from 'vitest'
import { type Inbound, type NativePort, initialState, nativeBridge, parseInbound } from './bridge'

describe('parseInbound', () => {
  it('accepts well-formed messages and fills missing state fields', () => {
    const m = parseInbound(JSON.stringify({ type: 'state', state: { phase: 'connected', active: true } }))
    expect(m).toEqual({ type: 'state', state: { ...initialState, phase: 'connected', active: true } })
    const odd = parseInbound(JSON.stringify({ type: 'state', state: { phase: 'connected', lockdown: 'yes', alwaysOn: true } }))
    expect(odd?.type === 'state' && [odd.state.lockdown, odd.state.alwaysOn]).toEqual([null, true])
    expect(parseInbound(JSON.stringify({ type: 'traffic', rx: 1, tx: 2, at: 3 }))).toEqual({ type: 'traffic', rx: 1, tx: 2, at: 3 })
    expect(parseInbound(JSON.stringify({ type: 'notice', kind: 'error', title: 'T', text: 'x' }))).toEqual({
      type: 'notice', kind: 'error', title: 'T', text: 'x',
    })
    expect(parseInbound(JSON.stringify({ type: 'insets', top: 24.5, bottom: '16' }))).toEqual({
      type: 'insets', top: 24.5, bottom: 16, left: 0, right: 0,
    })
  })

  it('drops anything malformed instead of throwing', () => {
    for (const bad of [
      '{not json',
      JSON.stringify(null),
      JSON.stringify({ type: 'state', state: { phase: 'hacked' } }),
      JSON.stringify({ type: 'traffic', rx: '1', tx: 2, at: 3 }),
      JSON.stringify({ type: 'notice', kind: 'info', text: 'x' }),
      JSON.stringify({ type: 'eval', code: 'alert(1)' }),
      42,
    ]) {
      expect(parseInbound(bad)).toBeNull()
    }
  })
})

describe('nativeBridge', () => {
  it('sends JSON strings and delivers parsed messages to subscribers', () => {
    const sent: string[] = []
    const port: NativePort = { postMessage: (d) => sent.push(d), onmessage: null }
    const bridge = nativeBridge(port)
    const got: Inbound[] = []
    const off = bridge.subscribe((m) => got.push(m))

    bridge.send({ type: 'connect' })
    expect(sent).toEqual(['{"type":"connect"}'])

    port.onmessage!({ data: JSON.stringify({ type: 'traffic', rx: 10, tx: 20, at: 30 }) })
    port.onmessage!({ data: 'garbage' })
    expect(got).toEqual([{ type: 'traffic', rx: 10, tx: 20, at: 30 }])

    off()
    port.onmessage!({ data: JSON.stringify({ type: 'traffic', rx: 1, tx: 1, at: 1 }) })
    expect(got).toHaveLength(1)
  })
})
