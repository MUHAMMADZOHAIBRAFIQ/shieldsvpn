// ShieldsVPN browser companion: shows the Windows app's VPN state and connects / disconnects it.
// It talks only to the native-messaging helper "com.shieldsvpn.native" (pqvpn/native_host.py), which relays a fixed
// set of commands to the running ShieldsVPN tray app.  The extension has no other permission and sends nothing to
// any website.  Everything is written with textContent (no HTML from outside).
'use strict'

const api = globalThis.browser ?? globalThis.chrome
const HOST = 'com.shieldsvpn.native'
const $ = (id) => document.getElementById(id)

const STATES = {
  connected: ['Connected', 'on', 'Post-quantum protection is on.'],
  connecting: ['Connecting…', 'busy', 'Running the post-quantum handshake.'],
  reconnecting: ['Reconnecting…', 'busy', 'The connection dropped; restoring it.'],
  error: ['Not connected', 'bad', ''],
  disconnected: ['Disconnected', '', 'Your traffic is not protected.'],
}

let busy = false

async function ask(cmd) {
  try {
    return await api.runtime.sendNativeMessage(HOST, { cmd })
  } catch {
    return { ok: false, helper: false }
  }
}

function show(headline, pill, tone, detail) {
  $('headline').textContent = headline
  $('pill').textContent = pill
  $('pill').className = `pill ${tone}`
  $('detail').textContent = detail
}

function button(el, label, onClick) {
  el.hidden = !label
  if (!label) return
  el.textContent = label
  el.disabled = busy
  el.onclick = onClick
}

function render(s) {
  $('facts').hidden = true
  button($('app'), '')
  if (s.helper === false) {
    show('Set up the companion', 'Setup', '', 'Install the ShieldsVPN app for Windows, then run ' +
      '"python -m pqvpn browser-host install" so this extension can reach it.')
    return button($('primary'), '')
  }
  if (!s.ok) {
    show('Something went wrong', 'Error', 'bad', String(s.error || 'The ShieldsVPN app did not answer.'))
    return button($('primary'), 'Try again', refresh)
  }
  if (!s.running) {
    show(s.starting ? 'Starting ShieldsVPN…' : 'ShieldsVPN is not running', 'Off', '',
      s.starting ? 'Approve the Windows prompt (Administrator) to start the VPN.' : 'Start the app to connect.')
    return button($('primary'), s.starting ? '' : 'Start ShieldsVPN', () => run('launch'))
  }
  const [headline, tone, text] = STATES[s.state] || STATES.disconnected
  show(headline, headline.replace('…', ''), tone, s.state === 'error' ? String(s.message || '') : text)
  if (s.state === 'connected') {
    $('server').textContent = String(s.server || '')
    $('address').textContent = String(s.address || '')
    $('encryption').textContent = String(s.encryption || '')
    $('facts').hidden = false
  }
  const active = ['connected', 'connecting', 'reconnecting'].includes(s.state)
  button($('primary'), active ? 'Disconnect' : 'Connect', () => run(active ? 'disconnect' : 'connect'))
  if (s.account) button($('app'), 'Free time & Pro', () => run('open'))
}

async function run(cmd) {
  busy = true
  render(await ask(cmd))
  busy = false
  setTimeout(refresh, 600)
}

async function refresh() {
  if (!busy) render(await ask('status'))
}

refresh()
setInterval(refresh, 1500)
