# ShieldsVPN browser extension

A companion extension for Chrome, Microsoft Edge, Brave, Opera, Chromium and Firefox on **Windows**. It shows the
state of the ShieldsVPN Windows app and connects or disconnects it with one click; "Free time & Pro" opens the app's
window. The tunnel itself stays in the Windows app, so the whole PC is protected by the post-quantum protocol, not
only the browser.

```text
extension popup ──native messaging──> pqvpn native-host ──127.0.0.1 + token──> tray app (winui.py) ──> VPN
(browser-extension/)                   (native_host.py)          (control.py)
```

## Security design

- The extension's only permission is `nativeMessaging`: no website access, tabs, history or storage. It sends nothing
  to any website and writes the page with `textContent` only (MV3's CSP forbids inline script anyway).
- The browser starts the helper only for the extension IDs listed in its manifest (`allowed_origins` /
  `allowed_extensions`), registered per user (HKCU) by `python -m pqvpn browser-host install`.
- The helper relays five commands (`status`, `connect`, `disconnect`, `launch`, `open`) and never reads keys,
  profiles or settings. Messages are limited to 64 KiB.
- The tray app's control channel listens on 127.0.0.1 only. Each request carries a 256-bit token from
  `%LOCALAPPDATA%\pqvpn\tray-control.json` (readable by this Windows user), compared in constant time; the protocol is
  one JSON line, not HTTP, so a web page cannot drive it. Only `status`, `connect` and `disconnect` exist there.
- `launch` starts the tray app, which asks for Administrator through UAC as usual; nothing gains privileges silently.

## Setting it up on a PC

1. Install the ShieldsVPN Windows app and register the PC (`python -m pqvpn app --portal https://...`) or import a
   profile, and start the tray app once.
2. Install the extension from the store (or, for testing, build it and use *Load unpacked* on
   `browser-extension/dist/chromium`).
3. Copy the extension's ID (chrome://extensions or edge://extensions, with developer mode on), then:

   ```text
   python -m pqvpn browser-host install --chrome-id <id> [--chrome-id <Edge store id>] [--firefox-id companion@shieldsvpn.app]
   ```

   It writes the helper and its manifests to `%LOCALAPPDATA%\pqvpn\native-host\` and registers them for Chrome, Edge,
   Brave, Chromium, Opera and Firefox (per user, no Administrator). `python -m pqvpn browser-host uninstall` removes
   the registration.

The Chrome Web Store and Edge Add-ons give the extension different IDs; pass both with `--chrome-id`. Opera and
Vivaldi read Chrome's registration; Brave reads its own and Chrome's.

## Building for the stores

```text
python tools/build_extension.py --firefox-id companion@shieldsvpn.app
```

writes `browser-extension/dist/shieldsvpn-extension-chromium-1.0.0.zip` (Chrome Web Store, Edge Add-ons, Opera
add-ons; Brave installs from the Chrome Web Store) and `...-firefox-1.0.0.zip` (addons.mozilla.org). Raise `version`
in `browser-extension/manifest.json` for every upload.

### What the stores ask

| Question | Answer |
| --- | --- |
| Single purpose (Chrome) | Show the status of the ShieldsVPN Windows app and connect or disconnect it. |
| Permission justification: `nativeMessaging` | Talks to the ShieldsVPN app installed on the same PC, which runs the VPN; no other way exists for an extension to control a desktop app. |
| Remote code | None: all script is in the package. |
| Data collection (Chrome privacy practices, Firefox `data_collection_permissions`) | None collected or transmitted by the extension. |
| Privacy policy | `https://shieldsvpn.vercel.app/privacy.html` |
| Description | "Companion for the ShieldsVPN app on Windows: see whether the post-quantum VPN is connected, and connect or disconnect it in one click. Requires the ShieldsVPN Windows app." |
| Screenshots | The popup in its connected and disconnected states (1280 × 800 for the Chrome Web Store). |

Be clear in every listing that the extension **requires the Windows app**; stores reject extensions whose main
function needs an undisclosed separate program.

### On the website

`public/index.html` has a *Browser extension* section (Chrome, Edge, Firefox) that says *Coming soon* until a store
approves the extension. Then paste each store page into `STORE_LINKS` in `public/site.js` (https only); that button
turns into *Add to Chrome* / *Add to Edge* / *Add to Firefox*.

## What was and wasn't verified (2026-10-30)

Verified: the control channel (token, unknown commands, oversized and HTTP-looking requests refused, stale file),
the helper's message framing and commands, the generated launcher answering a framed message exactly as a browser
would start it, the installer's manifests (restricted origins, IDs validated), and both store packages (MV3,
`nativeMessaging` only, icons, no inline script).

Not verified: the extension loaded in each browser against the running, elevated tray app (needs a UAC approval on
this PC), and store review.
