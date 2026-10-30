# Main store listing

Paste into Play Console → Grow → Store presence → Main store listing. Limits: app name 30 characters, short
description 80, full description 4000 (checked by `python tools/play_graphics.py --check-listing`).

Play's metadata policy forbids rankings ("best", "#1"), testimonials, misleading claims and keyword stuffing. Do not
add "ad blocking", "unlimited free" or "100% anonymous": the first conflicts with the VPN policy, the others are not
true.

## App name

```text
ShieldsVPN – Post-Quantum VPN
```

## Short description

```text
Quantum-safe VPN. One tap to encrypt your connection. Free with ads, or go Pro.
```

## Full description

One line per paragraph or bullet, as Play shows it (do not re-wrap these lines when pasting).

<!-- markdownlint-disable MD013 -->
```text
ShieldsVPN protects your internet connection with post-quantum encryption: the new generation of cryptography, standardised by NIST, that is designed to stay secure even against future quantum computers.

ONE TAP TO CONNECT
• Tap Connect: ShieldsVPN sets up your phone by itself. No files, no settings to copy.
• Free plan: no account needed. Watch a short video to get free VPN time.
• Pro: no ads and unlimited time, as a weekly, monthly or yearly subscription through Google Play. Cancel any time in Google Play.

POST-QUANTUM SECURITY
• Key exchange: ML-KEM-768 (FIPS 203) combined with X25519, so your connection stays protected even if one of the two is ever broken.
• Your phone creates its own ML-DSA (FIPS 204) key. It is protected by the Android Keystore and never leaves the device.
• Traffic is encrypted with ChaCha20-Poly1305 or AES-256-GCM, and the keys are renewed every few minutes.

PRIVACY
• We do not log the websites you visit, the content of your traffic or your DNS queries.
• No account is needed for the Free plan.
• You can delete your account in the app at any time.

MADE FOR ANDROID
• Supports Android's always-on VPN and "Block connections without VPN", the system kill switch.
• Reconnects by itself when you move between Wi-Fi and mobile data.
• Blocks IPv6 when it is not carried by the tunnel, so nothing leaks around it.

ABOUT THE VPN PERMISSION
ShieldsVPN uses Android's VpnService to create an encrypted tunnel from your device to the ShieldsVPN server. This is the app's core function. The tunnel only carries your traffic to our server: the app does not read, collect or sell it, and does not block or change ads in other apps.

Privacy policy: https://shieldsvpn.vercel.app/privacy.html
```
<!-- markdownlint-enable MD013 -->

## Other fields

| Field | Value |
| --- | --- |
| App category | Tools |
| Tags | VPN, Privacy, Security (pick from Play's list) |
| Contact email | `muhammadzohaibrafiq2@gmail.com` (shown publicly) |
| Website | `https://shieldsvpn.vercel.app/` |
| Privacy policy | `https://shieldsvpn.vercel.app/privacy.html` |
| App icon | `graphics/icon-512.png` (512 × 512, 32-bit PNG) |
| Feature graphic | `graphics/feature-graphic.png` (1024 × 500, PNG without transparency) |
| Phone screenshots | 2–8, taken from the real app (see [README.md](README.md) step 4) |
