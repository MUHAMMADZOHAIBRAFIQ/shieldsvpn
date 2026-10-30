# CLAUDE.md

Guidance for Claude Code working in this repository. Product intent is in [docs/PRD.md](docs/PRD.md), the system
spec in [docs/SPEC.md](docs/SPEC.md), the wire protocol in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## What this is

**ShieldsVPN** is a post-quantum, crypto-agile layer-3 VPN: hybrid ML-KEM + X25519/P-384 key exchange, ML-DSA device
certificates, an SLH-DSA root CA, ChaCha20-Poly1305/AES-256-GCM data plane. It has four deliverables:

| Part | Where | Stack |
| --- | --- | --- |
| VPN engine (server + client) | `pqvpn/` | Python ≥ 3.11 stdlib only; all crypto in OpenSSL ≥ 3.5 via `ctypes` |
| Web portal (accounts, profiles, plans, admin) | `pqvpn/portal/` | stdlib `http.server` + SQLite; Node.js only for the Nodemailer helper |
| Desktop clients | `pqvpn/winui.py` (Windows tray), `pqvpn/app.py` (tkinter one-tap window) | ctypes / tkinter |
| Android app | `android-app/` + `pqvpn/android_client.py` | Kotlin `VpnService`, Chaquopy Python 3.13, React 19 UI in a WebView, OpenSSL 3.5.9 for Android |

The product name is ShieldsVPN; the package, CLI and data paths stay **`pqvpn`** (`python -m pqvpn`, `/var/lib/pqvpn`).
Never rename them: live deployments, imports and certificate subjects depend on them.

## Commands

```bash
python -m pqvpn selftest                          # handshake + traffic for every suite (needs OpenSSL >= 3.5)
python -m pqvpn algorithms                        # shows which OpenSSL was loaded
python -m unittest discover -s tests -v           # all Python tests (~137, ~1.5 min); pytest -q also works
python tools/secret_scan.py                       # must report 0 findings before any commit
python tools/secret_scan.py <file.apk>            # before publishing an APK

cd android-app && ./gradlew testDebugUnitTest assembleDebug   # JVM + Vitest tests, debug APK (needs Node >= 22.12)
cd android-app/ui && npm ci && npm test                         # React UI tests only; `npm run dev` = mock bridge
cd android-app && ./gradlew bundleRelease -Pshieldsvpn.deploy=<play deploy.properties>   # Play Store .aab (store=play)
python tools/build_extension.py                                 # browser extension store ZIPs (browser-extension/dist)
python tools/play_graphics.py [--check-listing]                 # Play icon / feature graphic; listing length check
```

**OpenSSL selection.** `pqvpn/crypto/ossl.py` loads libcrypto at import time; point `PQVPN_LIBCRYPTO` at a 3.5+ build
when the default is older. On this developer PC:

- Windows: `PQVPN_LIBCRYPTO=C:/msys64/ucrt64/bin/libcrypto-4-x64.dll python -m pytest -q` (the default Python 3.11
  has OpenSSL 3.0, which lacks ML-KEM/ML-DSA).
- WSL Ubuntu 24.04: system OpenSSL is 3.0; use the private build at `~/pqvpn-test/ossl/lib/libcrypto.so.3`.
  The fd-based Android tests and real-TUN tests only run on Linux.

Run the suite on Windows **and** under WSL when touching `node.py`, `tun.py`, `netcfg.py` or `android_client.py`.

## Layout (where to make a change)

```text
pqvpn/crypto/ossl.py      OpenSSL binding. The only place that touches key material.
pqvpn/crypto/suites.py    Crypto-agility registry (suite + signature codepoints). Nothing else names an algorithm.
pqvpn/crypto/kdf.py       HKDF + TLS 1.3-style key schedule
pqvpn/wire.py             strict length-checked encoders/decoders
pqvpn/protocol.py         packet types, fragmentation, cookies, rate limiter, timer constants
pqvpn/handshake.py        pure initiator/responder state machines (no I/O)
pqvpn/session.py          keypairs, replay window, padding, cryptokey routing table
pqvpn/node.py             ServerNode / ClientNode event loops, BatchedUdpTransport
pqvpn/pki.py              PQVPN certificate format, CA, TrustStore
pqvpn/tun.py, netcfg.py   Linux TUN / Wintun / MemoryTun; routes, DNS, NAT with rollback
pqvpn/config.py           TOML loaders; unknown keys are errors
pqvpn/runner.py           run_server / run_client / selftest
pqvpn/cli.py              every `python -m pqvpn <command>`
pqvpn/portal/web.py       all portal pages + ROUTES table (one file, server-rendered HTML)
pqvpn/portal/store.py     SQLite schema + migrations (USER_COLUMNS), shared with the VPN server
pqvpn/portal/access.py    PortalAccess: per-handshake account/device check (incl. Free time) + live peer publishing
pqvpn/portal/service.py   profile ZIP issuance, portal-init
pqvpn/portal/{auth,plans,mail,vault,firebase,qr}.py
pqvpn/portal/devices.py   app devices: registration, Free time from ads, Pro, device limit (SPEC §16)
pqvpn/portal/api.py       /api/v1/ JSON API for the apps (bearer tokens, never the session cookie)
pqvpn/portal/accounts.py  sign-up / password reset shared by web.py and api.py
pqvpn/portal/rewards.py   AdMob server-side-verification signature check
pqvpn/portal/payments.py  Paddle Billing: checkout links, reconcile from Paddle's API, webhooks
pqvpn/portal/play.py      Google Play Billing for the Play build: purchase-token checks with Google's API, reconcile
pqvpn/portal/google.py    Google service-account sign-in (JWT bearer) shared by firebase.py and play.py
pqvpn/control.py          tray app's loopback control channel (token) for the browser extension
pqvpn/native_host.py      browser native-messaging host + per-user registration (`pqvpn browser-host install`)
browser-extension/        MV3 companion extension (nativeMessaging only); `tools/build_extension.py` builds store ZIPs
docs/play-store/          Play Console texts, Data safety, App content declarations, graphics, release plan
pqvpn/account_client.py   the apps' portal client (TLS pinning, profile writing); packaged in the APK
pqvpn/desktop_account.py  Windows/desktop device registration (DPAPI-sealed token and key passphrase)
pqvpn/android_client.py   profile import, enroll/renew/api_json, tunnel_settings() validation, AndroidTun, Session
android-app/app/src/main/java/com/shieldsvpn/vpn/   Kotlin: MainActivity, ShieldsVpnService, ProfileStore, SecretBox
android-app/ui/src/       React screen; bridge.ts <-> UiJson.kt message contract
android-app/native/       OpenSSL Android build scripts + PROVENANCE.md
research/                 benchmarks and the traffic-analysis study (not shipped)
deploy/                   systemd unit + placeholder example configs
public/                   static landing page (the only thing Vercel serves)
```

## Hard rules

1. **Do not change the wire protocol silently.** Packet format, handshake messages, transcript, key schedule, suite
   negotiation and certificate encoding are frozen at version 1 (`docs/PROTOCOL.md`). Deployed servers and phones must
   keep interoperating. A protocol change needs a version bump, negotiation, a PROTOCOL.md update and the user's
   explicit go-ahead.
2. **No home-made cryptography and no crypto in Python.** Primitives come from OpenSSL through `ossl.py`; Python only
   frames, sequences and applies policy. Add an algorithm by adding a codepoint in `suites.py` and a policy entry.
3. **No new pip dependencies** for `pqvpn/`. The server must run on a bare Python ≥ 3.11 + OpenSSL ≥ 3.5.
4. **Never weaken a check or delete a test** to get green. Certificate, transcript, replay, Origin/CSRF and Host
   checks fail closed on purpose.
5. **Secrets never enter git, APKs, logs or docs.** `*.key`, `*.pem`, `*.db*`, `portal-secrets.key`, profile ZIPs,
   `vpn-profiles/`, `vpn-pki*/`, `.local-pqvpn/`, `*.jks`, `keystore.properties`, Firebase keys are all git-ignored.
   Configs reference secrets **by path**. Run `tools/secret_scan.py` before committing. Logs report paths and types,
   never values (see `Redact.kt`, `REDACTED_ACTOR`).
6. **Fail closed on leaks.** Example: a full-tunnel Android profile without a pushed DNS server raises
   `TunnelConfigError` rather than leaking lookups. Keep that pattern for any new client path.
7. **The portal is admin-only by default** (`portal_access = "admins"`, `allow_signup = "0"`). The owner explicitly
   wants an admin portal; don't build user-facing sign-in features as the default. New public features go behind an
   admin setting that defaults off.
8. **Android packages only the modules listed in `syncPqvpnPython`** (`android-app/app/build.gradle.kts`). If
   `android_client.py` starts importing another `pqvpn` module, add it there or the APK breaks at runtime.
9. Commit or push only when asked. Never push `refs/agents/*` or `refs/codex/*` (local-only refs that contain test
   portal files).

## Do not touch

- `android/`, `capacitor.config.ts`, `package.json` (repo root): an **untracked** Capacitor wrapper of the landing page.
  `android/` holds the owner's release keystore. It is not the VPN app.
- `vpn-profiles/`, `vpn-pki-local/`, `.local-pqvpn/`: live or test key material.
- The live deployments (WSL `/var/lib/pqvpn`, Kali VM behind playit.gg). Don't regenerate their PKI or restart them
  without asking: a new CA invalidates every profile, and a restart drops connected users.

## Verification expectations

- **Portal / auth / header changes:** unit tests are not enough. `http.client` tests once passed while every real
  browser login failed (`Referrer-Policy: no-referrer` made browsers send `Origin: null`). Drive a real browser
  (headless Chrome over CDP) against a throwaway portal (`pqvpn portal-init --data /tmp/x --listen 127.0.0.1:8899`),
  never the live database (lockout counters, real email).
- **Data-plane changes:** run `research/benchmarks/bench_dataplane.py --transports` before and after; loopback numbers
  are not internet or phone numbers, say so.
- **Android changes:** `./gradlew testDebugUnitTest`, then the API 36 x86_64 emulator against a local `ServerNode`.
  The owner's phone has connected to the live server once (split tunnel); systematic physical-device testing, real
  IPv6 and full-tunnel internet through the live server are still unverified. Don't claim them.
- **Windows tray / Wintun:** needs Administrator; Claude sessions here are not elevated, so the user must approve a
  UAC prompt to test.

Report what was and wasn't verified. The docs keep explicit "verified / not verified" lists; update them.

## Conventions

- Python: `from __future__ import annotations`, type hints, dataclasses, module docstrings that name the standard
  being followed (RFC/FIPS/OWASP/NIST). Lines up to ~120 characters. Comments explain *why*.
- Config: every new TOML key goes through `config.py` (`_Section` helpers reject unknown keys), plus
  `deploy/examples/*.example.toml` and the templates in `cli.py` / `portal/service.py` if generated.
- Portal: server-rendered HTML, every dynamic value through `html.escape`, no inline script (CSP), every POST carries
  the CSRF field, every security event goes to `_audit()`. New DB columns go in `USER_COLUMNS` (additive migration);
  the VPN server opens the same database.
- Firebase mirror is one-way and allow-listed (`firebase.py`); never mirror hashes, TOTP seeds, sessions, codes or
  SMTP passwords. A test enforces this.
- Android UI: messages cross `bridge.ts` ↔ `UiJson.kt` only; add a message type on both sides with tests. Only display
  data crosses, never keys or paths.
- Docs: Markdown is kept markdownlint-clean. Commit messages: short subject, bullet body explaining why, and the
  `Co-Authored-By` trailer.
- Known stale fact: README says "63 tests"; the suite now has ~137 Python tests plus JVM and Vitest suites.
- App features (registration, ads, app sign-in, payments) are admin settings that default off; keep it that way.
  `android-app/deploy.properties` (git-ignored) holds the portal URL, certificate pin and AdMob IDs; without it the
  app behaves as before (ZIP import). Never leave an emulator `portalUrl=http://10.0.2.2...` file behind.

## Environment gotchas (this PC)

- Bash here is Git Bash on Windows; for WSL use `wsl -d Ubuntu -u root -- bash script.sh` and put `$VAR` code in a
  `.sh` file (Git Bash and PowerShell both expand it otherwise). Set `MSYS_NO_PATHCONV=1` for Linux paths.
- Keep SQLite on a native filesystem (WSL `/var/lib/...`, not `/mnt/d`).
- Full tunnel cannot be tested with server and client on one machine (routing loop); use split tunnel or the emulator.
- Each wrong test login counts toward the 5-failure lockout; give HTTP probes their own loopback source address.
- On Android, a VPN app's `registerDefaultNetworkCallback` follows its own VPN; use a NOT_VPN network request.
