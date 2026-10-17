# ShieldsVPN for Android

A native Android VPN app that runs the **existing pqvpn protocol** through Android's official `VpnService`. It uses the same post-quantum handshake (ML-KEM + X25519/P-384, ML-DSA, SLH-DSA CA), the same packet format, and the same rekey, roaming and reconnect logic as the desktop clients. It connects to an unmodified pqvpn server.

> **Status:** working debug build, tested end to end on the Android 16 (API 36) x86_64 emulator against a real `pqvpn` server process. It has not been tested on a physical phone or against your production server yet. See [What was verified](#what-was-verified). It has not been independently audited and is not production-ready.

## How it works

```text
React UI (ui/, WebView)  <- JSON ->  MainActivity (Kotlin): permissions, file picker, Keystore, import
                                      |
MainActivity                      ShieldsVpnService (VpnService, foreground)
  Connect ─► VpnService.prepare()   │ startForeground(systemExempted)
            (Android consent)       │ worker thread ─► Python (Chaquopy)
                                    │      pqvpn.android_client.Session.run()
                                    │        ├─ loads profile + decrypted key, verifies own certificate
                                    │        ├─ UDP socket ─► bridge.protectSocket(fd)
                                    │        ├─ ClientNode (unchanged desktop code): handshake, timers
                                    │        ├─ on "connected": tunnel_settings(server push, profile, cert)
                                    │        │     └─ bridge.establishTunnel(json) ─► Builder.establish()
                                    │        │           └─ detachFd() ─► AndroidTun owns the TUN fd
                                    │        └─ stop() ─► close TUN fd + socket
                                    └ network callback (best non-VPN network) ─► Session.network_changed()
```

* **React** (`ui/`, TypeScript, built with Node.js and Vite) draws the whole screen. It runs in a WebView and talks to Kotlin only through a JSON message bridge. See [The React UI](#the-react-ui).
* **Kotlin** (`app/src/main/java/com/shieldsvpn/vpn/`) handles the consent and notification permissions, the file picker, the foreground service, `VpnService.Builder`, network-change detection and credential storage.
* **Python** (`pqvpn/android_client.py` plus the unchanged pqvpn modules) does everything protocol-related. Gradle copies only the 13 modules the client needs into the APK. The portal, desktop UIs, `NetConfig` and the desktop TUN drivers are not included.
* **OpenSSL 3.5.9** is cross-compiled for Android as `libcrypto_pqvpn.so` (`app/src/main/jniLibs/<abi>/`). `pqvpn/crypto/ossl.py` loads it through `PQVPN_LIBCRYPTO`, which `android_client.configure()` sets to the extracted file in `nativeLibraryDir` before anything imports the crypto module. The library has its own SONAME and symbol versions (`OPENSSL_PQVPN_3.0.0`), so it cannot clash with Chaquopy's `libcrypto_python.so` or the platform's BoringSSL.

### Choosing the tunnel address before `establish()`

`VpnService.Builder` needs the interface address, routes and DNS before it returns a TUN descriptor. The pqvpn server sends routes, DNS, prefix length and MTU only inside the encrypted, signature-authenticated AUTH_R message. The app therefore:

1. Runs the full handshake **first**, with no TUN interface. Nothing on the device is captured or routed yet.
2. Validates the server's configuration (`android_client.tunnel_settings`):
   * Every pushed address must be a host address in the **client certificate**, which the CA signed. The server derives it from the same certificate, so a mismatch is refused rather than applied.
   * Routes, DNS servers and MTU must be well-formed and within limits. Profile overrides (`routes`, `dns`, `full_tunnel`) apply exactly as on the desktop client.
3. Calls `establish()` **once** with the real values, and hands the detached file descriptor to Python.

Later rekeys, roaming and reconnects reuse the same interface. While the session recovers, traffic stays queued or dropped inside the tunnel instead of leaking. No address is invented and no interface is rebuilt.

### TUN I/O

`AndroidTun` implements the pqvpn TUN contract (`start`, `write`, `close`) over the `VpnService` descriptor:

* The descriptor is non-blocking and serviced by `loop.add_reader` on the asyncio thread. There is no blocking read and no reader thread to race with `close()`.
* Each read event drains at most 128 packets in one batch, and then the loop runs other work. The UDP socket uses pqvpn's `BatchedUdpTransport`, which drains up to 64 datagrams per wake-up. asyncio's stock transport reads one per loop turn and lost 87–98 % of bursty traffic in the host benchmark. There are no unbounded queues. When the kernel queue is full on write, the packet is dropped, as on a congested link.
* All reads, writes and `close()` run on the loop thread, so they are serialised. `close()` removes the reader before closing the descriptor. Closing the last reference makes Android tear the VPN interface down.
* Packets of an IP version the tunnel has no address for are dropped locally.
* Before the interface exists, writes are discarded. That is the behaviour the client needs during the first handshake.

### Routing and leak behaviour

| Profile | Routes | IPv4 | IPv6 when the tunnel has no IPv6 address |
| --- | --- | --- | --- |
| `full_tunnel = false` (**portal default**) | the server's `push_routes` | only those networks use the VPN | uses the normal network (`allowFamily(AF_INET6)`) |
| `full_tunnel = true` | adds `0.0.0.0/0` (and `::/0` with an IPv6 tunnel address) | everything uses the VPN | **blocked** by Android (`::/0 unreachable`), no leak |

* The app's own traffic (the encrypted UDP flow and DNS lookups for the server name) is excluded from the VPN with `addDisallowedApplication`, and its socket is also `protect()`ed, so it can never loop into the tunnel.
* DNS servers come from the server push (plan DNS from the portal, or `[tunnel] dns` in `server.toml`), unless the profile sets `dns`. **A full tunnel without any DNS server is refused** with an error that names the fix. On Android, a VPN without DNS servers makes the system resolve through the underlying network, which would leak every lookup. This was verified on API 36 before the fix. In split tunnel without pushed DNS, the device's normal resolver is used, as intended.
* **Always-on VPN** is supported: Settings › Network › VPN › ShieldsVPN › Always-on. Android starts the service with the `SERVICE_INTERFACE` action, and it connects with the imported profile. **"Block connections without VPN"** (lockdown) is Android's kill switch. The app card shows whether Android reports it as on, off or unknown, read after the interface is established, and links to the system settings. The app never claims a kill switch that Android is not enforcing.

## The React UI

The screen is a React 19 app in `ui/`, written in TypeScript and bundled by Vite. Gradle runs `npm ci` and `npm run build` before every Android build, and the output is packaged as `assets/ui/` in the APK.

* **Screen:** a state-coloured connect button with a spinning arc while busy and a glow when connected, plus a status headline and a connected-for timer. It also shows live download and upload rates with 30-second sparklines, and connection details: server, tunnel IP, encryption chips, certificate algorithm, routing and DNS. A profile card shows the account, a validity countdown, and Replace, Portal and Remove actions. New users get a three-step onboarding card, errors appear in bottom sheets, and successes in toasts.
* **Bridge (`ui/src/bridge.ts`, `UiJson.kt`):** the page sends commands (`ready`, `connect`, `disconnect`, `importProfile`, `removeProfile`, `openPortal`). The app sends `state`, `traffic` (polled once a second from `Session.stats_json()`), `notice` and `insets`. Only display data crosses: no keys, certificates or file paths. Unknown or malformed messages are dropped on both sides.
* **WebView hardening (`MainActivity`):**
  * The page is served from the APK by `WebViewAssetLoader` at `https://appassets.androidplatform.net`. Every other URL gets an empty 404, and navigation away is blocked.
  * File and content access, zoom, pop-up windows and mixed content are all off.
  * The bridge object is injected with `addWebMessageListener` only for that origin and only into the main frame.
  * The built page carries a Content-Security-Policy: scripts only from the bundle, no inline script, and no network connections at all.
  * Remote debugging is enabled only in debug builds.
* **Startup:** the branded splash screen stays up until React has rendered and WebView reports the frame ready (`postVisualStateCallback`), so no blank window appears. There is a 10-second safety cap.
* **Requirements:** Android System WebView 89 or newer (the build target). Older WebViews get a message asking to update.

Develop the UI in a desktop browser. A mock bridge walks through the real states:

```bash
cd android-app/ui
npm ci
npm run dev        # http://localhost:5173 with the mock VPN
npm test           # Vitest: formatting, bridge parsing, every screen state
npm run build      # typecheck + bundle into app/build/generated/ui-assets/ui
```

## Provisioning and credential storage

The app uses the profile ZIP the portal already issues (**Download VPN profile**, or an admin's **New profile** button). No new server endpoint is needed.

1. Download the profile ZIP from the portal on the phone, or copy it there.
2. In the app, tap **Import profile** (or the power button when no profile is installed) and choose the ZIP.
3. Python validates the ZIP in memory and never extracts paths from it:
   * exactly one `client.toml`, which may reference only files in the same folder
   * the certificate chains to the bundled CA, is a client certificate, and is valid now
   * the private key matches the certificate
   * the PSK, if present, is 32 bytes
4. Storage, all app-private and excluded from backups:
   * `files/profile/` holds `client.toml` (stored **without** `psk_file`), the certificate, the CA certificate and a summary. These are not secret.
   * `no_backup/profile.secrets` holds the private key and the PSK, encrypted with AES-256-GCM under a non-exportable **Android Keystore** key. The plaintext key is never written to disk. At connect time it is decrypted in memory and handed to OpenSSL.
5. **Remove** deletes the profile, the encrypted secrets and the Keystore key. Downloading a new profile in the portal invalidates the old certificate on the server within about 2 seconds, which is how a lost phone is cut off.

The APK contains no CA key, server key, shared secret or enrollment token. The operator supplies a reachable server, a portal account, and a profile ZIP per device. The endpoint in that profile (`[vpn] endpoint` in `portal.toml`) must be reachable from the phone.

## Versions

| Component | Version | Why |
| --- | --- | --- |
| Android Gradle Plugin | 8.13.0 | already used in this repo; Chaquopy 17.1 supports AGP 7.3–9.4 |
| Gradle | 8.14.3 (wrapper, SHA-256 pinned) | required by AGP 8.13 |
| Kotlin Gradle plugin | 2.3.21 | supports AGP 8.2.2–9.0.0 and Gradle 7.6.3–9.3 |
| Chaquopy | 17.1.0 | supports Python 3.10–3.15, minSdk 24 |
| Python (on device) | 3.13 | 64-bit ABIs; pqvpn needs ≥ 3.11 |
| Node.js (build machine) | ≥ 22.12 (tested 24.19) | required by Vite 8 and Vitest 5 |
| React / React DOM | 19.3.1 | UI |
| Vite + @vitejs/plugin-react | 8.3.4 + 6.1.2 | bundler (the plugin requires Vite ^8) |
| TypeScript | 7.0.2 | `tsc --noEmit` type check in every build |
| Vitest | 5.0.5 | UI unit tests (supports Vite 6–8) |
| androidx.webkit / core-splashscreen | 1.14.0 / 1.2.0 | asset loader and origin-restricted bridge; splash held until the UI is ready |
| OpenSSL | 3.5.9 (built with NDK r28c, API 24) | first series with ML-KEM / ML-DSA / SLH-DSA |
| compileSdk / targetSdk / minSdk | 36 / 36 / 24 | |
| ABIs | `arm64-v8a`, `x86_64` | OpenSSL is built only for these; `x86_64` is for emulators |

## Build

Requirements: JDK 17 or 21, Android SDK (platform 36 is fetched automatically), **Node.js 22.12+ with npm** on `PATH` (Gradle builds the React UI), internet for the first build. The NDK is only needed to rebuild OpenSSL.

```bash
cd android-app
echo "sdk.dir=/path/to/Android/Sdk" > local.properties     # Windows: sdk.dir=C:/Users/<you>/AppData/Local/Android/Sdk
./gradlew testDebugUnitTest assembleDebug                     # Windows: gradlew.bat ...
# -> app/build/outputs/apk/debug/app-debug.apk
```

Signed release build. The keystore and its passwords never go in the repository. Point Gradle at a `keystore.properties` file (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`; `storeFile` is relative to that file). Without one, the release APK is built unsigned.

```bash
./gradlew assembleRelease -Pshieldsvpn.signing=/path/to/keystore.properties
# -> app/build/outputs/apk/release/app-release.apk  (check: apksigner verify --print-certs <apk>)
```

Rebuild the OpenSSL libraries (Linux or WSL, NDK r28c):

```bash
curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz   # verify its SHA-256
ANDROID_NDK_ROOT=$HOME/android-ndk-r28c ./native/build-openssl-android.sh openssl-3.5.9.tar.gz
ANDROID_NDK_ROOT=$HOME/android-ndk-r28c ./native/check-libs.sh     # ELF class/machine, 16 KB alignment, exports
```

Check the library on a device or emulator without the app:

```bash
ANDROID_NDK_ROOT=... ./native/build-selftest.sh
adb push native/build/pqcrypto_selftest-arm64-v8a app/src/main/jniLibs/arm64-v8a/libcrypto_pqvpn.so /data/local/tmp/
adb shell 'cd /data/local/tmp && ./pqcrypto_selftest-arm64-v8a'      # "all checks passed"
```

Tests:

* `python -m pytest -q`, run from the repository root, includes `tests/test_android_client.py`. It covers profile import and validation, tunnel-setting rules and leak handling, network-change handling, and a full session against a real `ServerNode` with an AF_UNIX socket pair standing in for the TUN fd. The fd-based tests need Linux or macOS and are skipped on Windows.
* `./gradlew testDebugUnitTest` runs the React UI tests (Vitest) and the JVM tests for tunnel-config parsing, state mapping, bridge JSON and redaction.

## Install and use

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

1. Open **ShieldsVPN**, then tap **Import profile** (or the power button) and pick the ZIP from the portal.
2. Tap the power button. Android asks once to allow notifications and once for **VPN consent** ("Connection request").
3. The ring turns green and shows **Connected**, a timer and live traffic, with the server, tunnel IP, encryption and routing. Android's key icon appears in the status bar, along with a persistent notification that has a **Disconnect** button.
4. Tap the button again, or Disconnect in the notification, to stop. Switching the VPN off in Settings, or another VPN app taking over, also stops it cleanly.

States: Disconnected · Preparing VPN · Connecting · Connected · Reconnecting · Error · Disconnecting.

## Permissions

| Permission | Why |
| --- | --- |
| `INTERNET` | the encrypted UDP connection to the server |
| `ACCESS_NETWORK_STATE` | detect Wi-Fi ↔ mobile switches and re-handshake immediately |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` | keep the VPN running with a visible notification. `systemExempted` is the type Android documents for apps holding VPN consent |
| `FOREGROUND_SERVICE_SPECIAL_USE` | fallback type if a device refuses `systemExempted` (not needed on the tested emulator) |
| `POST_NOTIFICATIONS` | show that notification (Android 13+) |
| `BIND_VPN_SERVICE` (on the service) | only the system may bind the VPN service |

## What was verified

All of this was on the API 36 x86_64 emulator (Google Play image), against a throwaway `pqvpn` server on the host. That server ran the real `ServerNode` with `PortalAccess` and a portal-issued profile. Its in-memory TUN answered ICMP with TTL 77, so a reply provably came back through the tunnel.

* **Import and storage:** a portal profile was imported, with no plaintext key or PSK on disk and files at mode 0600.
* **Consent:** Android's consent dialog appeared, the foreground service ran as `systemExempted`, and `tun0` was created only after the handshake.
* **Split tunnel:** pings to tunnel addresses returned TTL 77, and outside traffic stayed off the VPN.
* **Full tunnel:** 1.1.1.1 was answered by the VPN server, and IPv6 was blocked (`::/0 unreachable`).
* **Wi-Fi switch:** switching Wi-Fi off and on triggered a re-handshake 0.6 s after the new network appeared.
* **Server restart:** the app showed Reconnecting, kept `tun0`, and recovered automatically.
* **Account disabled in the portal:** the session was cut, and it recovered after the account was re-enabled.
* **Stopping:** disconnect from the app, from the notification, or by revocation in Settings removed the tunnel, the service and the notification.
* **Declined consent:** the app showed an error and started nothing.
* **No profile:** the power button opened the importer instead of connecting.
* **ARM64:** `libcrypto_pqvpn.so` passed `pqcrypto_selftest` on Android under the emulator's ARM translation (Berberis). The full app forced to `arm64-v8a` crashed on that emulator while Chaquopy's ARM64 Python interpreter was starting under translation, before any ShieldsVPN code or OpenSSL ran. **The ARM64 app still needs a test on a real ARM64 phone.**

**React UI, verified on the same emulator with the host GPU:**

* Cold start shows the splash, then the UI, within about 2 s, with no blank frame.
* Connect, live traffic counters and sparklines, and disconnect all worked.
* The remove confirmation sheet led to the empty-state onboarding, and the files were deleted.
* Importing a non-ZIP file showed the error sheet.
* A fresh import followed by connect worked.

**Reliability and leak checks (this revision, same emulator):**

* **DNS:** full tunnel without pushed DNS → lookups went to the underlying network (leak). After the fix the app refuses to connect and creates no `tun0`. With pushed DNS, lookups enter the tunnel.
* **Lockdown and always-on:** with lockdown enabled, DNS, TCP and ICMP were blocked after an in-app disconnect and while the process was killed during a reinstall. Always-on restarted the service and reconnected.
* **Connect/disconnect cycles:** 12 cycles, then 10 more on the rebuilt APK, then 5 on the final APK, all OK.
  * Handshake to tunnel took 54–223 ms (the first connect is cold).
  * File descriptors stayed at 251–254 and threads at 47–49, so nothing leaked.
  * `tun0` was removed every time.
  * A rapid connect, disconnect, connect sequence ended connected, with one `tun0`.
* **Tunnel RTT** to the server's tunnel address: 2.6/4.1/7.6 ms min/avg/max over 30 pings, 0 % loss.
* **Native self-test:** `pqcrypto_selftest` passed all 9 checks against the packaged x86_64 `libcrypto_pqvpn.so`. Provenance (verified tarball signature and NDK checksum) is in [native/PROVENANCE.md](native/PROVENANCE.md).
* **APK secret scan:** `python tools/secret_scan.py app/build/outputs/apk/debug/app-debug.apk` found 0 findings, including inside the nested Chaquopy archives.

**Not verified:** a physical device, your production server or playit endpoint, real internet browsing through a NAT-ing server, a real IPv6 network (the emulator has no global IPv6), and Android versions other than 16.

## Limitations

* **Python data plane:** throughput is CPU-bound, similar to the desktop client (roughly 100–200 Mbit/s per core on a PC, less on phones). Battery use under heavy traffic is higher than a native WireGuard client.
* **Disabled accounts:** a disabled account or superseded profile shows **Reconnecting** rather than a specific error. The protocol deliberately sends nothing to an unauthenticated client.
* **Configuration changes:** server-side DNS or route changes apply at the next connect, not during a session (same as desktop).
* **Unsupported features:** passphrase-protected profile keys, per-app split tunnelling and IPv6 without an IPv6 tunnel address are not supported.
* **Secrets in memory:** the decrypted private key briefly exists in JVM and Python memory, which cannot be zeroised reliably, until OpenSSL owns it.
* **APK size:** about 31 MB, because both ABIs each carry Python and OpenSSL. Ship an App Bundle so each device downloads one ABI.
* **Licences:** third-party notices and licence texts (OpenSSL Apache-2.0, Python PSF, Chaquopy MIT, React MIT) are shipped in `assets/licenses/`. They are not yet shown on an in-app screen.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| "Import failed: … certificate is not usable: certificate expired" | download a fresh profile from the portal |
| Stays on **Connecting** / **Reconnecting** | the server is not reachable from the phone (check the profile's server address and UDP port), or the account is disabled, or the profile was superseded by a newer download |
| "VPN permission was declined" | tap Connect again and accept Android's dialog |
| "Android did not create the VPN interface" | another VPN app took over, or consent was revoked; tap Connect again |
| "full tunnel needs a DNS server inside the tunnel …" | set `[tunnel] dns` in `server.toml`, or a plan DNS in the portal, to a resolver reachable through the tunnel |
| Full tunnel connects but websites don't load | the server needs `nat_interface` (Linux NAT) and DNS (`[tunnel] dns` or plan DNS in the portal) |
| Logs | `adb logcat -s ShieldsVpnService ShieldsPython python.stderr`. Keys and long base64 strings are redacted before logging. |
