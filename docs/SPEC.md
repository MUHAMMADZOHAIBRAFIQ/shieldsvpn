# ShieldsVPN — Technical Specification

| | |
| --- | --- |
| Version | 1.0, 2026-10-18, describes `pqvpn` 1.0.0 on branch `shieldsvpn-android-security-upgrade` |
| Audience | Engineers working on the server, portal or clients |
| Product requirements | [PRD.md](PRD.md) |
| Wire protocol (normative) | [PROTOCOL.md](PROTOCOL.md). This document summarises it and does not override it. |
| Threat model | [SECURITY.md](SECURITY.md), [../research/TRAFFIC_ANALYSIS.md](../research/TRAFFIC_ANALYSIS.md) |

Sections marked **Proposed** describe work that does not exist in the code yet.

## 1. System overview

```text
                         ┌──────────────────────── Linux host (/var/lib/pqvpn) ────────────────────────┐
 Android app ──UDP 51820─┤  pqvpn server (ServerNode)  ── reads/writes ──►  portal.db (SQLite, WAL)    │
 Windows tray/app ───────┤      │ TUN pqvpn0, NAT                                ▲                     │
 Linux client ───────────┤      └─ PortalAccess: per-handshake account check     │                     │
                         │                                                       │                     │
 Admin browser ──HTTPS───┤  pqvpn portal (stdlib HTTP server) ── issues profiles ┘ ── CA key (ca/ca.key)│
                         │      ├─ node send-mail.js (Nodemailer) ──► SMTP (Gmail)                      │
                         │      └─ Firestore REST (optional one-way mirror) ──► Firebase                 │
                         └─────────────────────────────────────────────────────────────────────────────┘
 Landing page (public/index.html) ── Vercel, static only
```

| Component | Process | Code |
| --- | --- | --- |
| VPN server | `python -m pqvpn server -c server.toml` (root or `CAP_NET_ADMIN`) | `runner.run_server`, `node.ServerNode` |
| Portal | `python -m pqvpn portal -c portal.toml` | `portal/web.py` |
| Desktop client | `pqvpn client`, `pqvpn tray` (Windows), `pqvpn app` (tkinter) | `runner.run_client`, `winui.py`, `app.py` |
| Android client | `com.shieldsvpn.vpn` APK | `android-app/`, `pqvpn/android_client.py` |

The server and portal are separate processes sharing one SQLite database. The VPN keeps working if the portal is
down (it only reads the database) and never depends on Firebase or email.

## 2. Runtime requirements

| | Requirement |
| --- | --- |
| Python | ≥ 3.11, standard library only (`tomllib`, `asyncio`, `sqlite3`, `ctypes`, `http.server`) |
| OpenSSL | ≥ 3.5 `libcrypto`, loaded by `ctypes`; override with `PQVPN_LIBCRYPTO` |
| Linux server | `/dev/net/tun`, `iproute2`; `iptables` for NAT; `resolvectl` for client DNS |
| Windows client | Administrator (UAC), signed `wintun.dll` next to `pqvpn/` or `PQVPN_WINTUN` |
| Portal email | Node.js ≥ 20 (`PQVPN_NODE` to override), `npm ci --omit=dev` in `pqvpn/portal/mailer` |
| Android | API 24+ (target 36), ABIs `arm64-v8a`, `x86_64`, WebView ≥ 89 |

## 3. Cryptography and protocol (summary)

Normative details, byte layouts and the key schedule are in PROTOCOL.md.

| Element | Specification |
| --- | --- |
| Suites (u16) | `0x0001` MLKEM768-X25519 / ChaCha20-Poly1305 / SHA-384 (default) · `0x0002` MLKEM768-X25519 / AES-256-GCM · `0x0003` MLKEM1024-P384 / AES-256-GCM · `0x0004` MLKEM1024 (pure PQ) / AES-256-GCM |
| Signatures | ML-DSA-44/65/87 for devices (default ML-DSA-65); SLH-DSA (SHA2/SHAKE 128–256, s/f) or ML-DSA-87 for CAs (default SLH-DSA-SHA2-192s) |
| Handshake | INIT → [COOKIE] → [RETRY] → RESPONSE → AUTH_I → AUTH_R → keepalive. IKEv2-style ordering, RFC 9370 hybrid KEX, TLS 1.3 key schedule (HKDF-SHA-384, labels prefixed `pqvpn1 `), SIGMA sign-and-MAC |
| Fragmentation | Application-layer, `CHUNK = 1184`, ≤ 64 fragments, every datagram ≤ 1216 B; AUTH messages AEAD-encrypted per fragment; senders retransmit cached datagrams byte-for-byte |
| Data plane | 16-byte header `0x04 | rsv | receiver_index | counter`, AEAD with the header as AAD, plaintext padded to 16 B, 2048-packet replay window updated after authentication |
| Optional PSK | 32 bytes, mixed as the early secret (third independent secret) |
| Config push | `addresses`, `routes`, `dns`, `mtu`, `rekey_interval`, optional `portal` — inside AUTH_R, covered by `fin_R` |

### 3.1 Timers (`protocol.py`)

| Timer | Value |
| --- | --- |
| Proactive rekey (client) | `rekey_interval`, default 120 s (30–3600) |
| Keypair rejection | 180 s (1.5 × rekey) |
| Handshake retransmit | 1, 2, 4, 8, 8 … s with jitter |
| New ephemerals after | 30 s without completion |
| Passive keepalive | 10 s |
| Dead-peer detection | 15 s silence after sending |
| Persistent keepalive (client) | 25 s default |
| Half-open / reassembly timeout | 15 s / 10 s |

### 3.2 DoS controls

Cookies when half-open handshakes ≥ `cookie_threshold` (default 64) or always (`always_require_cookie`); cookie secret
rotates every 120 s. Per-IP token bucket `handshake_rate_per_ip` (default 5/s, burst 2×). Reassembly bounded to 1024
entries / 16 MiB. RESPONSE is never larger than INIT. RETRY/COOKIE limited to 4 per attempt.

### 3.3 Invariants

- Wire format version 1 is frozen. Any change requires a version bump, explicit negotiation (capability bit in
  INIT/RESPONSE) and interoperability tests with deployed servers.
- Only `crypto/suites.py` names concrete algorithms; only `crypto/ossl.py` handles key material.
- Unknown or policy-disallowed algorithms are refused, never accepted silently.

## 4. PKI

- Custom compact certificate (`PQVPN CERTIFICATE` PEM), canonical encoding enforced on decode. Fields: role
  (CA/server/client), 16-byte serial, subject (≤ 64 chars), validity, key algorithm + public key, address list,
  issuer key ID. Signature context `pqvpn1 certificate`.
- **Addressing lives in the certificate.** A client certificate's first address is a single host (`/32` or `/128`) and
  becomes its tunnel IP; extra addresses are routed subnets behind the client (site-to-site). The server needs no
  per-client config.
- Validation: role, subject (the initiator checks `server_name`), validity ±300 s, revocation list, algorithm policy,
  issuer in the trusted CA set (several CAs may be trusted during a migration).
- Revocation: with the portal, by *superseding* — only the user's `active_serial` is accepted. Without the portal,
  `[security] revoked_serials` plus a server restart.

## 5. Configuration reference

All files are TOML. Relative paths resolve against the config file's directory. **Unknown keys and sections are
errors.** Secrets are referenced by path, never inlined. Templates: `deploy/examples/*.example.toml`.

### 5.1 `server.toml`

| Key | Default | Notes |
| --- | --- | --- |
| `[server] listen` | `0.0.0.0:51820` | `host:port` or `[v6]:port` |
| `certificate`, `private_key`, `ca` (list) | required | `private_key_passphrase_file` optional |
| `[tunnel] interface` | `pqvpn0` | 1–15 chars `[A-Za-z0-9_-]` |
| `mtu` | 1420 | 1280–9000 |
| `addresses` | from server certificate | CIDR interfaces |
| `dns` | `[]` | pushed to clients unless overridden per plan/user. **Full-tunnel clients require at least one.** |
| `push_routes` | server networks | split-tunnel routes |
| `nat_interface` | `""` | e.g. `eth0`: enables forwarding + MASQUERADE (Linux) |
| `[crypto] suites` | the three hybrid suites | server preference order |
| `peer_signature_algorithms` | ML-DSA-65, ML-DSA-87 | |
| `ca_signature_algorithms` | SLH-DSA family | |
| `rekey_interval` | 120 | 30–3600 |
| `psk_file` | none | base64 of 32 bytes |
| `[security] revoked_serials` | `[]` | lower-case hex |
| `max_peers` / `cookie_threshold` / `always_require_cookie` / `handshake_rate_per_ip` | 1024 / 64 / false / 5 | |
| `[portal] database` | none | enables account-based access control |
| `[portal] url` | `""` | pushed to clients ("Open portal") |

### 5.2 `client.toml`

`[client]` `server` (host:port, re-resolved on reconnect), `server_name`, `certificate`, `private_key`, `ca`,
`portal_url`, `private_key_passphrase_file`. `[tunnel]` `interface`, `mtu`, `full_tunnel` (false), `routes` (empty =
use pushed), `use_server_dns` (true), `dns`, `persistent_keepalive` (25). `[crypto]` as for the server.
`[security] revoked_serials`.

### 5.3 `portal.toml`

| Key | Default | Notes |
| --- | --- | --- |
| `[portal] listen` | `["127.0.0.1:8800"]` | Plain HTTP only on loopback or VPN-subnet addresses unless `allow_insecure_http` |
| `public_url`, `allowed_hosts` | `""`, `[]` | Host-header allow-list (loopback, listen addresses and configured URLs are implicit) |
| `database` | required | `portal.db` |
| `tls_certificate` + `tls_private_key` | none | both or neither; TLS ≥ 1.2 |
| `issuer` | `ShieldsVPN` | brand in UI, email and TOTP label |
| `require_2fa_for_admins` | true | |
| `session_idle_minutes` / `session_max_hours` | 30 / 12 | |
| `allow_internal_smtp` | false | permit a loopback/private SMTP relay |
| `[vpn] server_name`, `endpoint`, `subnet` | required | written into issued profiles |
| `reserved_addresses` | `[]` | never allocated (e.g. the server's tunnel IP) |
| `ca_certificate`, `ca_private_key`, `ca_passphrase_file` | | the portal signs client certificates |
| `psk_file` | none | copied into profiles |
| `client_algorithm` / `certificate_days` | ML-DSA-65 / 90 | |
| `suites` | defaults | written into profiles |
| `portal_url_in_vpn` | `""` | portal URL as seen through the tunnel |
| `full_tunnel` | false | issued profiles route everything through the VPN (`portal-init --nat-interface` sets true) |

## 6. Portal

### 6.1 Data model (`portal/store.py`)

SQLite in WAL mode, foreign keys on, busy timeout 5 s. Must live on a local filesystem. Additive migrations through
`USER_COLUMNS` run at open, inside `BEGIN IMMEDIATE`, by whichever process opens first.

| Table | Purpose | Key columns |
| --- | --- | --- |
| `users` | accounts | `username` (unique, NOCASE, = certificate subject), `role` (`admin`/`user`), `password_hash` (scrypt), `must_change_password`, `totp_secret`/`totp_enabled`/`totp_last_step`, `enabled`, `vpn_ip` (unique), `active_serial`, `profile_issued_at`, `failed_logins`/`locked_until`, `email` (unique NOCASE when set), `email_verified`, `plan` (`free`/`premium`), `plan_expires` (first second after the last paid day), `custom_dns` |
| `sessions` | portal sessions | `token_hash` (SHA-256 of a 256-bit token), `csrf`, `pending_2fa`, `pending_totp_secret`, timestamps, `ip`, `user_agent` |
| `devices` | known browsers for lockout scoping | `token_hash`, per-device `failed_logins`/`locked_until`; ≤ 20 per user, 60-day TTL |
| `password_resets` | emailed codes (recovery and sign-up verification) | `code_hash` (scrypt), `expires_at`, `attempts`, `used` |
| `audit` | security events | `ts`, `actor`, `ip`, `action`, `detail` (≤ 500 chars) |
| `peers` | live sessions, rewritten by the VPN server every ~2 s | endpoint, address, suite, key alg, connected/handshake times, rx/tx bytes |
| `meta` | `server_heartbeat` | server is "online" if the heartbeat is < 10 s old |
| `settings` | admin-editable key/values | see 6.3 |

### 6.2 HTTP routes (`ROUTES` in `portal/web.py`)

Levels: `public`, `pending` (password OK, awaiting 2FA), `any`, `user`, `admin`. Every POST requires the CSRF token
and a same-origin `Origin`; every request requires an allowed `Host`.

| Method | Path | Level | Purpose |
| --- | --- | --- | --- |
| GET | `/` | user | personal dashboard (status, profile, security, plan) |
| GET/POST | `/login` | public | sign in by username or email; `?next=` validated by `_safe_next` |
| GET/POST | `/login/2fa` | pending | TOTP step |
| POST | `/logout` | any | |
| GET/POST | `/forgot`, `/forgot/verify` | public | emailed 6-digit reset code |
| GET/POST | `/signup`, `/signup/verify` | public | only when `allow_signup = 1`; 404 otherwise |
| GET | `/upgrade` | user | Premium page; payment button is a disabled placeholder |
| POST | `/profile` | user | issue and download own profile ZIP |
| GET | `/api/status` | user | JSON: `now`, `server_online`, `me`; admins also get `peers` |
| GET/POST | `/account`, `/account/password`, `/account/email`, `/account/2fa`, `/account/2fa/disable` | user | self-service |
| GET | `/admin` | admin | dashboard, add-user form, user table, live peers, recent audit |
| POST | `/admin/users` | admin | create user (temporary password shown once) |
| GET | `/admin/users/{id}` | admin | user page |
| POST | `/admin/users/{id}/{action}` | admin | `edit`, `disable`, `enable`, `unlock`, `signout`, `reset-password`, `reset-2fa`, `profile`, `delete` (not on self for disable/delete) |
| GET | `/admin/audit` | admin | audit log |
| GET | `/admin/settings` | admin | settings page |
| POST | `/admin/settings/access`, `/dns`, `/email`, `/email/test` | admin | |
| POST | `/admin/settings/firebase/{connect,sync,pause,resume,remove}` | admin | |
| GET | `/static/{style.css,app.js}`, `/favicon.ico` | public | |

Authorization runs on every request, not only at sign-in: a demoted account or a changed access setting ends open
sessions immediately. Users who must change their password, or admins without 2FA when it is required, are redirected
until they comply.

### 6.3 Settings keys (`settings` table)

| Key | Default | Meaning |
| --- | --- | --- |
| `portal_access` | `admins` | `admins` or `everyone` may sign in |
| `allow_signup` | `0` | public sign-up (needs `everyone` and working email) |
| `dns_free_preset`, `dns_free_custom` | `default`, `""` | Free plan DNS |
| `dns_premium_preset`, `dns_premium_custom` | `adguard`, `""` | Premium plan DNS |
| `smtp_host`, `smtp_port`, `smtp_security`, `smtp_user`, `mail_from_name` | Gmail, 465, `ssl` | |
| `smtp_password` | | sealed `enc:v1:` with AES-256-GCM under `portal-secrets.key` |
| `firebase_*` | | mirror state; the key itself is `firebase-key.json` (0600) |

DNS presets: `default` (server.toml), `cloudflare`, `cloudflare-security`, `cloudflare-family`, `quad9`, `adguard`,
`adguard-family`, `google`, `custom` (≤ 4 servers).

### 6.4 Business rules

- **Effective plan:** `premium` only if `plan = premium` and `plan_expires` is unset or in the future; otherwise
  `free`. No job runs; it is evaluated at use.
- **DNS pushed to a user** (first match): user `custom_dns` → effective plan's preset/custom → server.toml `dns`.
  Applies at the next connection.
- **Profile issuance** (`service.issue_profile`): allocate `vpn_ip` from `subnet` minus `reserved_addresses` if
  unset; generate a fresh ML-DSA key; issue a client certificate (subject = username, address = `vpn_ip/32`,
  `certificate_days`); set `active_serial`; return a ZIP `pqvpn-<user>/{client.toml, <user>.crt, <user>.key, ca.crt,
  [psk.key], README.txt}`. The private key is never stored by the portal.
- **VPN access** (`access.PortalAccess.authorize`, every handshake): account exists, `enabled`, and
  `active_serial == certificate serial`. `sync()` every 2 s publishes peers and returns sessions to disconnect.
- **Sign-up:** creates a Free `user` with `email_verified = 0` and a certificate-safe username derived from the
  email; login is refused until the code is verified. An existing verified email gets an identical response and no
  email (no enumeration, no takeover). Re-sign-up of an unverified address adopts the new password and resends.

### 6.5 Authentication parameters

| Control | Value |
| --- | --- |
| Password hash | scrypt N=2^17, r=8, p=1, 16-byte salt; ≤ 4 concurrent hashes (memory bound); dummy hash for unknown users |
| Password policy | 10–128 chars, not common/breached sample, not containing the username (NIST SP 800-63B) |
| TOTP | RFC 6238, SHA-1, 6 digits, 30 s, ±1 step, replay-protected; QR enrolment |
| Lockout | 5 failures → 15 min, per known device; unknown clients share one bucket per account |
| Rate limit | per IP, 10 attempts burst, refill 10/min (sign-in, reset, sign-up, verification) |
| Reset / verify codes | 6 digits, scrypt-hashed, 10 min, single use, 5 guesses; resend ≥ 60 s apart, ≤ 5/hour; newest code supersedes |
| Sessions | cookie HttpOnly, SameSite=Strict, `Secure` + `__Host-` under TLS; 30 min idle / 12 h absolute; rotated at login; revoked at logout, password change, disable |
| Headers | CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin` (not `no-referrer`, which makes browsers send `Origin: null`), COOP/CORP same-origin, `Cache-Control: no-store`, HSTS under TLS |

### 6.6 Email

Python spawns `node pqvpn/portal/mailer/send-mail.js` per message; the message and SMTP password go over stdin (never
argv/env). TLS is mandatory (465 implicit, 587 STARTTLS) with certificate verification. The SMTP host is resolved
once, refused if loopback/private/reserved (unless `allow_internal_smtp`), and the connection is pinned to that IP
(SSRF and DNS-rebinding protection). Messages: reset code, sign-up code, password changed, test.

### 6.7 Firebase mirror (optional)

One-way, allow-listed copy to Firestore via REST with an RS256 service-account JWT signed by OpenSSL. Collections:
`users/{username}`, `connections/{username}`, `status/server`, `settings/portal`, `audit/{id}`. Writes only on change;
traffic counters and heartbeat at most every 300 s (free tier: 20k writes/day). The token endpoint is fixed
(`oauth2.googleapis.com`); a pasted key's `token_uri` is validated but never used as a URL. Never mirrored: password
hashes, TOTP secrets, sessions, codes, SMTP password. Access decisions never read from Firebase.

### 6.8 Audit events

`login`, `login_failed`, `login_locked`, `login_denied`, `login_disabled`, `login_unverified`, `login_rate_limited`,
`login_password_ok`, `logout`, `2fa_enabled`, `2fa_disabled`, `2fa_failed`, `2fa_reset`, `account_locked`,
`password_changed`, `password_change_failed`, `password_reset`, `password_reset_requested`, `password_reset_not_sent`,
`password_reset_code_failed`, `password_reset_rate_limited`, `password_reset_by_email`, `email_changed`,
`email_change_failed`, `email_sent`, `email_failed`, `email_settings_changed`, `signup_started`, `signup_resend`,
`signup_existing`, `signup_verified`, `signup_code_failed`, `signup_rate_limited`, `profile_issued`, `user_created`,
`user_updated`, `user_disabled`, `user_enabled`, `user_unlocked`, `user_deleted`, `sessions_revoked`,
`dns_settings_changed`, `portal_access_changed`, `firebase_connected`, `firebase_connect_failed`,
`firebase_key_removed`, `portal_initialised`. A typed login that matches no account is recorded as `(unknown)`.

## 7. Server data path

- `ServerNode.config_for(cert)` enforces `max_peers`, calls `PortalAccess.authorize`, refuses certificates claiming the
  server's own address, and builds the push: client host addresses with the server network's prefix length, routes
  (`push_routes` or server networks), DNS (override or server), MTU, rekey interval, portal URL.
- Cryptokey routing: outbound by longest-prefix match on certificate addresses; inbound source must route back to the
  same peer.
- Roaming: endpoint updated only on an authenticated packet with the highest counter on the current keypair.
- UDP I/O: `BatchedUdpTransport` drains up to 64 datagrams per readiness event on selector loops (Linux, Android,
  macOS); a full kernel send buffer drops the datagram. Windows keeps asyncio's Proactor transport.
- `NetConfig` registers an inverse for every OS change (addresses, routes, DNS, NAT) and undoes them on exit. Full
  tunnel on desktop uses `0.0.0.0/1` + `128.0.0.0/1` plus a pinned host route to the server.

## 8. Desktop clients

| Client | Behaviour |
| --- | --- |
| `pqvpn client` | Foreground CLI; Linux needs root, Windows an Administrator terminal |
| `pqvpn tray` (Windows) | Notification-area shield (grey/amber/green/red), notifications, menu (Connect, Disconnect, Open portal, Open log, Exit), auto-reconnect, single instance (`--replace` restarts), self-elevates via UAC, survives Explorer restarts. Log: `%LOCALAPPDATA%\pqvpn\pqvpn-tray.log`. AppUserModelID `PQVPN.PostQuantumVPN` |
| `pqvpn app` | tkinter "Tap to Connect" window: power button, status, timer, VPN address, encryption, server. UAC on Connect. `--install-shortcut` creates Desktop/Start-menu "ShieldsVPN" |

Known limit: Windows may still use DNS servers on other interfaces in full-tunnel mode (smart multi-homed
resolution).

## 9. Android client

### 9.1 Architecture

```text
React UI (WebView, assets/ui) ⇄ JSON bridge ⇄ MainActivity (Kotlin)
                                               │ connect / import / remove
                                               ▼
                                    ShieldsVpnService (VpnService, foreground)
                                               │ worker thread
                                               ▼
                         Chaquopy Python: pqvpn.android_client.Session.run()
                           ├─ protectSocket(fd) ─► VpnService.protect()
                           ├─ ClientNode handshake (unchanged desktop code)
                           ├─ tunnel_settings(push) ─► establishTunnel(json) ─► Builder.establish()
                           └─ AndroidTun over the detached fd (loop.add_reader, ≤ 128 packets per batch)
```

Gradle copies only these Python modules into the APK: `__init__`, `android_client`, `config`, `handshake`, `node`,
`pki`, `protocol`, `session`, `wire`, `crypto/{__init__,kdf,ossl,suites}`. OpenSSL 3.5.9 is packaged as
`libcrypto_pqvpn.so` (own SONAME and symbol versions, 16 KB page alignment), provenance in
`android-app/native/PROVENANCE.md`.

### 9.2 Connection sequence

1. Tap Connect → `VpnService.prepare()` consent (and notification permission on Android 13+).
2. Service enters the foreground (`systemExempted`, fallback `specialUse`).
3. Python loads the profile and the decrypted key, verifies its own certificate, opens and protects the UDP socket.
4. Handshake runs **with no TUN interface**; nothing is captured yet.
5. `tunnel_settings()` validates the authenticated push (9.3); on failure the session ends with an error.
6. `establish()` once; the fd is handed to Python. Rekeys, roaming and reconnects reuse it (traffic is held, not
   leaked).
7. Network changes (NOT_VPN network callback) trigger an immediate re-handshake.
8. Stop: from the UI, the notification, consent revocation or another VPN; the fd and socket are closed on the loop
   thread.

States: `DISCONNECTED`, `PREPARING`, `CONNECTING`, `CONNECTED`, `RECONNECTING`, `ERROR`, `DISCONNECTING`. A queued
Connect that arrives during shutdown runs after it (`pendingConnect`).

### 9.3 Tunnel-settings rules (`android_client.tunnel_settings`)

- Every pushed address must be a host address in the CA-signed client certificate; `/0` prefixes refused.
- Routes: profile `routes` override pushed ones; `full_tunnel` adds `0.0.0.0/0` (and `::/0` if an IPv6 address
  exists). Routes of a family with no tunnel address are dropped. ≤ 256 routes; at least one required.
- DNS: profile `dns`, else pushed DNS if `use_server_dns`; same-family only; ≤ 8.
- **Full tunnel with no DNS → `TunnelConfigError`** (Android would otherwise resolve outside the tunnel).
- Families without a tunnel address are **blocked** in full tunnel and **bypass** the VPN in split tunnel.
- MTU = min(profile, server push) within 1280–9000.
- The app's own UID is excluded (`addDisallowedApplication`) and its socket protected.

### 9.4 Profile import and storage

- Input: the portal ZIP (≤ 4 MiB, members ≤ 512 KiB), parsed in memory; exactly one `client.toml` referencing only
  sibling files; certificate chains to the bundled CA, is a client certificate, valid now, matches the key; PSK is
  32 bytes.
- `files/profile/`: `client.toml` (without `psk_file`), certificate, CA, summary — not secret.
- `no_backup/profile.secrets`: key + PSK sealed with AES-256-GCM under a non-exportable Android Keystore key, tagged
  with the certificate serial; a mismatching serial is refused. Backups and device transfer are disabled.
- Remove deletes files, sealed secrets and the Keystore key.

### 9.5 UI bridge contract (`ui/src/bridge.ts` ⇄ `UiJson.kt`)

| Direction | Messages |
| --- | --- |
| UI → app | `ready`, `connect`, `disconnect`, `importProfile`, `removeProfile`, `openPortal`, `openVpnSettings` |
| app → UI | `state` (phase, details, `alwaysOn`, `lockdown` as true/false/unknown), `traffic` (`rx`, `tx`, `at`, polled 1 Hz), `notice` (`ok`/`error`, title, text), `insets` |

Only display data crosses; no keys, certificates or paths. Unknown or malformed messages are dropped on both sides.
The page is served by `WebViewAssetLoader` from `https://appassets.androidplatform.net`, the bridge is injected only
for that origin and main frame, navigation is blocked, CSP forbids inline script and network access, and remote
debugging is debug-only.

### 9.6 Permissions

`INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`,
`FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`; the service requires `BIND_VPN_SERVICE` and declares
`SUPPORTS_ALWAYS_ON`.

## 10. CLI reference

| Command | Purpose |
| --- | --- |
| `algorithms` | list suites and signature algorithms with the loaded OpenSSL version |
| `selftest` | in-process handshake + data for every suite |
| `genpsk` | print a 32-byte base64 PSK |
| `quickstart --out --server-name --endpoint --clients [--subnet --ca-alg --alg --days --psk]` | CA + server + client bundles |
| `ca-init --out --name [--alg --days]` | root CA (passphrase prompt) |
| `issue --ca --role {server,client} --name [--address ... --pubkey --days --alg] --out` | issue a certificate |
| `genkey --out PREFIX [--alg]` | device key pair for CSR-less enrolment |
| `show FILE` | describe a certificate |
| `server -c`, `client -c` | run the VPN |
| `portal-init --data --server-name --endpoint [--subnet --admin --listen --public-url --issuer --psk --nat-interface --ca-alg]` | one-step deployment: CA, server identity, `server.toml`, `portal.toml`, first admin (one-time password) |
| `portal -c` | run the portal |
| `app -c [--connect --install-shortcut]` | desktop window |
| `tray -c [--no-connect --install-shortcut --replace]` | Windows tray app |

Global: `-v` (debug logging), `--version`.

## 11. Planned work (Proposed — not implemented)

### 11.1 Device enrollment (PRD U5)

Goal: a fresh app connects without importing a ZIP. Sketch, to be designed and reviewed before coding:

- The device generates its ML-DSA key locally (as `pqvpn genkey` does) so the private key never leaves it.
- A new authenticated portal endpoint signs the public key and returns certificate, CA, endpoint, server name and
  suites as JSON. Authentication options: a signed-in Premium account, or a short-lived single-use enrollment code for
  Free devices (no long-lived shared token in the APK).
- Rate limits and per-account device caps; each device gets its own certificate, so `active_serial` must become a
  per-device list (schema change in `users` → new `devices`-style table read by `PortalAccess`).
- The shared PSK cannot be distributed to anonymous devices safely; enrollment profiles should omit it, which requires
  a server that accepts both PSK and non-PSK clients (today a server has one PSK setting — a policy change, not a wire
  change).

### 11.2 Payments (PRD A6)

Provider checkout (Paddle / Lemon Squeezy / 2Checkout) → signed webhook endpoint → verify signature and idempotency
key → set `plan = premium`, `plan_expires`. No card data touches the portal. Needs a public HTTPS domain.

### 11.3 Google sign-in (PRD A5)

OpenID Connect authorization-code flow with PKCE, verified ID token, account linked by verified email. Needs a domain
with HTTPS and an OAuth client.

### 11.4 Protocol evolution (only if justified)

Candidates documented in TRAFFIC_ANALYSIS.md §4: a negotiated padding/dummy message, header-counter protection,
server-side shaping. Each is a versioned wire change.

## 12. Non-functional requirements and measurements

| Area | Requirement / measured value |
| --- | --- |
| Handshake | 5–14 ms CPU per handshake depending on suite (median 8.6 ms default suite on Linux); ≈ 47 KB on the wire with an SLH-DSA-192s CA |
| Throughput | 245–400 Mbit/s loopback on one core with batched receive; 135 Mbit/s real Linux TUN with kernel TCP. Not internet or phone figures |
| Android | handshake-to-tunnel 54–223 ms on the emulator; network-switch recovery 0.6 s; no fd/thread growth over 27 connect/disconnect cycles |
| APK size | ≈ 31 MB universal (two ABIs); ship an App Bundle |
| Privacy | No traffic or browsing logs; live-session metadata only; secrets never logged (paths and types only) |

## 13. Testing

| Suite | Command | Covers |
| --- | --- | --- |
| Engine | `python -m unittest discover -s tests` (`test_pqvpn.py`, 41 tests) | HKDF KATs, every suite, certificate tamper/role/expiry/revocation/foreign CA, downgrade, PSK mismatch, replay/tamper/spoofing, cookies, lost handshake, rekey, roaming, ICMP resilience, batched receive, 3000-case fuzzer |
| Portal | `test_portal.py` (46) with `fake_firestore.py` | auth, 2FA, lockout scoping, CSRF/Origin/Host, reset and sign-up flows, admin actions, plans/DNS, SSRF guard, vault, Firebase allow-list |
| Android Python | `test_android_client.py` (21) | profile import validation, tunnel rules and leak handling, network change, full session against a real `ServerNode` over a socketpair (Linux/macOS only) |
| Secrets | `test_secret_scan.py` (4) | repository is clean; example configs contain placeholders |
| Android JVM | `./gradlew testDebugUnitTest` | tunnel-config parsing, state mapping, bridge JSON, redaction, profile binding |
| React | `npm test` (Vitest) | formatting, bridge parsing, every screen state |
| Self-test | `python -m pqvpn selftest` | all suites end to end in-process |

Real-browser checks (headless Chrome over CDP) are required for portal, auth and header changes; see CLAUDE.md.

## 14. Deployment

- **Server host:** Linux with OpenSSL ≥ 3.5 (Debian 13, Ubuntu 25.04+, Fedora 42+, RHEL 10, Kali) or a private
  OpenSSL build via `PQVPN_LIBCRYPTO`. `deploy/pqvpn-server.service` runs the server with only `CAP_NET_ADMIN`/
  `CAP_NET_RAW`, `ProtectSystem=strict`, no core dumps. The portal runs as a second unit.
- **Data directory** `0700`; keys and database `0600`. Back up `portal.db` and `portal-secrets.key` separately.
- **Exposure:** UDP 51820 (or a UDP tunnel such as playit.gg); portal via TLS on a public name, or local only.
- **Landing page:** `vercel.json` serves `public/` statically; `.vercelignore` hides the Python app.
- **Current deployments (2026-10):** a development instance in WSL on the owner's PC and a test server on a Kali VM
  reached through a playit.gg UDP tunnel. Neither is always-on.

## 15. Known limitations

- Not independently audited.
- Python cannot zeroise secrets; session keys briefly exist as Python `bytes` (and in JVM memory on Android).
- The initiator reveals its (encrypted) identity before authenticating the server, as in IKEv2.
- Revocation without the portal requires a restart.
- Traffic is identifiable as pqvpn; timing and volume leak the activity class.
- Disabled accounts and superseded profiles show "Reconnecting" on clients (the server deliberately sends nothing to
  unauthenticated clients).
- Server-side DNS/route changes apply at the next connection.
- Android: no passphrase-protected keys, no per-app split tunnelling, no IPv6 without an IPv6 tunnel address,
  licences not shown in-app. Systematic testing on physical ARM64 phones and real IPv6 networks is still missing; the
  owner's phone has connected to the live server.
- Windows: Wintun and `netsh` paths have no automated tests.
