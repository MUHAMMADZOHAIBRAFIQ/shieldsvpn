# ShieldsVPN — Technical Specification

| | |
| --- | --- |
| Version | 1.1, 2026-10-22, describes `pqvpn` 1.0.0 on branch `shieldsvpn-android-security-upgrade` (+ §16: Free with ads, sign-in, Pro) |
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
rotates every 120 s. Per-source token bucket `handshake_rate_per_ip` (default 5/s, burst 2×; one bucket per IPv4
address or IPv6 /64). Reassembly bounded to 1024
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
| `max_peers` / `cookie_threshold` / `always_require_cookie` / `handshake_rate_per_ip` | 1024 / 64 / false / 5 | the rate counts per IPv4 address / IPv6 /64 |
| `log_peer_addresses` | false | true: clients' public IP:port appear in the log (connects, roaming, rejected handshakes) |
| `[stealth] key_file` | none | stealth mode: obfuscate every datagram under this key (PROTOCOL.md §8) |
| `[portal] database` | none | enables account-based access control |
| `[portal] url` | `""` | pushed to clients ("Open portal") |

### 5.2 `client.toml`

`[client]` `server` (host:port, re-resolved on reconnect), `server_name`, `certificate`, `private_key`, `ca`,
`portal_url`, `private_key_passphrase_file`. `[tunnel]` `interface`, `mtu`, `full_tunnel` (false), `routes` (empty =
use pushed), `use_server_dns` (true), `dns`, `persistent_keepalive` (25). `[crypto]` as for the server.
`[security] revoked_serials`. `[stealth] key_file` (stealth mode, must match the server's; PROTOCOL.md §8).

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
| `obfuscation_key_file` | none | stealth mode: the obfuscation key copied into every issued profile (PROTOCOL.md §8) |
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
| `users` | accounts | `username` (unique, NOCASE, = certificate subject; `d-` prefix reserved), `role` (`admin`/`user`), `password_hash` (scrypt), `must_change_password`, `totp_secret`/`totp_enabled`/`totp_last_step`, `enabled`, `vpn_ip` (unique), `active_serial`, `profile_issued_at`, `failed_logins`/`locked_until`, `email` (unique NOCASE when set), `email_verified`, `plan` (`free`/`premium`), `plan_expires` (first second after the last paid day), `custom_dns`, `paddle_customer_id`, `paddle_subscription_id` |
| `vpn_devices` | devices registered by the apps (§16) | `subject` (`d-` + 24 base32, = certificate subject), `token_hash` (SHA-256 of the bearer token), `user_id` (NULL = anonymous; SET NULL on account delete), `known_user_id`, `platform`, `vpn_ip`, `active_serial`, `cert_expires`, `enabled`, `free_seconds` (Free-time balance, used only while connected; `free_until` is the end time it replaced, converted on upgrade), `install_hash` (HMAC of the app's SHA-256 of Android's per-app ID: on re-registration of the same phone the unused balance and today's ad grants move to the new device and the old rows are deleted; account links are not carried), `failed_logins`/`locked_until`, `created_at`, `last_seen`, `enroll_ip` |
| `reward_grants` | one row per ad view | `device_id`, `kind` (`admob`/`web`), `nonce_hash`, `started_at`, `granted_at` (single use), `provider_ref` (unique: AdMob transaction id) |
| `pay_links` | one-time links to Paddle's checkout | `code_hash`, `user_id`, `txn_id`, `expires_at` (30 min), `completed_at` |
| `payments` | payments seen at Paddle | `provider_ref` (unique transaction id), `user_id`, `status`, `amount`, `currency` |
| `play_purchases` | Google Play subscription purchases (play.py) | `token` (one account per token), `user_id`, `product_id`, `base_plan`, `state`, `expires`, `test`, `replaced` |
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
| GET | `/upgrade` | user | Premium page; with payments on, a button to Paddle's checkout |
| POST | `/upgrade/checkout` | user | create a Paddle transaction, redirect to `/pay/<code>` |
| GET | `/pay/<code>`, `/pay/<code>/done` | public (one-time code) | Paddle checkout page (own CSP allowing Paddle's CDN and frame); thank-you page that re-checks the payment |
| GET/POST | `/reward/<nonce>` | public (one-time nonce) | Windows free time: ad page; POST grants time after the server-measured minimum |
| POST | `/profile` | user | issue and download own profile ZIP |
| GET | `/api/status` | user | JSON: `now`, `server_online`, `me`; admins also get `peers` |
| GET/POST | `/account`, `/account/password`, `/account/email`, `/account/2fa`, `/account/2fa/disable` | user | self-service |
| GET | `/admin` | admin | dashboard: the three product cards (Website, Browser extension, App) first, then VPN server tiles, add-user form, user table, live peers, recent audit |
| GET, POST | `/admin/website` | admin | website details: public address (`website_url`), legal pages, account portal, web accounts, Paddle and web ads; POST saves the address |
| POST | `/admin/website/check` | admin | HEAD the legal pages (HTTPS, public addresses only, no redirects; `products.check_pages`) |
| GET, POST | `/admin/extension` | admin | browser extension: package (`browser-extension/manifest.json`), store pages (`extension_*_url`, store hosts only), Windows PCs |
| GET | `/admin/app` | admin | app devices per platform, online now, Pro, free time and ads, Play / Paddle status, newest devices |
| POST | `/admin/users` | admin | create user (temporary password shown once) |
| GET | `/admin/users/{id}` | admin | user page |
| POST | `/admin/users/{id}/{action}` | admin | `edit`, `disable`, `enable`, `unlock`, `signout`, `reset-password`, `reset-2fa`, `profile`, `delete` (not on self for disable/delete) |
| GET | `/admin/audit` | admin | audit log |
| GET | `/admin/settings` | admin | settings page |
| POST | `/admin/settings/access`, `/dns`, `/email`, `/email/test` | admin | |
| POST | `/admin/settings/firebase/{connect,sync,pause,resume,remove}` | admin | |
| POST | `/admin/settings/apps`, `/admin/settings/payments` | admin | app switches and limits; Paddle settings |
| GET | `/admin/devices` | admin | registered app devices |
| POST | `/admin/devices/{id}/{signout,disable,enable,delete}` | admin | |
| * | `/api/v1/...` | bearer token | the app API, §16.3 |
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
| `app_enrollment`, `app_accounts` | `0`, `0` | apps may register themselves (Free); apps may sign in / sign up / reset passwords |
| `free_minutes`, `free_daily_rewards` | `30`, `16` | free time per watched ad (a balance used only while connected); ads that grant time per device per 24 h |
| `reward_gap_seconds` | `10` | wait between two ads for free time: ads may follow each other to build up time (`/me` `next_reward_in`; `429 too_soon` before it) |
| `toggle_ads`, `toggle_ad_gap` | `connect`, `0` | Free devices' interstitial after `connect`, after `both` connect and disconnect, or `off`; minimum seconds between two |
| `admob_enabled`, `admob_require_ssv` | `0`, `1` | Android rewarded ads; `0` = test mode (trust the app's report) |
| `web_ads_enabled`, `web_ads_test`, `reward_min_seconds` | `0`, `0`, `20` | Windows ad page; labelled placeholder ad; minimum viewing time |
| `pro_device_limit`, `device_cleanup_days`, `enroll_per_ip_day` | `5`, `30`, `20` | devices per account; forget unused anonymous devices; registrations per network (IPv4 address / IPv6 /64) per day |
| `enroll_per_hour` | `300` | registrations per hour from all networks together (bounds CA signing work) |
| `payments_enabled`, `paddle_env` | `0`, `sandbox` | sell Pro; `sandbox` or `live` |
| `paddle_product_id`, `pro_currency`, `paddle_client_token` | `""`, `USD` | Paddle product (`pro_…`) the Pro prices belong to; their currency; Paddle.js token (`test_…`/`live_…`) |
| `pro_price_week`, `pro_price_month`, `pro_price_year` | `""` | Pro amounts set by the admin (e.g. `4.99`); empty = that period is not sold |
| `paddle_price_week`, `paddle_price_month`, `paddle_price_year`, `paddle_price_history` | `""` | Paddle prices the portal created for those amounts (not edited by hand); every price it created (older checkouts still count) |
| `paddle_api_key`, `paddle_webhook_secret` | | sealed `enc:v1:` like `smtp_password` |
| `play_enabled`, `play_package`, `play_product_id` | `0`, `com.shieldsvpn.vpn`, `shieldsvpn_pro` | Google Play Billing for the Play build; the service-account key is the file `play-key.json` (0600) next to the database |

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
  `active_serial == certificate serial`. For a `d-…` subject the rules of §16.2 apply instead. `sync()` every 2 s
  publishes peers and returns sessions to disconnect (including Free devices whose time ran out); every 60 s it
  records connected devices' `last_seen`, and every hour it forgets anonymous devices unseen for
  `device_cleanup_days`.
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
| `pqvpn app` | tkinter "Tap to Connect" window: power button, status, timer, VPN address, encryption, server. UAC on Connect. `--install-shortcut` creates Desktop/Start-menu "ShieldsVPN". For a PC registered with the portal (§16.6) also a plan row: Free countdown, *Get free time* (web ad page), *Go Pro* / *Manage subscription*, *Sign in* / *Sign out* (dialogs for sign-in, sign-up with emailed code, password reset); stops the tunnel when Free time ends |

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

Gradle copies only these Python modules into the APK: `__init__`, `account_client`, `android_client`, `config`,
`handshake`, `node`, `pki`, `protocol`, `session`, `wire`, `crypto/{__init__,kdf,ossl,suites}`. OpenSSL 3.5.9 is
packaged as `libcrypto_pqvpn.so` (own SONAME and symbol versions, 16 KB page alignment), provenance in
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
| UI → app | `ready`, `connect`, `disconnect`, `importProfile`, `removeProfile`, `openPortal`, `openVpnSettings`, `refreshAccount`, `watchAd`, `signIn` {login, password, code}, `signUp` {email, password}, `verifyEmail` {email, code}, `forgotPassword` {login}, `resetPassword` {login, code, password}, `signOut`, `goPro` {period: `week`/`month`/`year`, or `""` for the default plan}, `manageSubscription`, `deleteAccount` {password, code}, `openPrivacy`, `overlay` {open: a menu or sheet is open, so Android's Back closes it}, `acceptTerms` {version}, `declineTerms` |
| app → UI | `state` (phase, details, `alwaysOn`, `lockdown` as true/false/unknown; `profile.enrolled`), `traffic` (`rx`, `tx`, `at`, polled 1 Hz), `notice` (`ok`/`error`, title, text), `insets`, `account` (plan card: `available`, `portal`, `busy`, `known`, `at`, `plan`, `freeSecondsLeft`, `proUntil`, `signedIn`, `email`, `rewardsLeft`, `freeMinutes`, feature flags, `priceLabel`, `prices` [{`period`, `name`, `label`}], `imports` (profile files allowed; false in the Play build), `privacy` (privacy link present)), `accountResult` (`op`, `ok`, `code`, `message`), `back` (Back pressed while an overlay was open), `terms` (`accepted`, `version`: the User Agreement; until it is accepted the app ignores every command except `ready`, `acceptTerms`, `declineTerms`, `overlay` and `openPrivacy`) |

Only display data crosses; no keys, certificates, tokens or paths. What the user types into the sign-in forms goes
to the app (never logged) and on to the portal over pinned or verified TLS. Unknown or malformed messages are
dropped on both sides.
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
| `app [-c PROFILE] [--portal URL --pin HEX --allow-http] [--connect --install-shortcut]` | desktop window; without `-c` it uses this PC's registered device, registering it first with `--portal` |
| `tray -c [--no-connect --install-shortcut --replace]` | Windows tray app |

Global: `-v` (debug logging), `--version`.

## 11. Planned work (Proposed — not implemented)

### 11.1 Device enrollment and 11.2 Payments — implemented

Built on 2026-10-22; see §16. Still open from the original sketch: dropping the shared PSK for app devices (needs a
server that accepts both PSK and non-PSK clients — a policy change, not a wire change).

### 11.5 Several server locations

Servers in other places cannot read the portal's SQLite file. They would ask the portal over an authenticated API
instead (the decisions of `PortalAccess` behind HTTPS), and the apps would get a server list and a picker. No wire
change; device certificates stay valid on every server that trusts the same CA.

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
| App API | `test_app_api.py` (16) | registration, certificate renewal, bearer tokens (cookies grant nothing), Origin/JSON/Host checks, AdMob test mode and signed SSV callbacks (tamper, age, key id, replay), daily limit, app sign-up/sign-in/lockout/2FA/device limit/reset, admin pages, VPN server enforcing Free time and Pro over a real handshake, the Python app client incl. certificate pinning |
| Payments | `test_payments.py` (6) with `fake_paddle.py` | checkout only for signed-in accounts, Pro only from Paddle data (wrong account or price ignored), pay-page CSP, webhook signature and replay window, renewal, sealed admin settings |
| Desktop | `test_desktop_account.py` (3) | PC registration, DPAPI-sealed passphrase and token, encrypted key, renewal, web-ad page minimum time / single use / cross-site refusal |
| Android JVM | `./gradlew testDebugUnitTest` | tunnel-config parsing, state mapping, bridge JSON, redaction, profile binding, plan/clock-skew maths and account messages |
| React | `npm test` (Vitest) | formatting, bridge parsing (incl. account messages), every screen state, plan card (Free/Pro/setup), ad-before-connect notice, side menu and its Pro entry, plan sheet |
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
- App devices: the shared PSK is effectively public once registration is on; app devices get a rotated PSK only by
  registering again. A web-page ad (Windows) cannot be verified like AdMob's signed callback. In AdMob test mode the
  app's report of a watched ad is trusted. With a self-signed portal, AdMob callbacks and Paddle webhooks cannot reach
  it (Pro is confirmed by asking Paddle's API instead).

## 16. App devices: Free with ads, sign-in and Pro

Implemented 2026-10-22. Code: `portal/devices.py` (rules), `portal/api.py` (JSON API), `portal/accounts.py`
(sign-up and reset shared with the web pages), `portal/rewards.py` (AdMob verification), `portal/payments.py`
(Paddle), `account_client.py` (the apps' client), `desktop_account.py` (Windows). The wire protocol is unchanged.

### 16.1 Model

| | Free | Pro |
| --- | --- | --- |
| Account | none needed (anonymous device) | required: a signed-in, email-verified account |
| Time | `free_minutes` per watched ad (default 30), at most `free_daily_rewards` ads per device per day | unlimited |
| Ads | rewarded video for time (Android), web ad page (Windows); interstitial after connecting (Android) | none |
| DNS | Free plan DNS | Premium plan DNS (default AdGuard) |
| Devices | one device | up to `pro_device_limit` devices on one account |

Signing in links the device to the account (`vpn_devices.user_id`); signing out unlinks it. A device's plan is the
linked account's effective plan, else Free.

### 16.2 VPN access for app devices

`PortalAccess.authorize` for a `d-…` subject: the device exists, is enabled, `active_serial` equals the certificate
serial, a linked account (if any) is enabled, and a Free device has `free_seconds` above zero. DNS comes from the
account's rules, or the Free plan's for anonymous devices. `sync()` drops sessions that stop meeting these rules.

**Free time is a balance used only while connected.** Every status interval `sync()` charges each connected Free
device for the seconds up to the **last packet** it sent (`peer.last_rx`; apps send a keepalive every 25 s). A client
that disconnects sends nothing more while its session lingers on the server until it expires, so time after the tap
on Disconnect is never charged; a silence longer than 40 s (`GAP`) is treated as disconnected and not charged
either (also when the same session comes back). At zero the session is dropped. Ads for time are refused (`409
connected`) while the device's packets still arrive (last packet within 12 s); `/me` reports `free_seconds`,
`free_counting` (packets within 40 s) and, for older app builds, `free_until` = now + balance. The peers table
publishes `last_rx`, so "connected now" on the admin pages means recent packets. Deleting an account turns its
devices into anonymous devices with no time left. The apps also stop the tunnel when the balance runs out
(Android service timer, Windows window/tray), with a message, so users see why.

**Ads on connect / disconnect (Android, Free).** `toggle_ads` = `connect` (default: an interstitial after
connecting), `both` (also after the user disconnects) or `off`; `toggle_ad_gap` = minimum seconds between two of
them (0 = every time). The ad's length is decided by the ad network (an AdMob interstitial unit limited to *Display*
ads shows short image ads); Google's policy forbids ads after every user action, so a gap is safer.

### 16.3 App API (`/api/v1/`, JSON, `Authorization: Bearer <device token>`)

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/enroll` | none (rate-limited) | `{platform, key_alg, public_key}` → `{token, profile, me}`; needs `app_enrollment` |
| POST | `/renew` | device | new certificate (same address) for a new public key; only within 15 days of expiry (`409 not_due` before) |
| GET | `/me` | device | plan, free time, account, feature flags, price label; re-checks a pending Paddle checkout |
| POST | `/login`, `/logout` | device | sign in (with `code` when 2FA is on) / out; needs `app_accounts` |
| POST | `/signup`, `/signup/verify` | device | create an account, verify the emailed code (then signed in) |
| POST | `/forgot`, `/forgot/verify` | device | emailed reset code; new password |
| POST | `/reward/start` | device | one-time nonce (`kind` `admob` or `web`; `web` also returns the ad page URL) |
| POST | `/reward/claim` | device | AdMob test mode only (`admob_require_ssv = 0`) |
| GET | `/admob/ssv` | Google's signature | AdMob server-side verification callback |
| POST | `/checkout`, `/manage` | device, signed in | one-time `/pay/<code>` link for `{"period": "week"/"month"/"year"}` (default: monthly, else the first plan on sale); Paddle customer-portal link |
| POST | `/paddle/webhook` | `Paddle-Signature` | Paddle notifications (each only triggers a re-check through Paddle's API) |
| POST | `/play/verify` | device, signed in | `{"product_id", "purchase_token"}` from Google Play Billing: checked with Google, acknowledged, applied (play.py) |
| POST | `/account/delete` | device, signed in | the account deletes itself: `{"password", "code"}` (code only with 2FA); not for administrators; wrong passwords count toward the lockout |

Errors are `{"error": code, "message": text}`. The session cookie is ignored; cross-site `Origin` is refused; bodies
are JSON ≤ 64 KiB. Device calls are rate-limited per device (burst 20, then one per 3 s); checkouts are capped at 5
unfinished per account per hour.

### 16.4 Ads

Android: Google Mobile Ads SDK with Google's consent form (UMP). The rewarded ad carries the portal's nonce as
server-side-verification `custom_data`; Google's signed callback grants the time (ECDSA P-256/SHA-256, Google's
published keys, one-hour validity, unique transaction id). Test mode trusts the app's `/reward/claim` instead. AdMob
IDs come from `deploy.properties` (Google's public test IDs by default). Windows: `/reward/<nonce>` shows a
labelled test ad (until an ad network is connected) and grants time after `reward_min_seconds`, single use.

### 16.5 Payments (Paddle Billing)

Pro plans: the admin sets a weekly, monthly and/or yearly amount (Settings → Payments; empty = not sold) in one
currency, under one Paddle product. On save the portal creates the recurring prices at Paddle (`POST /prices`,
`billing_cycle` week/month/year) *before* storing anything; if Paddle refuses one, the prices created in that save are
archived again and nothing is stored. Prices are never edited: a new amount, currency, product or environment gets a
new price and the old one is archived (`PATCH /prices/{id}` `status = archived`), so existing subscribers keep the
price they bought; every created price stays in `paddle_price_history`.

`/api/v1/checkout` (or `/upgrade/checkout` on the web, where the plans are radio choices) creates the Paddle customer
(by email) and a transaction for the chosen plan's price with `custom_data.shieldsvpn_user` = account id, and returns
a 30-minute one-time `/pay/<code>` link. The page opens Paddle's checkout (Paddle.js) for that transaction. Pro is
applied by `Payments.reconcile_user` from Paddle's API: transaction `paid`/`completed`, our account id, only prices
the portal created, and an active (or `past_due`) subscription → `plan = premium`,
`plan_expires = current_billing_period.ends_at + 1 day` (so a weekly plan runs a week, a yearly one a year). A
subscription first seen already `canceled` ends one day after `canceled_at`. Triggers: the app's next `/me`, the
thank-you page, webhooks, and a background reconcile every 6 h for subscriptions ending within three days (renewals
and cancellations). Refunds and chargebacks are not handled automatically yet: the admin sets the plan back by hand.

**Google Play Billing (Play Store build).** Google Play requires its own billing for subscriptions sold in an app from
Play, so the Play build (`store=play` in `deploy.properties`) sells Pro through Google: one subscription
(`play_product_id`) with weekly / monthly / yearly base plans priced in Play Console. The app buys with
`setObfuscatedAccountId` = the first 32 hex digits of `HMAC-SHA256(vault subkey, account id)` (sent in `/me` only
while signed in) and posts
the purchase token to `/api/v1/play/verify`. The portal calls `purchases.subscriptionsv2.get` with a service account:
our product, the same account reference, a token not owned by another account, state active / in grace / canceled but
unexpired → `plan = premium`, `plan_expires = max(current, expiryTime + 1 day)` (never shortening, never touching an
admin's open-ended Premium); it acknowledges pending purchases itself and marks a `linkedPurchaseToken` replaced. A
background reconcile every 6 h re-checks tokens ending within three days; the app re-sends Google's purchases at start
(restore). Refunds are, as with Paddle, applied by hand.

### 16.6 Clients

- **Android:** with `portalUrl` set in `android-app/deploy.properties`, the app registers itself on first start
  (`android_client.enroll_json`), keeps the device token sealed with the key, renews the certificate within 15 days
  of expiry, and shows the plan card. Without `portalUrl` it behaves as before (ZIP import only).
  **One tap:** the power button is all a new user needs. A tap while the registration runs (or after it failed)
  registers and then connects. A Free device with no time left and rewarded ads left plays one ad and connects when
  the time is granted (no interstitial for that connection); the screen says so before the tap ("A short ad gives
  you 30 free minutes"), which is the opt-in AdMob requires for rewarded ads. The ☰ menu holds *Sign up for Pro*
  (signed out: sign-up, then the plan sheet; signed in: the plan sheet with weekly / monthly / yearly), free time,
  sign-in / sign-out / delete account, the kill switch (Android VPN settings), profile import (direct builds) and
  the privacy policy.
- **Windows / desktop:** `pqvpn app --portal https://host:port/ [--pin HEX]` registers the PC once into
  `%LOCALAPPDATA%\pqvpn\device` (`desktop_account.py`) and opens the window; later `pqvpn app` uses that device.
  The tray connects with the same profile and stops at the end of Free time.
- **Pinning:** with a self-signed portal, the apps pin the SHA-256 of its certificate (`portalPin` / `--pin`); the
  portal logs this value at start-up.
