# ShieldsVPN — Product Requirements Document

| | |
| --- | --- |
| Product | ShieldsVPN (engine and CLI name: `pqvpn`) |
| Version of this document | 1.0, 2026-10-18 |
| Status | Working product, pre-launch. Not independently audited; not production-ready for paying customers. |
| Related | [SPEC.md](SPEC.md) (how it is built), [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md), [CREDENTIALS.md](CREDENTIALS.md) |

## 1. Summary

ShieldsVPN is a consumer VPN whose encryption is designed to stay safe against future quantum computers. It uses
only NIST-standardised post-quantum cryptography (ML-KEM, ML-DSA, SLH-DSA) combined with classical cryptography, the
same "hybrid" approach now used in TLS. It ships as a VPN server, a web portal for accounts and administration, a
Windows app, and an Android app.

The goal is a **freemium consumer product**: anyone installs the app, taps one button and is protected. Free users
get the VPN; Premium users pay for extras such as ad- and malware-blocking DNS.

## 2. Problem and opportunity

- **"Harvest now, decrypt later."** Traffic recorded today can be decrypted once large quantum computers exist. Most
  VPNs still rely only on classical key exchange. ShieldsVPN's key exchange is post-quantum for every session.
- **VPNs are hard to set up.** Users don't want certificates, configs or server addresses. The target experience is
  the one popularised by commercial VPN apps: install, tap Start, connected.
- **Trust.** Users worry that a VPN itself collects their data. ShieldsVPN logs no browsing activity and keeps
  account data on the operator's own server.

## 3. Product principles

These come directly from the owner's decisions during development and are binding.

1. **Standards only, no invented cryptography.** Crypto-agile design built on NIST FIPS 203/204/205 and RFC
   constructions. No "AI encryption" or home-made algorithms.
2. **One tap for the user.** The end user should never type server details or handle keys.
3. **The portal is an admin console.** Only selected people (administrators) sign in by default. Public features
   (self-service sign-up) exist only behind admin switches that default off.
4. **Admin is hidden.** The admin console has no public link; it is reached only by typing `/admin`.
5. **Secure by default.** HTTPS for the portal, 2FA for administrators, fail-closed behaviour on leaks.
6. **Honest claims.** No "military-grade", "unhackable", "anonymous", "undetectable" or "zero leaks" claims. Every
   capability is stated with what was and wasn't verified.
7. **Low running cost.** The owner is cost-sensitive: free tiers first (free tunnel services, Firebase free tier,
   free email via Gmail), paid services only when a feature requires them.

## 4. Users

| Persona | Who | Needs |
| --- | --- | --- |
| **Free user** | Someone who wants a private, safe connection on phone or PC | Install, tap Connect, see that it works. No account creation for basic use (target, see §6.1). |
| **Premium user** | A free user willing to pay | Sign up with email + password (or Google), pay by card, get Premium features. Sign-in is mandatory for Premium. |
| **Administrator** | The owner and trusted staff | Manage users, plans, DNS, email, access; see live connections; issue and revoke access; audit trail. |
| **Operator** | Whoever runs the server (today the owner) | Simple setup on a Linux host, safe defaults, clear runbooks for keys and rotation. |

## 5. Scope

### 5.1 In scope

- Post-quantum VPN server for Linux; clients for Windows, Linux and Android.
- Web portal: administrator console, optional user self-service, optional public sign-up, plans (Free/Premium),
  per-plan DNS filtering, password recovery by email, audit log, optional Firebase mirror.
- Windows tray app and one-tap desktop window; Android app with a one-tap screen.
- Static marketing landing page (Vercel).

### 5.2 Out of scope (explicit non-goals)

- Replacing the protocol with WireGuard or OpenVPN. Interoperability with the existing ShieldsVPN server is required.
- Anonymity or undetectability. ShieldsVPN traffic can be identified as ShieldsVPN on the wire, and the kind of
  activity is partly inferable from timing and volume (measured in `research/TRAFFIC_ANALYSIS.md`).
- Surveillance, OSINT, attribution or traffic-recording features in the VPN or its clients.
- Handling card numbers directly. Payments go through a payment provider.
- Hosting the VPN or portal on serverless platforms (Vercel, Supabase functions). They cannot hold a UDP port, a
  local database or long-lived processes. Vercel serves only the landing page.

## 6. Requirements

Priority: **P0** must exist before public launch, **P1** needed for a good launch, **P2** later.
Status: **Done**, **Partial**, **Not started**.

### 6.1 End-user connection

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| U1 | One prominent Connect/Disconnect button with clear states: Disconnected, Preparing, Connecting, Connected, Reconnecting, Error, Disconnecting | P0 | Done (Android, desktop window, tray) |
| U2 | "Connected" is shown only after an authenticated handshake and a working tunnel, never just because a service started | P0 | Done |
| U3 | Live details: connected time, server, tunnel IP, encryption, routing mode, DNS, live up/down traffic | P1 | Done (Android); partial (desktop) |
| U4 | Automatic recovery from network changes (Wi-Fi ↔ mobile), server restarts and outages without user action | P0 | Done |
| U5 | **No manual profile step for the user**: install, tap Start, connected. The app obtains its credentials automatically and securely. | P0 | **Done** for builds with a portal address (`deploy.properties`): the app registers itself on first start (SPEC §16). Windows: `pqvpn app --portal ...` once. Verified on the API 36 emulator against a local portal; not yet through playit.gg or on a real phone |
| U6 | Full-tunnel mode sends all traffic (including DNS) through the VPN; refuses to connect rather than leak DNS | P0 | Done (Android fails closed); portal option `full_tunnel` |
| U7 | Kill switch: support the OS-level always-on/lockdown VPN and show honestly whether it is on | P1 | Done (Android); not available on Windows |
| U8 | Server/location picker | P2 | Not started (one server today) |
| U9 | Licences and privacy notice viewable inside the app | P1 | Partial (shipped as files, no in-app screen) |

### 6.2 Accounts, plans and payments

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| A1 | Two plans: Free and Premium. Premium can have an end date, after which the user drops back to Free automatically | P0 | Done |
| A2 | Premium benefit: filtering DNS (ads, trackers, malware) chosen per plan by the admin; per-user DNS override | P0 | Done |
| A3 | Public sign-up with email + password and email verification (6-digit code), behind an admin switch (default off) | P1 | Done |
| A4 | Premium requires sign-in (mandatory account) | P0 | Done: portal, Android app (verified on the emulator) and Windows window (dialogs; screenshot-verified, not driven end to end) |
| A5 | "Sign in with Google" | P1 | Not started (needs a domain with HTTPS and Google OAuth setup) |
| A6 | Card payment for Premium via a Merchant-of-Record provider that serves Pakistan (Paddle, Lemon Squeezy or 2Checkout; Stripe is not available to Pakistani businesses). Payment success upgrades the plan automatically via a signed webhook | P0 for paid launch | **Partial:** Paddle Billing integration built (checkout, verification through Paddle's API, signed webhooks, renewals). Tested against a fake Paddle API and in a real browser (Paddle.js loads); **not yet tried with a real Paddle sandbox account**. Paddle's acceptance of a VPN product and a Pakistani seller is unconfirmed |
| A7 | Password recovery by emailed one-time code | P0 | Done |
| A8 | Users can download/replace their own profile when self-service is enabled | P1 | Done |

### 6.3 Administration

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| M1 | Admin dashboard: server online/offline, connected-now count, totals, setup health (email, access, Firebase), recent activity | P0 | Done |
| M2 | User management: create, edit (name, email, role, plan, end date, DNS override), disable/enable, unlock, reset password, reset 2FA, sign out everywhere, download profile, delete | P0 | Done |
| M3 | Disabling a user or issuing a new profile cuts the old access within seconds, with no CRL distribution | P0 | Done (~2 s) |
| M4 | Settings: portal access (admins only / everyone), public sign-up switch, DNS per plan with presets, SMTP email with test message, Firebase mirror | P0 | Done |
| M5 | Full audit log of security-relevant events | P0 | Done |
| M6 | Admin console reachable only by typing `/admin`; no links from user pages | P0 | Done |
| M7 | Read-only cloud copy of non-secret data (Firebase Firestore) within the free tier | P2 | Done (optional) |

### 6.4 Security and privacy

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| S1 | Hybrid post-quantum key exchange with forward secrecy; keys refreshed about every 2 minutes | P0 | Done |
| S2 | Mutual certificate authentication; post-quantum CA | P0 | Done |
| S3 | Portal: scrypt passwords, NIST password rules, TOTP 2FA (required for admins), lockout scoped by device, rate limiting, CSRF + Origin + Host checks, strict CSP, hashed sessions | P0 | Done |
| S4 | No secrets in the repository, APK, logs or cloud mirror; secret scanner in the test suite | P0 | Done |
| S5 | Portal served over HTTPS with a trusted certificate on a real domain | P0 | **Partial**: TLS supported; live deployments use self-signed certs; no domain yet |
| S6 | No browsing/traffic logs. Only account data and live-session metadata (endpoint, bytes, times) are kept | P0 | Done |
| S7 | Published privacy policy (also required by Google Play) | P0 for store launch | Not started |
| S8 | Independent security/cryptography audit before taking payments at scale | P1 | Not started |

### 6.5 Platforms and distribution

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| D1 | Linux server with a hardened systemd unit | P0 | Done |
| D2 | Windows client: tray app and one-tap window with Desktop/Start-menu shortcut | P0 | Done (needs Python + `wintun.dll`; no installer) |
| D3 | Windows installer (no Python knowledge needed) | P1 | Not started |
| D4 | Android app (Android 7.0+, arm64 and x86_64) | P0 | Done as a signed APK; tested on the API 36 emulator and on the owner's phone against the live server (handshake verified; full-tunnel internet fix pending re-test) |
| D5 | Google Play release: developer account, App Bundle, VPN-service declaration, privacy policy, Play App Signing | P0 for store launch | Not started |
| D6 | iOS / macOS clients | P2 | Not started |
| D7 | Landing page with a working "Sign in" link to the live portal | P1 | Partial (page live on Vercel; link waits for a public portal URL) |

### 6.6 Operations

| ID | Requirement | Priority | Status |
| --- | --- | --- | --- |
| O1 | Always-on hosting (24/7) with a public UDP port and a public HTTPS portal | P0 | **Not started.** Today: a laptop running Kali in VirtualBox, exposed through a free playit.gg UDP tunnel; the portal is local-only because playit TCP tunnels are paid |
| O2 | Domain name and trusted TLS certificate (e.g. Let's Encrypt) | P0 | Not started |
| O3 | Credential rotation runbook (client, PSK, server, CA, Android signing key) | P0 | Done (`CREDENTIALS.md`) |
| O4 | Backups of the portal database and the vault key, stored separately | P1 | Documented; not automated |

## 7. Key user journeys

**Today (working):**

1. Admin creates a user in `/admin` and clicks **Download profile (.zip)**.
2. The ZIP reaches the user's device (e.g. by messaging app). On Android: **Import profile** → pick the ZIP.
3. User taps Connect, accepts Android's one-time VPN consent, sees Connected.
4. Admin sees the user under "Connected now"; disabling the user cuts the session within ~2 s.

**Target (launch):**

1. User installs ShieldsVPN from Google Play and taps **Start**.
2. The app enrolls itself (generates its own key, gets a certificate from the server) without user input — U5.
3. Free plan applies immediately.
4. **Go Premium** → sign up (email/password or Google) → pay through the payment provider → plan switches to Premium
   automatically → filtering DNS at the next connection.

## 8. Success metrics (for launch)

| Metric | Target |
| --- | --- |
| Time from app install to first connection | < 60 s, no typing |
| Connect success rate (handshake completes within 10 s on a working network) | ≥ 98 % |
| Reconnect after a network switch | < 3 s (emulator measured 0.6 s) |
| DNS leaks in full-tunnel mode | 0 in automated leak tests |
| Server availability | ≥ 99.5 % monthly once on always-on hosting |
| Free → Premium conversion | Tracked from the first paid month; target set after launch |

## 9. Constraints

- **Budget:** prefer free services. Earlier options were rejected on cost (Google Cloud one-time $30, playit.gg TCP
  tunnel $3). Always-on hosting candidates: GitHub Student Pack / DigitalOcean credits, Oracle Cloud free tier (card
  hold failed once).
- **Payments from Pakistan:** Stripe unavailable; a Merchant-of-Record provider and a registered business with a bank
  account are needed to receive money.
- **Technical:** server needs Python ≥ 3.11 and OpenSSL ≥ 3.5; the data plane is single-threaded Python (hundreds of
  Mbit/s on a PC, less on phones). Multi-gigabit would need a Go/Rust port of the same protocol.
- **Store policy:** Google Play requires a privacy policy and a declaration for apps using `VpnService`.

## 10. Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Not independently audited | A flaw could undermine the security promise | Standards-only design, adversarial test suite, audit before paid launch (S8) |
| Laptop hosting | Outages whenever the laptop is off; not acceptable for customers | Move to always-on hosting (O1) before launch |
| Shared PSK in every profile | Rotating it requires reissuing all profiles | Documented runbook; consider dropping the PSK for consumer profiles once enrollment exists |
| Test credentials on the Kali deployment (admin password reset and admin 2FA disabled for testing) | Account takeover of the admin console | Change the admin password and set `require_2fa_for_admins = true` before any public exposure |
| Python performance on phones | Battery and throughput below native apps | Measure on a physical phone; native port only if data justifies it |
| Physical ARM64 phones only lightly tested | Crashes on some devices | Test on several real phones before store release |

## 11. Release plan

| Milestone | Contents | Exit criteria |
| --- | --- | --- |
| **M0 — Done** | Engine, portal, admin console, plans/DNS, email recovery, Firebase mirror, Windows apps, Android app, security pass | Tests green; APK built and signed |
| **M1 — Reliable private beta** | Full-tunnel internet through the live server re-tested on a real phone; admin password changed and 2FA back on; profiles shared with a few testers | Testers browse through the VPN for a week without manual fixes |
| **M2 — Always-on + domain** | VPS, domain, Let's Encrypt, public portal over HTTPS, landing page "Sign in" wired | Portal reachable at the domain; ≥ 99 % uptime over two weeks |
| **M3 — Frictionless onboarding** | Device enrollment (U5), app sign-in for Premium | New phone connects with zero typing |
| **M4 — Monetisation** | Payment provider, webhooks, Google sign-in, privacy policy | First paid Premium upgrade end to end |
| **M5 — Store launch** | Play Store listing, App Bundle, Windows installer, independent audit | App approved on Google Play |

## 12. Open questions

1. Which always-on host (and budget ceiling per month)?
2. Which payment provider will onboard the business, and what Premium price?
3. ~~Should Free users be anonymous devices (no account) and only Premium users have accounts?~~ Decided
   2026-10-22: yes. Free devices are anonymous; abuse is bounded by per-IP registration limits and the daily ad cap.
4. Keep the shared PSK for consumer profiles, or rely on certificates only?
5. Which Premium extras beyond filtering DNS (more locations, priority capacity)?

## 13. Decision log

| Date | Decision |
| --- | --- |
| 2026-10-06 | Build a crypto-agile VPN on NIST PQC standards; no invented algorithms |
| 2026-10-07 | Portal restricted to administrators; others are VPN-only accounts. Free/Premium plans with per-plan DNS. Password recovery by email through Nodemailer. Firebase as a one-way mirror, not the source of truth |
| 2026-10-09 | Security audit of the portal (injection, XSS, CSRF, SSRF, secrets, hashing, MFA and more) fixed. Admin console hidden at `/admin`. HTTPS required. Brand renamed from "PQ VPN" to ShieldsVPN. Code moved to a private GitHub repository |
| 2026-10-10 | Vercel cannot host the VPN; it serves the landing page only. Laptop + Kali VM + playit.gg UDP tunnel used as a free test server. One-tap desktop app built. Freemium direction: public sign-up behind an off-by-default switch; payments and Google sign-in deferred until a domain and provider exist |
| 2026-10-17 | Native Android app built on `VpnService` running the same protocol (no WireGuard substitute). Security/reliability pass: DNS-leak fail-closed, always-on support, secret hygiene, batched UDP receive, traffic-analysis study (no padding added: no measured benefit) |
| 2026-10-18 | Portal option to issue full-tunnel profiles; clearer profile download button; optional Android release signing |
| 2026-10-22 | Freemium model decided and built: Free needs no account and earns 30 min per watched ad (Android rewarded video, Windows web ad page; server-enforced), interstitial on connect; Pro needs sign-in and is paid through Paddle (sandbox first); price set by the admin; Android and Windows. Test through playit.gg before buying a domain; several server locations later. All new features off by default |
