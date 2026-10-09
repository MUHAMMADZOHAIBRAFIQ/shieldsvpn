# ShieldsVPN — a post-quantum, crypto-agile VPN

A layer-3 VPN whose key exchange and authentication resist quantum computers. It uses only **NIST-standardised post-quantum cryptography**, combined the way modern protocols do (hybrid, crypto-agile), and invents no algorithms of its own.

> **Name note:** the product is **ShieldsVPN**. The Python package and command-line tool are named `pqvpn` (the internal engine name), so commands below are run as `python -m pqvpn …` and data lives under `/var/lib/pqvpn`.

| Layer | Algorithm | Standard |
| --- | --- | --- |
| Key establishment | **ML-KEM-768** + X25519 hybrid (or ML-KEM-1024 + P-384) | FIPS 203 (+ RFC 7748 / SP 800-56A) |
| Peer authentication | **ML-DSA-65** (or 44/87) | FIPS 204 |
| Root of trust (CA) | **SLH-DSA-SHA2-192s** (any SLH-DSA set, or ML-DSA-87) | FIPS 205 |
| Traffic encryption | ChaCha20-Poly1305 or AES-256-GCM | RFC 8439 / SP 800-38D |
| Key schedule | HKDF-SHA-384, TLS 1.3 structure | RFC 5869 / RFC 8446 |

All cryptography runs inside **OpenSSL ≥ 3.5** (via `ctypes`). There are **no pip dependencies**: just Python ≥ 3.11 and an OpenSSL 3.5+ `libcrypto`.

The protocol design (IKEv2-style handshake, RFC 9370 hybrid KEX, RFC 7383 fragmentation, WireGuard data plane) is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md). The threat model and limitations are in [docs/SECURITY.md](docs/SECURITY.md).

## Features

- Hybrid PQ key exchange with forward secrecy. Keys are fresh every 2 minutes.
- Mutual certificate authentication: an SLH-DSA root CA issues ML-DSA device certificates. Certificates assign tunnel IPs, so the server needs no per-client config.
- Crypto agility: suites and signature algorithms are negotiable codepoints chosen by policy. Downgrade-protected, and multiple CAs can be trusted during an algorithm migration.
- No IP fragmentation: large PQ handshake messages are fragmented into ≤ 1216-byte datagrams, each encrypted and authenticated.
- DoS resistance: no amplification, stateless cookies under load, per-IP rate limiting, bounded state.
- Anti-replay window, cryptokey routing (anti-spoofing), roaming, NAT keepalives, dead-peer detection.
- Linux (`/dev/net/tun`) and Windows (Wintun) TUN support. Split or full tunnel, DNS push, Linux NAT gateway automation. Every network change is rolled back on exit.
- Optional pre-shared key as a third independent secret.

## Requirements

| | Requirement |
| --- | --- |
| Python | 3.11+ (stdlib only) |
| OpenSSL | **3.5 or newer** `libcrypto`. Check with `python -m pqvpn algorithms`. |
| Linux | root (or `CAP_NET_ADMIN`), `iproute2`; `iptables` for NAT; `resolvectl` for DNS |
| Windows | Administrator; [`wintun.dll`](https://www.wintun.net/) (signed by WireGuard LLC) placed next to the `pqvpn/` folder |

**Getting OpenSSL 3.5+:**

- **Linux:** Debian 13, Ubuntu 25.04+/26.04, Fedora 42+ and RHEL 10 ship it. On older systems (e.g. Ubuntu 24.04, which has 3.0), build it into a private prefix and set `PQVPN_LIBCRYPTO=/opt/ossl35/lib/libcrypto.so.3`.
- **Windows:** MSYS2 UCRT64 Python already links OpenSSL 3.6. Otherwise install a Win64 OpenSSL 3.5+ build and set `PQVPN_LIBCRYPTO` to its `libcrypto-3-x64.dll`.

## Quick start

```bash
# 0. Verify the crypto works on this machine (handshake + traffic for every suite)
python -m pqvpn selftest

# 1. Create a CA, the server bundle and one bundle per user (prompts for a CA passphrase)
python -m pqvpn quickstart --out vpn-pki \
    --server-name vpn.example.com --endpoint vpn.example.com:51820 \
    --clients alice,bob --psk
```

This creates:

```text
vpn-pki/ca/              ca.crt, ca.key   <- keep OFFLINE, only needed to add/renew users
vpn-pki/server/          server.toml, server.crt/.key, ca.crt, psk.key
vpn-pki/clients/alice/   client.toml, alice.crt/.key, ca.crt, psk.key
```

**Server (Linux):** copy `vpn-pki/server/` and the `pqvpn/` package to the server. Open UDP 51820. In `server.toml`, set `nat_interface = "eth0"` if clients should reach the Internet through the VPN. Then run:

```bash
sudo PQVPN_LIBCRYPTO=/path/if/needed python3 -m pqvpn server -c server.toml
```

For a permanent service, see [deploy/pqvpn-server.service](deploy/pqvpn-server.service).

**Client (Windows, Administrator terminal):** put `wintun.dll` next to the `pqvpn` folder, then run:

```powershell
python -m pqvpn client -c vpn-pki\clients\alice\client.toml
```

**Client (Linux):** `sudo python3 -m pqvpn client -c client.toml`

A successful connection logs:

```text
connected to vpn.example.com (203.0.113.10:51820) via MLKEM768-X25519_CHACHA20POLY1305_SHA384;
server key ML-DSA-65, tunnel address 10.66.0.2/24
```

Set `full_tunnel = true` in `client.toml` to send all traffic through the VPN.

## Login portal and Windows app

`pqvpn portal-init` sets up a complete deployment in one step:
- the root CA and the server identity
- `server.toml` and `portal.toml`
- the first administrator account

```bash
sudo python3 -m pqvpn portal-init --data /var/lib/pqvpn --server-name vpn.example.com     --endpoint vpn.example.com:51820 --subnet 10.66.0.0/24 --admin alice --psk --nat-interface eth0
sudo python3 -m pqvpn server -c /var/lib/pqvpn/server.toml
sudo python3 -m pqvpn portal -c /var/lib/pqvpn/portal.toml     # http://127.0.0.1:8800 + via the tunnel
```

**Portal (standard practices only):**
- scrypt password hashing (RFC 7914, OWASP parameters) with NIST SP 800-63B password rules
- TOTP two-factor authentication (RFC 6238) with QR enrolment for any authenticator app
- hashed session tokens with HttpOnly/SameSite cookies, CSRF tokens and Origin checks
- per-IP rate limiting and account lockout
- strict CSP and security headers, and a full audit log

**Who can sign in:** by default **only administrators**. Everyone else is a VPN-only account: an admin downloads their profile with *New profile* and hands it over. To give someone portal access, set their role to Administrator. To let users also sign in for self-service, choose *All users* under **Settings → Portal access**.

**What users can do (only with *All users*):** sign in with their username or email address, see their live VPN status and plan, and download their profile. Every download creates a fresh ML-DSA key; the previous profile stops working and private keys are never stored. They can set a recovery email and use **Forgot password?** on the sign-in page to reset their password with a 6-digit code sent by email.

**What admins can do:** after signing in, admins land on the **admin dashboard**. It shows:
- live server status and a connected-now count
- totals for users and Premium
- whether email and portal access are set up
- quick actions and recent activity
- a searchable user table where every row has Edit, Disable/Enable, Unlock, Reset password, New profile and Delete

From there admins can:
- create, edit (name, email, role), disable, unlock or delete users; reset passwords or 2FA; end a user's portal sessions; issue profiles
- put users on the **Free** or **Premium** plan, optionally with an end date (after it they drop back to Free automatically)
- choose the **DNS servers each plan gets** in *Settings*. Presets cover Cloudflare, Cloudflare Security/Family, Quad9, AdGuard (ads + trackers + malware), AdGuard Family and Google, or enter custom servers. A single user can also get a DNS override. Premium defaults to AdGuard.
- set up outgoing email and send a test message
- watch live connections and read the audit log

The VPN server pushes the DNS servers in the handshake, so plan and DNS changes apply at the user's next connection.

**Access control:** the VPN server only accepts clients whose portal account is enabled *and* whose certificate is their latest profile. Disabling a user cuts their live session within about 2 seconds.

Without TLS, the portal only listens on loopback and on the VPN tunnel address. To expose it anywhere else, configure `tls_certificate`/`tls_private_key`.

**Firebase (Firestore) mirror:** the portal can keep a live, read-only copy of its data in your Firebase project. It covers users, live connections, server status, plans/DNS/access settings and the audit log.
- **The VPN doesn't depend on Firebase.** It keeps checking its fast local SQLite database, so it works when the internet or Firebase is down.
- **Secrets stay local.** Only allow-listed fields are uploaded. Password hashes, 2FA secrets, sessions, reset codes and the email app password are never sent.
- **Fits the free tier.** Documents are written only when they change, and live traffic counters refresh at most every 5 minutes. That stays well inside Firestore's free 20,000 writes per day.
- **No extra Python packages.** It signs in with a standard service-account token (RS256 via OpenSSL) and uses Firestore's REST API.

Setup:
1. At <https://console.firebase.google.com>, create a project.
2. Open **Firestore Database → Create database** and choose **production mode**, so the data isn't public. The portal writes as an admin service account, which isn't affected by the security rules.
3. Go to **⚙ Project settings → Service accounts → Generate new private key**.
4. Paste the downloaded file's contents into the portal at **Settings → Firebase → Connect Firebase**.

The key is stored next to `portal.db` as `firebase-key.json` (mode 0600). The card shows the sync status and has **Sync now**, **Pause** and **Remove key**.

**Email for password recovery (Nodemailer):** the portal sends email through [Nodemailer](https://nodemailer.com/). Python starts a short-lived `node pqvpn/portal/mailer/send-mail.js` per message and passes the message on stdin. One-time setup on the portal host:

1. Install Node.js 20 or newer so that `node` is on `PATH`, or set `PQVPN_NODE=/path/to/node`.
2. Run `npm ci --omit=dev` in `pqvpn/portal/mailer`.
3. In the portal, open **Settings → Email** and enter the SMTP account. For Gmail: SMTP server `smtp.gmail.com`, SSL/TLS on port 465, the Gmail address, and an **App Password**. To get one, turn on 2-Step Verification, then create it at <https://myaccount.google.com/apppasswords>. The normal Gmail password is refused.
4. Click **Send test email**.
5. Give each account an email address, either on the user's page or under *Account*.

Until email is set up, *Forgot password?* tells users to ask an administrator.

**Windows taskbar app**, run from the unzipped profile:

```powershell
python -m pqvpn tray -c client.toml --install-shortcut   # creates "PQ VPN" on the Desktop + Start menu
python -m pqvpn tray -c client.toml                      # or double-click the shortcut (asks for UAC)
```

**What the taskbar app shows:**
- **A shield icon** in the notification area: grey = disconnected, amber = connecting/reconnecting, green = connected, red = error.
- **Windows notifications** titled "PQ VPN".
- **A right-click menu:** Connect, Disconnect, Open portal, Open log, Exit.
- **Auto-reconnect:** the app reconnects automatically after an outage.

Windows 10 hides new tray icons under `^` until you drag them onto the taskbar once.

## Operations

| Task | Command |
| --- | --- |
| Add a user | `python -m pqvpn issue --ca vpn-pki/ca --role client --name carol --address 10.66.0.4/32 --out carol/` |
| Enrol without moving private keys | On the device: `python -m pqvpn genkey --out carol`. Then the CA: `python -m pqvpn issue ... --pubkey carol.pub` |
| Revoke a user | Add the serial (from `pqvpn show carol.crt`) to `revoked_serials` in `server.toml`, then restart the server |
| Site-to-site | Add more `--address 192.168.50.0/24` entries to the client certificate. The server routes that subnet to the client. |
| Inspect a certificate | `python -m pqvpn show server.crt` |
| List algorithms | `python -m pqvpn algorithms` |
| Change crypto policy | Edit `[crypto] suites / peer_signature_algorithms / ca_signature_algorithms` |
| Migrate the CA algorithm | Create the new CA and list **both** CA certificates in `ca = [...]`. Reissue certificates, then remove the old CA. |
| Debug logging | `python -m pqvpn -v server -c server.toml` |
| Restart the Windows app on new code | `python -m pqvpn tray -c client.toml --replace` |

## Measured performance

These figures come from the development machine (single core, both endpoints on one host), using the default suite with an SLH-DSA-192s CA:

| Metric | Result |
| --- | --- |
| Full mutually-authenticated handshake | **5–9 ms**; ~189 handshakes/s |
| Handshake on the wire | INIT 1292 B → RESPONSE 1175 B → AUTH_I 22.2 KB → AUTH_R 22.4 KB (≈ 47 KB, every datagram ≤ 1216 B). Mostly the two 16 KB SLH-DSA certificate signatures. Measured alternatives: an SLH-DSA-128s CA gives 29.9 KB, an ML-DSA-87 CA gives 23.2 KB. |
| Data plane (memory TUN, both ends one core) | ≈ 190–220 Mbit/s, 1400-byte packets, zero loss |
| Real Linux TUN, kernel TCP through the tunnel | 135 Mbit/s; ping RTT 0.86 ms |

## Tests

```bash
python -m unittest discover -s tests -v      # 63 tests, ~50 s
python -m pqvpn selftest                     # all four suites end to end
```

Coverage:

- HKDF known-answer (RFC 5869) and KEM agreement for every suite, including ML-KEM implicit rejection
- Certificate tamper, role, revocation, expiry and foreign-CA checks
- Downgrade (suite stripping), wrong server name, PSK mismatch, a server certificate used as a client
- Replay, tamper and source-spoofing drops; cookie round trip; lost-handshake recovery; live rekey; roaming
- ICMP-unreachable resilience; a 3000-case fuzzer

Tested on Windows (Python 3.14, OpenSSL 3.6.4) and on Linux (Python 3.12, OpenSSL 3.5.9). The Linux run includes real TUN devices in network namespaces covering split/full tunnel, NAT rules and clean teardown.

## Layout

```text
pqvpn/crypto/ossl.py     OpenSSL binding (ML-KEM, ML-DSA, SLH-DSA, ECDH, AEAD, PEM)
pqvpn/crypto/suites.py   crypto-agility registry (suites, signature algorithms)
pqvpn/crypto/kdf.py      HKDF + TLS 1.3-style key schedule
pqvpn/pki.py             certificates, CA, trust store
pqvpn/protocol.py        wire constants, fragmentation, cookies, rate limits
pqvpn/handshake.py       initiator/responder state machines (pure, no I/O)
pqvpn/session.py         transport keypairs, replay window, cryptokey routing table
pqvpn/node.py            server/client event loops, timers, roaming
pqvpn/tun.py             Linux TUN, Windows Wintun
pqvpn/netcfg.py          addresses, routes, DNS, NAT with automatic rollback
pqvpn/config.py          TOML config validation
pqvpn/cli.py             command line
pqvpn/portal/            web portal: auth (scrypt, TOTP), store (SQLite), web UI, QR codes, access control,
                         plans.py (Free/Premium + DNS per plan), mail.py + mailer/ (Nodemailer email),
                         firebase.py (one-way Firestore mirror)
pqvpn/winui.py           Windows notification-area app (Shell_NotifyIcon via ctypes)
pqvpn/logo.py            shield logo: SVG + anti-aliased PNG/ICO renderer
```
