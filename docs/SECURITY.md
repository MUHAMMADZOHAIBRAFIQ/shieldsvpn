# Security design and threat model

## Goals

| Threat | Mitigation |
| --- | --- |
| **Harvest now, decrypt later.** Traffic is recorded today and decrypted with a future quantum computer. | Every session key derives from an **ephemeral ML-KEM** (FIPS 203) secret. Recorded traffic stays safe unless ML-KEM is broken. |
| A flaw is found in ML-KEM (or in its implementation) | **Hybrid:** the classical ECDH secret is also mixed in, so the session is as strong as the *stronger* of the two. Optional PSK adds a third independent layer. |
| Quantum forgery of identities | Peers authenticate with **ML-DSA** (FIPS 204). The trust anchor is **SLH-DSA** (FIPS 205), which rests only on hash-function security. |
| Long-term key compromise exposing past sessions | Forward secrecy: KEM and ECDH keys are generated per handshake (about every 2 minutes) and discarded. |
| Active MITM / downgrade to weaker suites | Mutual signatures cover the full transcript, including the offered suite list. Finished MACs bind identities to keys. |
| Replay, reordering, tampering | AEAD with per-direction keys; 64-bit counters as nonces; 2048-packet replay window updated only after authentication |
| Spoofed-source floods / amplification | No amplification (RESPONSE ≤ INIT; big messages only after reachability is proven). Stateless cookies and per-IP rate limits under load. Bounded reassembly and half-open state. |
| A client impersonating another client's IP | Cryptokey routing: inner source addresses must belong to the authenticated certificate. |
| Passive identity tracking | Certificates travel only inside the encrypted AUTH messages. |
| Algorithm breaks in the future | **Crypto agility:** every algorithm is a registry codepoint selected by policy. Several CAs can be trusted during a migration. Unknown or disallowed algorithms are refused, never silently accepted. |

## Why these choices

* **Standards only, no novel cryptography.** The primitives are NIST FIPS 203/204/205 plus RFC-standard ECDH, AEAD and HKDF. The protocol composition follows IKEv2, TLS 1.3 and WireGuard patterns that have formal analyses. "AI-designed" or home-made ciphers offer no assurance.
* **The primitives run inside OpenSSL ≥ 3.5** (constant-time C, FIPS-validated code base). pqvpn's Python code only handles message framing, policy and state. It never touches key-dependent arithmetic.
* **ML-KEM-768 by default** (NIST category 3), the same choice as the X25519MLKEM768 hybrid now deployed in TLS. ML-KEM-1024 + P-384 is offered for CNSA 2.0 alignment.
* **SLH-DSA for the root.** A root lives for years and signs rarely, so slow signing does not matter. Hash-based security is the most conservative assumption available. Results are cached, and verification takes about 0.5 ms.
* **ChaCha20-Poly1305 by default.** It is constant-time in software without AES-NI. AES-256-GCM suites rekey after 2^28 packets per the AEAD usage limits (`draft-irtf-cfrg-aead-limits`).

## Known limitations (read before production use)

1. **Not independently audited.** The design follows established patterns, and the code has a 38-test adversarial suite (downgrade, replay, tampering, spoofing, wrong CA, revoked certificates, PSK mismatch, packet loss, cookies, rekey, roaming, fuzzing). That is not a substitute for a third-party audit.
2. **Python memory hygiene.** Python cannot reliably zeroise secrets in memory. Private keys live inside OpenSSL objects (freed with `EVP_PKEY_free`), but derived session keys briefly exist as Python `bytes`. Protect the host: disable swap or use encrypted swap, and disable core dumps.
3. **Initiator identity vs. active attackers.** As in IKEv2, the client sends its (encrypted) certificate before it has authenticated the server. An active attacker who impersonates the server's network endpoint can learn *which* client is connecting, but cannot impersonate either side or read traffic.
4. **Handshake-level DoS by an on-path attacker.** An attacker who can see INIT can race a forged RESPONSE and stall that attempt. It fails closed, and a new attempt starts within 30 s. On-path attackers can always drop packets anyway.
5. **Revocation** is a serial-number list in the config, not OCSP/CRL distribution. Keep certificate lifetimes short (`--days`) and reload the server after revoking.
6. **Throughput.** The data plane is single-threaded Python: about 150–200 Mbit/s per core. For multi-gigabit links, port the specified protocol to Go or Rust. The wire format is specified for exactly this reason.
7. **Windows DNS.** In full-tunnel mode, Windows may still query DNS servers on other interfaces ("smart multi-homed resolution"). Use a host firewall rule or Group Policy if DNS leaks matter.
8. **Windows path testing.** The Wintun data path and `netsh` configuration were written against the documented APIs, but they were not exercised in the development environment (no Administrator rights). The Linux TUN, routing, full-tunnel and NAT paths were tested end to end in network namespaces.

## Portal security model

- **The portal host is security-critical.** It holds the CA private key so that it can issue profiles. Run it on the VPN server or another hardened host; the data directory is `0700` and the keys and database are `0600`.
- **Only administrators can sign in by default** (Settings → Portal access). The check runs at sign-in *and* on every request, so if an account is demoted or the setting changes, its open sessions stop working at once. Other accounts are VPN-only: their portal password is never shown or used, and password-reset codes are not sent to them.
- **Accounts are authenticated with standard mechanisms:**
  - passwords hashed with scrypt (N=2^17, r=8, p=1), with the NIST SP 800-63B policy
  - TOTP 2FA (RFC 6238) with replay protection; **required for administrators by default** (`require_2fa_for_admins`), enforced on every request until the admin has enrolled
  - lockout after 5 failures for 15 minutes, plus per-IP rate limiting. Lockout is **scoped by device** (OWASP device cookies): failures from a browser that has signed in before count only against that browser, and failures from unknown clients lock only the "unknown client" bucket — so an attacker who knows a username cannot lock the owner out of the browser they actually use. Re-authentication on the account pages (password change, email change, disabling 2FA) is rate-limited too.
  - generic error messages and a constant-time dummy hash, so attackers cannot discover which usernames exist
  - a typed login is never written to the audit log verbatim (it is sometimes a mistyped password); unknown-account events record `(unknown)`
- **Sessions:**
  - 256-bit random tokens, stored only as SHA-256 hashes
  - 30-minute idle and 12-hour absolute timeouts
  - rotated at login; revoked at logout, at password change and when an admin disables the account
- **Web hardening:**
  - CSRF synchronizer tokens and an Origin check on every POST (the token compare is done on bytes, so a crafted non-ASCII token is rejected cleanly instead of erroring)
  - a **Host-header allow-list** on every request, so a DNS-rebinding page on another origin cannot drive the portal; add extra names with `allowed_hosts` in `portal.toml` (loopback, the listen addresses and the configured URLs are allowed automatically)
  - a CSP that allows no inline script, plus frame-ancestors none, nosniff and no-store
  - `Referrer-Policy: same-origin`. With `no-referrer`, browsers send `Origin: null` on form POSTs (Fetch standard), which the Origin check would reject.
  - all output is HTML-escaped
- **Password recovery by email** follows the OWASP Forgot Password guidance:
  - A random 6-digit code is emailed to the address on the account. The code is stored only as an scrypt hash, expires after 10 minutes, works once, and allows 5 wrong guesses. A newer code replaces the older one.
  - Requests are throttled per IP and per account (one code per minute, five per hour), so the form cannot be used to flood someone's mailbox.
  - The response and its timing are the same whether or not the account exists. Email is sent in the background and the code is hashed even for unknown accounts.
  - A successful reset clears any lockout and signs out every session. The account owner then gets a "password was changed" email. 2FA still applies at the next sign-in.
  - Every step is in the audit log (`password_reset_requested`, `password_reset_not_sent`, `password_reset_code_failed`, `password_reset_by_email`, `email_sent`/`email_failed`).
  - **Recovery is only as strong as the mailbox.** Anyone who controls a user's email can reset their password. Users should protect their mailbox with 2FA. Admins should consider portal 2FA, which an email reset does not bypass.
- **Outgoing email** goes through Nodemailer with TLS: implicit TLS on 465, or STARTTLS on 587 where TLS is required, and the certificate is always verified. Before sending, the SMTP host is resolved once and refused if it is a loopback/private/reserved address, and the connection is pinned to that resolved IP (TLS still verified against the host name) — so the email settings cannot be turned into an SSRF probe of the internal network, and there is no rebind window between the check and the send. A local relay is allowed with `allow_internal_smtp = true` in `portal.toml`.
  - The SMTP App Password cannot be hashed (the portal must present it to the mail server), so it is **encrypted at rest** with AES-256-GCM. The key is a 32-byte file, `portal-secrets.key`, kept `0600` next to the database; stored values look like `enc:v1:…`. A copied or backed-up `portal.db` therefore does not reveal the password. **Back up `portal-secrets.key` separately** (lose it and you simply re-enter the App Password); keep it out of the same backup as the database. A plaintext value from an older database is re-encrypted automatically at start-up. The password reaches the Node process on stdin, never argv or the environment, and is never shown again in the UI.
- **Firebase mirror (optional):**
  - It is one-way: the portal writes to Firestore and never reads authorization data back. The VPN's access decisions stay local, so a compromised or unreachable Firebase project cannot let anyone into the VPN or lock them out.
  - Only allow-listed fields are uploaded (see `firebase.py`). Password hashes, TOTP secrets, sessions, reset codes and the SMTP password are never sent, and a test enforces this.
  - The mirrored data still includes names, emails, IP addresses and the audit log. Create the Firestore database in **production mode** so client access is denied, and don't relax the security rules.
  - The service-account key grants admin rights over the Firebase project. It is stored next to the database with mode 0600 and never shown again in the UI. The signed RS256 assertion is always sent to Google's fixed token endpoint (`oauth2.googleapis.com`) over verified TLS: the `token_uri` inside a pasted key is validated but **never used as a request URL**, and the `project_id` is validated, so a tampered key cannot redirect the request (or the assertion) to an attacker's server. Malformed responses from Google are reported as errors rather than crashing the mirror.
- **Two independent checks before VPN access:**
  1. A certificate from the trusted CA.
  2. An enabled portal account whose *current* profile serial matches that certificate.

  Old profiles and disabled users are rejected at handshake time and dropped from live sessions within about 2 s.
- **Plain HTTP is limited.** Without TLS, the portal refuses to listen anywhere except loopback and VPN-tunnel addresses. Put a real certificate on it before exposing it.

## Operational security checklist

- Generate the CA on an offline machine. Protect `ca.key` with a passphrase (`ca-init` prompts for one) and keep it offline.
- Prefer `pqvpn genkey` on each device plus `issue --pubkey`, so device private keys never travel.
- Use short certificate lifetimes. Revoke by adding `revoked_serials` and restarting the server.
- Run the server under the hardened systemd unit in `deploy/`. Keep the system OpenSSL patched.
- Optionally enable `psk_file` (`pqvpn genpsk`) for defence in depth.
- Keep `portal-secrets.key` `0600` and back it up apart from `portal.db`. Delete any old plaintext database backups made before encryption-at-rest was added (they still contain the App Password in the clear).
- Administrators enrol an authenticator app at first sign-in (enforced). Protect the recovery mailbox with its own 2FA; an email reset does not bypass portal 2FA but does reset the password.
