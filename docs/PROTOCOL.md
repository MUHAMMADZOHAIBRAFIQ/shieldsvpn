# pqvpn Protocol Specification — version 1

Status: implemented by `pqvpn` 1.0.0. All integers are big-endian (network order).
`vec8/vec16/vec32(x)` = length prefix of 1/2/4 bytes followed by `x`.

## 1. Design lineage

| Concern | Borrowed from | Why |
| --- | --- | --- |
| Two-exchange handshake, initiator reveals identity first, responder never retransmits on its own | IKEv2 (RFC 7296) | Address is validated before the large, CPU-heavy messages, so there's no amplification |
| Several independent key exchanges combined in one handshake | RFC 9370, `draft-ietf-tls-ecdhe-mlkem` | Hybrid: secure while **either** ML-KEM **or** ECDH holds |
| Application-layer fragmentation, per-fragment encryption | IKEv2 fragmentation (RFC 7383) | PQ messages exceed the MTU, and IP fragments are dropped on many paths |
| Key schedule, `HKDF-Expand-Label`, Finished MACs | TLS 1.3 (RFC 8446 §7) | A well-analysed structure |
| Return-routability cookies under load | IKEv2 COOKIE, WireGuard | Cheap rejection of spoofed floods |
| Suite negotiation with retry | TLS 1.3 HelloRetryRequest | Crypto agility without guessing |
| Transport format, replay window, session slots, timers | WireGuard, RFC 6479 | Proven data plane |

## 2. Algorithms and codepoints

### 2.1 Cipher suites (u16)

| ID | Name | Key exchange (in order) | AEAD | Hash | Rekey after |
| --- | --- | --- | --- | --- | --- |
| 0x0001 | `MLKEM768-X25519_CHACHA20POLY1305_SHA384` | ML-KEM-768, X25519 | ChaCha20-Poly1305 | SHA-384 | 2^60 pkts |
| 0x0002 | `MLKEM768-X25519_AES256GCM_SHA384` | ML-KEM-768, X25519 | AES-256-GCM | SHA-384 | 2^28 pkts |
| 0x0003 | `MLKEM1024-P384_AES256GCM_SHA384` | ML-KEM-1024, ECDH P-384 | AES-256-GCM | SHA-384 | 2^28 pkts |
| 0x0004 | `MLKEM1024_AES256GCM_SHA384` | ML-KEM-1024 (pure PQ) | AES-256-GCM | SHA-384 | 2^28 pkts |

A *key-exchange component* is modelled as a KEM:

* **ML-KEM**: the initiator's share is an ephemeral encapsulation key `ek` (FIPS 203). The response is the ciphertext `ct`. The shared secret `ss` (32 B) comes from Encaps/Decaps. Implementations MUST run the FIPS 203 `ek` input check. Decapsulation uses implicit rejection.
* **ECDH**: the share is an ephemeral public key. The response is the responder's ephemeral public key, and `ss` is the DH output. X25519 keys are raw 32 B; P-384 keys are uncompressed SEC1 (97 B). An all-zero `ss` MUST be rejected.

The combined secret is `ss = ss_1 || ss_2 || …` in suite order (PQ component first). Every share and response is bound by the transcript.

### 2.2 Signature algorithms (u16)

| ID | Name | Family | pk | sig |
| --- | --- | --- | --- | --- |
| 0x0101 / 0x0102 / 0x0103 | ML-DSA-44 / 65 / 87 | FIPS 204 | 1312 / 1952 / 2592 | 2420 / 3309 / 4627 |
| 0x0201 / 0x0202 | SLH-DSA-SHA2-128s / 128f | FIPS 205 | 32 | 7856 / 17088 |
| 0x0203 / 0x0204 | SLH-DSA-SHA2-192s / 192f | FIPS 205 | 48 | 16224 / 35664 |
| 0x0205 / 0x0206 | SLH-DSA-SHA2-256s / 256f | FIPS 205 | 64 | 29792 / 49856 |
| 0x0211 / 0x0213 / 0x0215 | SLH-DSA-SHAKE-128s / 192s / 256s | FIPS 205 | 32 / 48 / 64 | 7856 / 16224 / 29792 |

All signatures are the *pure* variants with a FIPS 204/205 **context string** for domain separation:

| Context string | Used for |
| --- | --- |
| `pqvpn1 certificate` | CA signature over a certificate TBS |
| `pqvpn1 initiator CertificateVerify` | initiator handshake signature |
| `pqvpn1 responder CertificateVerify` | responder handshake signature |

## 3. Certificates

```text
TBS  = "PQV1" | u8 version=1 | u8 role (1=CA, 2=server, 3=client) | serial[16]
     | vec8 subject (UTF-8, 1-64 chars) | u64 not_before | u64 not_after (Unix s)
     | u16 key_alg | vec16 public_key
     | u8 n { vec8 address_cidr (ASCII, normalised) }
     | issuer_key_id[32]            -- SHA-256(u16 alg || issuer public key)
cert = TBS | u16 sig_alg | vec32 Sign(issuer, TBS, ctx="pqvpn1 certificate")
```

The decoder MUST reject the certificate unless re-encoding reproduces the input byte for byte (canonical form). A client certificate's first address MUST be a single host (/32 or /128); that address becomes the client's tunnel IP. Later addresses are routed subnets behind the client (site-to-site). The CA is self-signed with role CA. Peers trust a *set* of CA certificates, which is what allows a CA-algorithm migration with no flag day.

## 4. UDP datagrams

The first byte is the packet type: `0x01` handshake fragment, `0x04` transport data. Anything else is dropped.

### 4.1 Handshake fragment (16-byte header)

```text
 0      1      2      3      4      5      6             8
+------+------+------+------+------+------+-------------+
| 0x01 | ver=1| msg  | fidx | fcnt | 0x00 | total_len   |
+------+------+------+------+------+------+-------------+
|        sender_index        |       receiver_index      |
+----------------------------+---------------------------+
| fragment payload                                       |
```

* `msg` is one of: 1 INIT, 2 RESPONSE, 3 AUTH_I, 4 AUTH_R, 5 RETRY, 6 COOKIE.
* `CHUNK = 1184`, and `fcnt = max(1, ceil(total_len / CHUNK))` MUST hold, with `1 ≤ fcnt ≤ 64`.
* Every fragment except the last carries exactly CHUNK plaintext bytes; the last carries the remainder.
* AUTH_I and AUTH_R fragments are individually encrypted: `AEAD(k_hs_dir, nonce = 0^10 || msg || fidx, aad = header, chunk)`, which adds a 16-byte tag. Every datagram is ≤ 1216 bytes, which fits the 1280-byte IPv6 minimum MTU.
* Receivers keep the first copy of each fragment and bound the reassembly state: 1024 entries, 16 MiB, 10 s.
* **A sender MUST cache and retransmit the exact same datagrams.** Rebuilding a message (with a fresh randomized signature) under the same handshake key would reuse a nonce.

### 4.2 Transport data (16-byte header)

```text
| 0x04 | 0x000000 | receiver_index (u32) | counter (u64) | AEAD ciphertext + tag |
nonce = 0x00000000 || counter          aad = the 16-byte header
plaintext = IP packet, zero-padded to a multiple of 16 bytes (never beyond the MTU)
```

An empty plaintext is a keepalive. Receivers recover the packet length from the IPv4 Total Length or IPv6 Payload Length field. Anti-replay uses a 2048-packet sliding window (RFC 6479), which is updated **only after** successful authentication.

## 5. Handshake

```text
Initiator                                              Responder
INIT        ------------------------------------------>
            <------------------------------------------ [COOKIE]   if under load and no valid cookie
            <------------------------------------------ [RETRY]    if its preferred suite ≠ key-share suite
            <------------------------------------------ RESPONSE
AUTH_I      ------------------------------------------>            (encrypted)
            <------------------------------------------ AUTH_R     (encrypted)
keepalive   ------------------------------------------>            (key confirmation)
```

### 5.1 Message bodies

```text
INIT     = u8 version=1 | nonce_i[32] | u8 n { u16 offered_suite } | u16 share_suite
         | u8 m { vec16 share } | vec8 cookie
RESPONSE = nonce_r[32] | u16 suite | u8 m { vec16 response }
RETRY    = u16 suite                                (sender_index = 0)
COOKIE   = vec8 cookie[16]                          (sender_index = 0)
AUTH_I   = vec32 cert_I | vec16 sig_I | fin_I[Hlen]
AUTH_R   = vec32 cert_R | vec16 sig_R | vec16 config_json | fin_R[Hlen]
```

### 5.2 Transcript

Each message adds `u8 msg | u32 sender | u32 receiver | u32 len(body) | body`, where the indices are the header values of that message. INIT is recorded with `receiver = 0`. `TH(…)` is the suite hash over the concatenation of entries plus any extra bytes listed.

### 5.3 Key schedule (Hlen = suite hash length, L = 32)

```text
HKDF-Expand-Label(S, label, ctx, len) = HKDF-Expand(S, u16 len | vec8("pqvpn1 " + label) | vec8 ctx, len)
Derive-Secret(S, label, th)           = HKDF-Expand-Label(S, label, th, Hlen)

early   = HKDF-Extract(0^Hlen, PSK or 0^Hlen)
hs      = HKDF-Extract(Derive-Secret(early, "derived", H("")), ss_1 || ss_2 || ...)
hs_i    = Derive-Secret(hs, "i hs traffic", TH(INIT, RESPONSE))
hs_r    = Derive-Secret(hs, "r hs traffic", TH(INIT, RESPONSE))
master  = HKDF-Extract(Derive-Secret(hs, "derived", H("")), 0^Hlen)
k_hs_x  = HKDF-Expand-Label(hs_x, "key", "", L)
fk_x    = HKDF-Expand-Label(hs_x, "finished", "", Hlen)
i2r     = HKDF-Expand-Label(Derive-Secret(master, "i ap traffic", TH(INIT..AUTH_R)), "key", "", L)
r2i     = HKDF-Expand-Label(Derive-Secret(master, "r ap traffic", TH(INIT..AUTH_R)), "key", "", L)
```

### 5.4 Authentication

```text
sig_I = Sign(sk_I, TH(INIT, RESPONSE, vec32 cert_I), ctx="pqvpn1 initiator CertificateVerify")
fin_I = HMAC(fk_i, TH(INIT, RESPONSE, vec32 cert_I, vec16 sig_I))
sig_R = Sign(sk_R, TH(INIT, RESPONSE, AUTH_I, vec32 cert_R), ctx="pqvpn1 responder CertificateVerify")
fin_R = HMAC(fk_r, TH(INIT, RESPONSE, AUTH_I, vec32 cert_R, vec16 sig_R, vec16 config))
```

Verification order is Finished first (cheap), then the certificate chain and policy (role, subject, validity ±300 s, revocation, algorithm policy, issuer), then the signature. The initiator MUST check that the responder certificate's subject equals the configured `server_name`. A failed AUTH_I is dropped silently and the half-open state is discarded.

### 5.5 Negotiation and downgrade resistance

The responder picks the first suite in **its own** preference list that the initiator offered. If that suite differs from `share_suite`, it sends RETRY and allocates no state. The initiator accepts a RETRY only for a suite it offered, keeps `nonce_i` (so a cookie stays valid), and sends fresh shares. Because the offered list is in the signed transcript, removing strong suites from INIT changes `TH` on one side only. The handshake keys then differ, AUTH_I fails to decrypt, and no session forms. RETRY and COOKIE are limited to 4 per attempt.

### 5.6 Cookies

`cookie = HMAC-SHA256(secret, ip | "|" | u16 port | u32 sender_index | nonce_i)[:16]`. The secret rotates every 120 s, and the previous secret remains valid. Cookies are required when pending half-open handshakes ≥ `cookie_threshold`, or always if configured. Under load, initiations are also rate-limited per source IP with a token bucket.

### 5.7 Configuration push

`config_json` (inside AUTH_R, so encrypted and covered by fin_R) contains:

* `addresses`: the client interface CIDRs, i.e. the certificate host address with the server network's prefix length
* `routes`
* `dns`
* `mtu`
* `rekey_interval`

## 6. Sessions and timers

Each peer has a `current`, `previous` and `next` slot. The initiator installs a new keypair as `current` and immediately sends a keepalive. The responder installs it as `next` and promotes it on the first authenticated packet (key confirmation). It never sends on keys the initiator might not hold.

| Timer | Value |
| --- | --- |
| Proactive rekey (initiator) | `rekey_interval` (default 120 s), or the suite's packet limit |
| Keypair rejection | 1.5 × `rekey_interval` |
| Handshake retransmit | 1, 2, 4, 8, 8 … s (+ jitter); the responder only answers duplicates, with cached replies |
| Fresh handshake (new ephemerals) | after 30 s without completion |
| Passive keepalive | 10 s after unacknowledged data; the responder also acknowledges the initiator's keepalives (never the reverse, so there is no ping-pong) |
| Dead-peer detection | 15 s of silence after sending data or a keepalive, which triggers a re-handshake. A completed handshake resets the timer. |
| Persistent keepalive (client, NAT) | default 25 s |

**Roaming:** the responder updates a peer's endpoint only on an authenticated packet that carries the highest counter seen on the current keypair. A replayed (old) packet therefore cannot redirect traffic.

**Cryptokey routing:** outbound packets go to the peer whose certificate addresses longest-prefix-match the destination. Inbound packets are accepted only if their source address routes back to the same peer.
