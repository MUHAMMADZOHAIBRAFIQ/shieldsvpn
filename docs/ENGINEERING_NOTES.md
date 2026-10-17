# Engineering notes: security, reliability and performance pass (2026-10-17)

These notes record what was audited, what changed and why, and the compatibility impact of each change. Test
evidence is summarised at the end. The detailed write-ups are in [CREDENTIALS.md](CREDENTIALS.md),
[../research/TRAFFIC_ANALYSIS.md](../research/TRAFFIC_ANALYSIS.md) and
[../android-app/native/PROVENANCE.md](../android-app/native/PROVENANCE.md).

## Constraints kept

* **Protocol and cryptography unchanged.** There are no changes to the packet format, handshake messages,
  transcript, key schedule, suite negotiation or certificate format. Existing servers and clients interoperate
  unchanged. Every change below is either local behaviour (I/O, UI, Android integration) or a fail-closed
  refusal on the client.
* Not replaced by WireGuard or OpenVPN.
* No certificate validation was weakened and no test was deleted.
* No commits, pushes or history rewrites, and no change to the production server.

## Audit summary

| Area | Findings |
| --- | --- |
| Credentials | Live client key and PSK (`vpn-profiles/`), two local test PKIs, a local portal DB and vault key, and the Android release keystore are all present in the working copy. None is tracked or on `origin`. Some test-portal files exist in **local-only** refs (`refs/agents/…`, `refs/codex/…`). `.gitignore` was incomplete for several of these types. |
| Crypto | Hybrid ML-KEM + X25519/P-384, ML-DSA device certificates and an SLH-DSA CA, per-fragment AEAD for handshake messages, a WireGuard-style data plane. No defects found in this pass. This is not an independent audit. |
| Android | Lifecycle, routing and IPv6 were correct. **A DNS leak in full tunnel without pushed DNS.** Kill-switch state was read too early. Always-on was not supported. A Connect during shutdown was dropped. Sealed secrets were not bound to the profile. |
| Performance | asyncio's selector datagram transport reads **one datagram per event-loop iteration**. Under bursty load the socket buffer overflowed: 87 % loss at burst 8 and 98 % at burst 64 (host benchmark). |
| Native | The OpenSSL build was from source but had no recorded provenance, and no licence notice was shipped in the APK. |
| UI | Demo mode (no native bridge) looked like a live app. There was no honest kill-switch display. |

## Changes, reasons and compatibility impact

| # | Change | Why | Compatibility | Regression test |
| --- | --- | --- | --- | --- |
| 1 | `android_client.tunnel_settings` raises `TunnelConfigError` when `full_tunnel` has no DNS server | Verified on API 36: a VPN with no DNS servers resolves through the underlying network, so every lookup leaked | Client-side refusal only; the server is unchanged. Operators must push DNS for full-tunnel profiles, which `deploy/examples/server.example.toml` does | `test_full_tunnel_without_dns_fails_closed` |
| 2 | `BatchedUdpTransport` + `open_udp_endpoint` in `pqvpn/node.py`, used by the server, client, Android client and loopback | The receive bottleneck described above | Local I/O only; datagrams on the wire are identical. One behaviour difference: when the kernel send buffer is full, a datagram is **dropped** (like a congested link) instead of being queued in user space. Handshake loss is covered by the protocol's retransmit timers. Windows (Proactor loop) keeps asyncio's transport | `TestBatchedReceive.test_drains_bursts_and_cleans_up` |
| 3 | Always-on support (`SUPPORTS_ALWAYS_ON = true`, `SERVICE_INTERFACE` start). `alwaysOn` and `lockdown` are read **after** `establish()` and shown as on/off/unknown | Before `establish()` Android reports false. The UI must not claim a kill switch Android isn't enforcing | App-only | `UiJsonTest`, React tests |
| 4 | `pendingConnect` in `ShieldsVpnService` | A Connect that arrived while the previous session was shutting down was lost | App-only | Emulator rapid-sequence test |
| 5 | Sealed secrets carry the certificate serial and are refused on mismatch. Interrupted installs are recovered only when the serials match. Keystore and crypto errors get friendly messages | Prevents pairing a key with the wrong profile after a crash | Profile ZIP format unchanged; the on-device storage format gains a `serial` field. Secrets stored by older builds (no `serial`) are still accepted, so no re-import is needed | `ProfileBindingTest` |
| 6 | `.gitignore` rewrite, `tools/secret_scan.py`, `tests/test_secret_scan.py`, `deploy/examples/*.example.toml`, `docs/CREDENTIALS.md` | Credential hygiene | None | Scanner tests, including a repository-clean test and an example-config test |
| 7 | `native/PROVENANCE.md` and licence texts in `assets/licenses/` | Supply-chain and licensing | None | `check-libs.sh` and the self-test |
| 8 | UI demo-mode banner, kill-switch card, link to Android VPN settings | Honest states; no fabricated stats | Bridge gains the `openVpnSettings` command (validated allow-list) | React tests (18) |
| 9 | Benchmarks (`research/benchmarks/bench_dataplane.py`, including the `--transports` A/B) and the traffic-analysis experiment | Measure before optimising; evidence for or against padding defences | None | The experiment checks its size model against the real AEAD; `test_receiver_accepts_larger_sender_padding` |

**Not changed, based on the evidence:** no padding or cover-traffic option was added. Bucket padding showed no
benefit, and MTU padding cost about +48 % bytes for a partial gain. See TRAFFIC_ANALYSIS.md.

## Measured results

* **UDP receive, A/B in the same run** (Linux/WSL 2, Python 3.12.3, OpenSSL 3.5.9, 1400-byte packets, offered
  load as fast as possible):

  | Burst | asyncio transport | batched transport |
  | --- | --- | --- |
  | 1 | 124.2 Mbit/s, 0 % loss | 244.8 Mbit/s, 0 % loss |
  | 8 | 64.1 Mbit/s, 87.4 % loss | 363.5 Mbit/s, 0 % loss |
  | 64 | 14.1 Mbit/s, 98.3 % loss | 403.9 Mbit/s, 0 % loss |

  Reproduce with `python3 research/benchmarks/bench_dataplane.py --transports`. These are loopback figures on one
  host. They are not internet throughput and not phone throughput.

* **Handshake CPU cost** (in-memory, median): MLKEM768-X25519 ChaCha20 8.6 ms, AES-GCM 7.1 ms,
  MLKEM1024-P384 12.4 ms, MLKEM1024 14.3 ms. These come from `research/results/baseline_linux.json`.

## Known gaps

* No physical-device test (ARM64 phone), no production-server test and no real IPv6 network test.
* Emulator throughput through the tunnel was not re-measured after change 2, because the test server ran on
  Windows (Proactor transport), which would have hidden the device-side effect.
* The arm64-v8a native self-test was not run.
* Licences are shipped as assets but not shown on an in-app screen.
* Local-only git refs containing test-portal files still exist. Deleting them is the owner's decision (see
  CREDENTIALS.md).
