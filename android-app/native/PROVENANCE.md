# Provenance of the native OpenSSL library

`app/src/main/jniLibs/<abi>/libcrypto_pqvpn.so` is OpenSSL's libcrypto. It is cross-compiled from the
unmodified upstream source by [build-openssl-android.sh](build-openssl-android.sh). No prebuilt third-party
binary is used. This file records exactly what went in, so anyone can rebuild the library and compare it.

## Inputs

| Input | Identity | How it was verified (2026-10-17) |
| --- | --- | --- |
| OpenSSL source | `openssl-3.5.9.tar.gz`, SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a` | 1. The SHA-256 equals the `openssl-3.5.9.tar.gz.sha256` published on the GitHub release `openssl/openssl` `openssl-3.5.9`. 2. `gpg --verify openssl-3.5.9.tar.gz.asc` (fresh keyring): **Good signature from "OpenSSL &lt;openssl@openssl.org&gt;"**. The signing subkey is `C46E D3F2 CBEF DA1F DAAD A442 64ED 7B1D CCE7 1CB2`. Its primary key, `B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40`, is the key that <https://openssl-library.org/source/> lists as the current signing key. The key was fetched from keys.openpgp.org. |
| Android NDK | r28c, `Pkg.Revision = 28.2.13676358`, `android-ndk-r28c-linux.zip` SHA-1 `a7b54a5de87fecd125a17d54f73c446199e72a64` | The SHA-1 equals the value listed for r28c on <https://github.com/android/ndk/wiki/Unsupported-Downloads>. |
| Build host | Ubuntu on WSL 2, x86_64 | — |

## Configuration

* Build script: `build-openssl-android.sh`.
* Targets: `android-arm64` and `android-x86_64`. Both use `shlib_variant "_pqvpn"`, so the library's SONAME is
  `libcrypto_pqvpn.so` and its symbols are versioned. It cannot clash with Chaquopy's `libcrypto_python.so` or the
  platform's BoringSSL.
* Configure options: `-D__ANDROID_API__=24`, `shared no-tests no-docs no-apps no-engine no-legacy no-module`,
  `-Wl,-Bsymbolic`, `-Wl,-z,max-page-size=16384` (16 KB page alignment, which Android 15+ devices need).
* Only `build_libs` is run. The output is then passed through `llvm-strip --strip-unneeded`. There are no source patches.

## Outputs (as packaged)

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `arm64-v8a/libcrypto_pqvpn.so` | 5 541 016 | `a242aaeb30b4b29d5d6a0ed2147427d3b022a8497372e074bdd99553b6d82abc` |
| `x86_64/libcrypto_pqvpn.so` | 5 877 592 | `4840a3cff9a4b6a93a9296f7db2572e1efc63b47fb20105d2218de8736440271` |

`check-libs.sh` (run 2026-10-17 with NDK r28c) checks both libraries. It confirms:

* ELF64 for the right machine;
* every LOAD segment is 0x4000-aligned;
* SONAME `libcrypto_pqvpn.so`, and the only NEEDED libraries are `libc.so` and `libdl.so`;
* every symbol `pqvpn/crypto/ossl.py` uses is exported;
* the version string is `OpenSSL 3.5.9 29 Sep 2026`.

The build has not been checked for bit-for-bit reproducibility. Rebuilding on a different host can produce
different hashes, because OpenSSL embeds build information. Verify a rebuild with `check-libs.sh` and the self-test
rather than by comparing hashes.

## Runtime self-test

[pqcrypto_selftest.c](pqcrypto_selftest.c) is built with `build-selftest.sh` and run against the packaged library
with `adb`. It checks the following through the EVP API:

* ML-KEM-768 and ML-KEM-1024: encapsulate and decapsulate;
* X25519: key agreement;
* ML-DSA-65, ML-DSA-87 and SLH-DSA-SHA2-128f: sign and verify with a context string, and confirm a tampered input is rejected;
* ChaCha20-Poly1305 and AES-256-GCM: seal and open, and confirm a forged tag is rejected.

It does **not** cover P-384 or SLH-DSA-SHA2-128s. Those are exercised on the host by the Python test suite and, on
the device, by the handshake itself, which fails closed if any primitive fails.

Last run on 2026-10-17, against the x86_64 library on the Android 16 (API 36) emulator: all 9 checks passed, exit
code 0. The arm64-v8a library has not been run, because no physical arm64 device was available.

## Licence

OpenSSL 3.x is under the Apache License 2.0. The licence text is shipped in the APK at
`assets/licenses/OpenSSL-LICENSE.txt`, together with `THIRD_PARTY_NOTICES.txt`.

## Updating

1. Download the new tarball together with its `.sha256` and `.asc` files.
2. Check the checksum, then run `gpg --verify` against the key fingerprint published on openssl-library.org.
3. Rebuild with the same script.
4. Run `check-libs.sh` and the self-test.
5. Update the tables above.
