#!/usr/bin/env bash
# Sanity-check the packaged OpenSSL libraries (run on Linux with ANDROID_NDK_ROOT set).
set -euo pipefail
B=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
cd "$(dirname "$0")/../app/src/main/jniLibs"
for a in arm64-v8a x86_64; do
    f=$a/libcrypto_pqvpn.so
    echo "== $f  $(stat -c %s "$f") bytes"
    "$B/llvm-readelf" -h "$f" | grep -E 'Class|Machine'
    echo "LOAD alignment: $("$B/llvm-readelf" -lW "$f" | awk '$1=="LOAD"{print $NF}' | sort -u | tr '\n' ' ')"
    "$B/llvm-readelf" -d "$f" | grep -E 'SONAME|NEEDED'
    syms=$("$B/llvm-nm" -D --defined-only "$f" | sed 's/@.*//' | awk '{print $NF}')
    for s in OpenSSL_version_num EVP_PKEY_encapsulate EVP_PKEY_decapsulate EVP_DigestSignInit_ex EVP_CIPHER_fetch \
             EVP_PKEY_new_raw_public_key_ex EVP_PKEY_get1_encoded_public_key PEM_write_bio_PKCS8PrivateKey; do
        grep -qx "$s" <<<"$syms" || { echo "MISSING $s"; exit 1; }
    done
    echo "all symbols used by pqvpn/crypto/ossl.py are exported"
    strings "$f" | grep '^OpenSSL 3\.' | head -1
done
