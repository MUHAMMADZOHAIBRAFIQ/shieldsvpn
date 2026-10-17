#!/usr/bin/env bash
# Build pqcrypto_selftest for arm64-v8a and x86_64 against the packaged libcrypto_pqvpn.so.
#   ANDROID_NDK_ROOT=... OPENSSL_INCLUDE=<openssl-work>/<abi>/include ./build-selftest.sh
set -euo pipefail
: "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT}"
WORK=${WORK:-$HOME/android-build/openssl-work}
HERE=$(cd "$(dirname "$0")" && pwd)
LIBS=$HERE/../app/src/main/jniLibs
OUT=${OUT:-$HERE/build}
BIN=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
mkdir -p "$OUT"
for pair in aarch64:arm64-v8a x86_64:x86_64; do
    triple=${pair%%:*}; abi=${pair##*:}
    "$BIN/$triple-linux-android24-clang" -O2 -Wall -I "$WORK/$abi/include" "$HERE/pqcrypto_selftest.c" \
        -L "$LIBS/$abi" -lcrypto_pqvpn -Wl,-rpath,'$ORIGIN' -o "$OUT/pqcrypto_selftest-$abi"
    echo "built $OUT/pqcrypto_selftest-$abi"
done
