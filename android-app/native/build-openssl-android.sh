#!/usr/bin/env bash
# Cross-compile OpenSSL (>= 3.5, needed for ML-KEM / ML-DSA / SLH-DSA) for the ShieldsVPN Android app.
#
#   ANDROID_NDK_ROOT=/path/to/android-ndk-r28c ./build-openssl-android.sh /path/to/openssl-3.5.9.tar.gz
#
# Output: android-app/app/src/main/jniLibs/<abi>/libcrypto_pqvpn.so for arm64-v8a and x86_64.
# The library gets its own name (shlib_variant "_pqvpn" -> SONAME libcrypto_pqvpn.so, versioned symbols
# OPENSSL_3.0.0_pqvpn ...) so it can never be confused with Chaquopy's OpenSSL or the platform's BoringSSL
# "libcrypto.so".  Only libcrypto is built; the TLS library and the command-line tools are not needed.
set -euo pipefail
TARBALL=${1:?usage: $0 openssl-3.x.y.tar.gz}
: "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT to an NDK (r28c tested)}"
API=${ANDROID_API:-24}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/../app/src/main/jniLibs}
WORK=${WORK:-$HOME/android-build/openssl-work}
export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

cat > "$WORK.conf" <<'CONF'
my %targets = (
    "pqvpn-android-arm64"  => { inherit_from => [ "android-arm64" ],  shlib_variant => "_pqvpn" },
    "pqvpn-android-x86_64" => { inherit_from => [ "android-x86_64" ], shlib_variant => "_pqvpn" },
);
CONF

for pair in arm64:arm64-v8a x86_64:x86_64; do
    arch=${pair%%:*}; abi=${pair##*:}
    dir=$WORK/$abi
    rm -rf "$dir"; mkdir -p "$dir"
    tar xzf "$TARBALL" -C "$dir" --strip-components=1
    ( cd "$dir"
      ./Configure --config="$WORK.conf" "pqvpn-android-$arch" -D__ANDROID_API__="$API" \
          shared no-tests no-docs no-apps no-engine no-legacy no-module \
          -Wl,-Bsymbolic -Wl,-z,max-page-size=16384 >configure.log
      make -j"$(nproc)" build_libs >make.log 2>&1 )
    lib=$(cd "$dir" && ls libcrypto_pqvpn.so* | head -1)
    mkdir -p "$OUT/$abi"
    cp "$dir/$lib" "$OUT/$abi/libcrypto_pqvpn.so"
    llvm-strip --strip-unneeded "$OUT/$abi/libcrypto_pqvpn.so"
    echo "== $abi: $lib"
    llvm-readelf -h "$OUT/$abi/libcrypto_pqvpn.so" | grep -E 'Class|Machine'
    llvm-readelf -d "$OUT/$abi/libcrypto_pqvpn.so" | grep -E 'SONAME|NEEDED'
done
