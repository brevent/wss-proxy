#!/bin/bash
# build static wss-proxy-client for macos (arm64 and x86_64)
# usage: macos/build.sh [arm64|x86_64]...  (default: both)
# optional env: VERSION_NAME
set -euo pipefail

export MACOSX_DEPLOYMENT_TARGET=12.0

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/build-macos
JOBS=$(sysctl -n hw.ncpu)

build() {
    local arch=$1 deps=$OUT/$1/deps
    local cmake_macos=(
        -DCMAKE_OSX_ARCHITECTURES=$arch
        -DCMAKE_BUILD_TYPE=Release
    )

    "$ROOT/deps/openssl.sh" "$OUT/$arch" "$deps" darwin64-$arch-cc
    "$ROOT/deps/libevent.sh" "$OUT/$arch" "$deps" "${cmake_macos[@]}"

    cmake -S "$ROOT" -B "$OUT/$arch/wss-proxy" "${cmake_macos[@]}" \
        -DCMAKE_PREFIX_PATH="$deps" \
        -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON \
        -DOPENSSL_ROOT_DIR="$deps" \
        -DOPENSSL_USE_STATIC_LIBS=ON
    cmake --build "$OUT/$arch/wss-proxy" --target wss-proxy-client -j"$JOBS"

    local bin=$OUT/$arch/wss-proxy/wss-proxy-client
    strip "$bin"
    # only system libraries may be linked dynamically
    if otool -L "$bin" | tail -n +2 | grep -v -e /usr/lib/ -e /System/Library/; then
        echo "unexpected dynamic library in $bin" >&2
        exit 1
    fi

    case $arch in
        arm64) suffix=arm64 ;;
        x86_64) suffix=x64 ;;
    esac
    local tgz=$OUT/wss-proxy-client-${VERSION_NAME:-0.0.0}-macos-$suffix.tar.gz
    tar czf "$tgz" -C "$(dirname "$bin")" wss-proxy-client
    echo "$tgz"
}

[ $# -gt 0 ] || set -- arm64 x86_64
for arch in "$@"; do
    build "$arch"
done
