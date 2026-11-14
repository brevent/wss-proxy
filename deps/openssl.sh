#!/bin/bash
# build static openssl with our quic patches
# usage: deps/openssl.sh <workdir> <prefix> [Configure target and options...]
set -euo pipefail

OPENSSL_VERSION=3.5.9
URL=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz

ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
WORK=$1 PREFIX=$2
shift 2

mkdir -p "$WORK"
cd "$WORK"
if [ ! -f "${URL##*/}" ]; then
    curl -fsSL --retry 3 -o "${URL##*/}.tmp" "$URL"
    mv "${URL##*/}.tmp" "${URL##*/}"
fi
rm -rf openssl-$OPENSSL_VERSION
tar xzf "${URL##*/}"

cd openssl-$OPENSSL_VERSION
patch -p1 < "$ROOT/deps/patches/quic-time.patch"
patch -p1 < "$ROOT/deps/patches/quic-conn-window.patch"
patch -p1 < "$ROOT/deps/patches/quic-txp.patch"

case ${1:-} in
VC-*)
    perl Configure "$@" -FS no-makedepend no-shared no-tests no-docs no-apps --prefix="$PREFIX" --libdir=lib
    jom -s -nologo build_libs >/dev/null
    jom -s -nologo install_dev
    ;;
*)
    ./Configure "$@" no-shared no-tests no-docs no-apps --prefix="$PREFIX" --libdir=lib
    make -j"$JOBS" build_libs >/dev/null
    make install_dev
    ;;
esac
