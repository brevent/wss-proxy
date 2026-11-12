#!/bin/bash
# build static openssl with our quic patches
# usage: deps/openssl.sh <workdir> <prefix> [Configure target and options...]
set -euo pipefail

OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
URL=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz

ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
WORK=$1 PREFIX=$2
shift 2

[ ! -f "$PREFIX/lib/libssl.a" ] || exit 0

mkdir -p "$WORK"
cd "$WORK"
if [ ! -f "${URL##*/}" ]; then
    curl -fsSL --retry 3 -o "${URL##*/}.tmp" "$URL"
    mv "${URL##*/}.tmp" "${URL##*/}"
fi
echo "$OPENSSL_SHA256  ${URL##*/}" | shasum -a 256 -c - >/dev/null
rm -rf openssl-$OPENSSL_VERSION
tar xzf "${URL##*/}"

cd openssl-$OPENSSL_VERSION
patch -p1 < "$ROOT/.github/vcpkg/quic-time.patch"
patch -p1 < "$ROOT/.github/vcpkg/quic-conn-window.patch"
patch -p1 < "$ROOT/.github/vcpkg/quic-txp.patch"
./Configure "$@" no-shared no-tests no-docs no-apps --prefix="$PREFIX" --libdir=lib
make -j"$JOBS" build_libs >/dev/null
make install_dev
