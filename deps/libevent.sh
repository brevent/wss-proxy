#!/bin/bash
# build static libevent_core
# usage: deps/libevent.sh <workdir> <prefix> [cmake options...]
set -euo pipefail

LIBEVENT_VERSION=2.1.13
LIBEVENT_SHA256=f7e9383b8c0baa81b687e5b5eecc01beefaf1b19b64151d95ed61647fe7a315c
URL=https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz

JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
WORK=$1 PREFIX=$2
shift 2

[ ! -f "$PREFIX/lib/libevent_core.a" ] || exit 0

mkdir -p "$WORK"
cd "$WORK"
if [ ! -f "${URL##*/}" ]; then
    curl -fsSL --retry 3 -o "${URL##*/}.tmp" "$URL"
    mv "${URL##*/}.tmp" "${URL##*/}"
fi
echo "$LIBEVENT_SHA256  ${URL##*/}" | shasum -a 256 -c - >/dev/null
rm -rf libevent-$LIBEVENT_VERSION-stable libevent
tar xzf "${URL##*/}"

cmake -S libevent-$LIBEVENT_VERSION-stable -B libevent "$@" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DEVENT__LIBRARY_TYPE=STATIC \
    -DEVENT__DISABLE_OPENSSL=ON \
    -DEVENT__DISABLE_THREAD_SUPPORT=ON \
    -DEVENT__DISABLE_TESTS=ON \
    -DEVENT__DISABLE_REGRESS=ON \
    -DEVENT__DISABLE_BENCHMARK=ON \
    -DEVENT__DISABLE_SAMPLES=ON
cmake --build libevent -j"$JOBS"
cmake --install libevent
