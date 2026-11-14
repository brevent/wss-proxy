#!/bin/bash
# build static libevent_core
# usage: deps/libevent.sh <workdir> <prefix> [cmake options...]
set -euo pipefail

LIBEVENT_VERSION=2.1.13
URL=https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz

JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
WORK=$1 PREFIX=$2
shift 2

mkdir -p "$WORK"
cd "$WORK"
if [ ! -f "${URL##*/}" ]; then
    curl -fsSL --retry 3 -o "${URL##*/}.tmp" "$URL"
    mv "${URL##*/}.tmp" "${URL##*/}"
fi
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
