#!/bin/bash
# build static wss-proxy for windows x64 with msvc v143
# run in git bash from an x64 developer prompt (vcvars64.bat -vcvars_ver=14.44), with nasm and jom in PATH
# usage: windows/build.sh [build-dir]  (default: build-windows/wss-proxy)
set -euo pipefail

WINNT=0x0601

ROOT=$(cygpath -m "$(cd "$(dirname "$0")/.." && pwd)")
OUT=$ROOT/build-windows
DEPS=$OUT/deps
BUILD=$(cygpath -m "${1:-$OUT/wss-proxy}")

if ! command -v cl >/dev/null || ! command -v nasm >/dev/null || ! command -v jom >/dev/null; then
    echo "cl, nasm and jom are required, run from an x64 developer prompt" >&2
    exit 1
fi
# msvc link.exe must come before coreutils link, openssl needs native perl
export PATH="$(dirname "$(command -v cl)"):/c/Strawberry/perl/bin:$PATH"

cmake_windows=(
    -G "NMake Makefiles JOM"
)

"$ROOT/deps/openssl.sh" "$OUT" "$(cygpath -w "$DEPS")" VC-WIN64A -D_WIN32_WINNT=$WINNT
# openssl replaces its default CFLAGS (/O2 /nologo ...) with env CFLAGS, so export it afterwards
export CFLAGS=-D_WIN32_WINNT=$WINNT
"$ROOT/deps/libevent.sh" "$OUT" "$DEPS" "${cmake_windows[@]}"

cmake -S "$ROOT" -B "$BUILD" "${cmake_windows[@]}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$DEPS" \
    -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=ON \
    -DOPENSSL_ROOT_DIR="$DEPS" \
    -DOPENSSL_USE_STATIC_LIBS=ON \
    -DOPENSSL_MSVC_STATIC_RT=ON
cmake --build "$BUILD"
