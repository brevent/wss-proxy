#!/bin/bash

set -e

openssl_version=3.6.5

root=$PWD
mkdir -p build/openssl
cd build/openssl

curl -q -sS -f -L --retry 3 https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz -O
rm -rf openssl-$openssl_version
tar xzf openssl-$openssl_version.tar.gz
cd openssl-$openssl_version
patch -p1 < "$root"/.github/vcpkg/quic-time.patch
patch -p1 < "$root"/.github/vcpkg/quic-conn-window.patch
patch -p1 < "$root"/.github/vcpkg/quic-txp.patch
./config no-shared no-tests no-docs no-apps --prefix="$root"/build/openssl/install --libdir=lib > /dev/null
make -j"$(nproc)" build_libs > /dev/null
make install_dev > /dev/null
cd "$root"

PKG_CONFIG_PATH="$root"/build/openssl/install/lib/pkgconfig cmake -S . -B build/openssl/wss-proxy -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR="$root"/build/openssl/install -DOPENSSL_USE_STATIC_LIBS=ON
cmake --build build/openssl/wss-proxy --target wss-proxy-client -j"$(nproc)"
cp build/openssl/wss-proxy/wss-proxy-client build/openssl/
