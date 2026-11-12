#!/bin/bash

set -e

root=$PWD
deps/openssl.sh build/openssl "$root"/build/openssl/install

PKG_CONFIG_PATH="$root"/build/openssl/install/lib/pkgconfig cmake -S . -B build/openssl/wss-proxy -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR="$root"/build/openssl/install -DOPENSSL_USE_STATIC_LIBS=ON
cmake --build build/openssl/wss-proxy --target wss-proxy-client -j"$(nproc)"
cp build/openssl/wss-proxy/wss-proxy-client build/openssl/
