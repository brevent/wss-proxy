#!/bin/bash

set -e

nginx_version=1.31.8

mkdir -p build/nginx
cd build/nginx

curl -q -sS -f -L --retry 3 https://nginx.org/download/nginx-$nginx_version.tar.gz -O
curl -q -sS -f -L --retry 3 https://github.com/nginx/nginx/pull/1683.patch -O
rm -rf nginx-$nginx_version
tar xzf nginx-$nginx_version.tar.gz
cd nginx-$nginx_version
patch -p1 < ../1683.patch

if [ "$(uname -s)" = Darwin ]; then
    ./configure --with-cc-opt="-I$(brew --prefix)/include" --with-ld-opt="-L$(brew --prefix)/lib" \
        --with-http_ssl_module --with-http_v2_module --with-http_v3_module
    make -j"$(sysctl -n hw.ncpu)"
else
    ./configure --with-http_ssl_module --with-http_v2_module --with-http_v3_module
    make -j"$(nproc)"
fi
cp objs/nginx ..
