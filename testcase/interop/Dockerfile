FROM martenseemann/quic-network-simulator-endpoint:latest

ARG OPENSSL_VERSION=3.5.9
ARG NGINX_VERSION=1.31.8

RUN apt-get update && apt-get install -y build-essential curl perl patch libpcre2-dev zlib1g-dev

COPY .github/vcpkg/*.patch testcase/interop/*.patch /patches/

RUN curl -q -sS -f -L --retry 3 https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz | tar xz && \
    cd openssl-$OPENSSL_VERSION && \
    patch -p1 < /patches/hq-interop-keyupdate.patch && \
    patch -p1 --fuzz=0 < /patches/quic-time.patch && \
    patch -p1 --fuzz=0 < /patches/quic-conn-window.patch && \
    patch -p1 --fuzz=0 < /patches/quic-txp.patch && \
    patch -p1 --fuzz=0 < /patches/quic-interop.patch && \
    ./Configure enable-sslkeylog enable-hqinterop no-shared no-docs --prefix=/opt/openssl --libdir=lib > /dev/null && \
    make -j"$(nproc)" build_libs test/quic-openssl-docker/hq-interop/quic-hq-interop > /dev/null && \
    make install_dev > /dev/null && \
    cp test/quic-openssl-docker/hq-interop/quic-hq-interop /usr/local/bin && \
    cd / && rm -rf openssl-$OPENSSL_VERSION

RUN curl -q -sS -f -L --retry 3 https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz | tar xz && \
    curl -q -sS -f -L --retry 3 https://github.com/nginx/nginx/pull/1683.patch -o 1683.patch && \
    cd nginx-$NGINX_VERSION && \
    patch -p1 < ../1683.patch && \
    ./configure --prefix=/opt/nginx --with-http_ssl_module --with-http_v3_module \
        --with-cc-opt=-I/opt/openssl/include --with-ld-opt="-L/opt/openssl/lib -ldl -lpthread" > /dev/null && \
    make -j"$(nproc)" > /dev/null && \
    make install > /dev/null && \
    cd / && rm -rf nginx-$NGINX_VERSION 1683.patch

COPY testcase/interop/nginx.conf /nginx.conf
COPY testcase/interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT [ "/run_endpoint.sh" ]
