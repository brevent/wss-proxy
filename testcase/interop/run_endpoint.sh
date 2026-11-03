#!/bin/bash

/setup.sh

function hq_interop() {
    SSLKEYLOGFILE=/logs/keys.log SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs \
        quic-hq-interop "$host" "$port" /reqfile.txt
}

case "$ROLE-$TESTCASE" in
client-handshake|client-transfer|client-retry|client-chacha20|client-multiconnect|client-resumption|client-keyupdate)
    /wait-for-it.sh sim:57832 -s -t 30
    if [ "$TESTCASE" = chacha20 ]; then
        export SSL_CIPHER_SUITES=TLS_CHACHA20_POLY1305_SHA256
    elif [ "$TESTCASE" = resumption ]; then
        export SSL_SESSION_FILE=/session.db
    elif [ "$TESTCASE" = keyupdate ]; then
        export KEY_UPDATE=1
    fi
    for req in $REQUESTS; do
        host=$(echo "$req" | sed -ne 's,^https://\([^/:]*\).*,\1,p')
        port=$(echo "$req" | sed -ne 's,^https://[^:/]*:\([^/]*\).*,\1,p')
        if [ "$TESTCASE" = multiconnect ] || [ "$TESTCASE" = resumption ]; then
            echo -n "$(basename "$req")" > /reqfile.txt
            hq_interop || exit 1
        else
            echo -n "$(basename "$req") " >> /reqfile.txt
        fi
    done
    if [ "$TESTCASE" != multiconnect ] && [ "$TESTCASE" != resumption ]; then
        hq_interop
    fi
    ;;
server-handshake|server-transfer|server-multiconnect|server-resumption|server-keyupdate|server-retry|server-chacha20|server-zerortt|server-http3)
    : > /extra.conf
    if [ "$TESTCASE" != http3 ]; then
        echo "http3_hq on;" >> /extra.conf
    fi
    if [ "$TESTCASE" = retry ]; then
        echo "quic_retry on;" >> /extra.conf
    elif [ "$TESTCASE" = chacha20 ]; then
        echo "ssl_conf_command Ciphersuites TLS_CHACHA20_POLY1305_SHA256;" >> /extra.conf
    elif [ "$TESTCASE" = zerortt ]; then
        echo "ssl_early_data on;" >> /extra.conf
    fi
    exec /opt/nginx/sbin/nginx -c /nginx.conf
    ;;
*)
    echo "unsupported test case: $TESTCASE"
    exit 127
    ;;
esac
