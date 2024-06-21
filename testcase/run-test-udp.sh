#!/bin/bash

set -e

if [ -f /usr/bin/python3 ]; then
    python3=/usr/bin/python3
else
    python3=python3
fi

if which ssserver >/dev/null 2>&1; then
    sslocal=sslocal
    ssserver=ssserver
elif which uname >/dev/null 2>&1 && uname -a | grep -i linux; then
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.20.0/shadowsocks-v1.20.0.x86_64-unknown-linux-musl.tar.xz -O
    tar xf shadowsocks-v1.20.0.x86_64-unknown-linux-musl.tar.xz sslocal ssserver
    sslocal=./sslocal
    ssserver=./ssserver
else
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.20.0/shadowsocks-v1.20.0.x86_64-pc-windows-msvc.zip -O
    unzip shadowsocks-v1.20.0.x86_64-pc-windows-msvc.zip sslocal.exe ssserver.exe
    sslocal=./sslocal.exe
    ssserver=./ssserver.exe
fi

if which pgrep >/dev/null 2>&1 && pgrep -f udp-echo-server.py > /dev/null; then
    echo_server_pid=""
else
    $python3 ../testcase/udp-echo-server.py &
    echo_server_pid=$!
fi

$ssserver -c ../testcase/sip003u-server.json &
spid=$!
sleep 1

if sed --version >/dev/null 2>&1; then
    sedi() { sed -i "$@"; }
else
    sedi() { sed -i '' "$@"; }
fi
function update_tls_server() {
    sedi -e "s|\"server\":.*|\"server\": \"$1\",|g" ../testcase/sip003u-client-{tls,http2,http3}.json
}

function cleanup() {
    echo $echo_server_pid "$lpid" "$lpid2" "$lpid3" "$lpid4" "$lpid5" $spid | xargs echo | xargs kill
    if which docker >/dev/null 2>&1 && docker version 2>/dev/null | grep -i linux/amd64; then
        docker ps | grep -F ':9999->443/udp' | awk '{print $1}' | xargs docker stop
    else
        :
    fi
    update_tls_server 127.0.0.1
}

function check() {
    port="$1"
    for _ in 1 2 3; do
        if ! curl -q -s -x socks5h://127.0.0.1:"$port" https://www.cloudflare.com/cdn-cgi/trace; then
            exit 1
        fi
        if ! $python3 ../testcase/check-udp.py "$port"; then
            exit 1
        fi
    done
}

trap cleanup SIGINT SIGTERM ERR EXIT

echo wss-proxy client - ss
$sslocal -c ../testcase/sip003u-client-ss.json &
lpid=$!
sleep 1
check 1081

echo wss-proxy client - ws
$sslocal -c ../testcase/sip003u-client-ws.json &
lpid2=$!
sleep 1
check 1082

if which docker >/dev/null 2>&1 && docker version 2>/dev/null | grep -i linux/amd64; then
    if [ ! -f ../testcase/nginx/pcre2-10.23-2.el7.x86_64.rpm ]; then
        if ! curl -q -s https://vault.centos.org/7.9.2009/os/x86_64/Packages/pcre2-10.23-2.el7.x86_64.rpm -o ../testcase/nginx/pcre2-10.23-2.el7.x86_64.rpm; then
            echo "cannot download pcre"
            exit 0
        fi
    fi
    if [ ! -f ../testcase/nginx/nginx-1.26.1-2.el7.wss.x86_64.rpm ]; then
        if ! curl -q -s https://cdn.jianyu.io/rpm/nginx-1.26.1-2.el7.wss.x86_64.rpm -o ../testcase/nginx/nginx-1.26.1-2.el7.wss.x86_64.rpm; then
            echo "cannot download nginx wss"
            exit 0
        fi
    fi
    docker run -d --rm --add-host=host.docker.internal:host-gateway -p 9999:443 -p 9999:443/udp -v "$PWD"/../testcase/nginx:/tmp/nginx centos:7.9.2009 \
        bash -c "yum install -y /tmp/nginx/*.rpm; cp /tmp/nginx/localhost.* /etc/nginx/conf.d/; nginx -g 'daemon off;'"

    for _ in $(seq 1 60); do
        if curl -q -s -v -k https://localhost:9999/ok; then
            break
        fi
        sleep 1
    done
else
    remote=$SECRET_REMOTE_IP
    if [ -z "$remote" ]; then
        exit 0
    fi
    if ! curl -q -s -v -k --connect-timeout 5 https://"$remote":9999/ok; then
        exit 0
    fi
    update_tls_server "$remote"
fi

echo wss-proxy client - tls
$sslocal -c ../testcase/sip003u-client-tls.json &
lpid3=$!
sleep 1
check 1083

echo wss-proxy client - http2
$sslocal -c ../testcase/sip003u-client-http2.json &
lpid4=$!
sleep 1
check 1084

if [ -f wss-proxy-client.exe ]; then
    wss_proxy_client=./wss-proxy-client.exe
else
    wss_proxy_client=./wss-proxy-client
fi
if ! grep -a "http3 is unsupported" $wss_proxy_client >/dev/null; then
    echo wss-proxy client - http3
    $sslocal -c ../testcase/sip003u-client-http3.json &
    lpid5=$!
    sleep 1
    check 1085
fi
