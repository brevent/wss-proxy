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
    caddy=caddy
elif which uname >/dev/null 2>&1 && uname -a | grep -i linux; then
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.25.0/shadowsocks-v1.25.0.x86_64-unknown-linux-musl.tar.xz -O
    tar xf shadowsocks-v1.25.0.x86_64-unknown-linux-musl.tar.xz sslocal ssserver
    sslocal=./sslocal
    ssserver=./ssserver
    curl -q -s -L https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.5.0/v2ray-plugin-linux-amd64-v1.5.0.tar.gz -O
    tar xf v2ray-plugin-linux-amd64-v1.5.0.tar.gz
    mv v2ray-plugin_linux_amd64 v2ray-plugin
    curl -q -s -L https://github.com/caddyserver/caddy/releases/download/v2.11.9/caddy_2.11.9_linux_amd64.tar.gz -O
    tar xzf caddy_2.11.9_linux_amd64.tar.gz caddy
    caddy=./caddy
else
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.25.0/shadowsocks-v1.25.0.x86_64-pc-windows-msvc.zip -O
    unzip shadowsocks-v1.25.0.x86_64-pc-windows-msvc.zip sslocal.exe ssserver.exe
    sslocal=./sslocal.exe
    ssserver=./ssserver.exe
    curl -q -s -L https://github.com/caddyserver/caddy/releases/download/v2.11.9/caddy_2.11.9_windows_amd64.zip -O
    unzip caddy_2.11.9_windows_amd64.zip caddy.exe
    caddy=./caddy.exe
fi

$python3 ../testcase/udp-echo-server.py &
echo_server_pid=$!

$ssserver -c ../testcase/sip003u-server.json &
spid=$!
if [ -f v2ray-plugin ]; then
    $ssserver -c ../testcase/sip003-server-v2ray.json &
    vspid=$!
fi
sleep 1

function cleanup() {
    echo $echo_server_pid "$lpid" "$lpid2" "$lpid3" "$lpid4" "$lpid5" $spid "$vspid" "$caddy_pid" | xargs echo | xargs kill
}

function check() {
    port="$1"
    for _ in 1 2 3; do
        if ! curl -q -s -x socks5h://127.0.0.1:"$port" https://www.cloudflare.com/cdn-cgi/trace; then
            exit 1
        fi
        if [ "$2" = tcp ]; then
            continue
        fi
        if ! $python3 ../testcase/check-udp.py "$port"; then
            exit 1
        fi
    done
}

trap cleanup SIGINT SIGTERM ERR EXIT

GODEBUG=http2xconnect=1 $caddy run --config ../testcase/caddy/Caddyfile --adapter caddyfile &
caddy_pid=$!

for _ in $(seq 1 10); do
    if curl -q -s -v -k https://localhost:8443/ok; then
        break
    fi
    sleep 1
done

echo wss-proxy client - tls
$sslocal -c ../testcase/sip003u-client-tls.json &
lpid=$!
sleep 1
check 1083

echo wss-proxy client - http2
$sslocal -c ../testcase/sip003u-client-http2.json &
lpid2=$!
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
    lpid3=$!
    sleep 1
    check 1085
fi

if [ -f v2ray-plugin ]; then
    echo v2ray-plugin client - wss-proxy server
    $sslocal -c ../testcase/sip003-client-v2ray.json &
    lpid4=$!
    sleep 1
    check 1086 tcp

    echo wss-proxy client - v2ray-plugin server
    $sslocal -c ../testcase/sip003-client-tls-v2ray.json &
    lpid5=$!
    sleep 1
    check 1087 tcp
fi
