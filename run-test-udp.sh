#!/bin/bash

set -e
laddr=127.0.0.1
lport=1081
sport=8888

if which ssserver; then
    sslocal=sslocal
    ssserver=ssserver
else
    curl -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.18.2/shadowsocks-v1.18.2.x86_64-unknown-linux-musl.tar.xz -O
    tar xf shadowsocks-v1.18.2.x86_64-unknown-linux-musl.tar.xz
    sslocal=./sslocal
    ssserver=./ssserver
fi

python3 ../testcase/udp-echo-server.py &
echo_server_pid=$!

$ssserver -c ../testcase/sip003u-server.json &
spid=$!

function cleanup() {
    kill $echo_server_pid $lpid $spid
    rm -rf o.*
}

trap cleanup SIGINT SIGTERM ERR EXIT

echo wss-proxy udp client - ss
$sslocal -c ../testcase/sip003u-client-ss.json &
lpid=$!
sleep 1
if ! python3 ../testcase/check-udp.py; then
  exit 1
fi

kill $lpid

echo wss-proxy udp client - wss
$sslocal -c ../testcase/sip003u-client-ws.json &
lpid=$!
sleep 1
if ! python3 ../testcase/check-udp.py; then
  exit 1
fi
