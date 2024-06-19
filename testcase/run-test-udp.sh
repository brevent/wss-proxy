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
elif which apt-get >/dev/null 2>&1; then
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.20.0/shadowsocks-v1.20.0.x86_64-unknown-linux-musl.tar.xz -O
    tar xf shadowsocks-v1.20.0.x86_64-unknown-linux-musl.tar.xz
    sslocal=./sslocal
    ssserver=./ssserver
else
    curl -q -s -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.20.0/shadowsocks-v1.20.0.x86_64-pc-windows-msvc.zip -O
    unzip shadowsocks-v1.20.0.x86_64-pc-windows-msvc.zip
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

function cleanup() {
    kill $echo_server_pid $lpid $lpid2 $spid
    rm -rf o.*
}

function check() {
  for x in $(seq 1 3); do
      if ! curl -q -s -v -x socks5h://127.0.0.1:$1 https://www.cloudflare.com/cdn-cgi/trace; then
          exit 1
      fi
      if ! $python3 ../testcase/check-udp.py $1; then
          exit 1
      fi
  done
}

trap cleanup SIGINT SIGTERM ERR EXIT

echo wss-proxy udp client - ss
$sslocal -c ../testcase/sip003u-client-ss.json &
lpid=$!
sleep 1
check 1081

echo wss-proxy udp client - wss
$sslocal -c ../testcase/sip003u-client-ws.json &
lpid2=$!
sleep 1
check 1082