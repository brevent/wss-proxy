#!/bin/bash

# rm -rf build
set -e
lport=1081
sport=8888

if which v2ray-plugin; then
    v2ray_plugin=v2ray-plugin
else
    curl -L https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.2/v2ray-plugin-linux-amd64-v1.3.2.tar.gz -O
    tar xf v2ray-plugin-linux-amd64-v1.3.2.tar.gz
    mv v2ray-plugin_linux_amd64 v2ray-plugin
    v2ray_plugin=./v2ray-plugin
fi

check() {
    urlb=dl.jianyv.com/128k.bin
    urlt=dl.jianyv.com/cdn-cgi/trace

    rm -rf o.*
    echo "checking donwload binary"
    curl -q -m 6 -4 -s -L $urlb -o o.bin
    curl -q -m 6 -4 -s -x socks5h://localhost:$lport -L $urlb -o o.ws.bin
    if ! cmp -s o.bin o.ws.bin; then
        echo "fail test binary"
        exit 1
    fi
    echo "download binary ok"

    echo "checking upload text"
    header=`head -c 4096 /dev/urandom | openssl base64`
    magic=`echo $header | openssl base64 -d | openssl md5 | awk '{print $NF}'`
    curl -q -m 6 -4 -s -L -H "X-magic: $magic" $urlt?mask={1,12,123,1234} https://$urlt?mask={1,12,123,1234} -o - > o.magic.txt
    if ! grep $magic o.magic.txt >/dev/null; then
        echo "fail check text"
        exit 1
    fi
    curl -q -m 6 -4 -s -L -H "X-header: $header" -H "X-magic: $magic" $urlt -o o.txt
    curl -q -m 6 -4 -s -L -x socks5h://localhost:$lport -H "X-magic: $magic" $urlt?mask={1,12,123,1234} https://$urlt?mask={1,12,123,1234} -o - > o.magic.ws.txt
    curl -q -m 6 -4 -s -L -x socks5h://localhost:$lport -H "X-header: $header" -H "X-magic: $magic" $urlt -o o.ws.txt
    if ! cmp -s o.magic.txt o.magic.ws.txt; then
        echo "fail test text magic"
        exit 1
    fi
    if ! cmp -s o.txt o.ws.txt; then
        echo "fail test text"
        exit 1
    fi
    echo "upload text ok"
}

function cleanup() {
    kill $lpid $spid
    rm -rf o.*
}

trap cleanup SIGINT SIGTERM ERR EXIT

echo wss-proxy client - v2ray-plugin server
ss-local -l $lport -s 127.0.0.1 -p $sport -m chacha20-ietf-poly1305 -k sip003 --plugin ./wss-proxy-client --plugin-opts "mux=0" &
lpid=$!
ss-server -s 127.0.0.1 -p $sport -m chacha20-ietf-poly1305 -k sip003 --plugin $v2ray_plugin --plugin-opts "server;mux=0" &
spid=$!
check

kill $spid
echo -n wss-proxy client - wss-proxy server
for x in 1 2 3; do
    echo -n .
    sleep 1
done
echo
ss-server -s 127.0.0.1 -p $sport -m chacha20-ietf-poly1305 -k sip003 --plugin ./wss-proxy-server --plugin-opts "mux=0" &
spid=$!
check

kill $lpid
echo v2ray-plugin client - wss-proxy server
for x in 1 2 3; do
    echo -n .
    sleep 1
done
echo
ss-local -l $lport -s 127.0.0.1 -p $sport -m chacha20-ietf-poly1305 -k sip003 --plugin $v2ray_plugin --plugin-opts "mux=0" &
lpid=$!
check
