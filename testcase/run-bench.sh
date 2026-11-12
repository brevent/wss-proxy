#!/bin/bash

set -e

caddy=./caddy
sslocal=./sslocal
ssserver=./ssserver
ss="-m chacha20-ietf-poly1305 -k sip003u"
cert=../testcase/caddy/localhost.crt

# each stream downloads a 512 MiB file over https, so truncated data fails curl
size=536870912
concurrencies="1 8"

mkdir -p root
truncate -s $size root/bench.bin

spids=()
lpids=()
names=()
concs=()
ports=()
plugins=()
speeds=()
costs=()
port=1090

function cleanup() {
    kill "${lpids[@]}" "${spids[@]}" "$caddy_pid" 2>/dev/null || true
}

trap cleanup SIGINT SIGTERM ERR EXIT

# one instance per concurrency, so peak RSS is per concurrency
function client() {
    for c in $concurrencies; do
        port=$((port + 1))
        $sslocal -b 127.0.0.1:$port -s 127.0.0.1:8443 $ss --plugin "$2" --plugin-opts "$3" > bench.$port.log 2>&1 &
        lpids+=($!)
        names+=("$1")
        concs+=("$c")
        ports+=($port)
    done
}

function cpu() {
    awk -v hz="$(getconf CLK_TCK)" '{print ($14 + $15) / hz}' /proc/"$1"/stat
}

function measure() {
    cpu0=$(cpu "${plugins[$i]}") &&
        start=$EPOCHREALTIME &&
        seq "$c" | xargs -P "$c" -I{} curl -q -s -f -k --noproxy '' -m 300 -o /dev/null \
            -w '%{size_download} %{exitcode}\n' -x socks5h://127.0.0.1:"${ports[$i]}" \
            https://localhost:9443/bench.bin > bench.curl.log &&
        end=$EPOCHREALTIME &&
        cpu1=$(cpu "${plugins[$i]}")
}

$ssserver -s 127.0.0.1:8888 $ss --plugin ./wss-proxy-server --plugin-opts "mux=0" &
spids+=($!)
$ssserver -s 127.0.0.1:8890 $ss --plugin ./v2ray-plugin --plugin-opts "server;path=/v2ray-mux" &
spids+=($!)

GODEBUG=http2xconnect=1 $caddy run --config ../testcase/caddy/Caddyfile.bench --adapter caddyfile &
caddy_pid=$!

for _ in $(seq 1 10); do
    if curl -q -s -k https://localhost:8443/ok; then
        break
    fi
    sleep 1
done

client "wss-proxy-client tls" ./openssl/wss-proxy-client "mux=0;host=localhost;tls"
client "wss-proxy-client http2" ./openssl/wss-proxy-client "mux=0;host=localhost;http2"
client "wss-proxy-client http3" ./openssl/wss-proxy-client "mux=0;host=localhost;http3"
client "v2ray-plugin mux=0" ./v2ray-plugin "mux=0;host=localhost;tls;cert=$cert"
client "v2ray-plugin mux=1" ./v2ray-plugin "mux=1;host=localhost;tls;path=/v2ray-mux;cert=$cert"
client "v2ray-plugin mux=8" ./v2ray-plugin "mux=8;host=localhost;tls;path=/v2ray-mux;cert=$cert"
sleep 1

# plugin is the child of sslocal
for i in "${!names[@]}"; do
    plugins+=("$(pgrep -P "${lpids[$i]}")") || {
        echo "${names[$i]}: plugin not found"
        exit 1
    }
done

for i in "${!names[@]}"; do
    c=${concs[$i]}
    : > bench.curl.log
    if ! measure; then
        echo "${names[$i]} x$c: failed, bytes and exit code of each stream:"
        cat bench.curl.log
        cat bench."${ports[$i]}".log
        nstat -az UdpRcvbufErrors UdpSndbufErrors UdpInErrors
        exit 1
    fi
    mib=$((size * c / 1048576))
    speeds+=("$(echo "$start $end" | awk -v mib=$mib '{printf "%.1f", mib / ($2 - $1)}')")
    costs+=("$(echo "$cpu0 $cpu1" | awk -v mib=$mib '{printf "%.2f", ($2 - $1) * 1024 / mib}')")
    echo "${names[$i]} x$c: ${speeds[$i]} MiB/s, ${costs[$i]} s/GiB"
done

summary="| client | concurrency | MiB/s | plugin CPU s/GiB | plugin peak RSS MiB |
|---|---|---|---|---|"
for c in $concurrencies; do
    for i in "${!names[@]}"; do
        if [ "${concs[$i]}" != "$c" ]; then
            continue
        fi
        rss=$(awk '/^VmHWM/ {printf "%.0f", $2 / 1024}' /proc/"${plugins[$i]}"/status)
        summary="$summary
| ${names[$i]} | $c | ${speeds[$i]} | ${costs[$i]} | $rss |"
    done
done
echo "$summary"
echo "$summary" >> "$GITHUB_STEP_SUMMARY"
