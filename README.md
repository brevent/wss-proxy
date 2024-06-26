SIP003 plugin for shadowsocks, based on WebSocket.

## Requirements

- [libevent](https://github.com/libevent/libevent) 2.1.8-stable+
- [OpenSSL](https://github.com/openssl/openssl) 1.1.1+ for TLS 1.3 support

## Build

- [CMake](https://cmake.org/) 3.16+

```bash
cmake -B build
cmake --build build
```

## Usage

### Client

`ss-local -c xxx.json`

```json
{
  "server": "xxx",
  "server_port": 443,
  "method": "none",
  "local_address": "0.0.0.0",
  "local_port": 1080,
  "plugin": "/path/to/wss-proxy-client",
  "plugin_opts": "tls;host=xxx;path=/xxx;mux=0"
}
```

#### Options compatible with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin/)
- `tls`, `tls` for https / wss, otherwise http / ws
- `host`, host name
- `path`, default `/`
- `loglevel`, default `INFO`, support `DEBUG`, `INFO`, `WARN`, `ERROR`
- `mux`, default `1` (only `0` is supported, specify for compatible with `v2ray-plugin`)

#### Options for `wss-proxy-client` only
- `ws` (since 0.2.6, [e7b7f36](https://github.com/brevent/wss-proxy/commit/e7b7f36)), default `1` to use websocket after handshake, `0` to use raw shadowsocks after handshake
  - don't use it if you're unsure
- `extra-listen-port` (since 0.3.0, [689f0e7](https://github.com/brevent/wss-proxy/commit/689f0e7)), extra listen port for shadowsocks client without sip003u
- `syslog` (since 0.3.3, [47d4681](https://github.com/brevent/wss-proxy/commit/47d4681)), log to syslog if supported
- `ipv6` (since 0.3.4, [a8b5f71](https://github.com/brevent/wss-proxy/commit/a8b5f71)), prefer ipv6 (should fallback to ipv4 if no ipv6)
- `http2` (since 0.4.0, WebSocket over HTTP/2, [RFC 8441](https://datatracker.ietf.org/doc/html/rfc8441))
- `http3` (since 0.4.0, WebSocket over HTTP/3, [RFC 9220](https://datatracker.ietf.org/doc/html/rfc9220))

### Server

`ss-server -c xxx.json`

```json
{
    "server":"127.0.0.1",
    "server_port":3448,
    "timeout":60,
    "method":"none",
    "plugin": "/path/to/wss-proxy-server",
    "plugin_opts": "mux=0"
}
```

#### Options compatible with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin/)
- `loglevel`, default `INFO`, support `DEBUG`, `INFO`, `WARN`, `ERROR`
- `mux`, default `1` (only `0` is supported, specify for compatible with `v2ray-plugin`)

Unsupported options:
- `tls`, use behind nginx, plugin server doesn't use tls.
- `host`, use behind nginx, plugin server support any host.
- `path`, use behind nginx, plugin server support any path.

#### Options for `wss-proxy-server` only
- `udp-port`, udp port to shadowsocks server without sip003u
  - There is no `tcp-port`, which is environment `SS_LOCAL_PORT`.
- `syslog` (since 0.3.3, [47d4681](https://github.com/brevent/wss-proxy/commit/47d4681)), log to syslog if supported
