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

### Server

There is unnecessary to specify `tls`, `host`, `path`:
- `tls`, use behind nginx, plugin server doesn't use tls.
- `host`, use behind nginx, plugin server support any host.
- `path`, use behind nginx, plugin server support any path.

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

### Compatible

Should compatible with `mux=0` with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin/).
