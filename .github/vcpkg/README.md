# OpenSSL QUIC patches

- `quic-time.patch`: keep QUIC time monotonic, https://github.com/openssl/openssl/issues/33403
- `quic-conn-window.patch`: connection window control, already in OpenSSL 4.1.0
- `quic-txp.patch`: retransmit lost MAX_STREAM_DATA frames, https://github.com/openssl/openssl/issues/33373
