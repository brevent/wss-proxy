#ifndef WSS_PROXY_WSS_CLIENT_H
#define WSS_PROXY_WSS_CLIENT_H

#include <event2/bufferevent.h>
#include <openssl/ssl.h>
#include "common.h"

enum http {
    http1,
    http2,
    http3,
};

struct wss_server_info {
    uint8_t tls: 1;
    uint8_t ws: 1;
    uint8_t ipv6: 1;
    uint8_t http2: 1;
    uint8_t http3: 1;
    uint8_t mux: 1;
    uint16_t port;
    const char *addr;
    const char *host;
    const char *path;
};

typedef struct bufferevent_http_stream bufferevent_http_stream;

#ifdef WSS_PROXY_CLIENT
#ifdef DEFINE_LHASH_OF_EX
DEFINE_LHASH_OF_EX(bufferevent_http_stream);
#else
DEFINE_LHASH_OF(bufferevent_http_stream);
#endif
#endif

struct wss_proxy_context {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    SSL *stream;
    LHASH_OF(bufferevent_http_stream) *http_streams;
    struct evbuffer *input;
    struct evbuffer *output;
    struct event *event_quic;
    uint8_t settings_sent: 1;
    uint32_t next_stream_id: 23;
    uint32_t initial_window_size;
    struct wss_server_info server;
    char user_agent[80];
};

struct bufferevent_context_ssl {
    struct bufferevent_context context;
    struct wss_proxy_context *proxy_context;
    enum http http: 2;
    uint8_t upgrade: 1;
    struct evbuffer *frame;
    uint32_t stream_id;
    uint32_t send_window;
    uint64_t total;
    union {
        SSL *ssl;
        SSL *stream;
    };
};

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) < (y) ? (y) : (x))
#endif

void free_context_ssl(struct wss_proxy_context *proxy_context);

size_t build_http2_frame(uint8_t *frame, size_t length, uint8_t type, uint8_t flags, uint32_t stream_id);

size_t parse_http3_frame(const uint8_t *buffer, size_t length, size_t *out_header_length);

size_t build_http3_frame(uint8_t *frame, uint8_t type, size_t length);

struct bufferevent *bufferevent_new(struct wss_proxy_context *context, struct bufferevent *raw);

#endif //WSS_PROXY_WSS_CLIENT_H
