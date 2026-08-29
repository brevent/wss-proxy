#ifndef WSS_PROXY_WSS_CLIENT_H
#define WSS_PROXY_WSS_CLIENT_H

#include <event2/bufferevent.h>
#include <openssl/ssl.h>
#include "common.h"

#define MOG(LOGX, wss_context, format, ...)                             \
    do {                                                                \
        if ((wss_context)->slot >= 0) {                                 \
            LOGX("connection %d " format, (wss_context)->slot, ## __VA_ARGS__); \
        } else {                                                        \
            LOGX(format, ## __VA_ARGS__);                               \
        }                                                               \
    } while (0)
#define MOGD(wss_context, format, ...) MOG(LOGD, wss_context, format, ## __VA_ARGS__)
#define MOGI(wss_context, format, ...) MOG(LOGI, wss_context, format, ## __VA_ARGS__)
#define MOGW(wss_context, format, ...) MOG(LOGW, wss_context, format, ## __VA_ARGS__)
#define MOGE(wss_context, format, ...) MOG(LOGE, wss_context, format, ## __VA_ARGS__)

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
    const char *ifname;
};

typedef struct bufferevent_http_stream bufferevent_http_stream;

#ifdef WSS_PROXY_CLIENT
#ifdef DEFINE_LHASH_OF_EX
DEFINE_LHASH_OF_EX(bufferevent_http_stream);
#else
DEFINE_LHASH_OF(bufferevent_http_stream);
#endif
#endif

struct wss_context {
    struct wss_mux_context *wss_mux_context;
    int slot;
    SSL_CTX *ssl_ctx;
    struct event_base *base;
    unsigned refs;
    SSL *ssl;
    SSL *stream;
    LHASH_OF(bufferevent_http_stream) *http_streams;
    unsigned http_streams_count;
    unsigned long active_streams;
    struct evbuffer *input;
    struct evbuffer *output;
    struct event *event_mux;
    struct timeval timeout;
    uint8_t settings_sent: 1;
    uint8_t ssl_goaway: 1;
    uint8_t ssl_error: 1;
    uint8_t ssl_connected: 1;
    uint8_t http2_evict_pending: 1;
    uint8_t closed: 1;
    uint32_t next_stream_id;
    uint32_t initial_window_size;
    uint32_t max_concurrent_streams;
    size_t send_window;
    size_t recv_window;
};

#ifndef MAX_MUX_CONNECTIONS
#define MAX_MUX_CONNECTIONS 16
#endif

struct wss_mux_context {
    SSL_CTX *ssl_ctx;
    struct event_base *base;
    struct wss_context *conns[MAX_MUX_CONNECTIONS];
    struct wss_server_info server;
    char user_agent[80];
};

struct bev_context_ssl {
    const struct bev_context *bev_context;
    struct wss_context *wss_context;
    enum http http;
    uint8_t upgrade: 1;
    uint8_t connected: 1;
    uint8_t rst_sent: 1;
    struct evbuffer *frame;
    uint32_t stream_id;
    uint32_t initial_window_size;
    ssize_t send_window;
    size_t recv_window;
    uint64_t total;
    SSL *ssl;
};

struct bufferevent_http_stream {
    uint32_t stream_id;
    struct bufferevent *bev;
    volatile uint8_t mark_free: 1;
    uint8_t in_closed: 1;
    uint8_t out_closed: 1;
    uint8_t rst_sent: 1;
    struct wss_context *wss_context;
};

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) < (y) ? (y) : (x))
#endif

#define HTTP2_HEADER_LENGTH 9
#define MAX_FRAME_SIZE (MAX_WSS_PAYLOAD_SIZE + MAX_WS_HEADER_SIZE + HTTP2_HEADER_LENGTH)

#define DEFAULT_INITIAL_WINDOW_SIZE 0xffff
#ifndef DEFAULT_MAX_CONCURRENT_STREAMS
#define DEFAULT_MAX_CONCURRENT_STREAMS 128
#endif
#define MAX_WINDOW_SIZE 0x7fffffff

#define WSS_EOF (0)
#define WSS_AGAIN (-1)
#define WSS_ERROR (-2)
#define WSS_MORE (-3)

void free_context_ssl(struct wss_mux_context *wss_mux_context);

enum ssl_type {
    ssl_read,
    ssl_write,
};

size_t build_http2_frame(uint8_t *frame, size_t length, uint8_t type, uint8_t flags, uint32_t stream_id);

void reset_streams_count(struct wss_context *wss_context);

void abort_http_stream(struct bufferevent_http_stream *http_stream);

void reset_http2_stream(struct wss_context *wss_context, uint32_t stream_id, int status);

int decode_huffman_digit(uint8_t *buffer, size_t size);

#define HTTP3_MAX_HEADER_LENGTH 9

SSL_CTX  *ssl_ctx_new_http3();

size_t build_http_request_v3(struct wss_mux_context *wss_mux_context, int udp, char *request);

void http_response_cb_v3(struct bufferevent *tev, void *raw);

size_t parse_http3_frame(const uint8_t *buffer, size_t length, size_t *out_header_length);

size_t build_http3_frame(uint8_t *frame, uint8_t type, size_t length);

int get_ssl_error_http3(SSL *ssl, int code);

ssize_t check_ssl_error_http3(struct bev_context_ssl *bev_context_ssl, enum ssl_type ssl_type);

SSL *init_http3_stream(SSL *ssl, struct sockaddr *sockaddr, uint16_t port);

int init_context_ssl_http3(struct bev_context_ssl *bev_context_ssl, SSL *ssl);

void free_context_ssl_http3(struct bev_context_ssl *bev_context_ssl);

struct event *init_ssl_http3(struct wss_context *wss_context, struct event_base *base, evutil_socket_t fd, SSL *ssl);

struct bufferevent *bufferevent_wss_new(struct wss_mux_context *wss_mux_context, struct bufferevent *raw);

#endif //WSS_PROXY_WSS_CLIENT_H
