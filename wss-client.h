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

struct wss_context {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    SSL *stream;
    LHASH_OF(bufferevent_http_stream) *http_streams;
    unsigned http_streams_count;
    struct event_base *base;
    struct evbuffer *input;
    struct evbuffer *output;
    struct event *event_mux;
    struct event *event_sighup;
    struct timeval timeout;
    uint8_t settings_sent: 1;
    uint8_t mock_ssl_timeout: 1;
    uint8_t ssl_goaway: 1;
    uint8_t ssl_error: 1;
    uint8_t ssl_connected: 1;
    uint8_t http2_evicted: 1;
    uint32_t next_stream_id: 23;
    uint32_t initial_window_size;
    ssize_t send_window;
    size_t recv_window;
    struct wss_server_info server;
    char user_agent[80];
};

struct bev_context_ssl {
    const struct bev_context *bev_context;
    struct wss_context *wss_context;
    enum http http: 2;
    uint8_t upgrade: 1;
    uint8_t connected: 1;
    struct evbuffer *frame;
    uint32_t stream_id;
    uint32_t initial_window_size;
    ssize_t send_window;
    size_t recv_window;
    uint64_t total;
    union {
        SSL *ssl;
        SSL *stream;
    };
};

struct bufferevent_http_stream {
    uint64_t stream_id;
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
#define MAX_WINDOW_SIZE 0x7fffffff

#define WSS_EOF (0)
#define WSS_AGAIN (-1)
#define WSS_ERROR (-2)
#define WSS_MORE (-3)

void free_context_ssl(struct wss_context *wss_context);

enum ssl_type {
    ssl_read,
    ssl_write,
};

size_t build_http2_frame(uint8_t *frame, size_t length, uint8_t type, uint8_t flags, uint32_t stream_id);

void reset_streams_count(struct wss_context *wss_context);

#define HTTP3_MAX_HEADER_LENGTH 9

SSL_CTX  *ssl_ctx_new_http3();

size_t build_http_request_v3(struct wss_context *wss_context, int udp, char *request);

void http_response_cb_v3(struct bufferevent *tev, void *raw);

size_t parse_http3_frame(const uint8_t *buffer, size_t length, size_t *out_header_length);

size_t build_http3_frame(uint8_t *frame, uint8_t type, size_t length);

int get_ssl_error_http3(SSL *ssl, int code);

ssize_t check_ssl_error_http3(struct bev_context_ssl *bev_context_ssl, enum ssl_type ssl_type);

SSL *init_http3_stream(SSL *ssl, struct sockaddr *sockaddr, uint16_t port);

int init_context_ssl_http3(struct bev_context_ssl *bev_context_ssl, SSL *ssl);

void free_context_ssl_http3(struct bev_context_ssl *bev_context_ssl);

struct event *init_ssl_http3(struct wss_context *wss_context, struct event_base *base, int fd, SSL *ssl);

struct bufferevent *bufferevent_new(struct wss_context *wss_context, struct bufferevent *raw);

#endif //WSS_PROXY_WSS_CLIENT_H
