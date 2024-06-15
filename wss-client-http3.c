#include <event2/event.h>
#include "wss-client.h"

#if HAVE_OSSL_QUIC_CLIENT_METHOD

SSL_CTX *ssl_ctx_new_http3() {
    return SSL_CTX_new(OSSL_QUIC_client_method());
}

static enum bufferevent_filter_result wss_output_filter_v3(struct evbuffer *src, struct evbuffer *dst,
                                                           ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                           void *tev) {
    size_t length, frame_header_length;
    struct bev_context_ssl *bev_context_ssl;
    uint8_t buffer[HTTP3_MAX_HEADER_LENGTH + MAX_WS_HEADER_SIZE + MAX_WSS_PAYLOAD_SIZE];

    (void) dst_limit;
    (void) mode;
    bev_context_ssl = bufferevent_get_context(tev);
    if (!bev_context_ssl || bev_context_ssl->wss_context->ssl_error) {
        return BEV_ERROR;
    }
    if (evbuffer_get_length(src) > sizeof(buffer) - HTTP3_MAX_HEADER_LENGTH) {
        return BEV_ERROR;
    }
    length = evbuffer_copyout(src, &buffer[HTTP3_MAX_HEADER_LENGTH], sizeof(buffer) - HTTP3_MAX_HEADER_LENGTH);
    frame_header_length = build_http3_frame(buffer, 0, length);
    if (frame_header_length == 0) {
        return BEV_ERROR;
    }
    memmove(buffer + (HTTP3_MAX_HEADER_LENGTH - frame_header_length), buffer, frame_header_length);
    evbuffer_add(dst, buffer + (HTTP3_MAX_HEADER_LENGTH - frame_header_length), length + frame_header_length);
    evbuffer_drain(src, length);
    return BEV_OK;
}

void http_response_cb_v3(struct bufferevent *tev, void *raw) {
    size_t length, frame_length;
    uint8_t buffer[HTTP3_MAX_HEADER_LENGTH];
    struct evbuffer *input;

    input = bufferevent_get_input(tev);
    frame_length = evbuffer_copyout(input, buffer, sizeof(buffer));
    frame_length = parse_http3_frame(buffer, frame_length, NULL);
    length = evbuffer_get_length(input);
    if (frame_length == 0 || length < frame_length) {
        return;
    }
    if (buffer[0] != 0x1) {
        LOGW("invalid frame %d, expect headers (0x1)", buffer[0]);
        goto error;
    }
    if (frame_length != length) {
        LOGW("invalid response, frame length %d, headers length: %d",
             (int) frame_length, (int) length);
        goto error;
    }
    evbuffer_drain(input, frame_length);
    LOGD("wss is ready for peer %d, remain: %zu", get_peer_port(raw), evbuffer_get_length(input));
    tunnel_wss(raw, tev, wss_output_filter_v3);
    return;
error:
    bufferevent_free(raw);
    bufferevent_free(tev);
}

size_t build_http_request_v3(struct wss_context *wss_context, int udp, char *request) {
    uint8_t *buffer;
    size_t length;
    buffer = (uint8_t *) request;
    *buffer++ = 0x01; // headers frame
    buffer += 2;      // reserve for length
    *buffer++ = 0;
    *buffer++ = 0;
    // :method = CONNECT
    *buffer++ = 0xc0 | 15;
    // :protocol = websocket
    buffer = memcpy(buffer, "\x27\x02:protocol\x09websocket", 21) + 21;
    // :scheme = https
    *buffer++ = 0xc0 | 23;
#define min(a, b) ((a > b) ? (b) : (a))
    // :path = ..., max 127
    buffer += snprintf((char *) buffer, 0x82, "\x51%c%s",
                       (char) min(strlen(wss_context->server.path), 0x7f), wss_context->server.path);
    // :authority = ..., max 127
    buffer += snprintf((char *) buffer, 0x82, "\x50%c%s",
                       (char) min(strlen(wss_context->server.host), 0x7f), wss_context->server.host);
    // sec-websocket-version = 13
    buffer = memcpy(buffer, "\x27\x0esec-websocket-version\x02\x31\x33", 26) + 26;
    // user-agent = ..., max 127
    buffer += snprintf((char *) buffer, 0x83, "\x5f\x50%c%s",
                       (char) min(strlen(wss_context->user_agent), 0x7f),
                       wss_context->user_agent);
    if (udp) {
        buffer = memcpy(buffer, "\x27\x04x-sock-type\x03udp", 17) + 17;
    }
    length = (char *) buffer - request - 3;
    if (length < 64) {
        request[1] = (char) length;
        memmove(&request[2], &request[3], length);
        length += 2;
    } else {
        request[1] = (char) (length >> 8 | 0x40);
        request[2] = (char) (length & 0xff);
        length += 3;
    }
    return length;
}

int get_ssl_error_http3(SSL *ssl, int code) {
    return SSL_get_error(SSL_get0_connection(ssl), code);
}

size_t parse_http3_frame(const uint8_t *buffer, size_t length, size_t *out_header_length) {
    size_t i, length_type, header_length, payload_length;
    if (length < 0x2) {
        if (out_header_length) {
            *out_header_length = 2;
        }
        return 0;
    }
    buffer++;
    length_type = *buffer >> 0x6;
    header_length = 1 + (1 << length_type);
    if (out_header_length) {
        *out_header_length = header_length;
    }
    if (length < header_length) {
        return 0;
    }
    payload_length = *buffer++ & 0x3f;
    for (i = 2; i < header_length; ++i) {
        payload_length = (payload_length << 8) | *buffer++;
    }
    return header_length + payload_length;
}

size_t build_http3_frame(uint8_t *frame, uint8_t type, size_t length) {
    *frame++ = type;
    if (length > 0x3fffffff) {
        return 0;
    } else if (length > 0x3fff) {
        *frame++ = 0xc0 | (length >> 24);
        *frame++ = length >> 16;
        *frame++ = length >> 8;
        *frame = length;
        return 5;
    } else if (length > 0x3f) {
        *frame++ = 0x40 | (length >> 8);
        *frame = length;
        return 3;
    } else {
        *frame = length;
        return 2;
    }
}

void http3_eventcb(evutil_socket_t sock, short event, void *context) {
    int i, is_infinite;
    SSL *ssl;
    struct timeval tv;
    struct wss_context *wss_context;

    (void) sock;
    (void) event;
    wss_context = context;
    ssl = wss_context->ssl;
    for (i = 0; i < 0x3; i++) {
        if (!SSL_get_event_timeout(ssl, &tv, &is_infinite)) {
            LOGW("cannot SSL_get_event_timeout");
            break;
        }
        if (is_infinite) {
            LOGI("infinite, remove timer and mark ssl as error");
            event_remove_timer(wss_context->event_quic);
            wss_context->ssl_error = 1;
            break;
        }
        if (tv.tv_sec || tv.tv_usec) {
            event_add(wss_context->event_quic, &tv);
            LOGD("handled %d, would handle events %lu.%03d later", i, tv.tv_sec, (int) tv.tv_usec / 1000);
            break;
        }
        SSL_handle_events(ssl);
    }
}

struct sock_event {
    evutil_socket_t sock;
    short event;
    uint8_t evicted: 1;
};

static void read_http3_stream(struct bufferevent_http_stream *http_stream, void *arg) {
    int enabled;
    struct sock_event *sock_event;
    struct bev_context_ssl *bev_context_ssl;
    struct event* ev_read;

    if (http_stream->mark_free) {
        return;
    }
    enabled = bufferevent_get_enabled(http_stream->bev) & EV_READ;
    bev_context_ssl = bufferevent_get_context(http_stream->bev);
    if (!enabled || !bev_context_ssl || bev_context_ssl->wss_context->ssl_error) {
        return;
    }
    sock_event = arg;
    ev_read = &(http_stream->bev->ev_read);
    event_get_callback(ev_read)(sock_event->sock, sock_event->event, event_get_callback_arg(ev_read));
    if (http_stream->mark_free) {
        sock_event->evicted = 1;
    }
}

static void close_http_stream(struct bufferevent_http_stream *http_stream, void *http_streams) {
    if (http_stream->mark_free) {
        LOGD("close http stream %lu: %p", (unsigned long) http_stream->stream_id, http_stream);
        lh_bufferevent_http_stream_delete(http_streams, http_stream);
        free(http_stream);
    }
}

void http3_readcb(evutil_socket_t sock, short event, void *context) {
    unsigned long hash_factor;
    struct sock_event sock_event;
    struct wss_context *wss_context;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    wss_context = context;
    if (wss_context->mock_ssl_timeout) {
        event_del(SSL_get_app_data(wss_context->ssl));
        return;
    }
    sock_event.sock = sock;
    sock_event.evicted = 0;
    sock_event.event = (short) ((event & ~EV_TIMEOUT) | EV_READ);
    http_streams = wss_context->http_streams;
    if (!wss_context->ssl_error) {
        lh_bufferevent_http_stream_doall_arg(http_streams, read_http3_stream, &sock_event);
    }
    if (sock_event.evicted) {
        hash_factor = lh_bufferevent_http_stream_get_down_load(http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, 0);
        lh_bufferevent_http_stream_doall_arg(http_streams, close_http_stream, http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, hash_factor);
    }
    if (wss_context->ssl_error) {
        LOGW("disable http3 read as ssl error");
        event_del(SSL_get_app_data(wss_context->ssl));
    } else if (!lh_bufferevent_http_stream_num_items(http_streams)) {
        reset_streams_count(wss_context);
        event_del(SSL_get_app_data(wss_context->ssl));
    }
    if (!event_pending(wss_context->event_quic, EV_TIMEOUT, NULL)) {
        event_active(wss_context->event_quic, EV_TIMEOUT, 0);
    }
}

ssize_t check_ssl_error_http3(struct bev_context_ssl *bev_context_ssl, enum ssl_type ssl_type) {
    SSL *ssl;
    int stream_state;

    ssl = bev_context_ssl->ssl;
    switch (ssl_type) {
        case ssl_read:
            stream_state = SSL_get_stream_read_state(ssl);
            break;
        case ssl_write:
            stream_state = SSL_get_stream_write_state(ssl);
            break;
        default:
            return WSS_ERROR;
    }
    switch (stream_state) {
        case SSL_STREAM_STATE_NONE:
        case SSL_STREAM_STATE_OK:
            LOGD("stream state: %d", stream_state);
            return WSS_AGAIN;
        case SSL_STREAM_STATE_WRONG_DIR:
            LOGW("stream state wrong direction");
            return WSS_AGAIN;
        case SSL_STREAM_STATE_FINISHED:
            LOGW("stream state finished, mark as eof");
            return WSS_EOF;
        case SSL_STREAM_STATE_RESET_LOCAL:
            LOGW("stream state reset local");
            return WSS_ERROR;
        case SSL_STREAM_STATE_RESET_REMOTE:
            LOGW("stream state reset remote");
            return WSS_ERROR;
        case SSL_STREAM_STATE_CONN_CLOSED:
            LOGW("stream state connection closed, mark as error");
            bev_context_ssl->wss_context->ssl_error = 1;
            return WSS_ERROR;
        default:
            LOGW("stream state %d", stream_state);
            return WSS_ERROR;
    }
}

static int set_peer_addr(SSL *ssl, struct sockaddr *sockaddr, uint16_t port) {
    void *addr;
    size_t addrlen;
    BIO_ADDR *peer_addr = BIO_ADDR_new();
    if (!peer_addr) {
        LOGW("cannot create bio addr");
        return 1;
    }
    if (sockaddr->sa_family == AF_INET6) {
        addr = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
        addrlen = sizeof(struct in6_addr);
    } else {
        addr = &(((struct sockaddr_in *) sockaddr)->sin_addr);
        addrlen = sizeof(struct in_addr);
    }
    if (!BIO_ADDR_rawmake(peer_addr, sockaddr->sa_family, addr, addrlen, ntohs(port))) {
        LOGW("cannot make peer address");
        goto error;
    }
    if (!SSL_set1_initial_peer_addr(ssl, peer_addr)) {
        LOGW("cannot set peer address");
        goto error;
    }
    BIO_ADDR_free(peer_addr);
    return 0;
error:
    BIO_ADDR_free(peer_addr);
    return 1;
}

static int send_h3_settings(SSL *stream) {
    int ret;
    size_t written;

    if (SSL_write_ex(stream, "\x00\x04\x00", 3, &written)) {
        return 0;
    }
    ret = SSL_get_error(stream, 0);
    if (ret == SSL_ERROR_WANT_READ) {
        return 0;
    } else {
        LOGW("cannot write http3 settings frame to ssl (%d)", ret);
        return 1;
    }
}

SSL *init_http3_stream(SSL *ssl, struct sockaddr *sockaddr, uint16_t port) {
    SSL *stream = NULL;
    if (set_peer_addr(ssl, sockaddr, port)) {
        return NULL;
    }
    stream = SSL_new_stream(ssl, SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI);
    if (stream == NULL) {
        LOGW("cannot make new quic stream");
        return NULL;
    }
    if (send_h3_settings(stream)) {
        SSL_free(stream);
        return NULL;
    }
    LOGD("send h3 settings");
    return stream;
}

struct event *init_ssl_http3(struct wss_context *wss_context, struct event_base *base, int fd, SSL *ssl) {
    struct event *event;
    if (SSL_set_alpn_protos(ssl, (uint8_t *) "\x02h3", 3)) {
        LOGW("cannot set h3 alpn");
        return NULL;
    }
    if (!SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE)) {
        LOGW("cannot set quic default stream mode to none");
        return NULL;
    }
    if (!SSL_set_blocking_mode(ssl, 0)) {
        LOGD("cannot set quic blocking mode");
        return NULL;
    }
    if (wss_context->event_quic) {
        event_free(wss_context->event_quic);
    }
    wss_context->event_quic = event_new(base, fd, EV_TIMEOUT | EV_PERSIST, http3_eventcb, wss_context);
    if (!wss_context->event_quic) {
        LOGW("cannot init quic ssl events");
        return NULL;
    }
    event = event_new(base, fd, EV_READ | EV_PERSIST, http3_readcb, wss_context);
    if (!event) {
        LOGW("cannot init http3 readcb");
        return NULL;
    }
    return event;
}

int init_context_ssl_http3(struct bev_context_ssl *bev_context_ssl, SSL *ssl) {
    SSL *stream;

    stream = SSL_new_stream(ssl, SSL_STREAM_FLAG_ADVANCE);
    if (stream == NULL) {
        LOGW("cannot new quic stream");
        bev_context_ssl->wss_context->ssl_error = 1;
        return 1;
    }
    bev_context_ssl->http = http3;
    bev_context_ssl->stream = stream;
    bev_context_ssl->stream_id = SSL_get_stream_id(stream);
    bev_context_ssl->frame = evbuffer_new();
    if (!bev_context_ssl->frame) {
        LOGW("cannot new quic stream frame");
        return 1;
    }
    LOGD("stream: %p", stream);
    return 0;
}

void free_context_ssl_http3(struct bev_context_ssl *bev_context_ssl) {
    SSL *stream;

    stream = bev_context_ssl->stream;
    LOGD("conclude stream: %p", stream);
    SSL_stream_conclude(stream, 0);
    SSL_free(stream);
}

#else

SSL_CTX *ssl_ctx_new_http3() {
    return NULL;
}

void http_response_cb_v3(struct bufferevent *tev, void *raw) {
    (void) tev;
    (void) raw;
}

size_t build_http_request_v3(struct wss_context *wss_context, int udp, char *request) {
    (void) wss_context;
    (void) udp;
    (void) request;
    return 0;
}

struct event *init_ssl_http3(struct wss_context *wss_context, struct event_base *base, int fd, SSL *ssl) {
    (void) wss_context;
    (void) base;
    (void) fd;
    (void) ssl;
    return NULL;
}

SSL *init_http3_stream(SSL *ssl, struct sockaddr *sockaddr, uint16_t port) {
    (void) ssl;
    (void) sockaddr;
    (void) port;
    return NULL;
}

int init_context_ssl_http3(struct bev_context_ssl *bev_context_ssl, SSL *ssl) {
    (void) bev_context_ssl;
    (void) ssl;
    return 0;
}

void free_context_ssl_http3(struct bev_context_ssl *bev_context_ssl) {
    (void) bev_context_ssl;
}

ssize_t check_ssl_error_http3(struct bev_context_ssl *bev_context_ssl, enum ssl_type ssl_type) {
    (void) bev_context_ssl;
    (void) ssl_type;
    return 0;
}

int get_ssl_error_http3(SSL *ssl, int code) {
    (void) ssl;
    (void) code;
    return 0;
}

size_t parse_http3_frame(const uint8_t *buffer, size_t length, size_t *out_header_length) {
    (void) buffer;
    (void) length;
    (void) out_header_length;
    return 0;
}

size_t build_http3_frame(uint8_t *frame, uint8_t type, size_t length) {
    (void) frame;
    (void) type;
    (void) length;
    return 0;
}

#endif