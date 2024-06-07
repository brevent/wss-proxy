#include <event2/event.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <signal.h>
#include "wss-client.h"
#include "common.h"

#define bufferevent_free safe_bufferevent_free

static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg);

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg);

#define HTTP2_HEADER_LENGTH 9
#define MAX_FRAME_SIZE (MAX_WSS_PAYLOAD_SIZE + MAX_WS_HEADER_SIZE + HTTP2_HEADER_LENGTH)

static void http2_readcb(evutil_socket_t sock, short event, void *context);

static void http2_writecb(struct evbuffer *output, const struct evbuffer_cb_info *info, void *context);

static ssize_t do_http2_write(struct wss_proxy_context *context, struct evbuffer *output);

static void free_all_http_streams(struct wss_proxy_context *proxy_context);

struct bufferevent_http_stream {
    uint64_t stream_id;
    struct bufferevent *bev;
    volatile uint8_t mark_free: 1;
    uint8_t in_closed: 1;
    uint8_t out_closed: 1;
    uint8_t rst_sent: 1;
};

static unsigned long bufferevent_http_stream_hash(const bufferevent_http_stream *a) {
    return a->stream_id;
}

static int bufferevent_http_stream_cmp(const bufferevent_http_stream *a, const bufferevent_http_stream *b) {
    if (a->stream_id < b->stream_id) {
        return -1;
    } else if (a->stream_id > b->stream_id) {
        return 1;
    } else {
        return 0;
    }
}

static void bufferevent_context_ssl_free(struct bufferevent_context *context) {
    uint8_t frame[HTTP2_HEADER_LENGTH + 4];
    struct bufferevent_http_stream key, *http_stream;
    struct bufferevent_context_ssl *context_ssl = (struct bufferevent_context_ssl *) context;
    struct wss_proxy_context *proxy_context;

    proxy_context = context_ssl->proxy_context;
    if (context_ssl->http == http3) {
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
        LOGD("conclude stream: %p", context_ssl->stream);
        SSL_stream_conclude(context_ssl->stream, 0);
        SSL_free(context_ssl->stream);
#endif
    } else if (context_ssl->http == http2 && proxy_context->output && !proxy_context->ssl_error) {
        build_http2_frame(frame, 0, 0, 1, context_ssl->stream_id);
        evbuffer_add(proxy_context->output, frame, HTTP2_HEADER_LENGTH);
    } else if (context_ssl->http == http1) {
        SSL_free(context_ssl->ssl);
    }
    if (proxy_context->http_streams) {
        key.stream_id = context_ssl->stream_id;
        http_stream = lh_bufferevent_http_stream_retrieve(proxy_context->http_streams, &key);
        if (http_stream) {
            if (context_ssl->http == http2) {
                http_stream->out_closed = 1;
                LOGD("http stream %lu: %p out closed", (unsigned long) key.stream_id, http_stream);
            }
            if (context_ssl->http != http2 || http_stream->in_closed) {
                http_stream->mark_free = 1;
                LOGD("would remove http stream %lu: %p", (unsigned long) key.stream_id, http_stream);
            }
        }
    }
    if (context_ssl->frame != NULL) {
        evbuffer_free(context_ssl->frame);
    }
    free(context_ssl);
}

size_t build_http2_frame(uint8_t *buffer, size_t length, uint8_t type, uint8_t flags, uint32_t stream_id) {
    if (length > 0xffffff) {
        return 0;
    }
    *(uint32_t *) buffer = htonl(length << 8 | type);
    buffer += 4;
    *buffer++ = flags;
    *(uint32_t *) buffer = htonl(stream_id);
    return 9;
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

#define WSS_EOF (0)
#define WSS_AGAIN (-1)
#define WSS_ERROR (-2)
#define WSS_MORE (-3)

static ssize_t check_ssl_error(struct bufferevent_context_ssl *context_ssl,
                               SSL *ssl, int read, int ret) {
    const char *s;
    ssize_t what;
#if HAVE_OSSL_QUIC_CLIENT_METHOD
    if (context_ssl->http == http3) {
        ret = SSL_get_error(SSL_get0_connection(ssl), ret);
    }
#endif
    s = read ? "read" : "write";
    switch (ret) {
        case SSL_ERROR_ZERO_RETURN:
            LOGW("cannot %s ssl, zero return, mark as eof", s);
            what = WSS_EOF;
            break;
        case SSL_ERROR_SSL: {
            unsigned long error = ERR_get_error();
            int lib = ERR_GET_LIB(error);
            int reason = ERR_GET_REASON(error);
            if (lib == ERR_LIB_SSL && reason == SSL_R_PROTOCOL_IS_SHUTDOWN) {
                LOGW("cannot %s ssl, ssl shutdown", s);
            } else if (lib == ERR_LIB_SSL && reason == SSL_R_CERTIFICATE_VERIFY_FAILED) {
                LOGE("cannot %s ssl, ssl certificate verify failed", s);
            } else {
                LOGW("cannot %s ssl, ssl error, lib: %d, reason: %d", s, lib, reason);
            }
            what = WSS_ERROR;
            break;
        }
        case SSL_ERROR_SYSCALL:
            ret = errno;
            LOGW("cannot %s ssl, syscall: %s (%d)", s, strerror(ret), ret);
            what = WSS_ERROR;
            break;
        default:
            LOGW("cannot %s ssl (%d)", s, ret);
            what = WSS_ERROR;
            break;
    }
    if (context_ssl->proxy_context) {
        context_ssl->proxy_context->ssl_error = 1;
    }
    return what;
}

#if HAVE_OSSL_QUIC_CLIENT_METHOD
static void http3_eventcb(evutil_socket_t sock, short event, void *context) {
    int i, is_infinite;
    SSL *ssl;
    struct timeval tv;
    struct wss_proxy_context *proxy_context;

    (void) sock;
    (void) event;
    proxy_context = context;
    ssl = proxy_context->ssl;
    for (i = 0; i < 0x3; i++) {
        if (!SSL_get_event_timeout(ssl, &tv, &is_infinite)) {
            LOGW("cannot SSL_get_event_timeout");
            break;
        }
        if (is_infinite) {
            LOGI("infinite, remove timer and mark ssl as error");
            event_remove_timer(proxy_context->event_quic);
            proxy_context->ssl_error = 1;
            break;
        }
        if (tv.tv_sec || tv.tv_usec) {
            event_add(proxy_context->event_quic, &tv);
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
    struct bufferevent_context_ssl *context_ssl;

    if (http_stream->mark_free) {
        return;
    }
    enabled = bufferevent_get_enabled(http_stream->bev) & EV_READ;
    context_ssl = (void *) http_stream->bev->wm_write.low;
    if (!enabled || !context_ssl) {
        return;
    }
    sock_event = arg;
    bufferevent_readcb(sock_event->sock, sock_event->event, http_stream->bev);
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

static void http3_readcb(evutil_socket_t sock, short event, void *context) {
    unsigned long hash_factor;
    struct timeval tv = {0, 15000};
    struct sock_event sock_event;
    struct wss_proxy_context *proxy_context;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    sock_event.sock = sock;
    sock_event.evicted = 0;
    sock_event.event = (short) ((event & ~EV_TIMEOUT) | EV_READ);
    proxy_context = context;
    http_streams = proxy_context->http_streams;
    lh_bufferevent_http_stream_doall_arg(http_streams, read_http3_stream, &sock_event);
    if (proxy_context->ssl_error) {
        free_all_http_streams(proxy_context);
        return;
    }
    if (sock_event.evicted) {
        hash_factor = lh_bufferevent_http_stream_get_down_load(http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, 0);
        lh_bufferevent_http_stream_doall_arg(http_streams, close_http_stream, http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, hash_factor);
    }
    if (!lh_bufferevent_http_stream_num_items(http_streams)) {
        LOGD("all streams are completed");
        event_del(SSL_get_app_data(proxy_context->ssl));
    } else {
        // seems bug of openssl 3.2.X, need to try later
        event_add(SSL_get_app_data(proxy_context->ssl), &tv);
    }
    if (!event_pending(proxy_context->event_quic, EV_TIMEOUT, NULL)) {
        event_active(proxy_context->event_quic, EV_TIMEOUT, 0);
    }
}

static ssize_t check_stream_error(int stream_state) {
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
#endif

static int update_socket_flag(evutil_socket_t sock) {
    if (evutil_make_socket_nonblocking(sock) < 0) {
        LOGW("cannot make socket nonblocking");
        return 1;
    }

    if (evutil_make_socket_closeonexec(sock) < 0) {
        LOGW("cannot make socket closeonexec");
        return 1;
    }

    if (evutil_make_listen_socket_reuseable(sock) < 0) {
        LOGW("cannot make socket reuseable");
        return 1;
    }

    return 0;
}

static int get_sockaddr(struct wss_proxy_context *context, struct sockaddr *sockaddr,
                        socklen_t *socklen) {
    char port[6];
    struct evutil_addrinfo hints, *ai = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = context->server.ipv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port, sizeof(port), "%d", context->server.port);
    if (evutil_getaddrinfo(context->server.addr, port, &hints, &ai) < 0) {
        LOGW("cannot resolve %s", context->server.addr);
        return -1;
    }

    for (; ai; ai = ai->ai_next) {
        int sock, ret;
        sock = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            continue;
        }
        ret = connect(sock, ai->ai_addr, ai->ai_addrlen);
        evutil_closesocket(sock);
        if (ret < 0) {
            continue;
        }
        *socklen = ai->ai_addrlen;
        memcpy(sockaddr, ai->ai_addr, ai->ai_addrlen);
        evutil_freeaddrinfo(ai);
        return 0;
    }

    evutil_freeaddrinfo(ai);
    return -1;
}

static void sighup_cb(evutil_socket_t fd, short event, void *context) {
    struct wss_proxy_context *proxy_context;
    (void) fd;
    (void) event;

    LOGW("received hangup, will reload");
    proxy_context = context;
    proxy_context->ssl_error = 1;
    free_all_http_streams(proxy_context);
}

static SSL *init_ssl(struct wss_proxy_context *context, struct event_base *base, int fd) {
    SSL *ssl;
    struct event *event = NULL;

    ssl = SSL_new(context->ssl_ctx);
    if (!ssl) {
        LOGW("cannot create ssl");
        return NULL;
    }
    SSL_set_connect_state(ssl);
    if (SSL_set_fd(ssl, fd) <= 0) {
        LOGW("cannot set fd to ssl");
        goto error;
    }
    if (!SSL_set_tlsext_host_name(ssl, context->server.host)) {
        LOGW("cannot set sni extension for ssl");
        goto error;
    }
    if (!SSL_set1_host(ssl, context->server.host)) {
        LOGW("cannot set certificate verification hostname for ssl");
        goto error;
    }
    if (context->server.http3) {
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
        if (SSL_set_alpn_protos(ssl, (uint8_t *) "\x02h3", 3)) {
            LOGW("cannot set h3 alpn");
            goto error;
        }
        if (!SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE)) {
            LOGW("cannot set quic default stream mode to none");
            goto error;
        }
        if (!SSL_set_blocking_mode(ssl, 0)) {
            LOGD("cannot set quic blocking mode");
            goto error;
        }
        if (context->event_quic) {
            event_free(context->event_quic);
        }
        context->event_quic = event_new(base, fd, EV_TIMEOUT | EV_PERSIST, http3_eventcb, context);
        if (!context->event_quic) {
            LOGW("cannot init quic ssl events");
            goto error;
        }
        event = event_new(base, fd, EV_READ | EV_PERSIST, http3_readcb, context);
        if (!event) {
            LOGW("cannot init http3 readcb");
            goto error;
        }
#else
        LOGW("http3 is unsupported");
#endif
    } else if (context->server.http2) {
        if (SSL_set_alpn_protos(ssl, (uint8_t *) "\x08http/1.1\x02h2", 12)) {
            LOGW("cannot set h2 alpn");
            goto error;
        }
        context->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
        context->send_window = DEFAULT_INITIAL_WINDOW_SIZE;
        context->recv_window = MAX_WINDOW_SIZE;
        context->next_stream_id = 1;
        context->settings_sent = 0;
        context->input = evbuffer_new();
        context->output = evbuffer_new();
        if (!context->input || !context->output) {
            LOGW("cannot init http2 frame and output");
            goto error;
        }
        evbuffer_add_cb(context->output, http2_writecb, context);
        event = event_new(base, fd, EV_READ | EV_PERSIST, http2_readcb, context);
        if (!event) {
            LOGW("cannot init http2 readcb");
            goto error;
        }
    }
    if (event) {
        SSL_set_app_data(ssl, event);
        event_add(event, NULL);
    }
    if (context->server.http2 || context->server.http3) {
        if (!context->event_sighup) {
            context->event_sighup = evsignal_new(base, SIGHUP, sighup_cb, context);
            if (context->event_sighup) {
                event_add(context->event_sighup, NULL);
            }
        }
        context->http_streams = lh_bufferevent_http_stream_new(bufferevent_http_stream_hash,
                                                               bufferevent_http_stream_cmp);
        if (!context->http_streams) {
            LOGE("cannot create http streams");
            goto error;
        }
    }
    return ssl;
error:
    if (context->input) {
        evbuffer_free(context->input);
        context->input = NULL;
    }
    if (context->output) {
        evbuffer_free(context->output);
        context->output = NULL;
    }
    if (context->http_streams) {
        lh_bufferevent_http_stream_free(context->http_streams);
        context->http_streams = NULL;
    }
    if (context->event_quic) {
        event_free(context->event_quic);
        context->event_quic = NULL;
    }
    if (event) {
        event_free(event);
    }
    SSL_free(ssl);
    return NULL;
}

static ssize_t parse_http3(struct bufferevent *bev, uint8_t *buffer, size_t size) {
    size_t total, header_length, frame_length;
    ssize_t header_size;
    uint8_t frame_type, header[9];
    struct bufferevent_context_ssl *context_ssl;

    total = size;
    context_ssl = (void *) bev->wm_write.low;
    evbuffer_add(context_ssl->frame, buffer, size);
    for (;;) {
        header_size = evbuffer_copyout(context_ssl->frame, header, 9);
        if (header_size < 2) {
            return WSS_MORE;
        }
        frame_length = parse_http3_frame(header, header_size, &header_length);
        if (frame_length == 0) {
            return WSS_MORE;
        } else if (frame_length > MAX_FRAME_SIZE) {
            LOGW("frame length %u is unsupported", (unsigned) frame_length);
            return WSS_ERROR;
        }
        frame_type = header[0];
        if (context_ssl->upgrade && frame_type != 0) {
            LOGW("only data is supported after upgrade");
            return WSS_ERROR;
        }
        if (evbuffer_get_length(context_ssl->frame) < frame_length) {
            return WSS_MORE;
        }
        if (frame_type == 1) {
            evbuffer_remove_buffer(context_ssl->frame, bev->input, frame_length);
        } else if (frame_type == 0) {
            evbuffer_drain(context_ssl->frame, header_length);
            evbuffer_remove_buffer(context_ssl->frame, bev->input, frame_length - header_length);
        } else {
            LOGW("frame_type %d is unsupported", frame_type);
            evbuffer_drain(context_ssl->frame, frame_length);
        }
        if (evbuffer_get_length(context_ssl->frame) == 0) {
            return (ssize_t) total;
        }
    }
}

struct http2_frame {
    uint32_t length: 23;
    uint8_t type;
    uint8_t flag;
    uint32_t stream_id;
};

static void handle_http2_frame(struct bufferevent *bev, struct http2_frame *http2_frame, struct evbuffer *frame) {
    short what;
    uint32_t delta;
    uint8_t header[HTTP2_HEADER_LENGTH + 4];
    struct bufferevent_context_ssl *context_ssl;
    struct wss_proxy_context *proxy_context;

    what = 0;
    context_ssl = (void *) bev->wm_write.low;
    proxy_context = context_ssl->proxy_context;
    if (http2_frame->type == 1 && !context_ssl->upgrade) {
        evbuffer_remove_buffer(frame, bev->input, http2_frame->length + HTTP2_HEADER_LENGTH);
    } else if (http2_frame->type == 0) {
        evbuffer_drain(frame, HTTP2_HEADER_LENGTH);
        evbuffer_remove_buffer(frame, bev->input, http2_frame->length);
        if (http2_frame->flag & 1) {
            what = BEV_EVENT_EOF;
        }
        context_ssl->recv_window -= http2_frame->length;
        proxy_context->recv_window -= http2_frame->length;
        if (context_ssl->recv_window < MAX_WINDOW_SIZE / 4) {
            LOGD("stream %u recv window %lu", context_ssl->stream_id, context_ssl->recv_window);
            build_http2_frame(header, 4, 8, 0, context_ssl->stream_id);
            *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(MAX_WINDOW_SIZE - context_ssl->recv_window);
            context_ssl->recv_window = MAX_WINDOW_SIZE;
            evbuffer_add(context_ssl->proxy_context->output, header, HTTP2_HEADER_LENGTH + 4);
        }
        if (proxy_context->recv_window < MAX_WINDOW_SIZE / 4) {
            LOGD("connection recv window %lu", proxy_context->recv_window);
            build_http2_frame(header, 4, 8, 0, 0);
            *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(MAX_WINDOW_SIZE - proxy_context->recv_window);
            proxy_context->recv_window = MAX_WINDOW_SIZE;
            evbuffer_add(context_ssl->proxy_context->output, header, HTTP2_HEADER_LENGTH + 4);
        }
    } else {
        if (http2_frame->type == 3) {
            what = BEV_EVENT_EOF;
        } else if (http2_frame->type == 8 && http2_frame->length == 4) {
            evbuffer_copyout(frame, header, sizeof(header));
            delta = ntohl(*((uint32_t *) (header + HTTP2_HEADER_LENGTH)));
            context_ssl->send_window += delta;
            LOGD("stream %u send window %ld, delta: 0x%x", context_ssl->stream_id, context_ssl->send_window, delta);
        } else {
            LOGW("unsupported frame type: %d", http2_frame->type);
            what = BEV_EVENT_ERROR;
        }
        evbuffer_drain(frame, http2_frame->length + HTTP2_HEADER_LENGTH);
    }
    if (bev->readcb && evbuffer_get_length(bev->input)) {
        bev->readcb(bev, bev->cbarg);
    }
    if (what) {
        bufferevent_disable(bev, EV_READ);
        if (bev->errorcb) {
            bev->errorcb(bev, BEV_EVENT_READING | what, bev->cbarg);
        }
    }
}

static void update_http_stream_window_size(struct bufferevent_http_stream *http_stream, void *arg) {
    struct wss_proxy_context *context;
    struct bufferevent_context_ssl *context_ssl;

    context = arg;
    context_ssl = (void *) http_stream->bev->wm_write.low;
    if (context_ssl && context_ssl->stream_id == http_stream->stream_id) {
        LOGD("update stream %u, old initial_window_size: %u, new initial_window_size: %u",
             (unsigned int) http_stream->stream_id, context_ssl->initial_window_size, context->initial_window_size);
        context_ssl->send_window += context->initial_window_size - context_ssl->initial_window_size;
        context_ssl->initial_window_size = context->initial_window_size;
        LOGD("stream %u send window %ld", context_ssl->stream_id, context_ssl->send_window);
    }
}

static void update_settings(struct wss_proxy_context *context, uint8_t *header, size_t length) {
    uint8_t *frame;
    short settings_type;
    uint32_t settings_value;

    frame = header;
    while (length > 0) {
        settings_type = ntohs(*((uint16_t *) frame));
        frame += 2;
        settings_value = ntohl(*((uint32_t *) frame));
        frame += 4;
        if (settings_type == 0x3) {
            LOGD("max concurrent streams: %u", settings_value);
        } else if (settings_type == 0x4) {
            LOGD("initial window size: %u", settings_value);
            context->initial_window_size = settings_value;
            lh_bufferevent_http_stream_doall_arg(context->http_streams, update_http_stream_window_size, context);
        } else if (settings_type == 0x5) {
            LOGD("max frame size: %u", settings_value);
        } else if (settings_type == 0x8) {
            LOGD("enable connect: %u", settings_value);
        } else {
            LOGD("unsupported settings %u : %u", settings_type, settings_value);
        }
        length -= 6;
    }
}

static void update_window_update(struct wss_proxy_context *context, const uint8_t *header) {
    uint32_t delta;

    delta = ntohl(*((uint32_t *) header));
    context->send_window += delta;
    LOGD("connection send window %ld, delta: 0x%x", context->send_window, delta);
}

static int reset_http2_stream(struct wss_proxy_context *context, struct bufferevent_http_stream *http_stream, int res) {
    uint8_t header[HTTP2_HEADER_LENGTH + 4];

    if (http_stream->rst_sent) {
        return 0;
    }
    http_stream->rst_sent = 1;
    build_http2_frame(header, 4, 3, 0, http_stream->stream_id);
    *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(res);
    evbuffer_add(context->output, header, HTTP2_HEADER_LENGTH + 4);
    return 1;
}

static void check_http2_stream(struct wss_proxy_context *context, struct http2_frame *http2_frame) {
    uint8_t in_closed;
    struct bufferevent_http_stream key, *http_stream;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    http_streams = context->http_streams;
    key.stream_id = http2_frame->stream_id;
    in_closed = http2_frame->type == 3 || (http2_frame->flag & 1);
    http_stream = lh_bufferevent_http_stream_retrieve(http_streams, &key);
    if (!http_stream) {
        if (!in_closed) {
            LOGD("cannot find stream %u, type: %d, length: %u",
                 http2_frame->stream_id, http2_frame->type, http2_frame->length);
        }
        evbuffer_drain(context->input, http2_frame->length + HTTP2_HEADER_LENGTH);
        return;
    }
    if (in_closed) {
        LOGD("http stream %lu: %p in closed", (unsigned long) http2_frame->stream_id, http_stream);
        http_stream->in_closed = 1;
    }
    if (!http_stream->out_closed && http_stream->bev) {
        handle_http2_frame(http_stream->bev, http2_frame, context->input);
        return;
    }
    evbuffer_drain(context->input, http2_frame->length + HTTP2_HEADER_LENGTH);
    if (http_stream->out_closed) {
        context->http2_evicted = 1;
        if (!http_stream->in_closed) {
            LOGD("stream %u, out closed with type %d, length: %u",
                 http2_frame->stream_id, http2_frame->type, http2_frame->length);
        }
    } else if (http2_frame->type != 0 && http2_frame->type != 1 && http2_frame->type != 3) {
        LOGW("stream %u, unsupported type: %d", http2_frame->stream_id, http2_frame->type);
        reset_http2_stream(context, http_stream, 0x1);
    }
}

static void check_http2_control(struct wss_proxy_context *context, uint8_t type, uint8_t *header, uint8_t length) {
    switch (type) {
        case 4: // settings
            update_settings(context, header + HTTP2_HEADER_LENGTH, length);
            break;
        case 8: // window update
            update_window_update(context, header + HTTP2_HEADER_LENGTH);
            break;
        case 7: // goaway
            LOGI("sever send goaway, mark as eof");
            context->ssl_error = 1;
            break;
        default:
            LOGW("unknown control frame %d", type);
            break;
    }
}

static ssize_t parse_http2(struct wss_proxy_context *context, uint8_t *buffer, size_t size) {
    size_t header_size, total;
    uint8_t header[HTTP2_HEADER_LENGTH + 42], *frame;
    struct http2_frame http2_frame;

    total = size;
    evbuffer_add(context->input, buffer, size);
    for (;;) {
        header_size = evbuffer_copyout(context->input, header, sizeof(header));
        if (header_size < HTTP2_HEADER_LENGTH) {
            return WSS_MORE;
        }
        frame = (uint8_t *) &header;
        http2_frame.length = (ntohl(*((uint32_t *) frame)) >> 8);
        if (http2_frame.length > MAX_FRAME_SIZE) {
            LOGW("frame length %u is unsupported", (unsigned) http2_frame.length);
            return WSS_ERROR;
        }
        frame += 3;
        http2_frame.type = *frame++;
        http2_frame.flag = *frame++;
        http2_frame.stream_id = ntohl(*((uint32_t *) frame));
        if (evbuffer_get_length(context->input) < http2_frame.length + (size_t) HTTP2_HEADER_LENGTH) {
            return WSS_MORE;
        }
        if (http2_frame.stream_id & 1) {
            check_http2_stream(context, &http2_frame);
        } else {
            check_http2_control(context, http2_frame.type, header, MIN(42, http2_frame.length));
            evbuffer_drain(context->input, http2_frame.length + HTTP2_HEADER_LENGTH);
        }
        if (evbuffer_get_length(context->input) == 0) {
            return (ssize_t) total;
        }
    }
}

static ssize_t do_ssl_read(struct bufferevent_context_ssl *context_ssl, struct bufferevent *bev) {
    int ret;
    size_t size;
    ssize_t res;
    SSL *ssl;
    uint8_t frame[MAX_FRAME_SIZE];
    struct wss_proxy_context *proxy_context;

    proxy_context = context_ssl->proxy_context;
    if (context_ssl->http == http2 || context_ssl->http == http3) {
        if (!proxy_context || !proxy_context->ssl) {
            LOGW("http mux read without ssl");
            return WSS_ERROR;
        } else if (proxy_context->ssl_error) {
            LOGW("http mux read while ssl error");
            return WSS_ERROR;
        }
    }

    ssl = context_ssl->ssl;
    for (;;) {
        if (!SSL_read_ex(ssl, frame, sizeof(frame), &size)) {
            goto error;
        }
        context_ssl->total += size;
        if (context_ssl->http == http3 && bev) {
            res = parse_http3(bev, frame, size);
        } else if (context_ssl->http == http2) {
            res = parse_http2(context_ssl->proxy_context, frame, size);
        } else if (context_ssl->http == http1 && bev) {
            evbuffer_add(bev->input, frame, size);
            res = (ssize_t) size;
        }
        if (res != WSS_MORE) {
            return res;
        }
    }
error:
    ret = SSL_get_error(ssl, 0);
    switch (ret) {
        case SSL_ERROR_ZERO_RETURN:
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
            if (context_ssl->http == http3) {
                return WSS_EOF;
            }
#endif
            break;
        case SSL_ERROR_WANT_READ:
            return WSS_AGAIN;
        case SSL_ERROR_WANT_WRITE:
            LOGD("cannot read ssl, want write, will try later");
            return WSS_AGAIN;
        case SSL_ERROR_SSL:
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
            if (context_ssl->http == http3) {
                return check_stream_error(SSL_get_stream_read_state(ssl));
            }
            break;
#endif
        default:
            break;
    }
    return check_ssl_error(context_ssl, ssl, 1, ret);
}

static ssize_t do_ssl_write(struct bufferevent_context_ssl *context_ssl, uint8_t *buffer, size_t size) {
    SSL *ssl;
    int ret;
    size_t written;
    struct wss_proxy_context *proxy_context;

    proxy_context = context_ssl->proxy_context;
    if (context_ssl->http == http2 || context_ssl->http == http3) {
        if (!proxy_context || !proxy_context->ssl) {
            LOGW("http mux write without ssl");
            return WSS_ERROR;
        } else if (proxy_context->ssl_error) {
            LOGW("http mux write while ssl error");
            return WSS_ERROR;
        }
    }

    ssl = context_ssl->ssl;
    if (context_ssl->http == http2 &&
        !context_ssl->proxy_context->settings_sent) {
        if (SSL_write_ex(ssl,
                         "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                         "\x00\x00\x12\x04\x00"
                         "\x00\x00\x00\x00"
                         "\x00\x02\x00\x00\x00\x00"
                         "\x00\x03\x00\x00\x00\xff"
                         "\x00\x04\x00\x00\xff\xff" // DEFAULT_INITIAL_WINDOW_SIZE
                         "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x7f\xff\x00\x00",
                         64, &written)) {
            context_ssl->proxy_context->settings_sent = 1;
        } else {
            goto error;
        }
    }

    if (SSL_write_ex(ssl, buffer, size, &written)) {
        return (ssize_t) written;
    }
error:
    ret = SSL_get_error(ssl, 0);
    switch (ret) {
        case SSL_ERROR_WANT_READ:
            // stream is not read yet
            return WSS_AGAIN;
        case SSL_ERROR_WANT_WRITE:
            LOGD("cannot write ssl, want write, will try later");
            return WSS_AGAIN;
        case SSL_ERROR_SSL:
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
            if (context_ssl->http == http3) {
                return check_stream_error(SSL_get_stream_write_state(ssl));
            }
            break;
#endif
        default:
            break;
    }
    return check_ssl_error(context_ssl, ssl, 0, ret);
}

static ssize_t check_socket_error(ssize_t n, evutil_socket_t fd) {
    int err;

    (void) fd;
    if (n >= 0) {
        return n;
    }
    err = evutil_socket_geterror(fd);
    if (EVUTIL_ERR_RW_RETRIABLE(err)) {
        return WSS_AGAIN;
    } else {
        LOGW("socket error: %s (%d)", evutil_socket_error_to_string(err), err);
        return WSS_ERROR;
    }
}

static ssize_t do_read(struct bufferevent *bev, evutil_socket_t fd) {
    ssize_t res;
    uint8_t buffer[4096];
    struct bufferevent_context_ssl *context_ssl;

    context_ssl = (struct bufferevent_context_ssl *) bufferevent_get_context(bev);
    if (context_ssl) {
        return do_ssl_read(context_ssl, bev);
    } else if (fd > 0) {
        res = check_socket_error(recv(fd, buffer, sizeof(buffer), 0), fd);
        if (res > 0) {
            evbuffer_add(bev->input, buffer, res);
        }
        return res;
    } else {
        LOGW("no ssl and no fd");
        return WSS_ERROR;
    }
}

static ssize_t do_write(struct bufferevent *bev, evutil_socket_t fd, uint8_t *buffer, size_t size) {
    struct bufferevent_context_ssl *context_ssl;

    context_ssl = (struct bufferevent_context_ssl *) bufferevent_get_context(bev);
    if (context_ssl != NULL) {
        return do_ssl_write(context_ssl, buffer, size);
    } else {
        return check_socket_error(send(fd, buffer, size, 0), fd);
    }
}

static void free_http_stream(struct bufferevent_http_stream *http_stream) {
    struct bufferevent *tev;
    struct bufferevent_context_ssl *context_ssl;

    LOGD("free http stream %lu: %p, mark free: %d",
         (unsigned long) http_stream->stream_id, http_stream, http_stream->mark_free);
    if (!http_stream->mark_free) {
        tev = http_stream->bev;
        context_ssl = (void *) tev->wm_write.low;
        if (context_ssl && context_ssl->stream_id == http_stream->stream_id && tev->errorcb) {
            bufferevent_disable(tev, EV_READ | EV_WRITE);
            tev->errorcb(tev, BEV_EVENT_READING | BEV_EVENT_ERROR, tev->cbarg);
        }
    }
    free(http_stream);
}

static void free_all_http_streams(struct wss_proxy_context *proxy_context) {
    unsigned long count;

    if (proxy_context->ssl && SSL_get_app_data(proxy_context->ssl)) {
        event_del(SSL_get_app_data(proxy_context->ssl));
    }
    if (proxy_context->event_quic) {
        event_remove_timer(proxy_context->event_quic);
    }
    if (proxy_context->http_streams) {
        count = lh_bufferevent_http_stream_num_items(proxy_context->http_streams);
        if (count) {
            LOGI("would free all streams, count: %lu", count);
            lh_bufferevent_http_stream_doall(proxy_context->http_streams, free_http_stream);
        }
        lh_bufferevent_http_stream_free(proxy_context->http_streams);
        proxy_context->http_streams = NULL;
    }
}

void free_context_ssl(struct wss_proxy_context *proxy_context) {
    struct event *event;

    free_all_http_streams(proxy_context);
    if (proxy_context->input) {
        evbuffer_free(proxy_context->input);
        proxy_context->input = NULL;
    }
    if (proxy_context->output) {
        evbuffer_free(proxy_context->output);
        proxy_context->output = NULL;
    }
    if (proxy_context->event_quic) {
        event_free(proxy_context->event_quic);
        proxy_context->event_quic = NULL;
    }
    if (proxy_context->ssl) {
        event = SSL_get_app_data(proxy_context->ssl);
        if (event) {
            event_free(event);
        }
        SSL_free(proxy_context->ssl);
        proxy_context->ssl = NULL;
    }
    if (proxy_context->stream) {
        SSL_free(proxy_context->stream);
        proxy_context->stream = NULL;
    }
}

static void evict_http2_stream(struct bufferevent_http_stream *http_stream, void *arg) {
    struct wss_proxy_context *context;

    context = arg;
    if (http_stream->out_closed || http_stream->mark_free) {
        if (!http_stream->in_closed && !http_stream->rst_sent) {
            LOGD("reset http stream %lu: %p", (unsigned long) http_stream->stream_id, http_stream);
            reset_http2_stream(context, http_stream, 0x5);
        }
        LOGD("close http stream %lu: %p", (unsigned long) http_stream->stream_id, http_stream);
        lh_bufferevent_http_stream_delete(context->http_streams, http_stream);
        free(http_stream);
    }
}

static void http2_readcb(evutil_socket_t sock, short event, void *context) {
    unsigned long hash_factor;
    struct bufferevent_context_ssl context_ssl;
    struct wss_proxy_context *proxy_context;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    (void) sock;
    (void) event;
    proxy_context = context;
    context_ssl.proxy_context = proxy_context;
    context_ssl.http = http2;
    context_ssl.ssl = context_ssl.proxy_context->ssl;
    proxy_context->http2_evicted = 0;
    do_ssl_read(&context_ssl, NULL);
    if (proxy_context->ssl_error) {
        free_all_http_streams(proxy_context);
        return;
    }
    if (proxy_context->http2_evicted) {
        http_streams = proxy_context->http_streams;
        hash_factor = lh_bufferevent_http_stream_get_down_load(http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, 0);
        lh_bufferevent_http_stream_doall_arg(http_streams, evict_http2_stream, proxy_context);
        lh_bufferevent_http_stream_set_down_load(http_streams, hash_factor);
    }
    do_http2_write(proxy_context, proxy_context->output);
}

static ssize_t do_http2_write(struct wss_proxy_context *context, struct evbuffer *output) {
    ssize_t res, size;
    size_t total;
    uint8_t buffer[WSS_PAYLOAD_SIZE];
    struct bufferevent_context_ssl context_ssl;

    if (!output) {
        LOGW("no output buffer");
        return WSS_ERROR;
    }

    total = evbuffer_get_length(output);
    if (!total) {
        return 0;
    }

    context_ssl.proxy_context = context;
    if (context_ssl.proxy_context->ssl_error) {
        LOGW("http2 write ssl error, length: %lu", (unsigned long) evbuffer_get_length(output));
        evbuffer_drain(output, evbuffer_get_length(output));
        return WSS_ERROR;
    }

    context_ssl.http = http2;
    context_ssl.ssl = context_ssl.proxy_context->ssl;
    for (;;) {
        size = evbuffer_copyout(output, buffer, WSS_PAYLOAD_SIZE);
        if (size < 0) {
            return WSS_ERROR;
        } else if (size == 0) {
            return (ssize_t) total;
        }
        res = do_ssl_write(&context_ssl, buffer, size);
        if (res <= 0) {
            return res;
        }
        evbuffer_drain(output, res);
    }
}

static void http2_writecb(struct evbuffer *output, const struct evbuffer_cb_info *info, void *context) {
    if (info->n_added > 0) {
        do_http2_write(context, output);
    }
}

static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg) {
    ssize_t res;
    short what = BEV_EVENT_READING;
    struct bufferevent *bev = arg;

    if (event == EV_TIMEOUT) {
        what |= BEV_EVENT_TIMEOUT;
        goto error;
    }

loop:
    res = do_read(bev, fd);
    if (res > 0 && bev->readcb) {
        bev->readcb(bev, bev->cbarg);
    }

    if (res == WSS_AGAIN) {
        goto reschedule;
    } else if (res == WSS_ERROR) {
        what |= BEV_EVENT_ERROR;
        goto error;
    } else if (res == 0) {
        what |= BEV_EVENT_EOF;
        goto error;
    }

    if (evbuffer_get_length(bev->input) < MAX_PROXY_BUFFER) {
        goto loop;
    }

reschedule:
    goto done;

error:
    bufferevent_disable(bev, EV_READ);
    if (bev->errorcb) {
        bev->errorcb(bev, what, bev->cbarg);
    }

done:
    return;
}

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg) {
    ssize_t res, size;
    uint8_t buffer[4096];
    short what = BEV_EVENT_WRITING;
    struct bufferevent *bev = arg;
    struct bufferevent_context_ssl *context_ssl;

    if (event == EV_TIMEOUT) {
        what |= BEV_EVENT_TIMEOUT;
        goto error;
    }

    context_ssl = (struct bufferevent_context_ssl *) bufferevent_get_context(bev);
    if (context_ssl && context_ssl->http == http2) {
        res = do_http2_write(context_ssl->proxy_context, context_ssl->proxy_context->output);
        if (res < 0) {
            goto write;
        }
    }

    if (evbuffer_get_length(bev->output)) {
        size = evbuffer_copyout(bev->output, buffer, sizeof(buffer));
        if (size <= 0) {
            what |= BEV_EVENT_ERROR;
            goto error;
        }
        res = do_write(bev, fd, buffer, size);
        if (res > 0) {
            evbuffer_drain(bev->output, res);
        }
        goto write;
    }

    if (evbuffer_get_length(bev->output) == 0) {
        event_del(&bev->ev_write);
    }

    if (bev->writecb && evbuffer_get_length(bev->output) == 0) {
        bev->writecb(bev, bev->cbarg);
    }

    goto done;

write:
    if (res == WSS_AGAIN) {
        goto reschedule;
    } else if (res == WSS_ERROR) {
        what |= BEV_EVENT_ERROR;
        goto error;
    } else if (res == 0) {
        what |= BEV_EVENT_EOF;
        goto error;
    }

reschedule:
    if (evbuffer_get_length(bev->output) == 0) {
        // should we check again?
        event_del(&bev->ev_write);
    }
    goto done;

error:
    bufferevent_disable(bev, EV_WRITE);
    if (bev->errorcb) {
        bev->errorcb(bev, what, bev->cbarg);
    }

done:
    return;
}

static int init_ssl_sock(struct wss_proxy_context *context, struct event_base *base, SSL **ssl1) {
    int sock;
    SSL *ssl, *stream = NULL;
    socklen_t socklen;
    struct sockaddr_storage sockaddr;

    if (context->server.tls && context->server.mux) {
        ssl = context->ssl;
        if (ssl) {
            *ssl1 = ssl;
            return SSL_get_fd(ssl);
        }
    }

    sock = socket(context->server.ipv6 ? AF_INET6 : AF_INET,
                  context->server.http3 ? SOCK_DGRAM : SOCK_STREAM,
                  context->server.http3 ? IPPROTO_UDP : IPPROTO_TCP);
    if (sock < 0) {
        LOGW("cannot init fd");
        return -1;
    }

    if (context->server.http2 || context->server.http3) {
        LOGI("new sock");
    }

    if (get_sockaddr(context, (struct sockaddr *) &sockaddr, &socklen)) {
        goto error;
    }

    if (!context->server.http3 && connect(sock, (struct sockaddr *) &sockaddr, socklen) < 0) {
        LOGW("cannot connect: %s", strerror(errno));
        goto error;
    }

    if (update_socket_flag(sock)) {
        goto error;
    }

    if (!context->server.tls) {
        return sock;
    }

    ssl = init_ssl(context, base, sock);
    if (!ssl) {
        goto error;
    }
    if (context->server.http3) {
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
        if (set_peer_addr(ssl, (struct sockaddr *) &sockaddr, context->server.port)) {
            goto error;
        }
        stream = SSL_new_stream(ssl, SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI);
        if (stream == NULL) {
            LOGW("cannot make new quic stream");
            goto error;
        }
        if (send_h3_settings(stream)) {
            goto error;
        }
        context->stream = stream;
        LOGD("send h3 settings");
#endif
    }
    if (context->server.http2 || context->server.http3) {
        context->ssl = ssl;
    }
    context->ssl_error = 0;
    context->timeout_count = 0;
    *ssl1 = ssl;
    return sock;
error:
    if (sock > 0) {
        evutil_closesocket(sock);
    }
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (stream != NULL) {
        SSL_free(stream);
    }
    return -1;
}

static struct bufferevent_context_ssl *init_ssl_context(struct wss_proxy_context *context, SSL *ssl) {
    SSL *stream = NULL;
    struct bufferevent_context_ssl *context_ssl;
    if (!context->server.tls) {
        return NULL;
    }
    context_ssl = calloc(1, sizeof(struct bufferevent_context_ssl));
    if (!context_ssl) {
        return NULL;
    }
    if (!ssl) {
        ssl = context->ssl;
    }
    context_ssl->proxy_context = context;
    context_ssl->context.ev_writecb = bufferevent_writecb;
    context_ssl->context.free = bufferevent_context_ssl_free;
    if (context->server.http3) {
#ifdef HAVE_OSSL_QUIC_CLIENT_METHOD
        stream = SSL_new_stream(ssl, SSL_STREAM_FLAG_ADVANCE);
        if (stream == NULL) {
            LOGW("cannot new quic stream");
            context->ssl_error = 1;
            goto error;
        }
        context_ssl->http = http3;
        context_ssl->stream = stream;
        context_ssl->stream_id = SSL_get_stream_id(stream);
        context_ssl->frame = evbuffer_new();
        if (!context_ssl->frame) {
            LOGW("cannot new quic stream frame");
            goto error;
        }
        LOGD("stream: %p", stream);
#else
        LOGW("http3 is unsupported");
        goto error;
#endif
    } else if (context->server.http2) {
        context_ssl->http = http2;
        context_ssl->ssl = ssl;
        context_ssl->stream_id = context->next_stream_id;
        context_ssl->initial_window_size = context->initial_window_size;
        context_ssl->send_window = context->initial_window_size;
        context_ssl->recv_window = DEFAULT_INITIAL_WINDOW_SIZE;
        context->next_stream_id += 2;
        LOGD("stream %u send window %ld, recv window %lu",
             context_ssl->stream_id, context_ssl->send_window, context_ssl->recv_window);
        LOGD("ssl: %p", ssl);
    } else {
        context_ssl->http = http1;
        context_ssl->ssl = ssl;
    }
    return context_ssl;
error:
    if (stream != NULL) {
        SSL_free(stream);
    }
    free(context_ssl);
    return NULL;
}

struct bufferevent *bufferevent_new(struct wss_proxy_context *context, struct bufferevent *raw) {
    int sock;
    SSL *ssl = NULL;
    struct event_base *base;
    struct bufferevent *tev;
    struct bufferevent_context_ssl *context_ssl = NULL;
    struct bufferevent_http_stream *http_stream;

start:
    if (context->ssl_error) {
        free_context_ssl(context);
    }
    base = bufferevent_get_base(raw);
    tev = bufferevent_socket_new(base, -1, context->server.mux ? 0 : BEV_OPT_CLOSE_ON_FREE);
    if (tev == NULL) {
        LOGW("cannot create bufferevent socket");
        return NULL;
    }
    sock = init_ssl_sock(context, base, &ssl);
    if (sock < 0) {
        goto error;
    }
    bufferevent_disable(tev, EV_READ | EV_WRITE);
    bufferevent_setfd(tev, sock);
    event_assign(&tev->ev_read, tev->ev_base,
                 (context->server.http2 || context->server.http3) ? -1 : sock,
                 EV_READ | EV_PERSIST | EV_FINALIZE, bufferevent_readcb, tev);
    event_assign(&tev->ev_write, tev->ev_base, sock,
                 EV_WRITE | EV_PERSIST | EV_FINALIZE, bufferevent_writecb, tev);
    if (context->server.tls) {
        context_ssl = init_ssl_context(context, ssl);
        if (!context_ssl) {
            goto error;
        }
        bufferevent_set_context(tev, (struct bufferevent_context *) context_ssl);
        if (context->server.http2 || context->server.http3) {
            http_stream = calloc(1, sizeof(struct bufferevent_http_stream));
            if (!http_stream) {
                LOGW("cannot new http stream");
                goto error;
            }
            http_stream->stream_id = context_ssl->stream_id;
            http_stream->bev = tev;
            lh_bufferevent_http_stream_insert(context->http_streams, http_stream);
            if (!event_pending(SSL_get_app_data(context->ssl), EV_READ, NULL)) {
                event_add(SSL_get_app_data(context->ssl), NULL);
                LOGD("add event for read");
            }
            LOGD("http stream %lu: %p, total: %lu", (unsigned long) http_stream->stream_id, http_stream,
                 lh_bufferevent_http_stream_num_items(context->http_streams));
        }
    }
    LOGD("bufferevent_new, tev: %p, raw: %p", tev, raw);

    return tev;
error:
    bufferevent_free(tev);
    if (context_ssl) {
        free(context_ssl);
    }
    if (context->ssl_error) {
        goto start;
    }
    return NULL;
}

void bufferevent_timeout(struct bufferevent *tev, int timeout) {
    struct bufferevent_context_ssl *context_ssl;
    struct wss_proxy_context *context;
    struct bufferevent_http_stream key, *http_stream;

    context_ssl = (void *) tev->wm_write.low;
    if (!context_ssl) {
        return;
    }
    context = context_ssl->proxy_context;
    if (!context) {
        return;
    }
    if (!timeout) {
        context->timeout_count = 0;
        return;
    }
    context->timeout_count++;
    if (context->timeout_count >= 0x3) {
        LOGW("http mux connection timeout %d, mark as ssl error", context->timeout_count);
        context->ssl_error = 1;
    } else {
        LOGI("http mux connection timeout %d", context->timeout_count);
    }
    key.stream_id = context_ssl->stream_id;
    http_stream = lh_bufferevent_http_stream_retrieve(context->http_streams, &key);
    if (http_stream) {
        http_stream->mark_free = 1;
        LOGD("http stream %lu: %p timeout", (unsigned long) key.stream_id, http_stream);
    }
}
