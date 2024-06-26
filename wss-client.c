#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif
#include <signal.h>
#include <event2/event.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "wss-client.h"
#include "common.h"

#define bufferevent_free safe_bufferevent_free

static void bufferevent_readcb(evutil_socket_t fd, short event, void *arg);

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg);

static void http2_readcb(evutil_socket_t sock, short event, void *context);

static void http2_output_cb(struct evbuffer *output, const struct evbuffer_cb_info *info, void *context);

static void http2_writecb(evutil_socket_t sock, short event, void *context);

static void free_all_http_streams(struct wss_context *wss_context);

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

static void bev_context_ssl_timeout(void *context);

static void bev_context_ssl_free(void *context) {
    uint8_t frame[HTTP2_HEADER_LENGTH + 4];
    struct bufferevent_http_stream key, *http_stream;
    struct bev_context_ssl *bev_context_ssl = context;
    struct wss_context *wss_context;

    wss_context = bev_context_ssl->wss_context;
    if (bev_context_ssl->http == http3) {
        free_context_ssl_http3(bev_context_ssl);
    } else if (bev_context_ssl->http == http2 && !wss_context->ssl_error && wss_context->output) {
        build_http2_frame(frame, 0, 0, 1, bev_context_ssl->stream_id);
        evbuffer_add(wss_context->output, frame, HTTP2_HEADER_LENGTH);
    } else if (bev_context_ssl->http == http1) {
        SSL_free(bev_context_ssl->ssl);
    }
    if (wss_context->http_streams) {
        key.stream_id = bev_context_ssl->stream_id;
        http_stream = lh_bufferevent_http_stream_retrieve(wss_context->http_streams, &key);
        if (http_stream) {
            if (bev_context_ssl->http == http2) {
                http_stream->out_closed = 1;
                LOGD("http stream %u: %p out closed", key.stream_id, http_stream);
            }
            if (bev_context_ssl->http != http2 || http_stream->in_closed) {
                http_stream->mark_free = 1;
                LOGD("would remove http stream %u: %p", key.stream_id, http_stream);
            }
        }
    }
    if (bev_context_ssl->frame != NULL) {
        evbuffer_free(bev_context_ssl->frame);
    }
    free(bev_context_ssl);
}

size_t build_http2_frame(uint8_t *buffer, size_t length, uint8_t type, uint8_t flags, uint32_t stream_id) {
    if (length > 0xffffff) {
        return 0;
    }
    *(uint32_t *) buffer = htonl((uint32_t) (length << 8 | type));
    buffer += 4;
    *buffer++ = flags;
    *(uint32_t *) buffer = htonl(stream_id);
    return 9;
}

static ssize_t check_ssl_error(struct bev_context_ssl *bev_context_ssl, enum ssl_type ssl_type, int code) {
    const char *s;
    ssize_t what;

    if (bev_context_ssl->http == http3) {
        code = get_ssl_error_http3(bev_context_ssl->ssl, code);
    }
    switch (ssl_type) {
        case ssl_read:
            s = "read";
            break;
        case ssl_write:
            s = "write";
            break;
        default:
            return WSS_ERROR;
    }
    switch (code) {
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
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
            } else if (lib == ERR_LIB_SSL && reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
                LOGW("cannot %s ssl, ssl unexpected eof", s);
#endif
            } else {
                LOGW("cannot %s ssl, ssl error, lib: %d, reason: %d", s, lib, reason);
            }
            what = WSS_ERROR;
            break;
        }
        case SSL_ERROR_SYSCALL:
            code = errno;
            LOGW("cannot %s ssl, syscall: %s (%d)", s, strerror(code), code);
            what = WSS_ERROR;
            break;
        default:
            LOGW("cannot %s ssl (%d)", s, code);
            what = WSS_ERROR;
            break;
    }
    if (bev_context_ssl->wss_context && SSL_get_app_data(bev_context_ssl->ssl)) {
        bev_context_ssl->wss_context->ssl_error = 1;
    }
    return what;
}

void reset_streams_count(struct wss_context *wss_context) {
    if (wss_context->http_streams_count > 1) {
        LOGI("%u streams are completed", wss_context->http_streams_count);
    }
    wss_context->http_streams_count = 0;
}

static int update_socket_flag(evutil_socket_t sock) {
    if (evutil_make_socket_nonblocking(sock) < 0) {
        LOGW("cannot make socket nonblocking");
        return 1;
    }
    if (evutil_make_socket_closeonexec(sock) < 0) {
        LOGW("cannot make socket closeonexec");
        return 1;
    }
    return 0;
}

static int get_sockaddr(struct wss_context *wss_context, struct sockaddr *sockaddr,
                        socklen_t *socklen) {
    char port[6];
    uint8_t ipv6;
    struct evutil_addrinfo hints, *res, *ai;

    ipv6 = wss_context->server.ipv6;
    snprintf(port, sizeof(port), "%d", wss_context->server.port);
start:
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ipv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (evutil_getaddrinfo(wss_context->server.addr, port, &hints, &res) < 0) {
        if (ipv6) {
            LOGD("cannot resolve6 %s", wss_context->server.addr);
            ipv6 = 0;
            goto start;
        }
        LOGW("cannot resolve %s", wss_context->server.addr);
        return -1;
    }

    for (ai = res; ai; ai = ai->ai_next) {
        evutil_socket_t sock;
        int ret;
        sock = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0) {
            continue;
        }
        ret = connect(sock, ai->ai_addr, (socklen_t) ai->ai_addrlen);
        evutil_closesocket(sock);
        if (ret < 0) {
            continue;
        }
        *socklen = (socklen_t) ai->ai_addrlen;
        memcpy(sockaddr, ai->ai_addr, ai->ai_addrlen);
        evutil_freeaddrinfo(res);
        return 0;
    }

    if (res) {
        evutil_freeaddrinfo(res);
    }
    if (ipv6) {
        LOGD("cannot connect6 to %s", wss_context->server.addr);
        ipv6 = 0;
        goto start;
    }
    LOGW("cannot connect to %s", wss_context->server.addr);
    return -1;
}

#ifdef SIGHUP
static void sighup_cb(evutil_socket_t fd, short event, void *context) {
    struct wss_context *wss_context;
    (void) fd;
    (void) event;

    LOGW("received hangup, will mock ssl timeout");
    wss_context = context;
    wss_context->mock_ssl_timeout = 1;
}
#endif

static SSL *init_ssl(struct wss_context *wss_context, struct event_base *base, evutil_socket_t fd) {
    SSL *ssl;
    struct event *event = NULL;

    ssl = SSL_new(wss_context->ssl_ctx);
    if (!ssl) {
        LOGW("cannot create ssl");
        return NULL;
    }
    SSL_set_connect_state(ssl);
#ifdef _WIN32
    if (fd > INT_MAX) {
        LOGW("fd %zu is too large", fd);
        goto error;
    }
#endif
    if (SSL_set_fd(ssl, (int) fd) <= 0) {
        LOGW("cannot set fd to ssl");
        goto error;
    }
    if (!SSL_set_tlsext_host_name(ssl, wss_context->server.host)) {
        LOGW("cannot set sni extension for ssl");
        goto error;
    }
    if (!SSL_set1_host(ssl, wss_context->server.host)) {
        LOGW("cannot set certificate verification hostname for ssl");
        goto error;
    }
    if (wss_context->server.http3) {
        event = init_ssl_http3(wss_context, base, fd, ssl);
        if (!event) {
            goto error;
        }
    } else if (wss_context->server.http2) {
        if (SSL_set_alpn_protos(ssl, (uint8_t *) "\x08http/1.1\x02h2", 12)) {
            LOGW("cannot set h2 alpn");
            goto error;
        }
        wss_context->initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
        wss_context->send_window = DEFAULT_INITIAL_WINDOW_SIZE;
        wss_context->recv_window = MAX_WINDOW_SIZE;
        wss_context->next_stream_id = 1;
        wss_context->settings_sent = 0;
        wss_context->input = evbuffer_new();
        wss_context->output = evbuffer_new();
        if (!wss_context->input || !wss_context->output) {
            LOGW("cannot init http2 frame and output");
            goto error;
        }
        evbuffer_add_cb(wss_context->output, http2_output_cb, wss_context);
        wss_context->event_mux = event_new(base, fd, EV_TIMEOUT | EV_PERSIST, http2_writecb, wss_context);
        if (!wss_context->event_mux) {
            LOGW("cannot init http2 mux writecb");
            return NULL;
        }
        event = event_new(base, fd, EV_READ | EV_PERSIST, http2_readcb, wss_context);
        if (!event) {
            LOGW("cannot init http2 readcb");
            goto error;
        }
    }
    if (event) {
        SSL_set_app_data(ssl, event);
        event_add(event, NULL);
    }
    if (wss_context->server.http2 || wss_context->server.http3) {
#ifdef SIGHUP
        if (!wss_context->event_sighup) {
            wss_context->event_sighup = evsignal_new(base, SIGHUP, sighup_cb, wss_context);
            if (wss_context->event_sighup) {
                event_add(wss_context->event_sighup, NULL);
            }
        }
#endif
        wss_context->http_streams_count = 0;
        wss_context->http_streams = lh_bufferevent_http_stream_new(bufferevent_http_stream_hash,
                                                                   bufferevent_http_stream_cmp);
        if (!wss_context->http_streams) {
            LOGE("cannot create http streams");
            goto error;
        }
    }
    return ssl;
error:
    if (wss_context->input) {
        evbuffer_free(wss_context->input);
        wss_context->input = NULL;
    }
    if (wss_context->output) {
        evbuffer_free(wss_context->output);
        wss_context->output = NULL;
    }
    if (wss_context->http_streams) {
        lh_bufferevent_http_stream_free(wss_context->http_streams);
        wss_context->http_streams = NULL;
    }
    if (wss_context->event_mux) {
        event_free(wss_context->event_mux);
        wss_context->event_mux = NULL;
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
    uint8_t frame_type, header[HTTP3_MAX_HEADER_LENGTH];
    struct bev_context_ssl *bev_context_ssl;

    total = size;
    bev_context_ssl = bufferevent_get_context(bev);
    evbuffer_add(bev_context_ssl->frame, buffer, size);
    for (;;) {
        header_size = evbuffer_copyout(bev_context_ssl->frame, header, sizeof(header));
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
        if (bev_context_ssl->upgrade && frame_type != 0) {
            LOGW("only data is supported after upgrade");
            return WSS_ERROR;
        }
        if (evbuffer_get_length(bev_context_ssl->frame) < frame_length) {
            return WSS_MORE;
        }
        if (frame_type == 1) {
            evbuffer_remove_buffer(bev_context_ssl->frame, bev->input, frame_length);
        } else if (frame_type == 0) {
            evbuffer_drain(bev_context_ssl->frame, header_length);
            evbuffer_remove_buffer(bev_context_ssl->frame, bev->input, frame_length - header_length);
        } else {
            LOGW("frame_type %d is unsupported", frame_type);
            evbuffer_drain(bev_context_ssl->frame, frame_length);
        }
        if (evbuffer_get_length(bev_context_ssl->frame) == 0) {
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
    struct bev_context_ssl *bev_context_ssl;
    struct wss_context *wss_context;

    what = 0;
    bev_context_ssl = bufferevent_get_context(bev);
    wss_context = bev_context_ssl->wss_context;
    if (http2_frame->type == 1 && !bev_context_ssl->upgrade) {
        evbuffer_remove_buffer(frame, bev->input, http2_frame->length + HTTP2_HEADER_LENGTH);
    } else if (http2_frame->type == 0) {
        evbuffer_drain(frame, HTTP2_HEADER_LENGTH);
        evbuffer_remove_buffer(frame, bev->input, http2_frame->length);
        if (http2_frame->flag & 1) {
            what = BEV_EVENT_EOF;
        }
        bev_context_ssl->recv_window -= http2_frame->length;
        wss_context->recv_window -= http2_frame->length;
        if (bev_context_ssl->recv_window < MAX_WINDOW_SIZE / 4) {
            LOGD("stream %u recv window %zu", bev_context_ssl->stream_id, bev_context_ssl->recv_window);
            build_http2_frame(header, 4, 8, 0, bev_context_ssl->stream_id);
            delta = MAX_WINDOW_SIZE - (uint32_t) bev_context_ssl->recv_window;
            *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(delta);
            bev_context_ssl->recv_window = MAX_WINDOW_SIZE;
            evbuffer_add(bev_context_ssl->wss_context->output, header, HTTP2_HEADER_LENGTH + 4);
        }
        if (wss_context->recv_window < MAX_WINDOW_SIZE / 4) {
            LOGD("connection recv window %zu", wss_context->recv_window);
            build_http2_frame(header, 4, 8, 0, 0);
            delta = MAX_WINDOW_SIZE - (uint32_t) wss_context->recv_window;
            *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(delta);
            wss_context->recv_window = MAX_WINDOW_SIZE;
            evbuffer_add(bev_context_ssl->wss_context->output, header, HTTP2_HEADER_LENGTH + 4);
        }
    } else {
        if (http2_frame->type == 3) {
            what = BEV_EVENT_EOF;
        } else if (http2_frame->type == 8 && http2_frame->length == 4) {
            evbuffer_copyout(frame, header, sizeof(header));
            delta = ntohl(*((uint32_t *) (header + HTTP2_HEADER_LENGTH)));
            bev_context_ssl->send_window += delta;
            LOGD("stream %u send window %zd, delta: 0x%x",
                 bev_context_ssl->stream_id, bev_context_ssl->send_window, delta);
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

static void update_window_size(struct bufferevent_http_stream *http_stream) {
    struct wss_context *wss_context;
    struct bev_context_ssl *bev_context_ssl;

    wss_context = http_stream->wss_context;
    bev_context_ssl = bufferevent_get_context(http_stream->bev);
    if (bev_context_ssl && bev_context_ssl->stream_id == http_stream->stream_id) {
        bev_context_ssl->send_window += wss_context->initial_window_size - bev_context_ssl->initial_window_size;
        bev_context_ssl->initial_window_size = wss_context->initial_window_size;
        LOGD("stream %u send window %zd", bev_context_ssl->stream_id, bev_context_ssl->send_window);
    }
}

static void update_settings(struct wss_context *wss_context, uint8_t *header, size_t length) {
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
            wss_context->initial_window_size = settings_value;
            lh_bufferevent_http_stream_doall(wss_context->http_streams, update_window_size);
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

static void update_window_update(struct wss_context *wss_context, const uint8_t *header) {
    uint32_t delta;

    delta = ntohl(*((uint32_t *) header));
    wss_context->send_window += delta;
    LOGD("connection send window %zd, delta: 0x%x", wss_context->send_window, delta);
}

static int reset_http2_stream(struct wss_context *wss_context, uint32_t stream_id, int status) {
    uint8_t header[HTTP2_HEADER_LENGTH + 4];

    build_http2_frame(header, 4, 3, 0, stream_id);
    *((uint32_t *) (header + HTTP2_HEADER_LENGTH)) = htonl(status);
    evbuffer_add(wss_context->output, header, HTTP2_HEADER_LENGTH + 4);
    return 1;
}

static void check_http2_stream(struct wss_context *wss_context, struct http2_frame *http2_frame) {
    uint8_t in_closed;
    struct bufferevent_http_stream key, *http_stream;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    http_streams = wss_context->http_streams;
    key.stream_id = http2_frame->stream_id;
    in_closed = http2_frame->type == 3 || (http2_frame->flag & 1);
    http_stream = lh_bufferevent_http_stream_retrieve(http_streams, &key);
    if (!http_stream) {
        if (!in_closed) {
            LOGD("cannot find stream %u, type: %d, length: %u",
                 http2_frame->stream_id, http2_frame->type, http2_frame->length);
            reset_http2_stream(wss_context, http2_frame->stream_id, 0x5);
        }
        evbuffer_drain(wss_context->input, http2_frame->length + HTTP2_HEADER_LENGTH);
        return;
    }
    if (in_closed) {
        LOGD("http stream %u: %p in closed", http2_frame->stream_id, http_stream);
        http_stream->in_closed = 1;
    }
    if (!http_stream->out_closed && http_stream->bev) {
        handle_http2_frame(http_stream->bev, http2_frame, wss_context->input);
        return;
    }
    evbuffer_drain(wss_context->input, http2_frame->length + HTTP2_HEADER_LENGTH);
    if (http_stream->out_closed) {
        if (!http_stream->in_closed) {
            LOGD("stream %u, out closed with type %d, length: %u",
                 http2_frame->stream_id, http2_frame->type, http2_frame->length);
        } else {
            wss_context->http2_evicted = 1;
        }
    } else if (http2_frame->type != 0 && http2_frame->type != 1 && http2_frame->type != 3) {
        LOGW("stream %u, unsupported type: %d", http2_frame->stream_id, http2_frame->type);
        if (!http_stream->rst_sent) {
            http_stream->rst_sent = 1;
            reset_http2_stream(wss_context, http2_frame->stream_id, 0x1);
        }
    }
}

static void handle_ping(struct wss_context *wss_context, uint8_t *header, size_t length) {
    if (header[0x4] == 1) {
        LOGI("server send ping with ack");
    } else if (header[0x4] == 0 && length == 8) {
        LOGI("server send ping, reply with ack");
        header[0x4] = 1;
        evbuffer_add(wss_context->output, header, HTTP2_HEADER_LENGTH + length);
    }
}

static void check_http2_control(struct wss_context *wss_context, uint8_t type, uint8_t *header, uint8_t length) {
    switch (type) {
        case 4: // settings
            update_settings(wss_context, header + HTTP2_HEADER_LENGTH, length);
            break;
        case 6: // ping
            handle_ping(wss_context, header, length);
            break;
        case 7: // goaway
            LOGI("server send goaway");
            wss_context->ssl_goaway = 1;
            break;
        case 8: // window update
            update_window_update(wss_context, header + HTTP2_HEADER_LENGTH);
            break;
        default:
            LOGW("unknown control frame %d", type);
            break;
    }
}

static ssize_t parse_http2(struct wss_context *wss_context, uint8_t *buffer, size_t size) {
    size_t header_size, total;
    uint8_t header[HTTP2_HEADER_LENGTH + 42], *frame;
    struct http2_frame http2_frame;

    total = size;
    evbuffer_add(wss_context->input, buffer, size);
    for (;;) {
        header_size = evbuffer_copyout(wss_context->input, header, sizeof(header));
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
        if (evbuffer_get_length(wss_context->input) < http2_frame.length + (size_t) HTTP2_HEADER_LENGTH) {
            return WSS_MORE;
        }
        if (http2_frame.stream_id & 1) {
            check_http2_stream(wss_context, &http2_frame);
        } else {
            check_http2_control(wss_context, http2_frame.type, header, (uint8_t) MIN(42, http2_frame.length));
            evbuffer_drain(wss_context->input, http2_frame.length + HTTP2_HEADER_LENGTH);
        }
        if (evbuffer_get_length(wss_context->input) == 0) {
            return (ssize_t) total;
        }
    }
}

static ssize_t do_ssl_read(struct bev_context_ssl *bev_context_ssl, struct bufferevent *bev) {
    int code;
    size_t size, total;
    ssize_t res;
    SSL *ssl;
    uint8_t frame[MAX_FRAME_SIZE];
    struct wss_context *wss_context;

    wss_context = bev_context_ssl->wss_context;
    if (bev_context_ssl->http == http2 || bev_context_ssl->http == http3) {
        if (!wss_context || !wss_context->ssl) {
            LOGW("http mux read without ssl");
            return WSS_ERROR;
        }
    }

    total = 0;
    ssl = bev_context_ssl->ssl;
    for (;;) {
        if (!SSL_read_ex(ssl, frame, sizeof(frame), &size)) {
            goto error;
        }
        total += size;
        bev_context_ssl->total += size;
        if (bev_context_ssl->wss_context) {
            bev_context_ssl->wss_context->timeout.tv_sec = 0;
        }
        if (bev_context_ssl->http == http3) {
            if (!bev) {
                LOGW("http3 no bev");
                return WSS_ERROR;
            }
            res = parse_http3(bev, frame, size);
        } else if (bev_context_ssl->http == http2) {
            res = parse_http2(bev_context_ssl->wss_context, frame, size);
        } else if (bev_context_ssl->http == http1) {
            if (!bev) {
                LOGW("http1 no bev");
                return WSS_ERROR;
            }
            evbuffer_add(bev->input, frame, size);
            res = (ssize_t) size;
        } else {
            LOGW("unsupported http type %d", bev_context_ssl->http);
            return WSS_ERROR;
        }
        if (res > 0) {
            return (ssize_t) total;
        } else if (res != WSS_MORE) {
            return res;
        }
    }
error:
    code = SSL_get_error(ssl, 0);
    switch (code) {
        case SSL_ERROR_ZERO_RETURN:
            if (bev_context_ssl->http == http3) {
                return WSS_EOF;
            }
            break;
        case SSL_ERROR_WANT_READ:
            return WSS_AGAIN;
        case SSL_ERROR_WANT_WRITE:
            LOGD("cannot read ssl, want write, will try later");
            return WSS_AGAIN;
        case SSL_ERROR_SSL:
            if (bev_context_ssl->http == http3) {
                return check_ssl_error_http3(bev_context_ssl, ssl_read);
            }
            break;
        default:
            break;
    }
    return check_ssl_error(bev_context_ssl, ssl_read, code);
}

static ssize_t do_ssl_write(struct bev_context_ssl *bev_context_ssl, uint8_t *buffer, size_t size) {
    SSL *ssl;
    int ret;
    size_t written;
    struct wss_context *wss_context;

    wss_context = bev_context_ssl->wss_context;
    if (bev_context_ssl->http == http2 || bev_context_ssl->http == http3) {
        if (!wss_context || !wss_context->ssl) {
            LOGW("http mux write without ssl");
            return WSS_ERROR;
        }
    }

    ssl = bev_context_ssl->ssl;
    if (bev_context_ssl->http == http2 &&
        !bev_context_ssl->wss_context->settings_sent) {
        if (SSL_write_ex(ssl,
                         "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                         "\x00\x00\x12\x04\x00"
                         "\x00\x00\x00\x00"
                         "\x00\x02\x00\x00\x00\x00"
                         "\x00\x03\x00\x00\x00\xff"
                         "\x00\x04\x00\x00\xff\xff" // DEFAULT_INITIAL_WINDOW_SIZE
                         "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x7f\xff\x00\x00",
                         64, &written)) {
            bev_context_ssl->wss_context->settings_sent = 1;
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
            if (bev_context_ssl->http == http3) {
                return check_ssl_error_http3(bev_context_ssl, ssl_write);
            }
            break;
        default:
            break;
    }
    return check_ssl_error(bev_context_ssl, ssl_write, ret);
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
    uint8_t buffer[WSS_PAYLOAD_SIZE];
    struct bev_context_ssl *bev_context_ssl;

    bev_context_ssl = bufferevent_get_context(bev);
    if (bev_context_ssl) {
        return do_ssl_read(bev_context_ssl, bev);
    } else if (fd > 0) {
        res = check_socket_error(recv(fd, (char *) &buffer, sizeof(buffer), 0), fd);
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
    struct bev_context_ssl *bev_context_ssl;

    bev_context_ssl = bufferevent_get_context(bev);
    if (bev_context_ssl != NULL) {
        return do_ssl_write(bev_context_ssl, buffer, size);
    } else {
        return check_socket_error(send(fd, (const char *) buffer, (int) size, 0), fd);
    }
}

static void free_http_stream(struct bufferevent_http_stream *http_stream) {
    struct bufferevent *tev;
    struct bev_context_ssl *bev_context_ssl;

    LOGD("free http stream %u: %p, mark free: %d", http_stream->stream_id, http_stream, http_stream->mark_free);
    if (!http_stream->mark_free && !http_stream->out_closed) {
        tev = http_stream->bev;
        bev_context_ssl = bufferevent_get_context(tev);
        if (bev_context_ssl && bev_context_ssl->stream_id == http_stream->stream_id && tev->errorcb) {
            bufferevent_disable(tev, EV_READ | EV_WRITE);
            tev->errorcb(tev, BEV_EVENT_READING | BEV_EVENT_EOF, tev->cbarg);
        }
    }
    free(http_stream);
}

static void free_all_http_streams(struct wss_context *wss_context) {
    unsigned long count;

    if (wss_context->ssl && SSL_get_app_data(wss_context->ssl)) {
        event_del(SSL_get_app_data(wss_context->ssl));
    }
    if (wss_context->event_mux) {
        event_del(wss_context->event_mux);
    }
    if (wss_context->http_streams) {
        count = lh_bufferevent_http_stream_num_items(wss_context->http_streams);
        if (count) {
            LOGI("would free all streams, count: %lu", count);
            lh_bufferevent_http_stream_doall(wss_context->http_streams, free_http_stream);
        }
        lh_bufferevent_http_stream_free(wss_context->http_streams);
        wss_context->http_streams = NULL;
    }
}

void free_context_ssl(struct wss_context *wss_context) {
    struct event *event;

    free_all_http_streams(wss_context);
    if (wss_context->input) {
        evbuffer_free(wss_context->input);
        wss_context->input = NULL;
    }
    if (wss_context->output) {
        evbuffer_free(wss_context->output);
        wss_context->output = NULL;
    }
    if (wss_context->event_mux) {
        event_free(wss_context->event_mux);
        wss_context->event_mux = NULL;
    }
    if (wss_context->ssl) {
        event = SSL_get_app_data(wss_context->ssl);
        if (event) {
            event_free(event);
        }
        SSL_free(wss_context->ssl);
        wss_context->ssl = NULL;
    }
    if (wss_context->stream) {
        SSL_free(wss_context->stream);
        wss_context->stream = NULL;
    }
}

static void evict_http2_stream(struct bufferevent_http_stream *http_stream) {
    struct wss_context *wss_context;

    wss_context = http_stream->wss_context;
    if ((http_stream->out_closed && http_stream->in_closed) || http_stream->mark_free) {
        LOGD("close http stream %u: %p", http_stream->stream_id, http_stream);
        lh_bufferevent_http_stream_delete(wss_context->http_streams, http_stream);
        free(http_stream);
    }
}

static void http2_readcb(evutil_socket_t sock, short event, void *context) {
    unsigned long hash_factor;
    struct bev_context_ssl bev_context_ssl;
    struct wss_context *wss_context;
    LHASH_OF(bufferevent_http_stream) *http_streams;

    (void) sock;
    (void) event;
    wss_context = context;
    if (wss_context->mock_ssl_timeout) {
        event_del(SSL_get_app_data(wss_context->ssl));
        return;
    }
    bev_context_ssl.wss_context = wss_context;
    bev_context_ssl.http = http2;
    bev_context_ssl.ssl = bev_context_ssl.wss_context->ssl;
    bev_context_ssl.total = 0;
    wss_context->http2_evicted = 0;
    if (!wss_context->ssl_error) {
        while (do_ssl_read(&bev_context_ssl, NULL) > 0) {
            // do nothing
        }
    }
    http_streams = wss_context->http_streams;
    if (wss_context->http2_evicted) {
        hash_factor = lh_bufferevent_http_stream_get_down_load(http_streams);
        lh_bufferevent_http_stream_set_down_load(http_streams, 0);
        lh_bufferevent_http_stream_doall(http_streams, evict_http2_stream);
        lh_bufferevent_http_stream_set_down_load(http_streams, hash_factor);
    }
    if (wss_context->ssl_error) {
        LOGW("disable read as ssl error");
        event_del(SSL_get_app_data(wss_context->ssl));
    } else if (!lh_bufferevent_http_stream_num_items(http_streams)) {
        reset_streams_count(wss_context);
    }
}

static void http2_writecb(evutil_socket_t sock, short event, void *context) {
    struct timeval tv = {1, 0};
    ssize_t size, res;
    uint8_t buffer[WSS_PAYLOAD_SIZE];
    struct evbuffer *output;
    struct wss_context *wss_context;
    struct bev_context_ssl bev_context_ssl;

    (void) sock;
    (void) event;
    wss_context = context;
    output = wss_context->output;

    if (!wss_context->ssl_connected) {
        goto done;
    }

    bev_context_ssl.wss_context = wss_context;
    bev_context_ssl.http = http2;
    bev_context_ssl.ssl = bev_context_ssl.wss_context->ssl;

    if (evbuffer_get_length(output)) {
        if (wss_context->ssl_error) {
            LOGW("http2 mux write ssl error, length: %zu", evbuffer_get_length(output));
            evbuffer_drain(output, evbuffer_get_length(output));
            goto error;
        }
        size = evbuffer_copyout(output, buffer, sizeof(buffer));
        if (size < 0) {
            goto error;
        } else if (size == 0) {
            goto done;
        }

        res = do_ssl_write(&bev_context_ssl, buffer, size);
        if (res > 0) {
            evbuffer_drain(output, res);
        } else if (res == WSS_ERROR || res == WSS_EOF) {
            goto error;
        }
    }

    goto done;

error:
    evbuffer_drain(output, evbuffer_get_length(output));

done:
    if (!evbuffer_get_length(output)) {
        event_del(wss_context->event_mux);
    } else {
        event_add(wss_context->event_mux, &tv);
    }
}

static void http2_output_cb(struct evbuffer *output, const struct evbuffer_cb_info *info, void *context) {
    struct timeval tv = {1, 0};
    struct wss_context *wss_context;

    (void) output;
    if (info->n_added) {
        wss_context = context;
        event_add(wss_context->event_mux, &tv);
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

enum status {
    error,
    eagain,
    connected,
};

static enum status is_ssl_connected(struct bev_context_ssl *bev_context_ssl, evutil_socket_t fd) {
    int err;
    ev_socklen_t len;

    if (bev_context_ssl) {
        if (bev_context_ssl->http == http1 && bev_context_ssl->connected) {
            return connected;
        }
        if (bev_context_ssl->http == http2 && bev_context_ssl->wss_context->ssl_connected) {
            return connected;
        }
        if (bev_context_ssl->http == http3) {
            return connected;
        }
    }
    len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) < 0) {
        err = evutil_socket_geterror(fd);
        LOGW("cannot getsockopt: %s", evutil_socket_error_to_string(err));
        return error;
    }
    if (err) {
        if (EVUTIL_ERR_CONNECT_RETRIABLE(err)) {
            return eagain;
        } else {
            LOGW("socket error: %s", evutil_socket_error_to_string(err));
            return error;
        }
    }
    if (bev_context_ssl) {
        if (bev_context_ssl->http == http1) {
            bev_context_ssl->connected = 1;
        }
        if (bev_context_ssl->http == http2) {
            bev_context_ssl->wss_context->ssl_connected = 1;
        }
    }
    return connected;
}

static void bufferevent_writecb(evutil_socket_t fd, short event, void *arg) {
    ssize_t res, size;
    uint8_t buffer[WSS_PAYLOAD_SIZE];
    short what = BEV_EVENT_WRITING;
    struct bufferevent *bev = arg;
    struct bev_context_ssl *bev_context_ssl;
    struct wss_context *wss_context;
    struct evbuffer *output;

    if (event == EV_TIMEOUT) {
        what |= BEV_EVENT_TIMEOUT;
        goto error;
    }

    bev_context_ssl = bufferevent_get_context(bev);
    switch (is_ssl_connected(bev_context_ssl, fd)) {
        case error:
            goto error;
        case eagain:
            goto done;
        case connected:
        default:
            break;
    }

    if (bev_context_ssl && bev_context_ssl->http == http2) {
        wss_context = bev_context_ssl->wss_context;
        if (bev_context_ssl->ssl != wss_context->ssl) {
            LOGW("http stream ssl is not same as context ssl, tev: %p", bev);
            what |= BEV_EVENT_ERROR;
            goto error;
        }
        if (evbuffer_get_length(bev->output)) {
            LOGW("write to http stream instead of context, tev: %p", bev);
            evbuffer_add_buffer(wss_context->output, bev->output);
        }
        output = wss_context->output;
    } else {
        output = bev->output;
    }

    if (evbuffer_get_length(output)) {
        if (bev_context_ssl && bev_context_ssl->wss_context->ssl_error) {
            LOGW("http mux write ssl error, length: %zu, tev: %p", evbuffer_get_length(output), bev);
            evbuffer_drain(output, evbuffer_get_length(output));
            what |= BEV_EVENT_ERROR;
            goto error;
        }
        size = evbuffer_copyout(output, buffer, sizeof(buffer));
        if (size <= 0) {
            LOGE("bufferevent_writecb cannot copy buffer");
            what |= BEV_EVENT_ERROR;
            goto error;
        }
        res = do_write(bev, fd, buffer, size);
        if (res <= 0) {
            goto check;
        }
        evbuffer_drain(output, res);
    }

    if (evbuffer_get_length(output) == 0) {
        event_del(&bev->ev_write);
    }

    if (bev->writecb) {
        bev->writecb(bev, bev->cbarg);
    }

    goto done;

check:
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
    if (evbuffer_get_length(output) == 0) {
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

static evutil_socket_t init_ssl_sock(struct wss_context *wss_context, struct event_base *base, SSL **ssl1) {
    evutil_socket_t sock = -1;
    int socket_error;
    SSL *ssl = NULL;
    socklen_t socklen;
    struct sockaddr_storage sockaddr;

    if (wss_context->server.tls && wss_context->server.mux) {
        ssl = wss_context->ssl;
        if (ssl) {
            *ssl1 = ssl;
            return SSL_get_fd(ssl);
        }
    }

    if (get_sockaddr(wss_context, (struct sockaddr *) &sockaddr, &socklen)) {
        goto error;
    }

    sock = socket(sockaddr.ss_family,
                  wss_context->server.http3 ? SOCK_DGRAM : SOCK_STREAM,
                  wss_context->server.http3 ? IPPROTO_UDP : IPPROTO_TCP);
    if (sock < 0) {
        LOGW("cannot init fd");
        return -1;
    }

    if (update_socket_flag(sock)) {
        goto error;
    }

    if (wss_context->server.http2 || wss_context->server.http3) {
        LOGI("new sock");
    }

    if (!wss_context->server.http3 && connect(sock, (struct sockaddr *) &sockaddr, socklen) < 0) {
        socket_error = evutil_socket_geterror(sock);
        if (!EVUTIL_ERR_CONNECT_RETRIABLE(socket_error)) {
            LOGW("cannot connect: %s", evutil_socket_error_to_string(socket_error));
            goto error;
        }
    }

    if (!wss_context->server.tls) {
        return sock;
    }

    ssl = init_ssl(wss_context, base, sock);
    if (!ssl) {
        goto error;
    }
    if (wss_context->server.http3) {
        wss_context->stream = init_http3_stream(ssl, (struct sockaddr *) &sockaddr, wss_context->server.port);
        if (!wss_context->stream) {
            goto error;
        }
    }
    if (wss_context->server.http2 || wss_context->server.http3) {
        wss_context->ssl = ssl;
    }
    *ssl1 = ssl;
    return sock;
error:
    if (sock > 0) {
        evutil_closesocket(sock);
    }
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    return -1;
}

static const struct bev_context const_bev_context_ssl = {
        "ssl",
        bev_context_ssl_free,
        bev_context_ssl_timeout,
};

static struct bev_context_ssl *init_bev_context_ssl(struct wss_context *wss_context, SSL *ssl) {
    struct bev_context_ssl *bev_context_ssl;
    if (!wss_context->server.tls) {
        return NULL;
    }
    bev_context_ssl = calloc(1, sizeof(struct bev_context_ssl));
    if (!bev_context_ssl) {
        return NULL;
    }
    if (!ssl) {
        ssl = wss_context->ssl;
    }
    bev_context_ssl->wss_context = wss_context;
    if (wss_context->server.http3) {
        if (init_context_ssl_http3(bev_context_ssl, ssl)) {
            goto error;
        }
    } else if (wss_context->server.http2) {
        bev_context_ssl->http = http2;
        bev_context_ssl->ssl = ssl;
        bev_context_ssl->stream_id = wss_context->next_stream_id;
        bev_context_ssl->initial_window_size = wss_context->initial_window_size;
        bev_context_ssl->send_window = wss_context->initial_window_size;
        bev_context_ssl->recv_window = DEFAULT_INITIAL_WINDOW_SIZE;
        wss_context->next_stream_id += 2;
        if (wss_context->next_stream_id > 0x7fffffff) {
            LOGW("stream id too large, mark as error");
            wss_context->ssl_error = 1;
            goto error;
        }
        LOGD("stream %u send window %zd, recv window %zu",
             bev_context_ssl->stream_id, bev_context_ssl->send_window, bev_context_ssl->recv_window);
        LOGD("ssl: %p", ssl);
    } else {
        bev_context_ssl->http = http1;
        bev_context_ssl->ssl = ssl;
    }
    return bev_context_ssl;
error:
    free(bev_context_ssl);
    return NULL;
}

struct bufferevent *bufferevent_wss_new(struct wss_context *wss_context, struct bufferevent *raw) {
    evutil_socket_t sock;
    SSL *ssl = NULL;
    struct event_base *base;
    struct bufferevent *tev;
    struct bev_context_ssl *bev_context_ssl = NULL;
    struct bufferevent_http_stream *http_stream;

start:
    if (wss_context->ssl_error || wss_context->ssl_goaway) {
        free_context_ssl(wss_context);
        wss_context->ssl_error = 0;
        wss_context->ssl_goaway = 0;
        wss_context->ssl_connected = 0;
        wss_context->mock_ssl_timeout = 0;
        wss_context->timeout.tv_sec = 0;
    }
    base = bufferevent_get_base(raw);
    tev = bufferevent_socket_new(base, -1, wss_context->server.mux ? 0 : BEV_OPT_CLOSE_ON_FREE);
    if (tev == NULL) {
        LOGW("cannot create bufferevent socket");
        return NULL;
    }
    evbuffer_unfreeze(tev->input, 0);
    evbuffer_unfreeze(tev->output, 1);
    sock = init_ssl_sock(wss_context, base, &ssl);
    if (sock < 0) {
        goto error;
    }
    bufferevent_disable(tev, EV_READ | EV_WRITE);
    bufferevent_setfd(tev, sock);
#ifndef EV_FINALIZE
#define EV_FINALIZE 0x40
#endif
    event_assign(&tev->ev_read, tev->ev_base,
                 (wss_context->server.http2 || wss_context->server.http3) ? -1 : sock,
                 EV_READ | EV_PERSIST | EV_FINALIZE, bufferevent_readcb, tev);
    event_assign(&tev->ev_write, tev->ev_base, sock,
                 EV_WRITE | EV_PERSIST | EV_FINALIZE, bufferevent_writecb, tev);
    if (wss_context->server.tls) {
        bev_context_ssl = init_bev_context_ssl(wss_context, ssl);
        if (!bev_context_ssl) {
            goto error;
        }
        bev_context_ssl->bev_context = &const_bev_context_ssl;
        bufferevent_set_context(tev, bev_context_ssl);
        if (wss_context->server.http2 || wss_context->server.http3) {
            http_stream = calloc(1, sizeof(struct bufferevent_http_stream));
            if (!http_stream) {
                LOGW("cannot new http stream");
                goto error;
            }
            http_stream->stream_id = bev_context_ssl->stream_id;
            http_stream->bev = tev;
            http_stream->wss_context = wss_context;
            lh_bufferevent_http_stream_insert(wss_context->http_streams, http_stream);
            wss_context->http_streams_count++;
            if (!event_pending(SSL_get_app_data(wss_context->ssl), EV_READ, NULL)) {
                event_add(SSL_get_app_data(wss_context->ssl), NULL);
                LOGD("add event for read");
            }
            LOGD("http stream %u: %p, total: %lu", http_stream->stream_id, http_stream,
                 lh_bufferevent_http_stream_num_items(wss_context->http_streams));
        }
    }
    LOGD("bufferevent_wss_new, tev: %p, raw: %p", tev, raw);

    return tev;
error:
    bufferevent_free(tev);
    if (bev_context_ssl) {
        free(bev_context_ssl);
    }
    if (wss_context->ssl_error) {
        goto start;
    }
    return NULL;
}

static void bev_context_ssl_timeout(void *context) {
    uint8_t frame[HTTP2_HEADER_LENGTH + 8];
    struct timeval timeout;
    struct wss_context *wss_context;
    struct bufferevent_http_stream key, *http_stream;
    struct bev_context_ssl *bev_context_ssl;

    bev_context_ssl = context;
    if (!bev_context_ssl) {
        return;
    }
    wss_context = bev_context_ssl->wss_context;
    if (!wss_context || !wss_context->http_streams) {
        return;
    }
    key.stream_id = bev_context_ssl->stream_id;
    http_stream = lh_bufferevent_http_stream_retrieve(wss_context->http_streams, &key);
    if (http_stream) {
        http_stream->mark_free = 1;
        LOGD("http stream %u: %p timeout", key.stream_id, http_stream);
    }
    event_base_gettimeofday_cached(wss_context->base, &timeout);
    if (!wss_context->timeout.tv_sec) {
        LOGD("http mux connection timeout");
        wss_context->timeout.tv_sec = timeout.tv_sec;
    } else if (!wss_context->ssl_goaway && timeout.tv_sec - wss_context->timeout.tv_sec >= WSS_TIMEOUT) {
        LOGW("http mux connection timeout, mark ssl as goaway");
        wss_context->ssl_goaway = 1;
    }
    if (bev_context_ssl->http == http2 && !wss_context->ssl_error && wss_context->output) {
        build_http2_frame(frame, 8, 6, 0, 0);
        RAND_bytes(frame + HTTP2_HEADER_LENGTH, 8);
        evbuffer_add(wss_context->output, frame, sizeof(frame));
        LOGD("send http2 ping");
    }
}
