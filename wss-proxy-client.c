#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "common.h"
#include "wss-client.h"

#define bufferevent_free safe_bufferevent_free

struct udp_context {
    LHASH_OF(bev_context_udp) *hash;
    struct event_base *base;
    struct wss_context *wss_context;
};

struct server_context {
    struct evconnlistener *listener;
    evutil_socket_t udp_sock;
    struct event *udp_event;
    struct udp_context udp_context;
};

static unsigned long bev_context_udp_hash(const bev_context_udp *a) {
    socklen_t i, max;
    unsigned long result = a->socklen;
    uint32_t *a32 = (uint32_t *) a->sockaddr;
    for (i = 0, max = (a->socklen >> 2); i < max; ++i, a32++) {
        result ^= *a32;
    }
    return result;
}

static int bev_context_udp_cmp(const bev_context_udp *a, const bev_context_udp *b) {
    int result = (int) a->socklen - (int) b->socklen;
    if (!result) {
        return result;
    }
    return memcmp(a->sockaddr, b->sockaddr, a->socklen);
}

static int init_raw_addr(struct sockaddr_storage *sockaddr, int *socklen) {
    int port;
    char *end;
    const char *local_host = getenv("SS_LOCAL_HOST");
    const char *local_port = getenv("SS_LOCAL_PORT");

    if (local_host == NULL) {
        LOGE("local host is not set");
        return EINVAL;
    }

    port = (int) strtol(local_port, &end, 10);
    if (port <= 0 || port > 65535 || *end != '\0') {
        LOGE("local port %s is unsupported", local_port);
        return EINVAL;
    }

    if (evutil_parse_sockaddr_port(local_host, (struct sockaddr *) sockaddr, socklen) != 0) {
        LOGE("local host %s is unsupported", local_host);
        return -1;
    }

    set_port(sockaddr, port);
    LOGI("raw server %s:%d", local_host, port);
    return 0;
}

static int init_wss_addr(struct wss_server_info *server) {
    int port, mux;
    char *end;
    const char *value, *wss;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");

    if (remote_host == NULL) {
        LOGE("remote host is not set");
        return EINVAL;
    }

    if (strchr(remote_host, '|') != NULL) {
        LOGE("remote host %s is unsupported", remote_host);
        return EINVAL;
    }
    server->addr = remote_host;

    port = (int) strtol(remote_port, &end, 10);
    if (port <= 0 || port > 65535 || *end != '\0') {
        LOGE("remote port %s is unsupported", remote_port);
        return EINVAL;
    }
    server->port = port;

    if (options != NULL && strchr(options, '\\') != NULL) {
        LOGE("plugin options %s (contains \\) is unsupported", options);
        return EINVAL;
    }

    // host
    server->host = find_option(options, "host", NULL);
    if (server->host == NULL) {
        server->host = remote_host;
    }
    // path
    server->path = find_option(options, "path", NULL);
    if (server->path == NULL) {
        server->path = "/";
    }
    // tls
    if ((value = find_option(options, "tls", "1")) != NULL) {
        server->tls = (int) strtol(value, NULL, 10);
    }
    // http2
    if (find_option(options, "http2", "1")) {
        server->http2 = 1;
    }
    // http3
    if (find_option(options, "http3", "1")) {
        server->http3 = 1;
#ifndef HAVE_OSSL_QUIC_CLIENT_METHOD
        LOGW("http3 is unsupported");
        return EINVAL;
#endif
    }
    // loglevel
    if ((value = find_option(options, "loglevel", NULL)) != NULL) {
        init_log_level(value);
    }

    // mux
    if ((value = find_option(options, "mux", "1")) != NULL) {
        mux = (int) strtol(value, NULL, 10);
    } else {
        mux = 1;
    }

    // wss
    if ((value = find_option(options, "ws", "1")) != NULL) {
        server->ws = (int) strtol(value, NULL, 10);
    } else {
        server->ws = 1;
    }

    // ipv6
    if ((value = find_option(options, "ipv6", "1")) != NULL) {
        server->ipv6 = (int) strtol(value, NULL, 10);
    }

    // strip
    server->host = strdup(server->host);
    if ((end = strchr(server->host, ';')) != NULL) {
        *end = '\0';
    }
    server->path = strdup(server->path);
    if ((end = strchr(server->path, ';')) != NULL) {
        *end = '\0';
    }

    if (server->http3 && server->http2) {
        server->http2 = 0;
    }

    if (server->http3 || server->http2) {
        server->tls = 1;
        server->ws = 1;
        server->mux = 1;
        LOGI("%s (tls%s ws)", server->http3 ? "http3" : "http2", server->mux ? " mux" : "");
    } else if (server->ws && mux) {
        server->mux = 0;
        LOGW("mux %d is unsupported", mux);
    }

    if (server->ws) {
        if (server->tls) {
            wss = "wss";
        } else {
            wss = "ws";
        }
    } else {
        if (server->tls) {
            wss = "sss";
        } else {
            wss = "ss";
        }
    }
    LOGI("wss client%s %s:%d (%s://%s%s)", server->ipv6 ? "6" : "", remote_host, port, wss, server->host, server->path);
    return 0;
}

static void http_response_cb(struct bufferevent *tev, void *raw) {
    size_t length;
    char buffer[WSS_PAYLOAD_SIZE];
    struct evbuffer *input;

    memset(buffer, 0, sizeof(buffer));
    input = bufferevent_get_input(tev);
    length = evbuffer_get_length(input);
    if (length == 0) {
        return;
    }
    evbuffer_copyout(input, buffer, sizeof(buffer));
    if (strstr(buffer, "\r\n\r\n") == NULL) {
        LOGW("uncompleted response: %s", buffer);
        return;
    }
    evbuffer_drain(input, length);
    // HTTP/1.1 xxx
    // 0123456789abc
    if (memcmp(&buffer[9], "101 ", 4) == 0) {
        LOGD("wss is ready for peer %d", get_peer_port(raw));
        if (strcasestr(buffer, X_UPGRADE ": " SHADOWSOCKS "\r\n")) {
            tunnel_ss(raw, tev);
        } else {
            tunnel_wss(raw, tev, NULL);
        }
    } else {
        buffer[0xc] = '\0';
        LOGE("wss fail for peer %d, status: %s", get_peer_port(raw), &buffer[9]);
        bufferevent_free(raw);
        bufferevent_free(tev);
    }
}

static size_t build_http_request(struct wss_context *wss_context, int udp, char *request) {
    char *start;
    unsigned char key[16], sec_websocket_key[25];

    start = request;
    evutil_secure_rng_get_bytes(key, 16);
    EVP_EncodeBlock(sec_websocket_key, key, 16);
    request += sprintf(request, "GET %s HTTP/1.1\r\n"
                                "Host: %s\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: %s\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "User-Agent: %s\r\n",
                       wss_context->server.path, wss_context->server.host,
                       sec_websocket_key, wss_context->user_agent);
    if (udp) {
        append_buffer(request, X_SOCK_TYPE ": " SOCK_TYPE_UDP "\r\n");
    }
    if (!wss_context->server.ws) {
        append_buffer(request, X_UPGRADE ": " SHADOWSOCKS "\r\n");
    }
    append_buffer(request, "\r\n");
    return request - start;
}

static enum bufferevent_filter_result wss_output_filter_v2(struct evbuffer *src, struct evbuffer *dst,
                                                           ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                           void *tev) {
    size_t length, frame_header_length;
    uint8_t buffer[HTTP2_HEADER_LENGTH + MAX_WS_HEADER_SIZE + WSS_PAYLOAD_SIZE];
    struct bev_context_ssl *bev_context_ssl;

    (void) dst;
    (void) dst_limit;
    (void) mode;
    bev_context_ssl = bufferevent_get_context(tev);
    if (!bev_context_ssl || bev_context_ssl->wss_context->ssl_error || !bev_context_ssl->wss_context->output) {
        return BEV_ERROR;
    }
    while (evbuffer_get_length(src)) {
        length = evbuffer_copyout(src, &buffer[HTTP2_HEADER_LENGTH], sizeof(buffer) - HTTP2_HEADER_LENGTH);
        frame_header_length = build_http2_frame(buffer, length, 0, 0, bev_context_ssl->stream_id);
        evbuffer_add(bev_context_ssl->wss_context->output, buffer, length + frame_header_length);
        evbuffer_drain(src, length);
        bev_context_ssl->send_window -= (ssize_t) length;
        bev_context_ssl->wss_context->send_window -= (ssize_t) length;
    }
    bufferevent_enable(tev, EV_WRITE);
    return BEV_OK;
}

int decode_huffman_digit(uint8_t *buffer, size_t size) {
    int n = 0, r = 0, x = 0, x5, x6;

    for (; size > 0; --size, buffer++) {
        r += 8;
        x = (x << 8) | *buffer;
        while (r >= 0x5) {
            x5 = x >> (r - 5);
            if (x5 >= 0 && x5 <= 2) {
                r -= 5;
                x &= (1 << r) - 1;
                n = n * 10 + x5;
            } else if (x5 >= 0xc && x5 <= 0xf) {
                if (r < 0x6) {
                    break;
                }
                x6 = (x >> (r - 6));
                if (x6 >= 0x19 && x6 <= 0x1f) {
                    r -= 6;
                    x &= (1 << r) - 1;
                    n = n * 10 + (x6 - (0x19 - 3));
                } else {
                    return -1;
                }
            } else if (size == 1) {
                break;
            } else {
                return -1;
            }
        }
    }
    if (x == (1 << r) - 1) {
        return n;
    }
    return -1;
}

static void http_response_cb_v2(struct bufferevent *tev, void *raw) {
    size_t length, header_length;
    int index, status, codes[] = {200, 204, 206, 304, 400, 404, 500};
    uint8_t buffer[HTTP2_HEADER_LENGTH + 6];
    struct evbuffer *input;

    input = bufferevent_get_input(tev);
    length = evbuffer_get_length(input);
    if (length < HTTP2_HEADER_LENGTH) {
        return;
    }
    memset(buffer, 0, sizeof(buffer));
    evbuffer_copyout(input, buffer, sizeof(buffer));
    header_length = (buffer[0] << 16) | (buffer[1] << 8) | buffer[2];
    if (length < HTTP2_HEADER_LENGTH + header_length) {
        return;
    }
    evbuffer_drain(input, HTTP2_HEADER_LENGTH + header_length);
    if (buffer[3] != 0x1) {
        return;
    }
    if (buffer[4] & 0x1) {
        LOGW("wss fail for peer %d, stream is end", get_peer_port(raw));
        goto error;
    }
    status = -1;
#define STATUS(x) ((x) >= 8 && (x) <= 14)
    index = buffer[HTTP2_HEADER_LENGTH];
    if (index == 0x88) {
        status = 200;
    } else if (index >> 7) {
        index &= 0x7f;
        if (STATUS(index)) {
            status = codes[index - 8];
        }
    } else if ((index >> 6) == 1) {
        index &= 0x3f;
        if (STATUS(index)) {
            if (buffer[HTTP2_HEADER_LENGTH + 1] == 0x3) {
                status = (int) evutil_strtoll((char *) &buffer[HTTP2_HEADER_LENGTH + 2], NULL, 10);
            } else if ((buffer[HTTP2_HEADER_LENGTH + 1] >> 7) && (buffer[HTTP2_HEADER_LENGTH + 1] & 0x7f) <= 3) {
                status = decode_huffman_digit(&buffer[HTTP2_HEADER_LENGTH + 2], buffer[HTTP2_HEADER_LENGTH + 1] & 0x7f);
            }
        }
    }
    if (status != 200) {
        LOGW("wss fail for peer %d, status: %d", get_peer_port(raw), status);
        goto error;
    }
    LOGD("wss is ready for peer %d, remain: %zu", get_peer_port(raw), evbuffer_get_length(input));
    tunnel_wss(raw, tev, wss_output_filter_v2);
    return;
error:
    bufferevent_free(raw);
    bufferevent_free(tev);
}

static size_t build_http_request_v2(struct wss_context *wss_context, int udp, char *request, uint32_t stream_id) {
    uint8_t *buffer, *header;
    size_t header_length;

    buffer = (uint8_t *) request;

    header = buffer;
    // reserved for headers
    buffer += HTTP2_HEADER_LENGTH;

    // :method = CONNECT
    buffer = memcpy(buffer, "\x02\x07" "CONNECT", 9) + 9;
    // :protocol = websocket
    buffer = memcpy(buffer, "\x00\x09:protocol\x09websocket", 21) + 21;
    // :scheme = https
    *buffer++ = 0x87;
    // :path = ..., max 127
    buffer += snprintf((char *) buffer, 0x82, "\x04%c%s",
                       (char) MIN(strlen(wss_context->server.path), 0x7f), wss_context->server.path);
    // :authority = ..., max 127
    buffer += snprintf((char *) buffer, 0x82, "\x01%c%s",
                       (char) MIN(strlen(wss_context->server.host), 0x7f), wss_context->server.host);
    // sec-websocket-version = 13
    buffer = memcpy(buffer, "\x00\x15sec-websocket-version\x02\x31\x33", 26) + 26;
    // user-agent = ..., max 127
    buffer += snprintf((char *) buffer, 0x83, "\x0f\x2b%c%s",
                       (char) MIN(strlen(wss_context->user_agent), 0x7f),
                       wss_context->user_agent);
    if (udp) {
        buffer = memcpy(buffer, "\x00\x0bx-sock-type\x03udp", 17) + 17;
    }
    header_length = buffer - header - HTTP2_HEADER_LENGTH;
    build_http2_frame(header, header_length, 1, 4, stream_id);
    buffer += build_http2_frame(buffer, 0x4, 0x8, 0, stream_id); // window_update
    *((uint32_t *) buffer) = htonl(MAX_WINDOW_SIZE - DEFAULT_INITIAL_WINDOW_SIZE);
    buffer += 4;
    return (char *) buffer - request;
}

static void tev_raw_event_cb(struct bufferevent *tev, short event, void *raw) {
    raw_event_cb(raw, event, tev);
}

static struct bufferevent *connect_wss(struct wss_context *wss_context, struct bufferevent *raw, int udp) {
    size_t length;
    char request[1024];
    struct bufferevent *tev;
    struct bev_context_ssl *bev_context_ssl;
    bufferevent_data_cb cb;
    struct timeval tv = {WSS_TIMEOUT, 0};

    tev = bufferevent_new(wss_context, raw);
    if (!tev) {
        return NULL;
    }
    bufferevent_setcb(raw, NULL, NULL, raw_event_cb, tev);
    if (wss_context->server.http3) {
        length = build_http_request_v3(wss_context, udp, request);
        cb = http_response_cb_v3;
    } else if (wss_context->server.http2) {
        bev_context_ssl = bufferevent_get_context(tev);
        length = build_http_request_v2(wss_context, udp, request, bev_context_ssl->stream_id);
        bev_context_ssl->recv_window = MAX_WINDOW_SIZE;
        LOGD("stream %u recv window %zu", bev_context_ssl->stream_id, bev_context_ssl->recv_window);
        cb = http_response_cb_v2;
    } else {
        length = build_http_request(wss_context, udp, request);
        cb = http_response_cb;
    }
    bufferevent_set_timeouts(tev, &tv, &tv);
    bufferevent_setcb(tev, cb, NULL, tev_raw_event_cb, raw);
    bufferevent_enable(tev, EV_READ | EV_WRITE);
    if (wss_context->server.http2) {
        evbuffer_add(wss_context->output, request, length);
    } else {
        bufferevent_write(tev, request, length);
    }
    return tev;
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *ctx) {
    struct event_base *base;
    struct bufferevent *raw = NULL;
    uint16_t port;

    (void) socklen;
    base = evconnlistener_get_base(listener);
    raw = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!raw) {
        goto error;
    }
    port = get_port(address);
    LOGD("new connection from %d", port);
    if (!connect_wss(ctx, raw, 0)) {
        goto error;
    }
    return;
error:
    if (raw) {
        bufferevent_free(raw);
    }
}

static evutil_socket_t init_udp_sock(const struct sockaddr *sockaddr, int socklen) {
    evutil_socket_t sock = socket(sockaddr->sa_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOGE("cannot create udp socket for %d", get_port(sockaddr));
        goto error;
    }
    if (evutil_make_socket_nonblocking(sock) < 0) {
        LOGE("cannot make udp socket nonblocking for %d", get_port(sockaddr));
        goto error;
    }
    if (evutil_make_socket_closeonexec(sock) < 0) {
        LOGE("cannot make udp socket closeonexec for %d", get_port(sockaddr));
        goto error;
    }
    if (evutil_make_listen_socket_reuseable(sock) < 0) {
        LOGE("cannot make udp socket reuseable for %d", get_port(sockaddr));
        goto error;
    }
    if (bind(sock, sockaddr, socklen) < 0) {
        LOGE("cannot bind udp socket for %d", get_port(sockaddr));
        goto error;
    }
    return sock;
error:
    if (sock > 0) {
        evutil_closesocket(sock);
    }
    return -1;
}

static void udp_timeout_cb(evutil_socket_t sock, short event, void *ctx) {
    (void) sock;
    if (event & EV_TIMEOUT) {
        struct bufferevent *raw = ctx;
        LOGD("udp timeout for peer %d", get_peer_port(raw));
        raw->errorcb(raw, BEV_EVENT_EOF, get_cbarg(raw));
    }
}

static struct bufferevent *init_udp_raw(struct bev_context_udp *bev_context_udp_key,
                                        struct udp_context *context, evutil_socket_t sock) {
    struct bev_context_udp *bev_context_udp;
    struct bufferevent *raw = NULL;

    bev_context_udp = lh_bev_context_udp_retrieve(context->hash, bev_context_udp_key);
    if (bev_context_udp != NULL) {
        return bev_context_udp->bev;
    }
    bev_context_udp = calloc(1, sizeof(struct bev_context_udp));
    if (!bev_context_udp) {
        LOGE("cannot calloc for peer %d", get_port(bev_context_udp_key->sockaddr));
        goto error;
    }
    raw = bufferevent_socket_new(context->base, -1, 0);
    if (!raw) {
        LOGE("cannot create bufferevent for peer %d", get_port(bev_context_udp_key->sockaddr));
        goto error;
    }
    bufferevent_disable(raw, EV_READ | EV_WRITE);
    bufferevent_setfd(raw, sock);
    event_assign(&(raw->ev_write), context->base, sock, EV_WRITE | EV_PERSIST, bev_context_udp_writecb, raw);
    event_assign(&(raw->ev_read), context->base, -1, EV_TIMEOUT | EV_PERSIST, udp_timeout_cb, raw);
    if (!connect_wss(context->wss_context, raw, 1)) {
        LOGE("cannot connect to wss for peer %d", get_port(bev_context_udp_key->sockaddr));
        goto error;
    }
    LOGD("udp init for peer %d", get_port(bev_context_udp_key->sockaddr));
    memcpy(&(bev_context_udp->sockaddr_storage), bev_context_udp_key->sockaddr, bev_context_udp_key->socklen);
    bev_context_udp->socklen = bev_context_udp_key->socklen;
    bev_context_udp->sockaddr = (struct sockaddr *) &(bev_context_udp->sockaddr_storage);
    bev_context_udp->bev = raw;
    bev_context_udp->hash = context->hash;
    bev_context_udp->bev_context = &const_bev_context_udp;
    bufferevent_set_context(raw, bev_context_udp);
    lh_bev_context_udp_insert(context->hash, bev_context_udp);
    return raw;
error:
    if (bev_context_udp) {
        free(bev_context_udp);
    }
    if (raw) {
        bufferevent_free(raw);
    }
    return NULL;
}

static void udp_read_cb_server(evutil_socket_t sock, short event, void *ctx) {
    struct udp_context *context = ctx;
    struct bufferevent *raw;
    struct bev_context_udp bev_context_udp;
    struct udp_frame udp_frame;
    struct timeval one_minute = {60, 0};
    (void) event;

    bev_context_udp.sockaddr = (struct sockaddr *) &(bev_context_udp.sockaddr_storage);
    for (;;) {
        ssize_t size;
        bev_context_udp.socklen = sizeof(bev_context_udp.sockaddr_storage);
        if ((size = udp_read(sock, &udp_frame, bev_context_udp.sockaddr, &(bev_context_udp.socklen))) < 0) {
            break;
        }
        if (size == 0) {
            LOGW("udp read empty from %d", get_port(bev_context_udp.sockaddr));
            continue;
        }
        if ((raw = init_udp_raw(&bev_context_udp, context, sock)) == NULL) {
            break;
        }
        evbuffer_add(raw->input, &udp_frame, size + UDP_FRAME_LENGTH_SIZE);
        if (raw->readcb) {
            raw->readcb(raw, raw->cbarg);
        }
        event_add(&(raw->ev_read), &one_minute);
    }
}

static void server_context_free(const struct server_context *server_context) {
    if (server_context->listener) {
        evconnlistener_free(server_context->listener);
    }
    if (server_context->udp_sock > 0) {
        evutil_closesocket(server_context->udp_sock);
    }
    if (server_context->udp_context.hash) {
        free_all_udp(server_context->udp_context.hash);
    }
    if (server_context->udp_event) {
        event_free(server_context->udp_event);
    }
}

static int init_server_context(struct server_context *server_context, struct event_base *base,
                               struct wss_context *wss_context, struct sockaddr *sockaddr, int socklen) {
    server_context->listener = evconnlistener_new_bind(base, accept_conn_cb, wss_context,
                                                       WSS_LISTEN_FLAGS, WSS_LISTEN_BACKLOG,
                                                       sockaddr, socklen);
    if (!server_context->listener) {
        LOGE("cannot listen to raw for %d", get_port(sockaddr));
        goto error;
    }

    server_context->udp_sock = init_udp_sock(sockaddr, socklen);
    if (server_context->udp_sock < 0) {
        goto error;
    }

    server_context->udp_context.hash = lh_bev_context_udp_new(bev_context_udp_hash, bev_context_udp_cmp);
    if (!server_context->udp_context.hash) {
        LOGE("cannot create lhash for %d", get_port(sockaddr));
        goto error;
    }
    server_context->udp_context.base = base;
    server_context->udp_context.wss_context = wss_context;

    server_context->udp_event = event_new(base, server_context->udp_sock, EV_READ | EV_PERSIST, udp_read_cb_server,
                                          &(server_context->udp_context));
    if (!server_context->udp_event) {
        LOGE("cannot create event for %d", get_port(sockaddr));
        goto error;
    }

    event_add(server_context->udp_event, NULL);
    return 0;
error:
    server_context_free(server_context);
    return 1;
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct event *event_parent = NULL, *event_sigquit = NULL;
    struct sockaddr_storage raw_addr, extra_raw_addr;
    struct server_context server_context, extra_server_context;
    int socklen, extra_port;
    struct wss_context wss_context;

    memset(&wss_context, 0, sizeof(wss_context));
    memset(&server_context, 0, sizeof(server_context));
    memset(&extra_server_context, 0, sizeof(server_context));

    if (init_wss_addr(&wss_context.server)) {
        return 1;
    }

    if (wss_context.server.tls) {
        if (wss_context.server.http3) {
            wss_context.ssl_ctx = ssl_ctx_new_http3();
        } else {
            wss_context.ssl_ctx = SSL_CTX_new(TLS_client_method());
        }
        if (!wss_context.ssl_ctx) {
            LOGE("cannot create ssl bev_context");
            goto error;
        }
        SSL_CTX_set_verify(wss_context.ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_set_default_verify_paths(wss_context.ssl_ctx)) {
            LOGE("cannot set default trusted certificate store");
            goto error;
        }
        if (!wss_context.server.http3
            && !SSL_CTX_set_min_proto_version(wss_context.ssl_ctx, TLS1_2_VERSION)) {
            LOGE("cannot set minimum TLS to 1.2");
            goto error;
        }
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
        SSL_CTX_set_keylog_callback(wss_context.ssl_ctx, ssl_keylog_callback);
#endif
    }

    socklen = sizeof(raw_addr);
    memset(&raw_addr, 0, socklen);
    if (init_raw_addr(&raw_addr, &socklen)) {
        goto error;
    }

    event_set_log_callback(log_callback);

    cfg = event_config_new();
    if (!cfg) {
        LOGE("cannot create event config");
        goto error;
    }
    event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
    event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);
#ifdef _WIN32
    event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
#endif
    base = event_base_new_with_config(cfg);
    if (!base) {
        LOGE("cannot create event base");
        goto error;
    }

    if (init_server_context(&server_context, base, &wss_context, (struct sockaddr *) &raw_addr, socklen)) {
        goto error;
    }

    extra_port = find_option_port("extra-listen-port", 0);
    if (extra_port > 0) {
        memcpy(&extra_raw_addr, &raw_addr, socklen);
        set_port(&extra_raw_addr, extra_port);
        if (init_server_context(&extra_server_context, base, &wss_context,
                                (struct sockaddr *) &extra_raw_addr, socklen)) {
            LOGW("cannot listen to extra port %d", extra_port);
        } else {
            LOGI("extra raw server %s:%d", getenv("SS_LOCAL_HOST"), extra_port);
        }
    }

#ifdef OPENSSL_VERSION_STRING
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s OpenSSL/%s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION_STRING));
#else
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s %s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION));
#endif

    if (init_event_signal(base, &event_parent, &event_sigquit)) {
        goto error;
    }

    wss_context.base = base;
    LOGI("%s", wss_context.user_agent);
    LOGI("started, pid: %d, ppid: %d", getpid(), getppid());

    event_base_dispatch(base);

    LOGI("graceful shutdown");

    code = 0;
error:
    server_context_free(&server_context);
    server_context_free(&extra_server_context);
    free_context_ssl(&wss_context);
    if (event_parent) {
        event_free(event_parent);
    }
    if (event_sigquit) {
        event_free(event_sigquit);
    }
    if (wss_context.event_sighup) {
        event_free(wss_context.event_sighup);
    }
    if (base) {
        event_base_free(base);
    }
    if (cfg) {
        event_config_free(cfg);
    }
    if (wss_context.ssl_ctx) {
        SSL_CTX_free(wss_context.ssl_ctx);
    }
    if (wss_context.server.host) {
        free((char *) wss_context.server.host);
    }
    if (wss_context.server.path) {
        free((char *) wss_context.server.path);
    }
    close_syslog();
    return code;
}
