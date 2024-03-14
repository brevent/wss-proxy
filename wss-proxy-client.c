#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include "common.h"

struct wss_server_info {
    uint8_t tls;
    uint16_t port;
    const char *addr;
    const char *host;
    const char *path;
};

struct wss_proxy_context {
    SSL_CTX *ssl_ctx;
    struct wss_server_info server;
    char user_agent[80];
};

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

    if (sockaddr->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(port);
    } else {
        ((struct sockaddr_in *) sockaddr)->sin_port = htons(port);
    }

    LOGI("raw server %s:%d", local_host, port);
    return 0;
}

static int init_wss_addr(struct wss_server_info *server) {
    int port;
    char *end;
    int mux = 1;
    const char *loglevel;
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

    if (options == NULL) {
        options = "";
    }
    if (strchr(options, '\\') != NULL) {
        LOGE("plugin options %s (contains \\) is unsupported", options);
        return EINVAL;
    }

    // host
    server->host = strstr(options, "host=");
    if (server->host == NULL) {
        server->host = remote_host;
    } else {
        server->host += 5;
    }
    // path
    server->path = strstr(options, "path=");
    if (server->path == NULL) {
        server->path = "/";
    } else {
        server->path += 5;
    }
    // tls
    if ((end = strstr(options, "tls")) != NULL) {
        end += 3;
        if (*end == '\0' || *end == ';') {
            server->tls = 1;
        }
    }
    // loglevel
    if ((loglevel = strstr(options, "loglevel=")) != NULL) {
        loglevel += 9;
        init_log_level(loglevel);
    }

    // mux
    if ((end = strstr(options, "mux=")) != NULL) {
        end += 4;
        mux = (int) strtol(end, NULL, 10);
    }

    // strip
    if ((end = strstr(server->host, ";")) != NULL) {
        *end = '\0';
    }
    if ((end = strstr(server->path, ";")) != NULL) {
        *end = '\0';
    }

    LOGI("wss client %s:%d (%s://%s%s)", remote_host, port, server->tls ? "wss" : "ws", server->host, server->path);
    if (mux) {
        LOGW("mux %d is unsupported", mux);
    }
    return 0;
}

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *ctx) {
    struct wss_frame_server server;
    uint8_t op;
    uint16_t len;
    (void) dst_limit;
    (void) mode;
    (void) ctx;
    if (evbuffer_get_length(src) < sizeof(FOP_MASK)) {
        return BEV_NEED_MORE;
    }
    evbuffer_copyout(src, &(server.fop), sizeof(FOP_MASK));
    if (!(server.fop & 0x80)) {
        LOGW("fin should be 1 (fragments is unsupported)");
        return BEV_ERROR;
    }
    if (server.fop & 0x70) {
        LOGW("rsv should be 0");
        return BEV_ERROR;
    }
    if (server.mlen & 0x80) {
        LOGW("server reply shouldn't mask");
        return BEV_ERROR;
    }
    op = server.fop & 0xf;
    switch (op) {
        case OP_CONTINUATION:
            LOGW("continuation frame is unsupported");
            return BEV_ERROR;
        case OP_TEXT:
            LOGW("text frame is unsupported");
            return BEV_ERROR;
        case OP_BINARY:
            break;
        case OP_CLOSE:
            LOGW("server send close frame");
            return BEV_ERROR;
        case OP_PING:
            LOGD("server send ping frame");
            break;
        case OP_PONG:
            LOGD("server send pong frame");
            break;
        default:
            LOGW("server send unsupported opcode: 0x%x", op);
            return BEV_ERROR;
    }
    len = server.mlen & 0x7f;
    if (len < 126) {
        if (evbuffer_get_length(src) < (size_t) len + sizeof(FOP_MASK)) {
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, sizeof(FOP_MASK));
    } else if (len == 126) {
        if (evbuffer_get_length(src) < sizeof(server.extend)) {
            return BEV_NEED_MORE;
        }
        evbuffer_copyout(src, &(server.extend.fop), sizeof(server.extend));
        len = htons(server.extend.elen);
        if (len > MAX_PAYLOAD_SIZE) {
            LOGW("payload length %d is unsupported", len);
            return BEV_ERROR;
        }
        if (evbuffer_get_length(src) < (size_t) len + sizeof(server)) {
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, sizeof(server));
    } else {
        LOGW("payload length 64K+ is unsupported");
        return BEV_ERROR;
    }
    if (op == OP_PING || op == OP_PONG) {
        // should we pong to ping?
        evbuffer_drain(src, len);
        return BEV_OK;
    }
    while (len > 0) {
        uint16_t size = len > WSS_PAYLOAD_SIZE ? WSS_PAYLOAD_SIZE : len;
        evbuffer_remove_buffer(src, dst, size);
        len -= size;
    }
    return BEV_OK;
}

static uint8_t *build_wss_frame(struct wss_frame_client *client, enum wss_op op, uint16_t len, uint8_t *header_len) {
    // should we support continuation frame?
    uint8_t fop = 0x80 | (op & 0xf);
    client->mask = 0;
    if (len < 126) {
        client->fop = fop;
        client->mlen = 0x80 | (uint8_t) len;
        *header_len = sizeof(FOP_MASK) + sizeof(client->mask);
        return &(client->fop);
    } else {
        client->extend.fop = fop;
        client->extend.mlen = 0x80 | 126;
        client->extend.elen = ntohs(len);
        *header_len = sizeof(client->extend) + sizeof(client->mask);
        return &(client->extend.fop);
    }
}

static void close_wss_data_cb(struct bufferevent *tev, void *wss) {
    (void) tev;
    LOGD("close wss %p", wss);
    evhttp_connection_free(wss);
}

static void close_wss_event_cb(struct bufferevent *tev, short event, void *wss) {
    (void) tev;
    (void) event;
    LOGD("close wss %p, event: 0x%02x", wss, event);
    evhttp_connection_free(wss);
}

static void close_wss(struct evhttp_connection *wss, uint16_t port, uint16_t reason) {
    struct bufferevent *tev;
    struct wss_frame_client_close {
        struct wss_frame_client client;
        struct {
            uint16_t reason;
            uint16_t unused; // padding to uint32_t for mask
        };
    } wss_frame_client_close;
    uint8_t *wss_header, wss_header_size;
    uint16_t size = sizeof(wss_frame_client_close.reason);
    wss_frame_client_close.reason = ntohs(reason);
    wss_header = build_wss_frame(&(wss_frame_client_close.client), OP_CLOSE, size, &wss_header_size);
    tev = evhttp_connection_get_bufferevent(wss);
    evbuffer_add(bufferevent_get_output(tev), wss_header, size + wss_header_size);
    LOGD("would close wss %p for peer %d", wss, port);
    bufferevent_setcb(tev, NULL, close_wss_data_cb, close_wss_event_cb, wss);
}

static void raw_forward_cb(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;
    struct bufferevent *tev;
    struct wss_frame_client_data {
        struct wss_frame_client client;
        char buffer[WSS_PAYLOAD_SIZE];
    } wss_frame_client_data;

    tev = evhttp_connection_get_bufferevent(wss);
    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    for (;;) {
        // should we use continuation fame?
        uint8_t *wss_header, wss_header_size;
        int size = evbuffer_remove(src, wss_frame_client_data.buffer, WSS_PAYLOAD_SIZE);
        if (size <= 0) {
            break;
        }
        wss_header = build_wss_frame(&(wss_frame_client_data.client), OP_BINARY, (uint16_t) size, &wss_header_size);
        evbuffer_add(dst, wss_header, size + wss_header_size);
        if (size < WSS_PAYLOAD_SIZE) {
            break;
        }
    }
}

static void raw_event_cb(struct bufferevent *raw, short event, void *wss) {
    uint16_t port;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        port = get_peer_port(raw);
        bufferevent_free(raw);
        LOGD("connection %u closed, event: 0x%02x", get_peer_port(raw), event);
        close_wss(wss, port, 1001);
    }
}

static void wss_forward_cb(struct bufferevent *wev, void *raw) {
    struct evbuffer *src;
    struct evbuffer *dst;

    src = bufferevent_get_input(wev);
    dst = bufferevent_get_output(raw);
    evbuffer_add_buffer(dst, src);
}

static void wss_event_cb(struct bufferevent *wev, short event, void *raw) {
    uint16_t port;
    struct evhttp_connection *wss;
    (void) wev;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        port = get_peer_port(raw);
        bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
        bufferevent_free(raw);
        LOGD("connection %u closing from wss, event: 0x%02x", port, event);
        close_wss(wss, port, 1000);
    }
}

static void wss_close_cb(struct evhttp_connection *wss, void *wev) {
    (void) wss;
    LOGD("wss %p closed", wss);
    bufferevent_free(wev);
}

static void wss_ready_cb(struct bufferevent *raw, struct evhttp_connection *wss) {
    struct bufferevent *tev;
    struct bufferevent *wev;

    tev = evhttp_connection_get_bufferevent(wss);
    wev = bufferevent_filter_new(tev, wss_input_filter, NULL, 0, NULL, NULL);
    evhttp_connection_set_closecb(wss, wss_close_cb, wev);

    bufferevent_enable(wev, EV_READ | EV_WRITE);
    bufferevent_setcb(wev, wss_forward_cb, NULL, wss_event_cb, raw);

    bufferevent_enable(raw, EV_READ | EV_WRITE);
    bufferevent_setcb(raw, raw_forward_cb, NULL, raw_event_cb, wss);
}

static void http_request_cb(struct evhttp_request *req, void *raw) {
    struct evhttp_connection *wss;
    int status = req == NULL ? -1 : evhttp_request_get_response_code(req);
    bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
    if (status == 101) {
        wss_ready_cb(raw, wss);
    } else {
        LOGE("wss fail for peer %d, status: %d", get_peer_port(raw), status);
        bufferevent_free(raw);
        evhttp_connection_free(wss);
    }
}

static struct evhttp_connection *connect_wss(struct wss_proxy_context *context, struct event_base *base,
                                             struct bufferevent *raw, uint16_t port) {
    SSL *ssl = NULL;
    struct bufferevent *tev = NULL;
    struct evhttp_connection *wss = NULL;
    struct evkeyvalq *output_headers = NULL;
    struct evhttp_request *req = NULL;

    if (context->server.tls) {
        ssl = SSL_new(context->ssl_ctx);
        if (!ssl) {
            LOGE("cannot create ssl for peer %d", port);
            return NULL;
        }

        SSL_set_tlsext_host_name(ssl, context->server.host);
        tev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    } else {
        tev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    }

    if (!tev) {
        LOGE("cannot create wss for peer %d", port);
        SSL_free(ssl);
        return NULL;
    }

    wss = evhttp_connection_base_bufferevent_new(base, NULL, tev,
                                                 context->server.addr, context->server.port);
    if (!wss) {
        LOGE("cannot connect to wss for peer %d", port);
        bufferevent_free(tev);
        return NULL;
    }

    evhttp_connection_set_timeout(wss, WSS_TIMEOUT);
    bufferevent_setcb(raw, NULL, NULL, raw_event_cb, wss);

    req = evhttp_request_new(http_request_cb, raw);
    if (!req) {
        LOGE("cannot new http request for peer %d", port);
        goto error;
    }

    output_headers = evhttp_request_get_output_headers(req);
    if (!output_headers) {
        goto error;
    }
    evhttp_add_header(output_headers, "Host", context->server.host);
    evhttp_add_header(output_headers, "Upgrade", "websocket");
    evhttp_add_header(output_headers, "Connection", "Upgrade");
#define WEBSOCKET_KEY "d3NzLXByb3h5LWNsaWVudA=="
    evhttp_add_header(output_headers, "Sec-WebSocket-Key", WEBSOCKET_KEY);
    evhttp_add_header(output_headers, "Sec-WebSocket-Version", "13");
    evhttp_add_header(output_headers, "User-Agent", context->user_agent);

    if (evhttp_make_request(wss, req, EVHTTP_REQ_GET, context->server.path)) {
        LOGE("cannot make http request for peer %d", port);
        goto error;
    }
    return wss;
error:
    // should we close req?
    evhttp_connection_free(wss);
    return NULL;
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *ctx) {
    struct event_base *base;
    struct bufferevent *raw = NULL;
    struct evhttp_connection *wss;
    uint16_t port;

    (void) socklen;
    base = evconnlistener_get_base(listener);
    raw = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!raw) {
        goto error;
    }
    port = get_port(address);
    LOGD("new connection from %d", port);
    wss = connect_wss(ctx, base, raw, port);
    if (!wss) {
        goto error;
    }
    return;
error:
    if (raw) {
        bufferevent_free(raw);
    }
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct evconnlistener *listener = NULL;
    struct sockaddr_storage raw_addr;
    int socklen;
    struct wss_proxy_context wss_context;

    memset(&wss_context, 0, sizeof(wss_context));
    if (init_wss_addr(&wss_context.server)) {
        return 1;
    }

    if (wss_context.server.tls) {
        wss_context.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!wss_context.ssl_ctx) {
            LOGE("cannot create ssl context");
            return 1;
        }
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
        SSL_CTX_set_keylog_callback(wss_context.ssl_ctx, ssl_keylog_callback);
#endif
    }

    socklen = sizeof(raw_addr);
    memset(&raw_addr, 0, socklen);
    if (init_raw_addr(&raw_addr, &socklen)) {
        return 1;
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

    listener = evconnlistener_new_bind(base, accept_conn_cb, &wss_context,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr *) &raw_addr, socklen);
    if (!listener) {
        LOGE("cannot listen to raw");
        goto error;
    }

#ifdef OPENSSL_VERSION_STRING
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s OpenSSL/%s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION_STRING));
#else
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s %s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION));
#endif

    init_event_signal(base);

    LOGI("%s", wss_context.user_agent);
    LOGI("started, pid: %d, ppid: %d", getpid(), getppid());

    event_base_dispatch(base);

    code = 0;
error:
    if (listener) {
        evconnlistener_free(listener);
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
    return code;
}
