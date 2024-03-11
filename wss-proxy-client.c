#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include "common.h"

struct wss_server_info {
    uint8_t tls;
    uint8_t debug;
    uint16_t port;
    const char *addr;
    const char *host;
    const char *path;
};

struct wss_proxy_context {
    SSL_CTX *ssl_ctx;
    struct evdns_base *dns_base;
    struct wss_server_info server;
    char user_agent[64];
} wss_context;

struct wss_tunnel_context {
    union {
        struct wss_frame_client client;
        struct wss_frame_server server;
    };
    unsigned char buffer[WSS_PAYLOAD_SIZE];
} tunnel_context;

static int init_raw_addr(struct sockaddr_storage *sockaddr, int *socklen) {
    int port;
    char *end;
    const char *local_host = getenv("SS_LOCAL_HOST");
    const char *local_port = getenv("SS_LOCAL_PORT");

    if (local_host == NULL) {
        fprintf(stderr, "local host is not set\n");
        return EINVAL;
    }

    port = (int) strtol(local_port, &end, 10);
    if (port <= 0 || port > 65535 || *end != '\0') {
        fprintf(stderr, "local port %s is unsupported\n", local_port);
        return EINVAL;
    }

    if (evutil_parse_sockaddr_port(local_host, (struct sockaddr *) sockaddr, socklen) != 0) {
        fprintf(stderr, "local host %s is unsupported\n", local_host);
        return -1;
    }

    if (sockaddr->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(port);
    } else {
        ((struct sockaddr_in *) sockaddr)->sin_port = htons(port);
    }

    printf("raw server %s:%d\n", local_host, port);
    return 0;
}

static int init_wss_addr(struct wss_server_info *server) {
    int port;
    char *end;
    int mux = 1;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");

    if (remote_host == NULL) {
        fprintf(stderr, "remote host is not set\n");
        return EINVAL;
    }

    if (strchr(remote_host, '|') != NULL) {
        fprintf(stderr, "remote host %s is unsupported\n", remote_host);
        return EINVAL;
    }
    server->addr = remote_host;

    port = (int) strtol(remote_port, &end, 10);
    if (port <= 0 || port > 65535 || *end != '\0') {
        fprintf(stderr, "remote port %s is unsupported\n", remote_port);
        return EINVAL;
    }
    server->port = port;

    if (strchr(options, '\\') != NULL) {
        fprintf(stderr, "plugin options %s (contains \\) is unsupported\n", options);
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

    if (options != NULL && strstr(options, "loglevel=debug") != NULL) {
        server->debug = 1;
    }

    printf("wss client %s:%d (%s://%s%s)\n", remote_host, port, server->tls ? "wss" : "ws", server->host, server->path);
    if (mux) {
        fprintf(stderr, "mux %d is unsupported\n", mux);
    }
    return 0;
}

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *ctx) {
    struct wss_tunnel_context *context = &tunnel_context;
    uint8_t fop;
    uint8_t mlen;
    uint16_t len;
    (void) dst_limit;
    (void) mode;
    (void) ctx;
    if (evbuffer_get_length(src) < 2) {
        return BEV_NEED_MORE;
    }
    evbuffer_copyout(src, &(context->server.f2.fop), 2);
    fop = context->server.f2.fop;
    mlen = context->server.f2.mlen;
    if (!(fop & 0x80)) {
        debug_wss("fin should be 1\n");
        return BEV_ERROR;
    }
    if (fop & 0x70) {
        debug_wss("rsv should be 0\n");
        return BEV_ERROR;
    }
    if (mlen & 0x80) {
        debug_wss("server reply shouldn't mask\n");
        return BEV_ERROR;
    }
    // FIXME: how to reset watermark
    switch (fop & 0xf) {
        case OP_CONTINUATION:
            debug_wss("continuation frame is unsupported\n");
            return BEV_ERROR;
        case OP_TEXT:
            debug_wss("text frame is unsupported\n");
            return BEV_ERROR;
        case OP_BINARY:
            break;
        case OP_CLOSE:
            debug_wss("server send close frame\n");
            return BEV_ERROR;
        case OP_PING:
            debug_wss("server send ping frame\n");
            return BEV_OK;
        case OP_PONG:
            debug_wss("server send pong frame\n");
            return BEV_OK;
        default:
            debug_wss("server send unsupported opcode: %d\n", fop & 0xf);
            return BEV_ERROR;
    }
    len = mlen & 0x7f;
    if (len < 126) {
        if (evbuffer_get_length(src) < (size_t) len + 2) {
            // FIXME: how to set watermark
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, 2);
    } else if (len == 126) {
        if (evbuffer_get_length(src) < 4) {
            return BEV_NEED_MORE;
        }
        evbuffer_copyout(src, &(context->server.f4.fop), 4);
        len = htons(context->server.f4.elen);
        if (len > MAX_PAYLOAD_SIZE) {
            debug_wss("maximum len is %d\n", MAX_PAYLOAD_SIZE);
            return BEV_ERROR;
        }
        if (evbuffer_get_length(src) < (size_t) len + 4) {
            // FIXME: how to set watermark
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, 4);
    } else {
        debug_wss("maximum len is %d\n", MAX_PAYLOAD_SIZE);
        return BEV_ERROR;
    }
    while (len > 0) {
        uint16_t size = len;
        if (size > WSS_PAYLOAD_SIZE) {
            size = WSS_PAYLOAD_SIZE;
        }
        len -= size;
        evbuffer_remove(src, context->buffer, size);
        evbuffer_add(dst, context->buffer, size);
    }
    return BEV_OK;
}

static uint8_t prepare_wss_data(struct wss_frame_client *client, enum wss_op op, uint16_t len) {
    uint8_t fop = 0x80 | (op & 0xf);
    client->mask = 0;
    if (len < 126) {
        client->f2.fop = fop;
        client->f2.mlen = 0x80 | (uint8_t) len;
        return 6;
    } else {
        client->f4.fop = fop;
        client->f4.mlen = 0x80 | 126;
        client->f4.elen = ntohs(len);
        return 8;
    }
}

static void close_wss_cb(struct bufferevent *tev, void *wss) {
    (void) tev;
    evhttp_connection_free(wss);
}

static void close_wss(struct evhttp_connection *wss) {
    struct bufferevent *tev;
    struct wss_tunnel_context *context = &tunnel_context;
    uint8_t pre = prepare_wss_data(&(context->client), OP_CLOSE, 2);
    context->buffer[0] = 0x03;
    context->buffer[1] = 0xe8;
    tev = evhttp_connection_get_bufferevent(wss);
    evbuffer_add(bufferevent_get_output(tev), &(context->client.f2.fop), 2 + pre);
    bufferevent_setcb(tev, NULL, close_wss_cb, NULL, wss);
}

static void raw_forward_cb(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;
    struct bufferevent *tev;
    struct wss_tunnel_context *context = &tunnel_context;

    tev = evhttp_connection_get_bufferevent(wss);
    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    for (;;) {
        uint8_t pre;
        int len = evbuffer_remove(src, context->buffer, WSS_PAYLOAD_SIZE);
        if (len <= 0) {
            break;
        }
        pre = prepare_wss_data(&(context->client), OP_BINARY, (uint16_t) len);
        if (pre == 6) {
            evbuffer_add(dst, &(context->client.f2.fop), len + pre);
        } else if (pre == 8) {
            evbuffer_add(dst, &(context->client.f4.fop), len + pre);
        }
        if (len < WSS_PAYLOAD_SIZE) {
            break;
        }
    }
}

static void raw_event_cb(struct bufferevent *raw, short what, void *wss) {
    struct bufferevent *tev;
    struct bufferevent *wev;
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        tev = evhttp_connection_get_bufferevent(wss);
        bufferevent_getcb(tev, NULL, NULL, NULL, (void **) &wev);
        bufferevent_free(wev);
        close_wss(wss);
        bufferevent_free(raw);
        debug_wss("%s, raw: %p, wss: %p, wev: %p, tev: %p\n", __func__, raw, wss, wev, tev);
        if (wss_context.server.debug) {
            printf("connection %u closed\n", get_peer_port(raw));
        }
    }
}

static void wss_forward_cb(struct bufferevent *wev, void *raw) {
    struct evbuffer *src;
    struct evbuffer *dst;

    src = bufferevent_get_input(wev);
    dst = bufferevent_get_output(raw);
    evbuffer_add_buffer(dst, src);
}

static void wss_event_cb(struct bufferevent *wev, short what, void *raw) {
    struct evhttp_connection *wss;
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
        bufferevent_free(wev);
        close_wss(wss);
        bufferevent_free(raw);
        debug_wss("%s, raw: %p, wss: %p, wev: %p, tev: %p\n", __func__, raw, wss, wev, bufferevent_get_underlying(wev));
        if (wss_context.server.debug) {
            printf("connection %u closing from wss\n", get_peer_port(raw));
        }
    }
}

static void wss_ready_cb(struct bufferevent *raw, struct evhttp_connection *wss) {
    struct bufferevent *tev;
    struct bufferevent *wev;

    tev = evhttp_connection_get_bufferevent(wss);
    wev = bufferevent_filter_new(tev, wss_input_filter, NULL, 0, NULL, NULL);

    bufferevent_enable(wev, EV_READ | EV_WRITE);
    bufferevent_setcb(wev, wss_forward_cb, NULL, wss_event_cb, raw);

    bufferevent_enable(raw, EV_READ | EV_WRITE);
    bufferevent_setcb(raw, raw_forward_cb, NULL, raw_event_cb, wss);
    debug_wss("%s, raw: %p, wss: %p, wev: %p, tev: %p\n", __func__, raw, wss, wev, tev);
}

static void http_request_cb(struct evhttp_request *req, void *raw) {
    struct evhttp_connection *wss;
    int status = req == NULL ? -1 : evhttp_request_get_response_code(req);
    bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
    if (status == 101) {
        wss_ready_cb(raw, wss);
    } else {
        fprintf(stderr, "wss fail for peer %d, status: %d\n", get_peer_port(raw), status);
        bufferevent_free(raw);
        evhttp_connection_free(wss);
    }
}

static const char *request_error_to_string(enum evhttp_request_error error) {
    switch (error) {
        case EVREQ_HTTP_TIMEOUT:
            return "Timeout";
        case EVREQ_HTTP_EOF:
            return "EOF";
        case EVREQ_HTTP_INVALID_HEADER:
            return "Invalid Header";
        case EVREQ_HTTP_BUFFER_ERROR:
            return "Buffer Error";
        case EVREQ_HTTP_REQUEST_CANCEL:
            return "Request Cancelled";
        case EVREQ_HTTP_DATA_TOO_LONG:
            return "Data Too Long";
        default:
            return "Request Error";
    }
}

static void http_error_cb(enum evhttp_request_error error, void *ctx) {
    fprintf(stderr, "http error for peer %d, error: %s, code: %d\n",
            get_peer_port(ctx), request_error_to_string(error), error);
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
            fprintf(stderr, "cannot create ssl for peer %d\n", port);
            return NULL;
        }

        SSL_set_tlsext_host_name(ssl, context->server.host);
        tev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    } else {
        tev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    }

    if (!tev) {
        fprintf(stderr, "cannot create wss for peer %d\n", port);
        SSL_free(ssl);
        return NULL;
    }

    wss = evhttp_connection_base_bufferevent_new(base, context->dns_base, tev,
                                                 context->server.addr, context->server.port);
    if (!wss) {
        fprintf(stderr, "cannot connect to wss for peer %d\n", port);
        bufferevent_free(tev);
        return NULL;
    }

    evhttp_connection_set_timeout(wss, WSS_TIMEOUT);

    req = evhttp_request_new(http_request_cb, raw);
    if (!req) {
        fprintf(stderr, "cannot new http request for peer %d\n", port);
        goto error;
    }

    evhttp_request_set_error_cb(req, http_error_cb);

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
        fprintf(stderr, "cannot make http request for peer %d\n", port);
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
    if (wss_context.server.debug) {
        printf("new connection from %d\n", port);
    }
    wss = connect_wss(ctx, base, raw, port);
    if (!wss) {
        goto error;
    }
    bufferevent_setcb(raw, NULL, NULL, raw_event_cb, wss);
    return;
error:
    if (raw) {
        bufferevent_free(raw);
    }
}

static void toggle_debug(int signal) {
    if (signal == SIGUSR2) {
        wss_context.server.debug = !wss_context.server.debug;
    }
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct evconnlistener *listener = NULL;
    struct sockaddr_storage raw_addr;
    int socklen;

    memset(&wss_context, 0, sizeof(wss_context));
    if (init_wss_addr(&wss_context.server)) {
        return 1;
    }

    if (wss_context.server.tls) {
        wss_context.ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!wss_context.ssl_ctx) {
            perror("cannot create ssl context");
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

    cfg = event_config_new();
    if (!cfg) {
        perror("cannot create event config");
        goto error;
    }
    event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
    event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);
#ifdef _WIN32
    event_config_set_flag(cfg, EVENT_BASE_FLAG_STARTUP_IOCP);
#endif
    base = event_base_new_with_config(cfg);
    if (!base) {
        perror("cannot create event base");
        goto error;
    }

    listener = evconnlistener_new_bind(base, accept_conn_cb, &wss_context,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr *) &raw_addr, socklen);
    if (!listener) {
        perror("cannot listen to raw");
        goto error;
    }

    wss_context.dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
#ifdef OPENSSL_VERSION_STRING
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s OpenSSL/%s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION_STRING));
#else
    snprintf(wss_context.user_agent, sizeof(wss_context.user_agent), "wss-proxy-client/%s libevent/%s %s",
             WSS_PROXY_VERSION, event_get_version(), OpenSSL_version(OPENSSL_VERSION));
#endif

    init_event_signal(base);

    printf("%s started, pid: %d, ppid: %d\n", wss_context.user_agent, getpid(), getppid());

    signal(SIGUSR2, toggle_debug);

    event_base_dispatch(base);

    code = 0;
error:
    if (listener) {
        evconnlistener_free(listener);
    }
    if (wss_context.dns_base) {
        evdns_base_free(wss_context.dns_base, 0);
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
