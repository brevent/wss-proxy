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
#include <openssl/err.h>
#include "common.h"

#define bufferevent_free safe_bufferevent_free

struct wss_server_info {
    uint8_t tls: 1;
    uint8_t ws: 1;
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

struct udp_context {
    LHASH_OF(bufferevent_udp) *hash;
    struct event_base *base;
    struct wss_proxy_context *wss_context;
};

struct server_context {
    struct evconnlistener *listener;
    evutil_socket_t udp_sock;
    struct event *udp_event;
    struct udp_context udp_context;
};

static unsigned long bufferevent_udp_hash(const bufferevent_udp *a) {
    socklen_t i, max;
    unsigned long result = a->socklen;
    uint32_t *a32 = (uint32_t *) a->sockaddr;
    for (i = 0, max = (a->socklen >> 2); i < max; ++i, a32++) {
        result ^= *a32;
    }
    return result;
}

static int bufferevent_udp_cmp(const bufferevent_udp *a, const bufferevent_udp *b) {
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
    char *end, *wss;
    const char *value;
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

    // strip
    server->host = strdup(server->host);
    if ((end = strchr(server->host, ';')) != NULL) {
        *end = '\0';
    }
    server->path = strdup(server->path);
    if ((end = strchr(server->path, ';')) != NULL) {
        *end = '\0';
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
    LOGI("wss client %s:%d (%s://%s%s)", remote_host, port, wss, server->host, server->path);
    if (server->ws && mux) {
        LOGW("mux %d is unsupported", mux);
    }
    return 0;
}

static int is_websocket_handshake(struct evhttp_request *req) {
    const char *accept;
    const char *key;
    char base64_accept[29];
    key = evhttp_find_header(evhttp_request_get_output_headers(req), "Sec-WebSocket-Key");
    accept = evhttp_find_header(evhttp_request_get_input_headers(req), "Sec-WebSocket-Accept");
    if (is_websocket_key(key)
        && calc_websocket_accept(key, base64_accept) > 0
        && strcmp(accept, base64_accept) == 0) {
        return 1;
    }
    LOGW("hand shake fail, key: %s, accept: %s", key, accept);
    return 0;
}

static void http_error_cb(enum evhttp_request_error error, void *raw) {
    int socket_error = EVUTIL_SOCKET_ERROR();
    uint16_t port = get_peer_port(raw);
    switch (error) {
        case EVREQ_HTTP_TIMEOUT:
            LOGE("http timeout for peer %d", port);
            break;
        case EVREQ_HTTP_EOF:
            LOGE("http eof for peer %d", port);
            break;
        case EVREQ_HTTP_INVALID_HEADER:
            LOGE("http invalid header for peer %d", port);
            break;
        case EVREQ_HTTP_BUFFER_ERROR:
            LOGE("http buffer error for peer %d", port);
            break;
        case EVREQ_HTTP_REQUEST_CANCEL:
            LOGE("http request cancel for peer %d", port);
            break;
        case EVREQ_HTTP_DATA_TOO_LONG:
            LOGE("http data too long for peer %d", port);
            break;
        default:
            LOGE("http unknown reason %d for peer %d", error, port);
            break;
    }
    EVUTIL_SET_SOCKET_ERROR(socket_error);
}

static void show_http_error(struct bufferevent *raw, struct evhttp_connection *wss, int socket_error, int show_unknown) {
    unsigned long tls_error;
    char error_buffer[256];
    uint16_t port = get_peer_port(raw);
    if ((tls_error = bufferevent_get_openssl_error(evhttp_connection_get_bufferevent(wss)))) {
        memset(error_buffer, 0, sizeof(error_buffer));
        ERR_error_string_n(tls_error, error_buffer, sizeof(error_buffer));
        LOGE("tls fail for peer %d: %s", port, error_buffer);
    } else if (socket_error == EWOULDBLOCK) {
        LOGE("wss fail for peer %d: socket timeout", port);
    } else if (socket_error) {
        LOGE("wss fail for peer %d: %s", port, evutil_socket_error_to_string(socket_error));
    } else if (show_unknown) {
        LOGE("wss fail for peer %d: unknown reason", port);
    }
}

static void http_request_cb(struct evhttp_request *req, void *raw) {
    struct evhttp_connection *wss = get_wss(raw);
    int socket_error = EVUTIL_SOCKET_ERROR();
    int status = req == NULL ? -1 : evhttp_request_get_response_code(req);
    if (status == 101 && is_websocket_handshake(req)) {
        LOGD("wss is ready for peer %d", get_peer_port(raw));
        if (IS_SHADOWSOCKS(evhttp_find_header(evhttp_request_get_input_headers(req), X_UPGRADE))) {
            tunnel_ss(raw, wss);
        } else {
            tunnel_wss(raw, wss);
        }
    } else {
        if (status > 0) {
            LOGE("wss fail for peer %d, status: %d", get_peer_port(raw), status);
        } else {
            show_http_error(raw, wss, socket_error, req != NULL);
        }
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
            goto error;
        }

        if (!SSL_set_tlsext_host_name(ssl, context->server.host)) {
            LOGE("cannot set sni extension for peer %d", port);
            goto error;
        }
        if (!SSL_set1_host(ssl, context->server.host)) {
            LOGE("cannot set certificate verification hostname for peer %d", port);
            goto error;
        }
        tev = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    } else {
        tev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    }

    if (!tev) {
        LOGE("cannot create wss for peer %d", port);
        goto error;
    }

    wss = evhttp_connection_base_bufferevent_new(base, NULL, tev,
                                                 context->server.addr, context->server.port);
    if (!wss) {
        LOGE("cannot connect to wss for peer %d", port);
        goto error;
    }

    evhttp_connection_set_timeout(wss, WSS_TIMEOUT);
    if (raw->be_ops) {
        bufferevent_setcb(raw, NULL, NULL, raw_event_cb, wss);
    } else {
        raw->cbarg = wss;
    }

    req = evhttp_request_new(http_request_cb, raw);
    if (!req) {
        LOGE("cannot new http request for peer %d", port);
        goto error;
    }
    evhttp_request_set_error_cb(req, http_error_cb);

    output_headers = evhttp_request_get_output_headers(req);
    if (!output_headers) {
        LOGE("cannot get output headers for peer %d", port);
        goto error;
    }
    evhttp_add_header(output_headers, "Host", context->server.host);
    evhttp_add_header(output_headers, "Upgrade", "websocket");
    evhttp_add_header(output_headers, "Connection", "Upgrade");
#ifndef WSS_MOCK_KEY
    {
        char websocket_key[25];
        unsigned char key[16];
        evutil_secure_rng_get_bytes(key, 16);
        EVP_EncodeBlock((unsigned char *) websocket_key, key, 16);
        evhttp_add_header(output_headers, "Sec-WebSocket-Key", websocket_key);
    }
#else
    evhttp_add_header(output_headers, "Sec-WebSocket-Key", "d3NzLXByb3h5LWNsaWVudA==");
#endif
    evhttp_add_header(output_headers, "Sec-WebSocket-Version", "13");
    evhttp_add_header(output_headers, "User-Agent", context->user_agent);
    if (!raw->be_ops) {
        evhttp_add_header(output_headers, X_SOCK_TYPE, SOCK_TYPE_UDP);
    }
    if (!context->server.ws) {
        evhttp_add_header(output_headers, X_UPGRADE, SHADOWSOCKS);
    }

    if (evhttp_make_request(wss, req, EVHTTP_REQ_GET, context->server.path)) {
        LOGE("cannot make http request for peer %d", port);
        goto error;
    }
    return wss;
error:
    // should we close req?
    if (ssl != NULL) {
        SSL_free(ssl);
    }
    if (tev != NULL) {
        bufferevent_free(tev);
    }
    if (wss != NULL) {
        evhttp_connection_free(wss);
    }
    return NULL;
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
    if (!connect_wss(ctx, base, raw, port)) {
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
        raw->errorcb(raw, BEV_EVENT_EOF, get_wss(raw));
    }
}

static struct bufferevent_udp *init_udp_server(struct bufferevent_udp *key, struct udp_context *context,
                                               evutil_socket_t sock, int port) {
    struct bufferevent_udp *data;
    struct bufferevent *raw;
    data = lh_bufferevent_udp_retrieve(context->hash, key);
    if (data != NULL) {
        return data;
    }
    data = calloc(1, sizeof(struct bufferevent_udp));
    if (!data) {
        LOGE("cannot calloc for peer %d", port);
        return NULL;
    }
    memcpy(&(data->sockaddr_storage), &(key->sockaddr_storage), key->socklen);
    data->sock = sock;
    data->socklen = key->socklen;
    data->sockaddr = (struct sockaddr *) &(data->sockaddr_storage);
    data->hash = context->hash;
    raw = (struct bufferevent *) data;
    if (!connect_wss(context->wss_context, context->base, raw, port)) {
        LOGE("cannot connect to wss for peer %d", port);
        free(data);
        return NULL;
    }
    raw->ev_base = context->base;
    raw->input = evbuffer_new();
    raw->output = evbuffer_new();
    evbuffer_add_cb(raw->output, udp_send_cb, data);
    event_assign(&(raw->ev_read), context->base, sock, EV_READ | EV_PERSIST, udp_timeout_cb, data);
    LOGD("udp init for peer %d", port);
    lh_bufferevent_udp_insert(context->hash, data);
    return data;
}

static void udp_read_cb_server(evutil_socket_t sock, short event, void *ctx) {
    struct udp_context *context = ctx;
    struct bufferevent_udp key, *data;
    struct udp_frame udp_frame;
    struct timeval one_minute = {60, 0};
    (void) event;
    key.sockaddr = (struct sockaddr *) &(key.sockaddr_storage);
    for (;;) {
        ssize_t size;
        key.socklen = sizeof(struct sockaddr_storage);
        if ((size = udp_read(sock, &udp_frame, key.sockaddr, &(key.socklen))) < 0) {
            break;
        }
        if ((data = init_udp_server(&key, context, sock, get_port(key.sockaddr))) == NULL) {
            break;
        }
        evbuffer_add(data->be.input, &udp_frame, size + UDP_FRAME_LENGTH_SIZE);
        event_add(&(data->be.ev_read), &one_minute);
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
        lh_bufferevent_udp_free(server_context->udp_context.hash);
    }
    if (server_context->udp_event) {
        event_free(server_context->udp_event);
    }
}

static int init_server_context(struct server_context *server_context, struct event_base *base,
                               struct wss_proxy_context *wss_context, struct sockaddr *sockaddr, int socklen) {
    unsigned flags = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE;
    server_context->listener = evconnlistener_new_bind(base, accept_conn_cb, wss_context, flags, -1,
                                                       sockaddr, socklen);
    if (!server_context->listener) {
        LOGE("cannot listen to raw for %d", get_port(sockaddr));
        goto error;
    }

    server_context->udp_sock = init_udp_sock(sockaddr, socklen);
    if (server_context->udp_sock < 0) {
        goto error;
    }

    server_context->udp_context.hash = lh_bufferevent_udp_new(bufferevent_udp_hash, bufferevent_udp_cmp);
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
        SSL_CTX_set_verify(wss_context.ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (!SSL_CTX_set_default_verify_paths(wss_context.ssl_ctx)) {
            LOGE("cannot set default trusted certificate store");
            return 1;
        }
        if (!SSL_CTX_set_min_proto_version(wss_context.ssl_ctx, TLS1_2_VERSION)) {
            LOGE("cannot set minimum TLS to 1.2");
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

    memset(&server_context, 0, sizeof(server_context));
    if (init_server_context(&server_context, base, &wss_context, (struct sockaddr *) &raw_addr, socklen)) {
        goto error;
    }

    extra_port = find_option_port("extra-listen-port", 0);
    memset(&extra_server_context, 0, sizeof(server_context));
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

    LOGI("%s", wss_context.user_agent);
    LOGI("started, pid: %d, ppid: %d", getpid(), getppid());

    event_base_dispatch(base);

    LOGI("graceful shutdown");

    code = 0;
error:
    if (event_parent) {
        event_free(event_parent);
    }
    if (event_sigquit) {
        event_free(event_sigquit);
    }
    server_context_free(&server_context);
    server_context_free(&extra_server_context);
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
    return code;
}
