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

const enum wss_role role = wss_client;

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

static void http_request_cb(struct evhttp_request *req, void *raw) {
    struct evhttp_connection *wss;
    int status = req == NULL ? -1 : evhttp_request_get_response_code(req);
    bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
    if (status == 101 && is_websocket_handshake(req)) {
        tunnel_wss(raw, wss);
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

static uint16_t get_port(struct sockaddr *sockaddr) {
    if (sockaddr->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) sockaddr)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) sockaddr)->sin_port);
    }
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
