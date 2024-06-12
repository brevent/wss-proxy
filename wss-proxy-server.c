#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include "common.h"

#define bufferevent_free safe_bufferevent_free

struct raw_server_info {
    const char *addr;
    int socklen;
    int port;
    struct sockaddr_storage sockaddr;
    int udp_port;
    struct sockaddr_storage udp_sockaddr;
    LHASH_OF(bev_context_udp) *hash;
};

static unsigned long bev_context_udp_hash(const bev_context_udp *a) {
    return a->sock;
}

static int bev_context_udp_cmp(const bev_context_udp *a, const bev_context_udp *b) {
    return a->sock - b->sock;
}

static int init_ws_info(const char **addr, int *port) {
    int mux;
    char *end;
    const char *value;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");
    if (remote_host != NULL && strchr(remote_host, '|') != NULL) {
        LOGE("remote host %s is not supported", remote_host);
        return EINVAL;
    }
    *addr = remote_host == NULL ? "127.0.0.1" : remote_host;
    *port = remote_port == NULL ? 0 : (int) strtol(remote_port, &end, 10);
    if (*port <= 0 || *port > 65535 || *end != '\0') {
        LOGE("remote port %s is not supported", remote_port);
        return EINVAL;
    }
    if (options != NULL && strchr(options, '\\') != NULL) {
        LOGE("plugin options %s (contains \\) is unsupported", options);
        return EINVAL;
    }
    // mux
    if ((value = find_option(options, "mux", NULL)) != NULL) {
        mux = (int) strtol(value, NULL, 10);
    } else {
        mux = 1;
    }
    // loglevel
    if ((value = find_option(options, "loglevel", NULL)) != NULL) {
        init_log_level(value);
    }
    LOGI("wss server %s:%d", *addr, *port);
    if (mux) {
        LOGW("mux %d is unsupported", mux);
    }
    return 0;
}

static int init_raw_info(struct raw_server_info *raw_server_info) {
    char *end;
    const char *local_host = getenv("SS_LOCAL_HOST");
    const char *local_port = getenv("SS_LOCAL_PORT");
    raw_server_info->addr = local_host == NULL ? "127.0.0.1" : local_host;
    if (local_port == NULL) {
        LOGE("local port is not set");
        return EINVAL;
    }
    raw_server_info->port = (int) strtol(local_port, &end, 10);
    if (raw_server_info->port <= 0 || raw_server_info->port > 65535 || *end != '\0') {
        LOGE("local port %s is not supported", local_port);
        return EINVAL;
    }

    raw_server_info->udp_port = find_option_port("udp-port", raw_server_info->port);

    if (raw_server_info->udp_port > 0) {
        LOGI("raw client tcp://%s:%d, udp://%s:%d", raw_server_info->addr, raw_server_info->port,
             raw_server_info->addr, raw_server_info->udp_port);
    } else {
        LOGI("raw client %s:%d", raw_server_info->addr, raw_server_info->port);
    }
    return 0;
}

static int do_websocket_handshake(char *request, char *sec_websocket_accept) {
    char *sec_websocket_key;
    if (memcmp(request, "GET ", 4) != 0) {
        LOGW("handshake fail, invalid method: %s", request);
        return 0;
    }
    if (!strcasestr(request, "\r\nUpgrade: websocket\r\n") ||
        !strcasestr(request, "\r\nConnection: Upgrade\r\n") ||
        !strcasestr(request, "\r\nSec-WebSocket-Version: 13\r\n")) {
        LOGW("handshake fail, invalid request: %s", request);
        return 0;
    }
    sec_websocket_key = strcasestr(request, "\r\nSec-WebSocket-Key: ");
    if (sec_websocket_key == NULL || strlen(sec_websocket_key) <= 47) {
        LOGW("handshake fail, no Sec-WebSocket-Key: %s", request);
        return 0;
    }
    sec_websocket_key += sizeof("\r\nSec-WebSocket-Key: ") - 1;
    if (!is_websocket_key(sec_websocket_key)) {
        LOGW("handshake fail, invalid Sec-WebSocket-Key: %s", request);
        return 0;
    }
    sec_websocket_key[24] = '\0';
    calc_websocket_accept(sec_websocket_key, sec_websocket_accept);
    sec_websocket_key[24] = '\r';
    return 1;
}

static void udp_read_cb_client(evutil_socket_t sock, short event, void *ctx) {
    struct bufferevent *raw = ctx;
    if (event & EV_TIMEOUT) {
        LOGD("udp timeout for peer %d", get_peer_port(raw->cbarg));
        raw->errorcb(raw, BEV_EVENT_EOF, raw->cbarg);
    } else if (event & EV_READ) {
        struct udp_frame udp_frame;
        ev_socklen_t socklen;
        struct sockaddr_storage sockaddr;
        struct timeval one_minute = {60, 0};
        for (;;) {
            ssize_t size;
            socklen = sizeof(struct sockaddr_storage);
            if ((size = udp_read(sock, &udp_frame, (struct sockaddr *) &sockaddr, &socklen)) < 0) {
                break;
            }
            if (size == 0) {
                LOGW("udp read empty from %d", get_port((const struct sockaddr *) &sockaddr));
                continue;
            }
            evbuffer_add(raw->input, &udp_frame, size + UDP_FRAME_LENGTH_SIZE);
            if (raw->readcb) {
                raw->readcb(raw, raw->cbarg);
            }
            event_add(&(raw->ev_read), &one_minute);
        }
    }
}

static struct bufferevent *init_udp_client(struct event_base *base, struct raw_server_info *raw_server_info) {
    evutil_socket_t sock;
    struct bev_context_udp *bev_context_udp;
    struct bufferevent *raw;
    struct timeval one_minute = {60, 0};

    sock = socket(raw_server_info->udp_sockaddr.ss_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOGE("cannot create udp socket");
        goto error;
    }
    if (evutil_make_socket_nonblocking(sock) < 0) {
        LOGE("cannot make udp socket nonblocking");
        goto error;
    }
    if (evutil_make_socket_closeonexec(sock) < 0) {
        LOGE("cannot make udp socket closeonexec");
        goto error;
    }
    bev_context_udp = calloc(1, sizeof(struct bev_context_udp));
    if (bev_context_udp == NULL) {
        LOGE("cannot calloc for udp socket");
        goto error;
    }
    raw = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!raw) {
        LOGE("cannot create udp bufferevent");
        goto error;
    }
    bufferevent_disable(raw, EV_READ | EV_WRITE);
    bufferevent_setfd(raw, sock);
    event_assign(&(raw->ev_write), base, sock, EV_WRITE | EV_PERSIST, bev_context_udp_writecb, raw);
    event_assign(&(raw->ev_read), base, sock, EV_READ | EV_PERSIST, udp_read_cb_client, raw);
    event_add(&(raw->ev_read), &one_minute);
    bev_context_udp->socklen = raw_server_info->socklen;
    bev_context_udp->sockaddr = (struct sockaddr *) &(raw_server_info->udp_sockaddr);
    bev_context_udp->bev = raw;
    bev_context_udp->hash = raw_server_info->hash;
    bev_context_udp->sock = sock;
    bev_context_udp->bev_context = &const_bev_context_udp;
    bufferevent_set_context(raw, bev_context_udp);
    lh_bev_context_udp_insert(raw_server_info->hash, bev_context_udp);
    return raw;
error:
    if (sock > 0) {
        evutil_closesocket(sock);
    }
    return NULL;
}

static struct bufferevent *init_tcp_client(struct event_base *base, struct raw_server_info *raw_server_info) {
    struct bufferevent *raw = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (raw == NULL) {
        LOGW("cannot create raw connection");
        return NULL;
    }
    if (bufferevent_socket_connect(raw, (struct sockaddr *) &(raw_server_info->sockaddr), raw_server_info->socklen)) {
        LOGW("cannot connect raw at %s:%u", raw_server_info->addr, raw_server_info->port);
        bufferevent_free(raw);
        return NULL;
    }
    return raw;
}

static void http_request_cb(struct bufferevent *tev, void *ctx) {
    size_t length;
    struct event_base *base;
    struct evbuffer *input;
    struct bufferevent *raw;
    struct raw_server_info *raw_server_info = ctx;
    char request[1024], sec_websocket_accept[29], *buffer;
    int ss, udp;

    memset(request, 0, sizeof(request));
    input = bufferevent_get_input(tev);
    length = evbuffer_get_length(input);
    if (length == 0) {
        LOGW("no request data");
        goto error;
    }
    evbuffer_copyout(input, request, sizeof(request));
    if (strstr(request, "\r\n\r\n") == NULL) {
        LOGW("uncompleted response: %s", request);
        goto error;
    }
    if (!do_websocket_handshake(request, sec_websocket_accept)) {
        goto error;
    }
    evbuffer_drain(input, length);
    LOGD("new connection from %d", get_peer_port(tev));
    base = bufferevent_get_base(tev);
    udp = strcasestr(request, "\r\n" X_SOCK_TYPE ": " SOCK_TYPE_UDP "\r\n") != NULL;
    if (udp) {
        raw = init_udp_client(base, raw_server_info);
    } else {
        raw = init_tcp_client(base, raw_server_info);
    }
    if (raw == NULL) {
        goto error;
    }
    bufferevent_setcb(raw, NULL, NULL, raw_event_cb, tev);

    buffer = request;
    buffer += sprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\n"
                              "Upgrade: websocket\r\n"
                              "Connection: Upgrade\r\n"
                              "Sec-WebSocket-Accept: %s\r\n", sec_websocket_accept);
    ss = strcasestr(request, "\r\n" X_UPGRADE ": " SHADOWSOCKS "\r\n") != NULL;
    if (ss) {
        append_line(buffer, X_UPGRADE ": " SHADOWSOCKS "\r\n");
    }
    append_line(buffer, "\r\n");
    bufferevent_write(tev, request, buffer - request);

    if (ss) {
        tunnel_ss(raw, tev);
    } else {
        tunnel_wss(raw, tev, NULL);
    }
    return;
error:
    bufferevent_write(tev, "HTTP/1.1 400 Bad Request\r\n\r\n", sizeof("400 Bad Request\r\n\r\n") - 1);
    bufferevent_free(tev);
}

static void client_event_cb(struct bufferevent *tev, short event, void *ctx) {
    uint16_t port;
    (void) ctx;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        port = get_peer_port(tev);
        LOGD("connection %u closed for wss, event: 0x%02x", port, event);
        bufferevent_free(tev);
    }
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *ctx) {
    struct event_base *base;
    struct bufferevent *tev;

    (void) socklen;
    base = evconnlistener_get_base(listener);
    tev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (tev == NULL) {
        LOGW("cannot handle request from port %d", get_port(address));
        evutil_closesocket(fd);
    } else {
        bufferevent_enable(tev, EV_READ | EV_WRITE);
        bufferevent_setcb(tev, http_request_cb, NULL, client_event_cb, ctx);
    }
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct event *event_parent = NULL, *event_sigquit = NULL;
    const char *addr;
    int port;
    struct sockaddr_storage sockaddr_storage;
    int socklen;
    struct evconnlistener *listener = NULL;
    struct raw_server_info raw_server_info;

    memset(&raw_server_info, 0, sizeof(raw_server_info));
    if (init_raw_info(&raw_server_info)) {
        goto error;
    }
    raw_server_info.socklen = sizeof(struct sockaddr_storage);
    if (evutil_parse_sockaddr_port(raw_server_info.addr, (struct sockaddr *) &(raw_server_info.sockaddr),
                                   &(raw_server_info.socklen)) < 0) {
        LOGE("cannot parse %s", raw_server_info.addr);
        goto error;
    }
    set_port(&(raw_server_info.sockaddr), raw_server_info.port);
    if (raw_server_info.udp_port > 0) {
        memcpy(&(raw_server_info.udp_sockaddr), &(raw_server_info.sockaddr), raw_server_info.socklen);
        set_port(&(raw_server_info.udp_sockaddr), raw_server_info.udp_port);
        raw_server_info.hash = lh_bev_context_udp_new(bev_context_udp_hash, bev_context_udp_cmp);
        if (!raw_server_info.hash) {
            LOGE("cannot create lhash for udp");
            goto error;
        }
    }

    if (init_ws_info(&addr, &port)) {
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

    socklen = sizeof(struct sockaddr_storage);
    if (evutil_parse_sockaddr_port(addr, (struct sockaddr *) &(sockaddr_storage), &socklen) < 0) {
        LOGE("cannot parse %s", addr);
        goto error;
    }
    set_port(&(sockaddr_storage), port);
    listener = evconnlistener_new_bind(base, accept_conn_cb, &raw_server_info,
                                       WSS_LISTEN_FLAGS, WSS_LISTEN_BACKLOG,
                                       (const struct sockaddr *) &(sockaddr_storage), socklen);
    if (listener == NULL) {
        LOGE("cannot listen to %s:%d", addr, port);
        goto error;
    }

    if (init_event_signal(base, &event_parent, &event_sigquit)) {
        goto error;
    }

    LOGI("wss-proxy-server/%s libevent/%s", WSS_PROXY_VERSION, event_get_version());
    LOGI("started, pid: %d, ppid: %d", getpid(), getppid());

    event_base_dispatch(base);

    LOGI("graceful shutdown");

    code = 0;
error:
    if (raw_server_info.hash) {
        free_all_udp(raw_server_info.hash);
    }
    if (event_parent) {
        event_free(event_parent);
    }
    if (event_sigquit) {
        event_free(event_sigquit);
    }
    if (listener) {
        evconnlistener_free(listener);
    }
    if (base) {
        event_base_free(base);
    }
    if (cfg) {
        event_config_free(cfg);
    }
    close_syslog();
    return code;
}
