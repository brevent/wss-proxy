#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/http.h>
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
};

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

static int do_websocket_handshake(struct evhttp_request *req, char *sec_websocket_accept) {
    const char *value;
    struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
#define HAS_HEADER(key, expected) ((value = evhttp_find_header(headers, key)) != NULL \
    && evutil_ascii_strcasecmp(value, expected) == 0)
    if (!HAS_HEADER("Upgrade", "websocket") ||
        !HAS_HEADER("Connection", "Upgrade") ||
        !HAS_HEADER("Sec-WebSocket-Version", "13")) {
        LOGW("handshake fail, invalid headers");
        LOGD("Upgrade: %s, Connection: %s, Sec-WebSocket-Version: %s",
             evhttp_find_header(headers, "Upgrade"),
             evhttp_find_header(headers, "Connection"),
             evhttp_find_header(headers, "Sec-WebSocket-Version"));
        return 0;
    }
    value = evhttp_find_header(headers, "Sec-WebSocket-Key");
    if (!is_websocket_key(value)) {
        LOGW("handshake fail, invalid Sec-WebSocket-Key: %s", value);
        return 0;
    }
    calc_websocket_accept(value, sec_websocket_accept);
    return 1;
}

static void udp_read_cb_client(evutil_socket_t sock, short event, void *ctx) {
    struct bufferevent *raw = ctx;
    struct evhttp_connection *wss = get_wss(raw);
    if (event & EV_TIMEOUT) {
        LOGD("udp timeout for peer %d", get_http_port(wss));
        raw->errorcb(raw, BEV_EVENT_EOF, wss);
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
            evbuffer_add(raw->input, &udp_frame, size + UDP_FRAME_LENGTH_SIZE);
            event_add(&(raw->ev_read), &one_minute);
        }
    }
}

static struct bufferevent *init_udp_client(struct event_base *base, struct raw_server_info *raw_server_info) {
    evutil_socket_t sock;
    struct bufferevent_udp *data;
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
    if (evutil_make_listen_socket_reuseable(sock) < 0) {
        LOGE("cannot make udp socket reuseable");
        goto error;
    }
    data = calloc(1, sizeof(struct bufferevent_udp));
    if (data == NULL) {
        LOGE("cannot calloc for udp socket");
        goto error;
    }
    data->sock = sock;
    data->socklen = raw_server_info->socklen;
    data->sockaddr = (struct sockaddr *) &(raw_server_info->udp_sockaddr);
    raw = (struct bufferevent *) data;
    raw->ev_base = base;
    raw->input = evbuffer_new();
    raw->output = evbuffer_new();
    evbuffer_add_cb(raw->output, udp_send_cb, raw);
    event_assign(&(raw->ev_read), base, sock, EV_READ | EV_PERSIST, udp_read_cb_client, raw);
    event_add(&(raw->ev_read), &one_minute);
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

static void generic_request_handler(struct evhttp_request *req, void *ctx) {
    struct event_base *base;
    struct bufferevent *raw = NULL;
    struct evhttp_connection *wss = NULL;
    struct raw_server_info *raw_server_info = ctx;
    char sec_websocket_accept[29];
    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    int ss;
    int udp;

    if (!do_websocket_handshake(req, sec_websocket_accept)) {
        goto error;
    }

    wss = evhttp_request_get_connection(req);
    LOGD("new connection from %d", get_http_port(wss));
    base = evhttp_connection_get_base(wss);
    udp = IS_UDP(evhttp_find_header(evhttp_request_get_input_headers(req), X_SOCK_TYPE));
    if (udp) {
        raw = init_udp_client(base, raw_server_info);
    } else {
        raw = init_tcp_client(base, raw_server_info);
    }
    if (raw == NULL) {
        goto error;
    }
    if (raw->be_ops) {
        bufferevent_setcb(raw, NULL, NULL, raw_event_cb, wss);
    } else {
        raw->cbarg = wss;
    }

    evhttp_add_header(headers, "Upgrade", "websocket");
    evhttp_add_header(headers, "Connection", "Upgrade");
    evhttp_add_header(headers, "Sec-WebSocket-Accept", (char *) sec_websocket_accept);
    ss = IS_SHADOWSOCKS(evhttp_find_header(evhttp_request_get_input_headers(req), X_UPGRADE));
    if (ss) {
        evhttp_add_header(headers, X_UPGRADE, SHADOWSOCKS);
    }
    evhttp_send_reply(req, 101, "Switching Protocols", NULL);

    if (ss) {
        tunnel_ss(raw, wss);
    } else {
        tunnel_wss(raw, wss);
    }
    return;
error:
    evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct event *event_parent = NULL, *event_sigquit = NULL;
    struct evhttp *http_server = NULL;
    const char *addr;
    int port;
    struct raw_server_info raw_server_info;

    memset(&raw_server_info, 0, sizeof(raw_server_info));
    if (init_raw_info(&raw_server_info)) {
        return 1;
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
    }

    if (init_ws_info(&addr, &port)) {
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

    http_server = evhttp_new(base);
    if (!http_server) {
        LOGE("cannot create http server");
        goto error;
    }
    if (evhttp_bind_socket(http_server, addr, (ev_uint16_t) port)) {
        LOGE("cannot bind http server to %s:%u", addr, (uint16_t) port);
        goto error;
    }
    evhttp_set_gencb(http_server, generic_request_handler, &raw_server_info);

    if (init_event_signal(base, &event_parent, &event_sigquit)) {
        goto error;
    }

    LOGI("wss-proxy-server/%s libevent/%s", WSS_PROXY_VERSION, event_get_version());
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
    if (http_server) {
        evhttp_free(http_server);
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
