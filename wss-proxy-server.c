#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/listener.h>
#include "common.h"

const enum wss_role role = wss_server;

struct raw_server_info {
    int port;
    const char *addr;
};

static int init_ws_info(const char **addr, int *port) {
    int mux = 1;
    char *end;
    const char *remote_host = getenv("SS_REMOTE_HOST");
    const char *remote_port = getenv("SS_REMOTE_PORT");
    const char *options = getenv("SS_PLUGIN_OPTIONS");
    const char *loglevel;
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
    if (options == NULL) {
        options = "";
    }
    // mux
    if ((end = strstr(options, "mux=")) != NULL) {
        end += 4;
        mux = (int) strtol(end, NULL, 10);
    }
    // loglevel
    if ((loglevel = strstr(options, "loglevel=")) != NULL) {
        loglevel += 9;
        init_log_level(loglevel);
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
    LOGI("raw client %s:%d", raw_server_info->addr, raw_server_info->port);
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

static void generic_request_handler(struct evhttp_request *req, void *ctx) {
    struct event_base *base;
    struct bufferevent *raw = NULL;
    struct evhttp_connection *wss = NULL;
    struct raw_server_info *raw_server_info = ctx;
    char sec_websocket_accept[29];
    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);

    if (!do_websocket_handshake(req, sec_websocket_accept)) {
        goto error;
    }

    wss = evhttp_request_get_connection(req);
    base = evhttp_connection_get_base(wss);
    raw = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (raw == NULL) {
        LOGW("cannot create raw connection");
        goto error;
    }
    if (bufferevent_socket_connect_hostname(raw, NULL, AF_UNSPEC, raw_server_info->addr, raw_server_info->port)) {
        LOGW("cannot connect raw at %s:%u", raw_server_info->addr, raw_server_info->port);
        goto error;
    }

    evhttp_add_header(headers, "Upgrade", "websocket");
    evhttp_add_header(headers, "Connection", "Upgrade");
    evhttp_add_header(headers, "Sec-WebSocket-Accept", (char *) sec_websocket_accept);
    evhttp_send_reply(req, 101, "Switching Protocols", NULL);

    tunnel_wss(raw, wss);
    return;
error:
    evhttp_send_error(req, HTTP_BADREQUEST, "Bad Request");
    if (raw != NULL) {
        bufferevent_free(raw);
    }
}

int main() {
    int code = 1;
    struct event_base *base = NULL;
    struct event_config *cfg = NULL;
    struct evhttp *http_server = NULL;
    const char *addr;
    int port;
    struct raw_server_info raw_server_info;

    memset(&raw_server_info, 0, sizeof(raw_server_info));
    if (init_raw_info(&raw_server_info)) {
        return 1;
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

    init_event_signal(base);

    LOGI("wss-proxy-server/%s libevent/%s", WSS_PROXY_VERSION, event_get_version());
    LOGI("started, pid: %d, ppid: %d", getpid(), getppid());

    event_base_dispatch(base);

    code = 0;
error:
    if (http_server) {
        evhttp_free(http_server);
    }
    if (base) {
        event_base_free(base);
    }
    if (cfg) {
        event_config_free(cfg);
    }
    return code;
}
