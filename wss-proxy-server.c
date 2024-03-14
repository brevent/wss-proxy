#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/listener.h>
#include "common.h"

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

static uint16_t get_http_port(struct evhttp_connection *evcon) {
    char *address;
    uint16_t port;
    evhttp_connection_get_peer(evcon, &address, &port);
    return port;
}

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *ctx) {
    struct wss_frame_client client;
    uint8_t op;
    uint16_t len;
    (void) dst_limit;
    (void) mode;
    (void) ctx;
    if (evbuffer_get_length(src) < sizeof(client) - sizeof(client.unused)) {
        return BEV_NEED_MORE;
    }
    memset(&client, 0, sizeof(client));
    evbuffer_copyout(src, &(client.fop), sizeof(client) - sizeof(client.unused));
    if (!(client.fop & 0x80)) {
        LOGW("fin should be 1 (fragments is unsupported)");
        return BEV_ERROR;
    }
    if (client.fop & 0x70) {
        LOGW("rsv should be 0");
        return BEV_ERROR;
    }
    if (!(client.mlen & 0x80)) {
        LOGW("client request should mask");
        return BEV_ERROR;
    }
    op = client.fop & 0xf;
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
    len = client.mlen & 0x7f;
    if (len < 126) {
        if (evbuffer_get_length(src) < (size_t) len + sizeof(client) - sizeof(client.unused)) {
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, sizeof(client) - sizeof(client.unused));
    } else if (len == 126) {
        if (evbuffer_get_length(src) < sizeof(client)) {
            return BEV_NEED_MORE;
        }
        evbuffer_copyout(src, &(client.extend.fop), sizeof(client));
        len = htons(client.extend.elen);
        if (len > MAX_PAYLOAD_SIZE) {
            LOGW("payload length %d is unsupported", len);
            return BEV_ERROR;
        }
        if (evbuffer_get_length(src) < (size_t) len + sizeof(client)) {
            return BEV_NEED_MORE;
        }
        evbuffer_drain(src, sizeof(client));
    } else {
        LOGW("payload length 64K+ is unsupported");
        return BEV_ERROR;
    }
    if (op == OP_PING || op == OP_PONG) {
        // should we pong to ping?
        evbuffer_drain(src, len);
        return BEV_OK;
    }
    if (client.mask) {
        char buffer[WSS_PAYLOAD_SIZE];
        while (len > 0) {
            int size = evbuffer_remove(src, buffer,MAX_WSS_FRAME(len));
            if (size <= 0) {
                break;
            }
            unmask(buffer, (uint16_t) size, client.mask);
            evbuffer_add(dst, buffer, (uint16_t) size);
            len -= (uint16_t) size;
        }
    } else {
        while (len > 0) {
            int size = evbuffer_remove_buffer(src, dst, MAX_WSS_FRAME(len));
            if (size <= 0) {
                break;
            }
            len -= (uint16_t) size;
        }
    }
    return BEV_OK;
}

static uint8_t *build_wss_frame(struct wss_frame_server *server, enum wss_op op, uint16_t len, uint8_t *header_len) {
    // should we support continuation frame?
    uint8_t fop = 0x80 | (op & 0xf);
    if (len < 126) {
        server->fop = fop;
        server->mlen = (uint8_t) len;
        *header_len = sizeof(FOP_MASK);
        return &(server->fop);
    } else {
        server->extend.fop = fop;
        server->extend.mlen = 126;
        server->extend.elen = ntohs(len);
        *header_len = sizeof(server->extend);
        return &(server->extend.fop);
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
    struct wss_frame_server_close {
        struct wss_frame_server server;
        struct {
            uint16_t reason;
            uint16_t unused; // padding to uint32_t for mask
        };
    } wss_frame_server_close;
    uint8_t *wss_header, wss_header_size;
    uint16_t size = sizeof(wss_frame_server_close.reason);
    wss_frame_server_close.reason = ntohs(reason);
    wss_header = build_wss_frame(&(wss_frame_server_close.server), OP_CLOSE, size, &wss_header_size);
    tev = evhttp_connection_get_bufferevent(wss);
    evbuffer_add(bufferevent_get_output(tev), wss_header, size + wss_header_size);
    LOGD("would close wss %p for peer %d", wss, port);
    bufferevent_setcb(tev, NULL, close_wss_data_cb, close_wss_event_cb, wss);
}

static void raw_forward_cb(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;
    struct bufferevent *tev;
    struct wss_frame_server_data {
        struct wss_frame_server server;
        char buffer[WSS_PAYLOAD_SIZE];
    } wss_frame_server_data;

    tev = evhttp_connection_get_bufferevent(wss);
    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    for (;;) {
        // should we use continuation fame?
        uint8_t *wss_header, wss_header_size;
        int size = evbuffer_remove(src, wss_frame_server_data.buffer, WSS_PAYLOAD_SIZE);
        if (size <= 0) {
            break;
        }
        wss_header = build_wss_frame(&(wss_frame_server_data.server), OP_BINARY, (uint16_t) size, &wss_header_size);
        evbuffer_add(dst, wss_header, size + wss_header_size);
    }
}

static void raw_event_cb(struct bufferevent *raw, short event, void *wss) {
    uint16_t port;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        port = get_http_port(wss);
        bufferevent_free(raw);
        LOGD("connection %u closed, event: 0x%02x", port, event);
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
        bufferevent_getcb(raw, NULL, NULL, NULL, (void **) &wss);
        port = get_http_port(wss);
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

    wss_ready_cb(raw, wss);
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
