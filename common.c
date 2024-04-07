#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#ifdef WSS_PROXY_CLIENT
#include <openssl/rand.h>
#endif
#include "common.h"

void safe_bufferevent_free(struct bufferevent *bev) {
    if (bev->be_ops) {
        bufferevent_free(bev);
    } else {
        bufferevent_udp_free(bev);
    }
}

void bufferevent_udp_free(struct bufferevent *raw) {
#ifdef WSS_PROXY_CLIENT
    LOGD("udp eof for peer %d", get_peer_port(raw));
#endif
#ifdef WSS_PROXY_SERVER
    LOGD("udp eof for peer %d", get_http_port(get_wss(raw)));
#endif
    event_del(&(raw->ev_read));
    evbuffer_free(raw->output);
    evbuffer_free(raw->input);
#ifdef WSS_PROXY_CLIENT
    lh_bufferevent_udp_delete(((struct bufferevent_udp *) raw)->hash, ((struct bufferevent_udp *) raw));
#endif
    free(raw);
}

#define bufferevent_free safe_bufferevent_free

#ifdef WSS_PROXY_CLIENT
uint16_t get_peer_port(struct bufferevent *bev) {
    evutil_socket_t sock;
    ev_socklen_t socklen;
    struct sockaddr_storage sockaddr;

    if (!bev->be_ops) {
        return get_port(((struct bufferevent_udp *) bev)->sockaddr);
    }
    sock = bufferevent_getfd(bev);
    if (sock < 0) {
        return 0;
    }
    socklen = sizeof(sockaddr);
    if (getpeername(sock, (struct sockaddr *) &sockaddr, &socklen) == -1) {
        return 0;
    }
    return get_port((struct sockaddr *)&sockaddr);
}
#endif

#ifdef WSS_PROXY_SERVER
uint16_t get_http_port(struct evhttp_connection *evcon) {
    char *address;
    uint16_t port;
    evhttp_connection_get_peer(evcon, &address, &port);
    return port;
}
#endif

uint16_t get_port(const struct sockaddr *sockaddr) {
    if (sockaddr->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) sockaddr)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) sockaddr)->sin_port);
    }
}

void set_port(struct sockaddr_storage *sockaddr, uint16_t port) {
    if (sockaddr->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(port);
    } else {
        ((struct sockaddr_in *) sockaddr)->sin_port = htons(port);
    }
}

static void check_parent(evutil_socket_t fd, short event, void *arg) {
    (void) fd;
    (void) event;
    (void) arg;
    if (getppid() == 1) {
        LOGE("parent process has been terminated.");
        exit(EXIT_SUCCESS);
    }
}

void log_callback(int severity, const char *msg) {
    switch (severity) {
        case EVENT_LOG_DEBUG:
            LOGD("libevent: %s", msg);
            break;
        case EVENT_LOG_MSG:
            LOGI("libevent: %s", msg);
            break;
        case EVENT_LOG_WARN:
            LOGW("libevent: %s", msg);
            break;
        case EVENT_LOG_ERR:
            LOGE("libevent: %s", msg);
            break;
        default:
            LOGW("???event: %s", msg);
            break;
    }
}

#ifndef NDEBUG
static enum log_level log_level = DEBUG;
#else
static enum log_level log_level = INFO;
#endif

static void set_log_level(enum log_level level) {
    log_level = level;
}

void init_log_level(const char *loglevel) {
    if (loglevel == NULL || !evutil_ascii_strncasecmp(loglevel, "info", 4)) {
        set_log_level(INFO);
    } else if (!evutil_ascii_strncasecmp(loglevel, "debug", 5)) {
        set_log_level(DEBUG);
    } else if (!evutil_ascii_strncasecmp(loglevel, "warn", 4)) {
        set_log_level(WARN);
    } else if (!evutil_ascii_strncasecmp(loglevel, "error", 5)) {
        set_log_level(ERROR);
    }
}

enum log_level get_log_level() {
    return log_level;
}

const char *find_option(const char *options, const char *key, const char *no_value) {
    size_t len;
    const char *pos, *value;
    if (options == NULL) {
        return NULL;
    }
    pos = options;
    len = strlen(key);
    while ((pos = strstr(pos, key)) != NULL) {
        if (pos == options || *(pos - 1) == ';') {
            value = pos + len;
            if (*value == '=') {
                return value + 1;
            } else if (*value == ';' || *value == '\0') {
                return no_value;
            }
        }
        pos += len;
    }
    return NULL;
}

int find_option_port(const char *key, int default_port) {
    char *end;
    const char *value;
    value = find_option(getenv("SS_PLUGIN_OPTIONS"), key, NULL);
    if (value != NULL) {
        int port = (int) strtol(value, &end, 10);
        if (port <= 0 || port > 65535 || (*end != '\0' && *end != ';')) {
            port = -1;
        }
        return port;
    }
    return default_port;
}

static void on_native_signal(int signal) {
    if (signal == SIGINT) {
        LOGW("received interrupt, will exit");
        exit(EXIT_SUCCESS);
    } else if (signal == SIGTERM) {
        LOGW("received termination, will exit");
        exit(EXIT_SUCCESS);
    }
    switch (signal) {
        case SIGUSR1:
            LOGI("received SIGUSR1, change loglevel to debug");
            set_log_level(DEBUG);
            break;
        case SIGUSR2:
            LOGI("received SIGUSR2, change loglevel to info");
            set_log_level(INFO);
            break;
        case SIGPIPE:
            LOGD("received SIGPIPE");
            break;
        default:
            // Handle unknown signal
            break;
    }
}

static void sigquit_cb(evutil_socket_t fd, short event, void *arg) {
    (void) fd;
    (void) event;
    event_base_loopbreak((struct event_base *) arg);
}

int init_event_signal(struct event_base *base, struct event **event_parent, struct event **event_sigquit) {
    struct rlimit rlim;
    struct timeval one_minute = {60, 0};
    *event_parent = event_new(base, -1, EV_PERSIST, check_parent, NULL);
    if (*event_parent) {
        event_add(*event_parent, &one_minute);
    } else {
        LOGW("cannot add event to check parent");
    }
#ifdef RLIMIT_NOFILE
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim_t cur_limit = rlim.rlim_cur;
        rlim_t new_limit;
#if defined(__APPLE__)
        size_t size = sizeof(new_limit);
        if (sysctlbyname("kern.maxfilesperproc", &new_limit, &size, NULL, 0)) {
            new_limit = 10240;
        }
#else
        new_limit = rlim.rlim_max;
#endif
        rlim.rlim_cur = new_limit;
        if (cur_limit < new_limit && setrlimit(RLIMIT_NOFILE, &rlim) == 0) {
            LOGI("open files: %u -> %u", (uint32_t) cur_limit, (uint32_t) rlim.rlim_cur);
        } else {
            LOGI("open files: %u", (uint32_t) cur_limit);
        }
    }
#endif
    signal(SIGINT, on_native_signal);
    signal(SIGTERM, on_native_signal);
    signal(SIGUSR1, on_native_signal);
    signal(SIGUSR2, on_native_signal);
    signal(SIGPIPE, on_native_signal);
    *event_sigquit = evsignal_new(base, SIGQUIT, sigquit_cb, base);
    if (!*event_sigquit) {
        LOGE("cannot event sigquit");
        return -1;
    } else {
        event_add(*event_sigquit, NULL);
        return 0;
    }
}

int is_websocket_key(const char *websocket_key) {
    unsigned char buffer[19];
    if (websocket_key != NULL && strlen((char *) websocket_key) == 24
        && websocket_key[22] == '=' && websocket_key[23] == '='
        && EVP_DecodeBlock(buffer, (unsigned char *) websocket_key, 24) > 15) {
        return 1;
    } else {
        return 0;
    }
}

int calc_websocket_accept(const char *websocket_key, char *websocket_accept) {
    char buffer[61];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    sprintf(buffer, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", websocket_key);
    SHA1((unsigned char *) buffer, 60, sha1);
    return EVP_EncodeBlock((unsigned char *) websocket_accept, sha1, SHA_DIGEST_LENGTH);
}

static uint8_t *build_ws_frame(enum ws_op op, void *payload, uint16_t size, uint8_t *header_size) {
    uint8_t *header;
    struct ws_header_info info;
    memset(&info, 0, sizeof(struct ws_header_info));
    info.fin = 1;
    info.op = op;
#ifdef WSS_PROXY_CLIENT
    info.mask = 1;
#ifndef WSS_MOCK_MASK
    RAND_bytes((unsigned char *) &(info.mask_key), MASK_SIZE);
    mask(payload, size, info.mask_key);
#endif
#endif
    header = build_ws_header(&info, payload, size);
    *header_size = info.header_size;
    return header;
}

static void send_pong(struct evbuffer *src, uint16_t payload_size, uint32_t mask_key, struct bufferevent *raw) {
    struct bufferevent *tev;
    struct evhttp_connection *wss;
    uint8_t *wss_header, header_size;
    struct wss_frame_pong {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[MAX_CONTROL_FRAME_SIZE];
    } wss_frame_pong;
    uint16_t remain_size, size = 0;
    if (payload_size > 0) {
        size = evbuffer_remove(src, wss_frame_pong.buffer, MIN(MAX_CONTROL_FRAME_SIZE, payload_size));
    }
    if ((remain_size = payload_size - size) > 0) {
        evbuffer_drain(src, remain_size);
        LOGD("pong frame too large: %u", payload_size);
        return;
    }
#ifdef WSS_PROXY_CLIENT
    (void) mask_key;
#endif
#ifdef WSS_PROXY_SERVER
    unmask(wss_frame_pong.buffer, (uint16_t) size, mask_key);
#endif
    wss_header = build_ws_frame(OP_PONG, &(wss_frame_pong.buffer), size, &header_size);
    wss = get_wss(raw);
    tev = evhttp_connection_get_bufferevent(wss);
    evbuffer_add(bufferevent_get_output(tev), wss_header, size + header_size);
}

static void reply_close(struct evbuffer *src, uint16_t payload_size, uint32_t mask_key, struct bufferevent *raw) {
    uint16_t reason = CLOSE_NORMAL_CLOSURE;
    if (payload_size >= 2) {
        evbuffer_copyout(src, &reason, 2);
#ifdef WSS_PROXY_CLIENT
        (void) mask_key;
#endif
#ifdef WSS_PROXY_SERVER
        unmask(&reason, 2, mask_key);
#endif
        reason = htons(reason);
    }
    evbuffer_drain(src, payload_size);
    send_close(raw, reason);
}

#ifdef WSS_ENABLE_PING
void send_ping(struct bufferevent *tev, const char *payload, uint8_t size) {
    uint8_t *wss_header, header_size, payload_size;
    struct wss_frame_ping {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[MAX_CONTROL_FRAME_SIZE];
    } wss_frame_ping;
    payload_size = size > 0 ? MIN(size, MAX_WS_HEADER_SIZE): 0;
    if (payload_size > 0) {
        memcpy(wss_frame_ping.buffer, payload, payload_size);
    }
    wss_header = build_ws_frame(OP_PING, &(wss_frame_ping.buffer), payload_size, &header_size);
    evbuffer_add(bufferevent_get_output(tev), wss_header, payload_size + header_size);
}

void set_ping_timeout(struct bufferevent *wev, int sec) {
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    bufferevent_set_timeouts(wev, &tv, NULL);
}
#endif

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *raw) {
    uint8_t header[MAX_WS_HEADER_SIZE];
    ssize_t header_size;
    int result;
    struct ws_header_info info;

    (void) dst_limit;
    (void) mode;

    header_size = evbuffer_copyout(src, header, MAX_WS_HEADER_SIZE);
    if (header_size < WS_HEADER_SIZE) {
        return BEV_NEED_MORE;
    }
    memset(&info, 0, sizeof(struct ws_header_info));
    result = parse_ws_header(header, header_size, &info);
    if (result < 0) {
        LOGW("payload length 64K+ is unsupported");
        send_close(raw, CLOSE_MESSAGE_TOO_BIG);
        return BEV_ERROR;
    } else if (result > 0) {
        return BEV_NEED_MORE;
    }
    if (!info.fin) {
        LOGW("fin should be 1 (fragments is unsupported)");
        send_close(raw, CLOSE_PROTOCOL_ERROR);
        return BEV_ERROR;
    }
    if (info.rsv) {
        LOGW("rsv should be 0");
        send_close(raw, CLOSE_PROTOCOL_ERROR);
        return BEV_ERROR;
    }
#ifdef WSS_PROXY_CLIENT
    if (info.mask) {
        LOGW("server response shouldn't mask");
        return BEV_ERROR;
    }
#endif
#ifdef WSS_PROXY_SERVER
    if (!info.mask) {
        LOGW("client request should mask");
        send_close(raw, CLOSE_PROTOCOL_ERROR);
        return BEV_ERROR;
    }
#endif
    switch (info.op) {
        case OP_CONTINUATION:
            LOGW("continuation frame is unsupported");
            send_close(raw, CLOSE_UNSUPPORTED_DATA);
            return BEV_ERROR;
        case OP_TEXT:
            LOGW("text frame is unsupported");
            send_close(raw, CLOSE_UNSUPPORTED_DATA);
            return BEV_ERROR;
        case OP_BINARY:
            break;
        case OP_CLOSE:
#ifdef WSS_PROXY_CLIENT
            LOGD("server send close frame");
#endif
#ifdef WSS_PROXY_SERVER
            LOGD("client send close frame");
#endif
            break;
        case OP_PING:
#ifdef WSS_PROXY_CLIENT
            LOGD("server send ping frame");
#endif
#ifdef WSS_PROXY_SERVER
            LOGD("client send ping frame");
#endif
            break;
        case OP_PONG:
#ifdef WSS_PROXY_CLIENT
            LOGD("server send pong frame");
#endif
#ifdef WSS_PROXY_SERVER
            LOGD("client send pong frame");
#endif
            break;
        default:
            LOGW("op 0x%x is unsupported", info.op);
            send_close(raw, CLOSE_PROTOCOL_ERROR);
            return BEV_ERROR;
    }
    if (evbuffer_get_length(src) < (uint32_t) info.header_size + info.payload_size) {
        return BEV_NEED_MORE;
    }
    if (info.op == OP_PONG) {
        evbuffer_drain(src, info.header_size + info.payload_size);
        return BEV_OK;
    }
    evbuffer_drain(src, info.header_size);
    if (info.op == OP_PING) {
        send_pong(src, info.payload_size, info.mask_key, raw);
        return BEV_OK;
    }
    if (info.op == OP_CLOSE) {
        reply_close(src, info.payload_size, info.mask_key, raw);
        return BEV_ERROR;
    }
#ifdef WSS_PROXY_SERVER
    if (info.mask_key) {
        char buffer[MAX_WSS_PAYLOAD_SIZE];
        uint16_t payload_size = info.payload_size;
        while (payload_size > 0) {
            int size = evbuffer_remove(src, buffer, MIN(payload_size, MAX_WSS_PAYLOAD_SIZE));
            if (size <= 0) {
                LOGW("cannot read more data");
                send_close(raw, CLOSE_INTERNAL_ERROR);
                return BEV_ERROR;
            }
            unmask(buffer, (uint16_t) size, info.mask_key);
            evbuffer_add(dst, buffer, (uint16_t) size);
            payload_size -= (uint16_t) size;
        }
        return BEV_OK;
    }
#endif
    {
        uint16_t payload_size = info.payload_size;
        while (payload_size > 0) {
            int size = evbuffer_remove_buffer(src, dst, payload_size);
            if (size <= 0) {
                LOGW("cannot read more data");
                send_close(raw, CLOSE_INTERNAL_ERROR);
                return BEV_ERROR;
            }
            payload_size -= (uint16_t) size;
        }
        return BEV_OK;
    }
}

static void close_wss_data_cb(struct bufferevent *tev, void *wss) {
    (void) tev;
    LOGD("close wss %p in read callback", wss);
    evhttp_connection_free(wss);
}

static void close_wss_event_cb(struct bufferevent *tev, short event, void *wss) {
    (void) tev;
    LOGD("close wss %p in event callback, event: 0x%02x", wss, event);
    evhttp_connection_free(wss);
}

static void wss_closed_write_cb(struct bufferevent *raw, void *wss) {
    (void) raw;
    (void) wss;
}

int send_close(struct bufferevent *raw, uint16_t reason) {
    struct bufferevent *tev;
    struct evhttp_connection *wss = get_wss(raw);
    if (raw->writecb == wss_closed_write_cb) {
        LOGD("wss %p closed", wss);
        return 0;
    } else {
        uint8_t *wss_header, header_size;
        struct wss_frame_close {
            char header[MAX_WS_HEADER_SIZE];
            uint16_t reason;
        } wss_frame_close;
        raw->writecb = wss_closed_write_cb;
        wss_frame_close.reason = ntohs(reason);
        wss_header = build_ws_frame(OP_CLOSE, &(wss_frame_close.reason), 2, &header_size);
        tev = evhttp_connection_get_bufferevent(wss);
        evbuffer_add(bufferevent_get_output(tev), wss_header, 2 + header_size);
        return 1;
    }
}

enum close_reason {
    close_reason_raw,
    close_reason_wss,
};

static void close_wss(struct bufferevent *raw, enum close_reason close_reason, short event) {
    int sent;
    struct evhttp_connection *wss = get_wss(raw);
    if (close_reason == close_reason_raw) {
        sent = send_close(raw, CLOSE_GOING_AWAY);
    } else if (event & BEV_EVENT_EOF) {
        // we can do nothing
        sent = 0;
    } else {
        // we should have sent out
        sent = send_close(raw, CLOSE_INTERNAL_ERROR);
    }
    bufferevent_free(raw);
    if (sent) {
        struct bufferevent *tev = evhttp_connection_get_bufferevent(wss);
        bufferevent_setcb(tev, close_wss_data_cb, NULL, close_wss_event_cb, wss);
    } else {
        LOGD("close wss %p as close was send", wss);
        evhttp_connection_free(wss);
    }
}

static void raw_forward_cb(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;
    struct bufferevent *tev;
    int payload_size;

    tev = evhttp_connection_get_bufferevent(wss);
    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    payload_size = raw->be_ops ? WSS_PAYLOAD_SIZE : MAX_WSS_PAYLOAD_SIZE;
    for (;;) {
        // should we use continuation fame?
        uint8_t *wss_header, wss_header_size;
        struct wss_frame_data {
            char header[MAX_WS_HEADER_SIZE];
            char buffer[MAX_WSS_PAYLOAD_SIZE];
        } wss_frame_data;
        int size = evbuffer_remove(src, wss_frame_data.buffer, payload_size);
        if (size <= 0) {
            break;
        }
        wss_header = build_ws_frame(OP_BINARY, &(wss_frame_data.buffer), (uint16_t) size, &wss_header_size);
        evbuffer_add(dst, wss_header, (uint16_t) size + wss_header_size);
    }
}

void raw_event_cb(struct bufferevent *raw, short event, void *wss) {
    uint16_t port;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_http_port(wss);
#endif
        LOGD("connection %u closed for wss, event: 0x%02x", port, event);
        bufferevent_free(raw);
        evhttp_connection_free(wss);
    }
}

static void raw_event_cb_wss(struct bufferevent *raw, short event, void *wss) {
    uint16_t port;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_http_port(wss);
#endif
        LOGD("connection %u closed for wss %p, event: 0x%02x", port, wss, event);
        close_wss(raw, close_reason_raw, event);
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
        wss = get_wss(raw);
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_http_port(wss);
#endif
        LOGD("connection %u closing from wss %p, event: 0x%02x", port, wss, event);
        close_wss(raw, close_reason_wss, event);
    }
#ifdef WSS_ENABLE_PING
    if (event & BEV_EVENT_TIMEOUT) {
        struct bufferevent *tev = bufferevent_get_underlying(wev);
        bufferevent_enable(tev, EV_READ | EV_WRITE);
        LOGD("timeout, send ping, event: 0x%x", event);
        send_ping(tev, NULL, 0);
    }
#endif
}

static void wss_close_cb(struct evhttp_connection *wss, void *wev) {
    LOGD("wss %p closed", wss);
    bufferevent_free(wev);
}

void tunnel_wss(struct bufferevent *raw, struct evhttp_connection *wss) {
    struct bufferevent *tev;
    struct bufferevent *wev;

    tev = evhttp_connection_get_bufferevent(wss);
    wev = bufferevent_filter_new(tev, wss_input_filter, NULL, 0, NULL, raw);
    evhttp_connection_set_closecb(wss, wss_close_cb, wev);

    bufferevent_enable(wev, EV_READ | EV_WRITE);
    bufferevent_setcb(wev, wss_forward_cb, NULL, wss_event_cb, raw);
#ifdef WSS_ENABLE_PING
    set_ping_timeout(tev, 30);
#endif

    if (raw->be_ops) {
        bufferevent_enable(raw, EV_READ | EV_WRITE);
        bufferevent_setcb(raw, raw_forward_cb, NULL, raw_event_cb_wss, wss);
    } else {
        raw->enabled = EV_READ | EV_WRITE;
        raw->readcb = raw_forward_cb;
        raw->errorcb = raw_event_cb_wss;
        raw->cbarg = wss;
    }
}

static void wss_event_cb_ss(struct bufferevent *tev, short event, void *raw) {
    uint16_t port;
    struct evhttp_connection *wss;
    (void) tev;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        wss = get_wss(raw);
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_http_port(wss);
#endif
        LOGD("connection %u closing from wss, event: 0x%02x", port, event);
        bufferevent_free(raw);
        evhttp_connection_free(wss);
    }
}

static void raw_forward_cb_ss(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;

    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(evhttp_connection_get_bufferevent(wss));
    evbuffer_add_buffer(dst, src);
}

void tunnel_ss(struct bufferevent *raw, struct evhttp_connection *wss) {
    struct bufferevent *tev;

    tev = evhttp_connection_get_bufferevent(wss);
    bufferevent_enable(tev, EV_READ | EV_WRITE);
    bufferevent_setcb(tev, wss_forward_cb, NULL, wss_event_cb_ss, raw);

    if (raw->be_ops) {
        bufferevent_enable(raw, EV_READ | EV_WRITE);
        bufferevent_setcb(raw, raw_forward_cb_ss, NULL, raw_event_cb, wss);
    } else {
        raw->enabled = EV_READ | EV_WRITE;
        raw->readcb = raw_forward_cb_ss;
        raw->errorcb = raw_event_cb;
        raw->cbarg = wss;
    }
}

void udp_send_cb(struct evbuffer *buf, const struct evbuffer_cb_info *info, void *arg) {
    char *payload;
    uint8_t offset;
    unsigned length;
    uint16_t payload_length;
    struct udp_frame udp_frame;
    struct bufferevent *raw = arg;
    struct bufferevent_udp *bev_udp = arg;
    size_t size = evbuffer_get_length(buf);
    (void) info;
    while (size > 0) {
        if (raw->errorcb == raw_event_cb) {
            offset = 2;
            if (size < offset) {
                break;
            }
            if (evbuffer_copyout(buf, &(udp_frame.raw.length), offset) < 0) {
                LOGD("cannot read udp 2 for %d, will try later", get_port(bev_udp->sockaddr));
                break;
            }
            payload_length = htons(udp_frame.raw.length);
            if (size < payload_length + offset) {
                LOGD("cannot read udp %u + 2 for %d, will try later", payload_length, get_port(bev_udp->sockaddr));
                break;
            }
        } else {
            offset = 0;
            payload_length = size;
        }
        length = payload_length + offset;
        if (evbuffer_copyout(buf, &udp_frame, length) != (int) length) {
            LOGE("cannot copy udp %d for %d", (int) length, get_port(bev_udp->sockaddr));
            raw_event_cb(raw, BEV_EVENT_ERROR, get_wss(raw));
            break;
        }
        payload = raw->errorcb == raw_event_cb ? udp_frame.raw.buffer : udp_frame.buffer;
        if (sendto(bev_udp->sock, payload, payload_length, 0, bev_udp->sockaddr, bev_udp->socklen) < 0) {
            // is there any chance to sendto later?
            int socket_error = evutil_socket_geterror(bev_udp->sock);
            LOGE("cannot send udp to %d: %s", get_port(bev_udp->sockaddr), evutil_socket_error_to_string(socket_error));
            raw_event_cb(raw, BEV_EVENT_ERROR, get_wss(raw));
            break;
        }
        LOGD("udp sent %d to peer %d", payload_length, get_port(bev_udp->sockaddr));
        evbuffer_drain(buf, length);
        size -= length;
    }
}

int udp_read_cb(evutil_socket_t sock, struct bufferevent *raw, struct sockaddr *sockaddr, ev_socklen_t *socklen) {
    struct udp_frame udp_frame;
    struct timeval one_minute = {60, 0};
    char *payload = raw->errorcb == raw_event_cb ? udp_frame.raw.buffer : udp_frame.buffer;
    ssize_t size = recvfrom(sock, payload, MAX_UDP_FRAME_SIZE, 0, sockaddr, socklen);
#ifdef WSS_PROXY_CLIENT
#define get_common_port() get_port(sockaddr)
#endif
#ifdef WSS_PROXY_SERVER
#define get_common_port() get_http_port(get_wss(raw))
#endif
    if (!raw->readcb || !raw->errorcb) {
        LOGE("no readcb or errorcb");
        return -1;
    }
    if (size < 0) {
        int socket_error = evutil_socket_geterror(sock);
        if (!EVUTIL_ERR_RW_RETRIABLE(socket_error)) {
            LOGE("cannot recvfrom udp: %s", evutil_socket_error_to_string(socket_error));
        }
        return -1;
    } else if (size == 0) {
        LOGE("udp receive 0 for peer %d", get_common_port());
        raw->errorcb(raw, BEV_EVENT_EOF, raw->cbarg);
    } else {
        size_t old_size = evbuffer_get_length(raw->input);
        if (old_size) {
            LOGE("udp receive %d for peer %d, previous: %d", (int) size, get_common_port(), (int) old_size);
        }
        event_add(&(raw->ev_read), &one_minute);
        if (raw->errorcb == raw_event_cb) {
            udp_frame.raw.length = ntohs(size);
            evbuffer_add(raw->input, &udp_frame, size + 2);
        } else {
            evbuffer_add(raw->input, &udp_frame, size);
        }
        LOGD("udp read %d for peer %d", (int) size, get_common_port());
        raw->readcb(raw, raw->cbarg);
    }
    return 0;
}

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line) {
    char *keylog_file_name;
    FILE *keylog_file_fp;

    (void) ssl;

    keylog_file_name = getenv("SSLKEYLOGFILE");
    if (!keylog_file_name) {
        return;
    }

#if defined(_WIN32)
#define FOPEN_APPEND_TEXT "at"
#else
#define FOPEN_APPEND_TEXT "a"
#endif
    keylog_file_fp = fopen(keylog_file_name, FOPEN_APPEND_TEXT);
    if (keylog_file_fp) {
        fprintf(keylog_file_fp, "%s\n", line);
        fclose(keylog_file_fp);
    }
}
#endif
