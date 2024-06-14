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

static int send_close(struct bufferevent *tev, uint16_t reason);

static void tev_write_cb(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg);

void bufferevent_set_context(struct bufferevent *bev, void *context) {
    if (context == NULL || (!bev->wm_read.low && !bev->wm_write.low)) {
        bev->wm_read.low = bev->wm_write.low = (size_t) context;
    }
}

void *bufferevent_get_context(struct bufferevent *bev) {
    if (bev->wm_read.low && bev->wm_write.low) {
        return bev->wm_read.low == bev->wm_write.low ? (void *) bev->wm_read.low : NULL;
    }
    return NULL;
}

void safe_bufferevent_free(struct bufferevent *bev) {
    struct bev_context **bev_context;

    LOGD("free %p", bev);
    bev_context = bufferevent_get_context(bev);
    if (bev_context != NULL && *bev_context != NULL) {
        (*bev_context)->free(bev_context);
        bufferevent_set_context(bev, NULL);
    }
    bufferevent_free(bev);
}

#define bufferevent_free safe_bufferevent_free

static int is_udp(struct bufferevent *bev) {
    struct bev_context_udp *bev_context_udp;

    bev_context_udp = bufferevent_get_context(bev);
    return bev_context_udp && bev_context_udp->bev_context == &const_bev_context_udp;
}

static void bev_context_udp_free(void *context) {
    lh_bev_context_udp_delete(((struct bev_context_udp *) context)->hash, context);
    free(context);
}

const struct bev_context const_bev_context_udp = {
        "udp",
        bev_context_udp_free,
};

static void free_udp(bev_context_udp *udp) {
    struct bufferevent *raw, *wev, *tev;

    raw = udp->bev;
    wev = raw->cbarg;
    tev = wev ? bufferevent_get_underlying(wev) : NULL;
    LOGD("free udp for peer %d, raw: %p, wev: %p, tev: %p", get_peer_port(raw), raw, wev, tev);
    if (tev) {
        close_wss(tev, close_reason_eof, BEV_EVENT_EOF);
    } else {
        raw->errorcb(raw, BEV_EVENT_EOF, get_cbarg(raw));
    }
}

void free_all_udp(LHASH_OF(bev_context_udp) *hash) {
    lh_bev_context_udp_set_down_load(hash, 0);
    lh_bev_context_udp_doall(hash, free_udp);
    lh_bev_context_udp_free(hash);
}

uint16_t get_peer_port(struct bufferevent *bev) {
    evutil_socket_t sock;
    ev_socklen_t socklen;
    struct sockaddr_storage sockaddr;
    struct bev_context_udp *bev_context_udp;

    bev_context_udp = bufferevent_get_context(bev);
    if (bev_context_udp && bev_context_udp->bev_context == &const_bev_context_udp) {
        return get_port(bev_context_udp->sockaddr);
    }
    sock = bufferevent_getfd(bev);
    if (sock < 0) {
        return 0;
    }
    socklen = sizeof(sockaddr);
    if (getpeername(sock, (struct sockaddr *) &sockaddr, &socklen) == -1) {
        return 0;
    }
    return get_port((struct sockaddr *) &sockaddr);
}

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
static volatile int log_level = DEBUG;
#else
static volatile int log_level = INFO;
#endif

static volatile int log_to_syslog = -1;

static void set_log_level(int level) {
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

int get_log_level() {
    return log_level;
}

int use_syslog(void) {
    if (log_to_syslog == -1) {
#ifdef HAVE_SYSLOG
        log_to_syslog = find_option(getenv("SS_PLUGIN_OPTIONS"), "syslog", "1") != NULL;
        if (log_to_syslog) {
            openlog(LOGGER_NAME, LOG_PID | LOG_CONS, LOG_DAEMON);
        }
#else
        log_to_syslog = 0;
#endif
    }
    return log_to_syslog;
}

void close_syslog(void) {
#ifdef HAVE_SYSLOG
    if (log_to_syslog) {
        closelog();
    }
#endif
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
    struct rlimit rlimit;
    struct timeval one_minute = {60, 0};
    *event_parent = event_new(base, -1, EV_PERSIST, check_parent, NULL);
    if (*event_parent) {
        event_add(*event_parent, &one_minute);
    } else {
        LOGW("cannot add event to check parent");
    }
#ifdef RLIMIT_NOFILE
    if (getrlimit(RLIMIT_NOFILE, &rlimit) == 0) {
        rlim_t cur_limit = rlimit.rlim_cur;
        rlim_t new_limit;
#if defined(__APPLE__)
        size_t size = sizeof(new_limit);
        if (sysctlbyname("kern.maxfilesperproc", &new_limit, &size, NULL, 0)) {
            new_limit = 10240;
        }
#else
        new_limit = rlimit.rlim_max;
#endif
        rlimit.rlim_cur = new_limit;
        if (cur_limit < new_limit && setrlimit(RLIMIT_NOFILE, &rlimit) == 0) {
            LOGI("open files: %u -> %u", (uint32_t) cur_limit, (uint32_t) rlimit.rlim_cur);
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
    if (websocket_key != NULL && strlen(websocket_key) >= 26
        && websocket_key[22] == '=' && websocket_key[23] == '='
        && websocket_key[24] == '\r' && websocket_key[25] == '\n'
        && EVP_DecodeBlock(buffer, (unsigned char *) websocket_key, 24) > 15) {
        return 1;
    } else {
        return 0;
    }
}

int calc_websocket_accept(const char *websocket_key, char *websocket_accept) {
    char buffer[60];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    memcpy(buffer, websocket_key, 24);
    memcpy(buffer + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
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

static void send_pong(struct evbuffer *src, uint16_t payload_size, uint32_t mask_key,
                      struct bufferevent *tev, enum ws_op op) {
    uint8_t *wss_header, header_size;
    struct wss_frame_pong {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[MAX_CONTROL_FRAME_SIZE];
    } wss_frame_pong;
    uint16_t size = 0;
    if (payload_size > 0) {
        size = evbuffer_copyout(src, wss_frame_pong.buffer, MIN(MAX_CONTROL_FRAME_SIZE, payload_size));
        evbuffer_drain(src, payload_size);
    }
#ifdef WSS_PROXY_CLIENT
    (void) mask_key;
#endif
#ifdef WSS_PROXY_SERVER
    unmask(wss_frame_pong.buffer, (uint16_t) size, mask_key);
#endif
    wss_header = build_ws_frame(op, &(wss_frame_pong.buffer), size, &header_size);
    evbuffer_add(bufferevent_get_output(tev->cbarg), wss_header, size + header_size);
}

static void reply_close(struct evbuffer *src, uint16_t payload_size, uint32_t mask_key, struct bufferevent *tev) {
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
    send_close(tev, reason);
}

#ifdef WSS_ENABLE_PING
void send_ping(struct bufferevent *tev, const char *payload, uint8_t size) {
    uint8_t *wss_header, header_size, payload_size;
    struct wss_frame_ping {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[MAX_CONTROL_FRAME_SIZE];
    } wss_frame_ping;
    payload_size = size > 0 ? MIN(size, MAX_WS_HEADER_SIZE) : 0;
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

static enum bufferevent_filter_result common_wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                              void *tev, int tcp) {
    uint8_t header[MAX_WS_HEADER_SIZE];
    ssize_t header_size;
    int result;
    struct ws_header_info info;
    struct udp_frame udp_frame;

    header_size = evbuffer_copyout(src, header, sizeof(header));
    if (header_size < WS_HEADER_SIZE) {
        return BEV_NEED_MORE;
    }
    memset(&info, 0, sizeof(struct ws_header_info));
    result = parse_ws_header(header, header_size, &info);
    if (result < 0) {
        LOGW("payload length 64K+ is unsupported");
        send_close(tev, CLOSE_MESSAGE_TOO_BIG);
        return BEV_ERROR;
    } else if (result > 0) {
        return BEV_NEED_MORE;
    }
    if (!info.fin) {
        LOGW("fin should be 1 (fragments is unsupported)");
        send_close(tev, CLOSE_PROTOCOL_ERROR);
        return BEV_ERROR;
    }
    if (info.rsv) {
        LOGW("rsv should be 0");
        send_close(tev, CLOSE_PROTOCOL_ERROR);
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
        send_close(tev, CLOSE_PROTOCOL_ERROR);
        return BEV_ERROR;
    }
#endif
    switch (info.op) {
        case OP_CONTINUATION:
            LOGW("continuation frame is unsupported");
            send_close(tev, CLOSE_UNSUPPORTED_DATA);
            return BEV_ERROR;
        case OP_TEXT:
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
            send_close(tev, CLOSE_PROTOCOL_ERROR);
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
        send_pong(src, info.payload_size, info.mask_key, tev, OP_PONG);
        return BEV_OK;
    }
    if (info.op == OP_TEXT) {
        send_pong(src, info.payload_size, info.mask_key, tev, OP_TEXT);
        return BEV_OK;
    }
    if (info.op == OP_CLOSE) {
        reply_close(src, info.payload_size, info.mask_key, tev);
        return BEV_ERROR;
    }
    if (evbuffer_remove(src, udp_frame.buffer, info.payload_size) != info.payload_size) {
        LOGW("cannot read more data");
        send_close(tev, CLOSE_INTERNAL_ERROR);
        return BEV_ERROR;
    }
    if (info.mask_key) {
        unmask(udp_frame.buffer, info.payload_size, info.mask_key);
    }
    if (tcp) {
        evbuffer_add(dst, udp_frame.buffer, info.payload_size);
    } else {
        udp_frame.length = ntohs(info.payload_size);
        evbuffer_add(dst, &udp_frame, info.payload_size + UDP_FRAME_LENGTH_SIZE);
    }
    return BEV_OK;
}

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *tev) {
    (void) dst_limit;
    (void) mode;
    return common_wss_input_filter(src, dst, tev, 1);
}

static enum bufferevent_filter_result wss_input_filter_udp(struct evbuffer *src, struct evbuffer *dst,
                                                           ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                           void *tev) {
    (void) dst_limit;
    (void) mode;
    return common_wss_input_filter(src, dst, tev, 0);
}

static void close_wev(struct bufferevent *wev, struct bufferevent *tev) {
    if (wev->cbarg && wev->cbarg != tev) {
        evbuffer_remove_cb(tev->output, tev_write_cb, wev->cbarg);
        bufferevent_free(wev->cbarg);
        wev->cbarg = NULL;
    }
    bufferevent_free(wev);
}

static void do_close_wss(struct bufferevent *tev) {
    if (tev->cbarg) {
        close_wev(tev->cbarg, tev);
    }
    bufferevent_free(tev);
}

static void close_wss_data_cb(struct bufferevent *tev, void *arg) {
    (void) arg;
    LOGD("close wss %p in data callback", tev);
    do_close_wss(tev);
}

static void close_wss_event_cb(struct bufferevent *tev, short event, void *arg) {
    (void) arg;
    LOGD("close wss %p in event callback, event: 0x%02x", tev, event);
    do_close_wss(tev);
}

static int send_close(struct bufferevent *tev, uint16_t reason) {
    struct bufferevent *wev = tev->cbarg;
    if (wev == NULL) {
        LOGD("wss %p closed", tev);
        return 0;
    } else {
        uint8_t *wss_header, header_size;
        struct wss_frame_close {
            char header[MAX_WS_HEADER_SIZE];
            uint16_t reason;
        } wss_frame_close;
        wss_frame_close.reason = ntohs(reason);
        wss_header = build_ws_frame(OP_CLOSE, &(wss_frame_close.reason), 2, &header_size);
        evbuffer_add(bufferevent_get_output(tev->cbarg), wss_header, 2 + header_size);
        return 1;
    }
}

void close_wss(struct bufferevent *tev, enum close_reason close_reason, short event) {
    int close_later;
    struct bufferevent *wev;

    if (close_reason == close_reason_raw) {
        close_later = send_close(tev, CLOSE_GOING_AWAY);
    } else if (close_reason == close_reason_eof) {
        send_close(tev, CLOSE_GOING_AWAY);
        close_later = 0;
    } else if (event & BEV_EVENT_EOF) {
        // we can do nothing
        close_later = 0;
    } else {
        // we should have sent out
        close_later = send_close(tev, CLOSE_INTERNAL_ERROR);
    }
    wev = tev->cbarg;
    if (close_later) {
        LOGD("close wss %p later", tev);
        bufferevent_setcb(tev, close_wss_data_cb, NULL, close_wss_event_cb, NULL);
        if (wev) {
            close_wev(wev, tev);
        }
    } else {
        LOGD("close wss %p", tev);
        do_close_wss(tev);
    }
}

static void raw_forward_cb(struct bufferevent *raw, void *tev) {
    struct evbuffer *src;
    struct evbuffer *dst;
    uint8_t udp;
    size_t total_size;

    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    udp = is_udp(raw);
    total_size = evbuffer_get_length(src);
    while (total_size > 0) {
        // should we use continuation fame?
        uint8_t *wss_header, wss_header_size;
        struct wss_frame_data {
            union {
                char header[MAX_WS_HEADER_SIZE];
                struct {
                    char unused[MAX_WS_HEADER_SIZE - UDP_FRAME_LENGTH_SIZE];
                    uint16_t length;
                };
            };
            char buffer[MAX_WSS_PAYLOAD_SIZE];
        } wss_frame_data;
        int size;
        if (!udp) {
            size = evbuffer_remove(src, wss_frame_data.buffer, WSS_PAYLOAD_SIZE);
            if (size <= 0) {
                LOGE("remove %d from src, total size: %d", size, (int) total_size);
                break;
            }
            total_size -= size;
        } else {
            size_t udp_frame_size;
            if (total_size < UDP_FRAME_LENGTH_SIZE) {
                LOGW("total size too small: %d", (int) total_size);
                break;
            }
            if (evbuffer_copyout(src, &(wss_frame_data.length), UDP_FRAME_LENGTH_SIZE) != UDP_FRAME_LENGTH_SIZE) {
                LOGE("cannot copy 2 from src for payload, total size: %d", (int) total_size);
                break;
            }
            size = htons(wss_frame_data.length);
            udp_frame_size = size + UDP_FRAME_LENGTH_SIZE;
            if (total_size < udp_frame_size) {
                LOGE("total size too small: %d, payload: %d", (int) total_size, (int) size);
                break;
            }
            if (evbuffer_copyout(src, &(wss_frame_data.length), udp_frame_size) != (int) udp_frame_size) {
                LOGE("cannot copy %d from src for wss_frame_data, total size: %d",
                     (int) udp_frame_size, (int) total_size);
                break;
            }
            evbuffer_drain(src, udp_frame_size);
            total_size -= udp_frame_size;
        }
        wss_header = build_ws_frame(OP_BINARY, &(wss_frame_data.buffer), (uint16_t) size, &wss_header_size);
        evbuffer_add(dst, wss_header, (uint16_t) size + wss_header_size);
    }
}

static enum bufferevent_filter_result wss_output_filter(struct evbuffer *src, struct evbuffer *dst,
                                                        ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                        void *tev) {
    (void) dst_limit;
    (void) mode;
    (void) tev;
    evbuffer_add_buffer(dst, src);
    return BEV_OK;
}

void raw_event_cb(struct bufferevent *raw, short event, void *tev) {
    uint16_t port;

#ifdef WSS_PROXY_CLIENT
    port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
    (void) raw;
    port = get_peer_port(tev);
#endif
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LOGD("connection %u closed for wss %p, event: 0x%02x", port, tev, event);
        do_close_wss(tev);
    } else if (event & BEV_EVENT_TIMEOUT) {
        LOGW("connection %u timeout for wss %p, event: 0x%02x", port, tev, event);
        do_close_wss(tev);
    }
}

static void raw_event_cb_wss(struct bufferevent *raw, short event, void *wev) {
    uint16_t port;
    struct bufferevent *tev;

    (void) raw;
    tev = bufferevent_get_underlying(wev);
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_peer_port(tev);
#endif
        LOGD("connection %u closed for wss %p, event: 0x%02x", port, tev, event);
        if (tev && tev->cbarg) {
            close_wss(tev, close_reason_raw, event);
        } else {
            bufferevent_free(raw);
        }
    }
}

static void wss_forward_cb(struct bufferevent *wev, void *raw) {
    struct evbuffer *src;
    struct evbuffer *dst;

    src = bufferevent_get_input(wev);
    if (!evbuffer_get_length(src)) {
        return;
    }
    dst = bufferevent_get_output(raw);
    evbuffer_add_buffer(dst, src);
}

static void wss_event_cb(struct bufferevent *wev, short event, void *raw) {
    uint16_t port;
    struct bufferevent *tev;

    tev = bufferevent_get_underlying(wev);
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        port = get_peer_port(tev);
#endif
        LOGD("connection %u closing from wss %p, event: 0x%02x", port, get_cbarg(raw), event);
        close_wss(tev, close_reason_wss, event);
    }
#ifdef WSS_ENABLE_PING
    if (event & BEV_EVENT_TIMEOUT) {
        bufferevent_enable(tev, EV_READ | EV_WRITE);
        LOGD("timeout, send ping, event: 0x%x", event);
        send_ping(wev, NULL, 0);
    }
#endif
}

static void tev_write_cb(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg) {
    size_t length;
    struct bufferevent *raw;

    raw = arg;
    if (is_udp(raw)) {
        return;
    }
    length = evbuffer_get_length(buffer);
    if (info->n_deleted) {
        if (length <= MIN_PROXY_BUFFER && length + info->n_deleted > MIN_PROXY_BUFFER) {
            LOGD("enable raw for read, length: %zu", length);
            bufferevent_enable(raw, EV_READ);
        }
    } else if (info->n_added) {
        if (length >= MAX_PROXY_BUFFER && length - info->n_added < MAX_PROXY_BUFFER) {
            LOGD("disable raw for read, length: %zu", length);
            bufferevent_disable(raw, EV_READ);
        }
    }
}

void tunnel_wss(struct bufferevent *raw, struct bufferevent *tev, bufferevent_filter_cb output_filter) {
    struct bufferevent *wev;
    bufferevent_filter_cb tev_input_filter, tev_output_filter;

    evbuffer_add_cb(tev->output, tev_write_cb, raw);
    tev_input_filter = is_udp(raw) ? wss_input_filter_udp : wss_input_filter;
    tev_output_filter = output_filter ? output_filter : wss_output_filter;
    wev = bufferevent_filter_new(tev, tev_input_filter, tev_output_filter, 0, NULL, tev);
    LOGD("wev: %p, tev: %p, raw: %p", wev, tev, raw);

    bufferevent_enable(wev, EV_READ | EV_WRITE);
    bufferevent_setcb(wev, wss_forward_cb, NULL, wss_event_cb, raw);
#ifdef WSS_ENABLE_PING
    set_ping_timeout(tev, 30);
#endif

    bufferevent_enable(raw, EV_READ | EV_WRITE);
    bufferevent_setcb(raw, raw_forward_cb, NULL, raw_event_cb_wss, wev);
    raw->readcb(raw, raw->cbarg);
}

static void wss_event_cb_ss(struct bufferevent *tev, short event, void *raw) {
    uint16_t port;
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
#ifdef WSS_PROXY_CLIENT
        port = get_peer_port(raw);
#endif
#ifdef WSS_PROXY_SERVER
        (void) raw;
        port = get_peer_port(tev);
#endif
        LOGD("connection %u closing from wss %p, event: 0x%02x", port, tev, event);
        do_close_wss(tev);
    }
}

static void raw_forward_cb_ss(struct bufferevent *raw, void *tev) {
    struct evbuffer *src;
    struct evbuffer *dst;

    src = bufferevent_get_input(raw);
    if (!evbuffer_get_length(src)) {
        return;
    }
    dst = bufferevent_get_output(tev);
    evbuffer_add_buffer(dst, src);
}

void tunnel_ss(struct bufferevent *raw, struct bufferevent *tev) {
    evbuffer_add_cb(tev->output, tev_write_cb, raw);
    bufferevent_enable(tev, EV_READ | EV_WRITE);
    bufferevent_setcb(tev, wss_forward_cb, NULL, wss_event_cb_ss, raw);

    bufferevent_enable(raw, EV_READ | EV_WRITE);
    bufferevent_setcb(raw, raw_forward_cb_ss, NULL, raw_event_cb, tev);
    raw->readcb(raw, raw->cbarg);
}

void bev_context_udp_writecb(evutil_socket_t fd, short event, void *arg) {
    int err;
    size_t size;
    ssize_t res;
    unsigned length;
    uint16_t payload_length;
    struct evbuffer *buf;
    struct bufferevent *raw;
    struct bev_context_udp *bev_context_udp;
    struct udp_frame udp_frame;
    short what = BEV_EVENT_WRITING;

    (void) event;
    raw = arg;
    bev_context_udp = bufferevent_get_context(raw);
    buf = raw->output;
    size = evbuffer_get_length(buf);

    if (size < UDP_FRAME_LENGTH_SIZE) {
        goto reschedule;
    }
    if (evbuffer_copyout(buf, &udp_frame, UDP_FRAME_LENGTH_SIZE) != UDP_FRAME_LENGTH_SIZE) {
        LOGE("cannot copy udp to get payload length for %d", get_port(bev_context_udp->sockaddr));
        what |= BEV_EVENT_ERROR;
        goto error;
    }
    payload_length = htons(udp_frame.length);
    length = payload_length + UDP_FRAME_LENGTH_SIZE;
    if (size < length) {
        goto reschedule;
    }
    if (evbuffer_copyout(buf, &udp_frame, length) != (ssize_t) length) {
        LOGE("cannot copy udp %d for %d", (int) length, get_port(bev_context_udp->sockaddr));
        what |= BEV_EVENT_ERROR;
        goto error;
    }
    res = sendto(fd, udp_frame.buffer, payload_length, 0, bev_context_udp->sockaddr, bev_context_udp->socklen);
    if (res < 0) {
        err = evutil_socket_geterror(fd);
        if (EVUTIL_ERR_RW_RETRIABLE(err)) {
            goto reschedule;
        }
        LOGW("cannot send udp to %d: %s", get_port(bev_context_udp->sockaddr), evutil_socket_error_to_string(err));
        what |= BEV_EVENT_ERROR;
        goto error;
    }
    if (res == 0) {
        what |= BEV_EVENT_EOF;
        goto error;
    }
    if (res != payload_length) {
        LOGW("cannot send entire udp packet to %d", get_port(bev_context_udp->sockaddr));
        what |= BEV_EVENT_ERROR;
        goto error;
    }
#ifndef NDEBUG
    LOGD("udp sent %d to peer %d", payload_length, get_port(bev_context_udp->sockaddr));
#endif
    evbuffer_drain(buf, length);

    if (evbuffer_get_length(buf) == 0) {
        event_del(&raw->ev_write);
    }

    if (raw->writecb) {
        raw->writecb(raw, raw->cbarg);
    }

    goto done;

reschedule:
    if (evbuffer_get_length(buf) == 0) {
        event_del(&raw->ev_write);
    }
    goto done;

error:
    bufferevent_disable(raw, EV_WRITE);
    if (raw->errorcb) {
        raw->errorcb(raw, what, raw->cbarg);
    }

done:
    return;
}

ssize_t udp_read(evutil_socket_t sock, struct udp_frame *udp_frame, struct sockaddr *sockaddr, ev_socklen_t *socklen) {
    ssize_t size = recvfrom(sock, udp_frame->buffer, MAX_UDP_FRAME_SIZE, 0, sockaddr, socklen);
    if (size < 0) {
        int socket_error = evutil_socket_geterror(sock);
        if (!EVUTIL_ERR_RW_RETRIABLE(socket_error)) {
            LOGE("cannot recvfrom udp: %s", evutil_socket_error_to_string(socket_error));
        }
        return -1;
    } else if (size == 0) {
        LOGE("udp receive 0 from port %d", get_port(sockaddr));
        return 0;
    } else {
        udp_frame->length = ntohs(size);
#ifndef NDEBUG
        LOGD("udp read %d from port %d", (int) size, get_port(sockaddr));
#endif
        return (int) size;
    }
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
