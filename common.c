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
#include "common.h"

uint16_t get_peer_port(struct bufferevent *bev) {
    int fd;
    socklen_t len;
    struct sockaddr_storage sin;

    fd = bufferevent_getfd(bev);
    if (fd < 0) {
        return 0;
    }
    len = sizeof(sin);
    if (getpeername(fd, (struct sockaddr *) &sin, &len) == -1) {
        return 0;
    }
    if (sin.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) &sin)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) &sin)->sin_port);
    }
}

static uint16_t get_http_port(struct evhttp_connection *evcon) {
    char *address;
    uint16_t port;
    evhttp_connection_get_peer(evcon, &address, &port);
    return port;
}

static void on_signal(int fd, short signal, void *base) {
    (void) fd;
    if (signal == SIGTERM) {
        LOGW("received termination");
        event_base_loopbreak(base);
    } else if (signal == SIGINT) {
        LOGW("received interrupt");
        event_base_loopbreak(base);
    } else if (signal == SIGUSR1) {
        event_base_loopexit(base, 0);
        LOGW("received SIGUSR1");
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

static void toggle_debug(int signal) {
    if (signal == SIGUSR2) {
        if (get_log_level() == DEBUG) {
            set_log_level(INFO);
        } else {
            set_log_level(DEBUG);
        }
    }
}

void init_event_signal(struct event_base *base) {
    struct rlimit rlim;
    struct timeval one_minute = {60, 0};
    struct event *ev;
    ev = event_new(base, -1, EV_PERSIST, check_parent, NULL);
    if (ev) {
        event_add(ev, &one_minute);
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
    evsignal_new(base, SIGTERM, on_signal, base);
    evsignal_new(base, SIGINT, on_signal, base);
    evsignal_new(base, SIGUSR1, on_signal, base);
    signal(SIGUSR2, toggle_debug);
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
    info.mask = role == wss_client ? 1 : 0;
#ifndef WSS_MOCK_MASK
    if (info.mask) {
        evutil_secure_rng_get_bytes(&(info.mask_key), MASK_SIZE);
        mask(payload, size, info.mask_key);
    }
#endif
    header = build_ws_header(&info, payload, size);
    *header_size = info.header_size;
    return header;
}

static void send_pong(struct evbuffer *src, uint16_t size, uint32_t mask_key, struct bufferevent *tev) {
    uint8_t *header, header_size;
    struct wss_frame_ping {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[125];
    } wss_frame_ping;
    if (size > 125) {
        LOGD("ping payload length %d is unsupported", size);
    } else if ((header_size = evbuffer_remove(src, wss_frame_ping.buffer, size)) == size) {
        mask(wss_frame_ping.buffer, (uint16_t) size, mask_key);
        header = build_ws_frame(OP_PONG, &(wss_frame_ping.buffer), size, &header_size);
        evbuffer_add(bufferevent_get_output(tev), header, (uint16_t) size + header_size);
    } else {
        LOGD("ping payload %d, read: %d", size, header_size);
    }
}

static enum bufferevent_filter_result wss_input_filter(struct evbuffer *src, struct evbuffer *dst,
                                                       ev_ssize_t dst_limit, enum bufferevent_flush_mode mode,
                                                       void *ctx) {
    uint8_t header[MAX_WS_HEADER_SIZE];
    size_t length;
    int result;
    struct ws_header_info info;

    (void) dst_limit;
    (void) mode;

    length = evbuffer_get_length(src);
    evbuffer_copyout(src, header, MIN(MAX_WS_HEADER_SIZE, length));
    memset(&info, 0, sizeof(struct ws_header_info));
    result = parse_ws_header(header, length, &info);
    if (result < 0) {
        LOGW("payload length 64K+ is unsupported");
        return BEV_ERROR;
    } else if (result > 0) {
        return BEV_NEED_MORE;
    }
    if (!info.fin) {
        LOGW("fin should be 1 (fragments is unsupported)");
        return BEV_ERROR;
    }
    if (info.rsv) {
        LOGW("rsv should be 0");
        return BEV_ERROR;
    }
    if (role == wss_client && info.mask) {
        LOGW("server response shouldn't mask");
        return BEV_ERROR;
    } else if (role == wss_server && !info.mask) {
        LOGW("client request should mask");
        return BEV_ERROR;
    }
    switch (info.op) {
        case OP_CONTINUATION:
            LOGW("continuation frame is unsupported");
            return BEV_ERROR;
        case OP_TEXT:
            LOGW("text frame is unsupported");
            return BEV_ERROR;
        case OP_BINARY:
            break;
        case OP_CLOSE:
            if (role == wss_client) {
                LOGW("server send close frame");
            } else {
                LOGD("client send close frame");
            }
            return BEV_ERROR;
        case OP_PING:
            LOGD("%s send ping frame", role == wss_client ? "client" : "server");
            break;
        case OP_PONG:
            LOGD("%s send pong frame", role == wss_client ? "client" : "server");
            break;
        default:
            LOGW("op 0x%x is unsupported", info.op);
            return BEV_ERROR;
    }
    if (info.payload_size > MAX_PAYLOAD_SIZE) {
        LOGW("payload length %d is unsupported", info.payload_size);
        return BEV_ERROR;
    }
    if (length < (uint32_t) info.header_size + info.payload_size) {
        return BEV_NEED_MORE;
    }
    if (info.op == OP_PONG) {
        evbuffer_drain(src, info.header_size + info.payload_size);
        return BEV_OK;
    }
    evbuffer_drain(src, info.header_size);
    length = info.payload_size;
    if (info.op == OP_PING) {
        send_pong(src, length, info.mask_key, ctx);
        return BEV_OK;
    }
    if (info.mask_key) {
        char buffer[WSS_PAYLOAD_SIZE];
        while (length > 0) {
            int size = evbuffer_remove(src, buffer, MIN(length, WSS_PAYLOAD_SIZE));
            if (size <= 0) {
                break;
            }
            mask(buffer, (uint16_t) size, info.mask_key);
            evbuffer_add(dst, buffer, (uint16_t) size);
            length -= (uint16_t) size;
        }
    } else {
        while (length > 0) {
            int size = evbuffer_remove_buffer(src, dst, MIN(length, WSS_PAYLOAD_SIZE));
            if (size <= 0) {
                break;
            }
            length -= (uint16_t) size;
        }
    }
    return BEV_OK;
}

static void close_wss_data_cb(struct bufferevent *tev, void *wss) {
    (void) tev;
    LOGD("close wss %p", wss);
    evhttp_connection_free(wss);
}

static void close_wss_event_cb(struct bufferevent *tev, short event, void *wss) {
    (void) tev;
    LOGD("close wss %p, event: 0x%02x", wss, event);
    evhttp_connection_free(wss);
}

static void close_wss(struct evhttp_connection *wss, uint16_t port, uint16_t reason) {
    struct bufferevent *tev;
    struct wss_frame_close {
        char header[MAX_WS_HEADER_SIZE];
        uint16_t reason;
    } wss_frame_close;
    uint8_t *wss_header, header_size;
    uint16_t size = sizeof(wss_frame_close.reason);
    wss_frame_close.reason = ntohs(reason);
    wss_header = build_ws_frame(OP_CLOSE, &(wss_frame_close.reason), size, &header_size);
    tev = evhttp_connection_get_bufferevent(wss);
    evbuffer_add(bufferevent_get_output(tev), wss_header, size + header_size);
    LOGD("would close wss %p for peer %d", wss, port);
    bufferevent_setcb(tev, NULL, close_wss_data_cb, close_wss_event_cb, wss);
}

static void raw_forward_cb(struct bufferevent *raw, void *wss) {
    struct evbuffer *src;
    struct evbuffer *dst;
    struct bufferevent *tev;
    struct wss_frame_data {
        char header[MAX_WS_HEADER_SIZE];
        char buffer[WSS_PAYLOAD_SIZE];
    } wss_frame_data;

    tev = evhttp_connection_get_bufferevent(wss);
    src = bufferevent_get_input(raw);
    dst = bufferevent_get_output(tev);

    for (;;) {
        // should we use continuation fame?
        uint8_t *wss_header, wss_header_size;
        int size = evbuffer_remove(src, wss_frame_data.buffer, WSS_PAYLOAD_SIZE);
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
        if (role == wss_client) {
            port = get_peer_port(raw);
        } else {
            port = get_http_port(wss);
        }
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
        if (role == wss_client) {
            port = get_peer_port(raw);
        } else {
            port = get_http_port(wss);
        }
        bufferevent_free(raw);
        LOGD("connection %u closing from wss, event: 0x%02x", port, event);
        close_wss(wss, port, 1000);
    }
}

static void wss_close_cb(struct evhttp_connection *wss, void *wev) {
    LOGD("wss %p closed", wss);
    bufferevent_free(wev);
}

void tunnel_wss(struct bufferevent *raw, struct evhttp_connection *wss) {
    struct bufferevent *tev;
    struct bufferevent *wev;

    tev = evhttp_connection_get_bufferevent(wss);
    wev = bufferevent_filter_new(tev, wss_input_filter, NULL, 0, NULL, tev);
    evhttp_connection_set_closecb(wss, wss_close_cb, wev);

    bufferevent_enable(wev, EV_READ | EV_WRITE);
    bufferevent_setcb(wev, wss_forward_cb, NULL, wss_event_cb, raw);

    bufferevent_enable(raw, EV_READ | EV_WRITE);
    bufferevent_setcb(raw, raw_forward_cb, NULL, raw_event_cb, wss);
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
