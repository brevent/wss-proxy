#ifndef WSS_PROXY_COMMON_H
#define WSS_PROXY_COMMON_H

#include <stdint.h>
#include <time.h>
#include <event2/bufferevent.h>
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
#include <openssl/ssl.h>
#endif

/**
 * fop: fin:1, rsv:3, opcode: 4
 * mlen: mask: 1, length: 7
 */
#define FOP_MASK struct {   \
    uint8_t fop;            \
    uint8_t mlen;           \
}

#define WSS_HEADER union {  \
    struct {                \
        uint16_t unused;    \
        FOP_MASK;           \
    };                      \
    struct {                \
        FOP_MASK;           \
        uint16_t elen;      \
    } extend;               \
}

struct wss_frame_client {
    WSS_HEADER;
    uint32_t mask;
};

struct wss_frame_server {
    WSS_HEADER;
};

enum wss_op {
    OP_CONTINUATION = 0x0,
    OP_TEXT = 0x1,
    OP_BINARY = 0x2,
    OP_CLOSE = 0x8,
    OP_PING = 0x9,
    OP_PONG = 0xa,
};

#ifndef WSS_PAYLOAD_SIZE
#define WSS_PAYLOAD_SIZE 4096
#endif

#if (WSS_PAYLOAD_SIZE % 4)
#error "WSS_PAYLOAD_SIZE must be a multiple of 4"
#endif

#ifndef MAX_PAYLOAD_SIZE
#define MAX_PAYLOAD_SIZE 0x4050
#endif

#ifndef WSS_TIMEOUT
#define WSS_TIMEOUT 10
#endif

#ifndef WSS_PROXY_VERSION
#define WSS_PROXY_VERSION "0.1.0"
#endif

uint16_t get_port(struct sockaddr *sockaddr);

uint16_t get_peer_port(struct bufferevent *bev);

#ifndef LOGGER_NAME
#define LOGGER_NAME "wss-proxy"
#endif

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define LOGD(format, ...)                                                   \
    do {                                                                    \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stdout, " %s DEBUG " LOGGER_NAME " " format "\n", timestr,  \
                    ## __VA_ARGS__);                                        \
        fflush(stdout);                                                     \
    }                                                                       \
    while (0)

#define LOGI(format, ...)                                                   \
    do {                                                                    \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stdout, " %s INFO " LOGGER_NAME " " format "\n", timestr,   \
                    ## __VA_ARGS__);                                        \
        fflush(stdout);                                                     \
    }                                                                       \
    while (0)

#define LOGW(format, ...)                                                   \
    do {                                                                    \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stderr, " %s WARN " LOGGER_NAME " " format "\n", timestr,   \
                    ## __VA_ARGS__);                                        \
        fflush(stderr);                                                     \
    } while (0)

#define LOGE(format, ...)                                                   \
    do {                                                                    \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stderr, " %s ERROR " LOGGER_NAME " " format "\n", timestr,  \
                    ## __VA_ARGS__);                                        \
        fflush(stderr);                                                     \
    } while (0)

void init_event_signal(struct event_base *base);

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line);
#endif

#endif //WSS_PROXY_COMMON_H
