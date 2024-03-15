#ifndef WSS_PROXY_COMMON_H
#define WSS_PROXY_COMMON_H

#include <stdint.h>
#include <time.h>
#include <event2/bufferevent.h>
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
#include <openssl/ssl.h>
#endif
#include "ws-header.h"

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
#define WSS_PROXY_VERSION "0.2.0"
#endif

#ifndef LOGGER_NAME
#define LOGGER_NAME "wss-proxy"
#endif

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

enum log_level {
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

uint16_t get_peer_port(struct bufferevent *bev);

void log_callback(int severity, const char *msg);

void init_log_level(const char *loglevel);

enum log_level get_log_level(void);

#define LOG(format, stream, level, ...)                                             \
    do {                                                                            \
        if (get_log_level() <= level) {                                             \
            time_t now = time(NULL);                                                \
            char timestr[20];                                                       \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                    \
            fprintf(stream, " %s " #level " " LOGGER_NAME " " format "\n", timestr, \
                        ## __VA_ARGS__);                                            \
            fflush(stream);                                                         \
        }                                                                           \
    } while (0)


#define LOGD(format, ...) LOG(format, stdout, DEBUG, ## __VA_ARGS__)
#define LOGI(format, ...) LOG(format, stdout, INFO, ## __VA_ARGS__)
#define LOGW(format, ...) LOG(format, stderr, WARN, ## __VA_ARGS__)
#define LOGE(format, ...) LOG(format, stderr, ERROR, ## __VA_ARGS__)

void init_event_signal(struct event_base *base);

int is_websocket_key(const char *websocket_key);

int calc_websocket_accept(const char *websocket_key, char *websocket_accept);

enum wss_role {
    wss_server = 0,
    wss_client = 1,
};

extern const enum wss_role role;

void raw_event_cb(struct bufferevent *raw, short event, void *wss);

void tunnel_wss(struct bufferevent *raw, struct evhttp_connection *wss);

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line);
#endif

#endif //WSS_PROXY_COMMON_H
