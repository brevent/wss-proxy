#ifndef WSS_PROXY_COMMON_H
#define WSS_PROXY_COMMON_H

#include <stdint.h>
#include <time.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/http.h>
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

#ifndef WSS_TIMEOUT
#define WSS_TIMEOUT 10
#endif

#ifndef WSS_PROXY_VERSION
#define WSS_PROXY_VERSION "0.2.7"
#endif

#ifndef LOGGER_NAME
#ifdef WSS_PROXY_SERVER
#define LOGGER_NAME "wss-proxy-server"
#endif
#ifdef WSS_PROXY_CLIENT
#define LOGGER_NAME "wss-proxy-client"
#endif
#ifndef LOGGER_NAME
#define LOGGER_NAME "wss-proxy"
#endif
#endif

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

enum log_level {
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

#ifdef WSS_PROXY_CLIENT
uint16_t get_peer_port(struct bufferevent *bev);
#endif

#ifdef WSS_PROXY_SERVER
uint16_t get_http_port(struct evhttp_connection *evcon);
#endif

uint16_t get_port(struct sockaddr *sockaddr);

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

#define get_wss(raw) ((struct evhttp_connection *) (((struct bufferevent *) raw)->cbarg))

void raw_event_cb(struct bufferevent *raw, short event, void *wss);

void tunnel_wss(struct bufferevent *raw, struct evhttp_connection *wss);

/**
 * @return whether close frame is sent
 */
int send_close(struct bufferevent *raw, uint16_t reason);

#ifdef WSS_ENABLE_PING
void send_ping(struct bufferevent *tev, const char *payload, uint8_t size);

void set_ping_timeout(struct bufferevent *wev, int sec);
#endif

#define X_UPGRADE "X-Upgrade"
#define SHADOWSOCKS "shadowsocks"
#define IS_SHADOWSOCKS(x) (x != NULL && !evutil_ascii_strcasecmp(x, SHADOWSOCKS))
void tunnel_ss(struct bufferevent *raw, struct evhttp_connection *wss);

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line);
#endif

#endif //WSS_PROXY_COMMON_H
