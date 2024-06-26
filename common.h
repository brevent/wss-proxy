#ifndef WSS_PROXY_COMMON_H
#define WSS_PROXY_COMMON_H

#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/util.h>
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
#include <openssl/ssl.h>
#endif
#include <openssl/lhash.h>
#ifdef HAVE_SYSLOG
#include <syslog.h>
#else
#define syslog(x, y, ...) do {} while (0)
#endif
#include "ws-header.h"

#ifdef _WIN32
typedef ev_ssize_t ssize_t;
#endif

#ifndef WSS_PAYLOAD_SIZE
#define WSS_PAYLOAD_SIZE 4096
#endif

#if (WSS_PAYLOAD_SIZE % 4)
#error "WSS_PAYLOAD_SIZE must be a multiple of 4"
#endif

#ifndef WSS_TIMEOUT
#define WSS_TIMEOUT 5
#endif

#ifndef WSS_LISTEN_BACKLOG
#define WSS_LISTEN_BACKLOG 511
#endif

#define WSS_LISTEN_FLAGS (LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE)

#ifndef WSS_PROXY_VERSION
#define WSS_PROXY_VERSION "0.5.3"
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

#ifdef HAVE_SYSLOG
#define ERROR   LOG_ERR
#define WARN    LOG_WARNING
#define NOTICE  LOG_NOTICE
#define INFO    LOG_INFO
#define DEBUG   LOG_DEBUG
#else
#ifdef ERROR
#undef ERROR
#endif
#define ERROR   3
#define WARN    (ERROR + 1)
#define NOTICE  (ERROR + 2)
#define INFO    (ERROR + 3)
#define DEBUG   (ERROR + 4)
#endif

#define MAX_UDP_FRAME_SIZE 65535
#define UDP_FRAME_LENGTH_SIZE 2
struct udp_frame {
    uint16_t length;
    char buffer[MAX_UDP_FRAME_SIZE];
};
#define MAX_WSS_PAYLOAD_SIZE MAX_UDP_FRAME_SIZE

#define MAX_PROXY_BUFFER (512 * 1024)
#define MIN_PROXY_BUFFER (64 * 1024)

typedef struct bev_context_udp bev_context_udp;

#ifdef DEFINE_LHASH_OF_EX
DEFINE_LHASH_OF_EX(bev_context_udp);
#else
DEFINE_LHASH_OF(bev_context_udp);
#endif

struct bev_context {
    const char *name;
    void (*free)(void *ptr);
    void (*timeout)(void *ptr);
};

struct bev_context_udp {
    const struct bev_context *bev_context;
    ev_socklen_t socklen;
    struct sockaddr *sockaddr;
    struct bufferevent *bev;
    LHASH_OF(bev_context_udp) *hash;
#ifdef WSS_PROXY_CLIENT
    union {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } sockaddr_storage;
#endif
#ifdef WSS_PROXY_SERVER
    evutil_socket_t sock;
#endif
};

void free_all_udp(LHASH_OF(bev_context_udp) *hash);

void bufferevent_set_context(struct bufferevent *bev, void *context);

void *bufferevent_get_context(struct bufferevent *bev);

extern const struct bev_context const_bev_context_udp;

void safe_bufferevent_free(struct bufferevent *bev);

void close_bufferevent_later(struct bufferevent *bev);

#ifndef _WIN32
#define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == EINTR || (e) == EAGAIN || (e) == EWOULDBLOCK)
#define EVUTIL_ERR_CONNECT_RETRIABLE(e) ((e) == EINTR || (e) == EINPROGRESS)
#else
#define EVUTIL_ERR_RW_RETRIABLE(e) ((e) == WSAEINTR || (e) == WSAEWOULDBLOCK)
#define EVUTIL_ERR_CONNECT_RETRIABLE(e) ((e) == WSAEINTR || (e) == WSAEINPROGRESS || (e) == WSAEWOULDBLOCK)
#endif

uint16_t get_peer_port(struct bufferevent *bev);

uint16_t get_port(const struct sockaddr *sockaddr);

void set_port(struct sockaddr_storage *sockaddr, uint16_t port);

void log_callback(int severity, const char *msg);

void init_log_level(const char *loglevel);

int get_log_level(void);

int use_syslog(void);

void close_syslog(void);

#define LOG(format, stream, level, ...)                                         \
    do {                                                                        \
        if (get_log_level() >= level) {                                         \
            if (use_syslog()) {                                                 \
                syslog(level, format,  ## __VA_ARGS__);                         \
            } else {                                                            \
                time_t now = time(NULL);                                        \
                char timestr[20];                                               \
                strftime(timestr, 20, TIME_FORMAT, localtime(&now));            \
                fprintf(stream, " %s " #level " " LOGGER_NAME " " format "\n",  \
                        timestr, ## __VA_ARGS__);                               \
                fflush(stream);                                                 \
            }                                                                   \
        }                                                                       \
    } while (0)

#define LOGD(format, ...) LOG(format, stdout, DEBUG, ## __VA_ARGS__)
#define LOGI(format, ...) LOG(format, stdout, INFO, ## __VA_ARGS__)
#define LOGW(format, ...) LOG(format, stderr, WARN, ## __VA_ARGS__)
#define LOGE(format, ...) LOG(format, stderr, ERROR, ## __VA_ARGS__)

const char *find_option(const char *options, const char *key, const char *no_value);

int find_option_port(const char *key, int default_port);

int init_event_signal(struct event_base *base, struct event **event_parent, struct event **event_sigquit);

int is_websocket_key(const char *websocket_key);

int calc_websocket_accept(const char *websocket_key, char *websocket_accept);

#define get_cbarg(bev) (((struct bufferevent *) bev)->cbarg)

void raw_event_cb(struct bufferevent *raw, short event, void *wss);


void tunnel_wss(struct bufferevent *raw, struct bufferevent *tev, bufferevent_filter_cb output_filter);

enum close_reason {
    close_reason_raw,
    close_reason_wss,
    close_reason_eof,
};

void close_wss(struct bufferevent *tev, enum close_reason close_reason, short event);

#ifdef WSS_ENABLE_PING
void send_ping(struct bufferevent *tev, const char *payload, uint8_t size);

void set_ping_timeout(struct bufferevent *wev, int sec);
#endif

#define X_UPGRADE "X-Upgrade"
#define SHADOWSOCKS "shadowsocks"
void tunnel_ss(struct bufferevent *raw, struct bufferevent *tev);

#define X_SOCK_TYPE "X-Sock-Type"
#define SOCK_TYPE_UDP "udp"

#define append_buffer(buffer, x) do { \
    memcpy(buffer, (x), sizeof(x) - 1); \
    buffer += sizeof(x) - 1; \
} while (0)

ssize_t udp_read(evutil_socket_t sock, struct udp_frame *udp_frame, struct sockaddr *sockaddr, ev_socklen_t *socklen);

void bev_context_udp_writecb(evutil_socket_t fd, short event, void *arg);

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line);
#endif

#ifdef _WIN32
char *strcasestr(const char *s, const char *find);
#endif

#endif //WSS_PROXY_COMMON_H
