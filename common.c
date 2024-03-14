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
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "common.h"

uint16_t get_port(struct sockaddr *sockaddr) {
    if (sockaddr->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *) sockaddr)->sin6_port);
    } else {
        return ntohs(((struct sockaddr_in *) sockaddr)->sin_port);
    }
}

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
    char buffer[25];
    if (strcmp(websocket_key, WEBSOCKET_KEY) == 0) {
        return 1;
    }
    if (websocket_key != NULL && strlen(websocket_key) == 24
        && EVP_DecodeBlock((uint8_t *) buffer, (uint8_t *) websocket_key, 24) == 18 && strlen(buffer) == 16) {
        return 1;
    } else {
        LOGW("handshake fail, invalid Sec-WebSocket-Key: %s", websocket_key);
        return 0;
    }
}

int calc_websocket_accept(const char *websocket_key, char *websocket_accept) {
    char buffer[61];
    unsigned char sha1[SHA_DIGEST_LENGTH];
    if (strcmp(websocket_key, WEBSOCKET_KEY) == 0) {
        strcpy(websocket_accept, WEBSOCKET_ACCEPT);
        return 1;
    }
    sprintf(buffer, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", websocket_key);
    SHA1((uint8_t *) buffer, 60, sha1);
    return EVP_EncodeBlock((uint8_t *) websocket_accept, sha1, SHA_DIGEST_LENGTH);
}

#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
void ssl_keylog_callback(const SSL *ssl, const char *line) {
    char *keylog_file_name;
    FILE *keylog_file_fp;

    (void) ssl;

    if (!line)
        return;

    keylog_file_name = getenv("SSLKEYLOGFILE");
    if (!keylog_file_name)
        return;

#if defined(_WIN32)
#define FOPEN_APPEND_TEXT "at"
#else
#define FOPEN_APPEND_TEXT "a"
#endif
    keylog_file_fp = fopen(keylog_file_name, FOPEN_APPEND_TEXT);
    if (!keylog_file_fp)
        return;

    fprintf(keylog_file_fp, "%s\n", line);
    fclose(keylog_file_fp);
}
#endif
