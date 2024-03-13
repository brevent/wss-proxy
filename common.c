#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include <event2/event.h>
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
