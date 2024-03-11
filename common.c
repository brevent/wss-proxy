#include <signal.h>
#include <stdio.h>
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
        fprintf(stderr, "received termination\n");
        event_base_loopbreak(base);
    } else if (signal == SIGINT) {
        fprintf(stderr, "received interrupt\n");
        event_base_loopbreak(base);
    } else if (signal == SIGUSR1) {
        event_base_loopexit(base, 0);
        fprintf(stderr, "received SIGUSR1\n");
    }
}

void init_event_signal(struct event_base *base) {
    evsignal_new(base, SIGTERM, on_signal, base);
    evsignal_new(base, SIGINT, on_signal, base);
    evsignal_new(base, SIGUSR1, on_signal, base);
    evsignal_new(base, SIGUSR2, on_signal, base);
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
