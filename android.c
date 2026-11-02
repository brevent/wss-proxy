#ifdef __ANDROID__

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <openssl/x509.h>

#include "common.h"

int protect_socket(int fd) {
    int sock;
    struct sockaddr_un addr;
    struct msghdr msg = {0};
    struct iovec iov;
    struct cmsghdr *cmsg;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    char ret = 0;
    struct timeval tv;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGW("protect socket() failed: %s", strerror(errno));
        return -1;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "protect_path", sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOGW("protect connect failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    iov.iov_base = "";
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock, &msg, 0) == -1) {
        LOGW("protect sendmsg failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // shadowsocks-android replies 0 on success, 1 on failure
    switch (recv(sock, &ret, 1, 0)) {
        case -1:
            LOGW("protect recv failed: %s", strerror(errno));
            close(sock);
            return -1;
        case 0:
            LOGW("protect recv failed: eof");
            close(sock);
            return -1;
        default:
            break;
    }

    close(sock);
    LOGD("protected fd %d, ret %d", fd, ret);
    return ret == 0 ? 0 : -1;
}

static size_t add_certs_from_dir(X509_STORE *store, const char *path) {
    DIR *dir;
    struct dirent *entry;
    char name[PATH_MAX];
    size_t count = 0;

    if ((dir = opendir(path)) == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        snprintf(name, sizeof(name), "%s/%s", path, entry->d_name);
        if (X509_STORE_load_file(store, name)) {
            count++;
        }
    }
    closedir(dir);
    return count;
}

size_t add_android_certs(X509_STORE *store) {
    size_t count;

    // since android 14, the updatable store in conscrypt apex supersedes the system one
    count = add_certs_from_dir(store, "/apex/com.android.conscrypt/cacerts");
    if (!count) {
        count = add_certs_from_dir(store, "/system/etc/security/cacerts");
    }
    return count;
}

#endif
