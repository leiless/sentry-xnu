/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/errno.h>
#include <sys/time.h>

#include <sys/socket.h>     /* PF_INET */
#include <netinet/in.h>     /* IPPROTO_IP */

#include "utils.h"

/**
 * Make sure type of two variables are compatible to each other
 */
#define ASSURE_TYPE_ALIAS(a, b) \
    BUILD_BUG_ON(!__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))

#define ENDPOINT    "52.20.38.43"       /* postman-echo.com */

/**
 * see:
 *  benavento/mac9p/blob/master/kext/socket.c#recvsendn_9p
 *  https://stackoverflow.com/q/3198049/10725426
 *  https://stackoverflow.com/q/15938022/10725426
 */
static int so_send_recv_n(
        socket_t so,
        void *buf,
        size_t size,
        int flags,
        bool send)
{
    int e = 0;
    errno_t (*sock_op)(socket_t, /* [const] */ struct msghdr *, int, size_t *);
    struct iovec aio;
    struct msghdr msg;
    size_t i, n;

    sock_op = send ? (__typeof__(sock_op)) sock_send : sock_receive;

    for (n = 0; n < size; n += i) {
        i = 0;

        aio.iov_base = buf + n;
        aio.iov_len = size - n;
        bzero(&msg, sizeof(msg));
        msg.msg_iov = &aio;
        msg.msg_iovlen = 1;

        e = sock_op(so, &msg, flags, &i);
        if (e != 0 || i == 0) {
            if (e == 0) e = -ENODATA; /* Distinguish return value */
            break;
        }
    }

    LOG_DBG("%s size: %lu", send ? "send" : "recv", (unsigned long) n);

    return e;
}

static inline int so_send_n(socket_t so, void *buf, size_t size, int flags)
{
    return so_send_recv_n(so, buf, size, flags, true);
}

static inline int so_recv_n(socket_t so, void *buf, size_t size, int flags)
{
    return so_send_recv_n(so, buf, size, flags, false);
}

#define BUFSZ       1024

static void pseudo_http_post(socket_t so, const char *arg, const char *msg)
{
    int e;
    char buf[BUFSZ];

    kassert_nonnull(so);
    kassert_nonnull(arg);
    kassert_nonnull(msg);

    (void) snprintf(buf, BUFSZ, "POST /post?arg=%s HTTP/1.0\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: %zu\r\n"
                                "\r\n%s",
                                arg, strlen(msg), msg);

    LOG_DBG("%s", buf);

    LOG_DBG("Sending..");
    e = so_send_n(so, buf, strlen(buf), MSG_WAITALL);
    if (e != 0) {
        LOG_ERR("so_send_n() fail  errno: %d", e);
        return;
    }

    LOG_DBG("Receiving..");
    (void) snprintf(buf, BUFSZ, "<no data>");
    e = so_recv_n(so, buf, BUFSZ, MSG_WAITALL);
    if (e != 0 && e != -ENODATA) {
        LOG_ERR("so_recv_n() fail  errno: %d", e);
        return;
    }

    LOG("HTTP POST response:\n%s", buf);
}

kern_return_t sentry_xnu_start(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);

    int e, e2;
    socket_t so = NULL;
    struct sockaddr_in sin;
    struct timeval tv;

    ASSURE_TYPE_ALIAS(errno_t, int);
    ASSURE_TYPE_ALIAS(kern_return_t, int);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

    e = sock_socket(PF_INET, SOCK_STREAM, IPPROTO_IP, NULL, NULL, &so);
    if (e != 0) {
        LOG_ERR("sock_socket() fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_exit;
    }

    bzero(&sin, sizeof(sin));
    /*
     * XXX:
     *  (struct sockaddr).sin_len must be sizeof(struct sockaddr)
     *  otherwise sock_connect will return EINVAL
     *
     * see:
     *  xnu/bsd/kern/kpi_socket.c#sock_connect
     *  xnu/bsd/kern/uipc_socket.c#soconnectlock
     *  xnu/bsd/netinet/raw_ip.c#rip_usrreqs, rip_connect
     */
    sin.sin_len = sizeof(sin);
    sin.sin_family = PF_INET;
    sin.sin_port = htons(80);
    e = inet_aton(ENDPOINT, &sin.sin_addr);
    kassertf(e == 1, "inet_aton() fail  endpoint: " ENDPOINT);

    e = sock_connect(so, (struct sockaddr *) &sin, 0);
    if (e != 0) {
        LOG_ERR("sock_connect() fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_close;
    }

    LOG("Endpoint " ENDPOINT "  connected: %d nonblocking: %d",
            sock_isconnected(so), sock_isnonblocking(so));

    tv.tv_sec = 10;
    tv.tv_usec = 0;

    e = sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (e != 0) {
        LOG_ERR("sock_setsockopt() SO_SNDTIMEO fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    e = sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (e != 0) {
        LOG_ERR("sock_setsockopt() SO_RCVTIMEO fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    pseudo_http_post(so, "foobar", "hello world!");

out_shutdown:
    e2 = sock_shutdown(so, SHUT_RDWR);
    if (e2 != 0) LOG_ERR("sock_shutdown() RDWR fail  errno: %d", e2);
out_close:
    sock_close(so);
out_exit:
    return e;
}

kern_return_t sentry_xnu_stop(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);
    LOG("unloading..");
    return KERN_SUCCESS;
}

#ifdef __kext_makefile__
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);

/* Will expand name if it's a macro */
#define KMOD_EXPLICIT_DECL2(name, ver, start, stop) \
    __attribute__((visibility("default")))          \
        KMOD_EXPLICIT_DECL(name, ver, start, stop)

KMOD_EXPLICIT_DECL2(BUNDLEID, KEXTBUILD_S, _start, _stop)

/* If you intended to write a kext library  NULLify _realmain and _antimain */
__private_extern__ kmod_start_func_t *_realmain = sentry_xnu_start;
__private_extern__ kmod_stop_func_t *_antimain = sentry_xnu_stop;

__private_extern__ int _kext_apple_cc = __APPLE_CC__;
#endif

