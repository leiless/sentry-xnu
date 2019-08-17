/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/errno.h>
#include <sys/time.h>
#include <kern/clock.h>

#include <sys/socket.h>     /* PF_INET */
#include <netinet/in.h>     /* IPPROTO_IP */

#include "utils.h"

/**
 * Make sure type of two variables are compatible to each other
 */
#define ASSURE_TYPE_ALIAS(a, b) \
    BUILD_BUG_ON(!__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))

/*
 * DNS A-record of sentry.io
 * TODO: implement a in-kernel gethostbyname()
 */
#define SENTRY_IP           "35.188.42.15"

#define SENTRY_XNU_NAME     "sentry-udev"
#define SENTRY_XNU_VER      "0.1"
#define SENTRY_UA           SENTRY_XNU_NAME "/" SENTRY_XNU_VER

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

/**
 * Get unix time stamp in seconds
 * see:
 *  Miscellaneous Kernel Services - Apple Developer
 *  https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/services/services.html
 */
static clock_sec_t time(clock_sec_t * __nullable p)
{
    clock_sec_t s;
    clock_usec_t __unused u;
    clock_get_calendar_microtime(&s, &u);
    if (p != NULL) *p = s;
    return s;
}

static void format_x_sentry_auth(
        char *buf,
        size_t sz,
        uint32_t ver,
        const char *key)
{
    int n;
    kassert_nonnull(buf);
    kassert(sz != 0);
    kassert_nonnull(key);
    /* snprintf() always return value >= 0 */
    n = snprintf(buf, sz,
            "Sentry "
            "sentry_version=%u, "
            "sentry_timestamp=%lu, "
            "sentry_key=%s", ver, time(NULL), key);
    kassertf(n >= 0, "snprintf() fail  n: %d", n);
}

static void uuid_string_generate(uuid_string_t out)
{
    uuid_t u;
    kassert_nonnull(out);
    uuid_generate_random(u);
    uuid_unparse_lower(u, out);
}

#define ISO8601_TM_BUFSZ    20u

#define EPOCH_YEAR_SECS     31556926u
#define EPOCH_MONTH_SECS    2629743u
#define EPOCH_DAY_SECS      86400u
#define EPOCH_HOUR_SECS     3600u
#define EPOCH_MINUTE_SECS   60u

struct kern_tm {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t sec;
};

/* NOTE: buggy implementation */
static void format_iso8601_time(char *buf, size_t sz)
{
    int n;
    clock_sec_t t;

    struct kern_tm tm;

    kassert_nonnull(buf);
    kassertf(sz >= ISO8601_TM_BUFSZ,
                "Insufficient ISO-8601 time buffer size  %zu vs %u",
                sz, ISO8601_TM_BUFSZ);

    t = time(NULL);

    tm.year = (uint32_t) t / EPOCH_YEAR_SECS;
    t -= tm.year * EPOCH_YEAR_SECS;

    tm.month = (uint32_t) t / EPOCH_MONTH_SECS;
    t -= tm.month * EPOCH_MONTH_SECS;

    tm.day = (uint32_t) t / EPOCH_DAY_SECS;
    t -= tm.day * EPOCH_DAY_SECS;

    tm.hour = (uint32_t) t / EPOCH_HOUR_SECS;
    t -= tm.hour * EPOCH_HOUR_SECS;

    tm.minute = (uint32_t) t / EPOCH_MINUTE_SECS;
    t -= tm.minute * EPOCH_MINUTE_SECS;

    tm.sec = (uint32_t) t;
    kassertf(tm.sec < EPOCH_MINUTE_SECS,
                "Why tm.sec %u >= %u?!", tm.sec, EPOCH_MINUTE_SECS);

    n = snprintf(buf, sz, "%04u-%02u-%02uT%02u:%02u:%02u",
            tm.year + 1970, tm.month + 1, tm.day + 1,
            tm.hour, tm.minute, tm.sec);
    kassertf(n >= 0, "snprintf() fail  n: %d", n);
}

static void format_message_payload(
        char *buf,
        size_t sz,
        const char * __nullable msg)
{
    int n;
    uuid_string_t u;
    char t[ISO8601_TM_BUFSZ];

    kassert_nonnull(buf);
    kassert(sz != 0);

    uuid_string_generate(u);
    format_iso8601_time(t, sizeof(t));

    n = snprintf(buf, sz,
            "{\"event_id\":\"%s\","
            "\"timestamp\":\"%s\","
            "\"logger\":\"(default)\","
            "\"platform\":\"c\","
            "\"sdk\":{\"name\":\"" SENTRY_XNU_NAME "\",\"version\":\"" SENTRY_XNU_VER "\"},"
            "\"message\":\"%s\""
            "}", u, t, msg);
    kassertf(n >= 0, "snprintf() fail  n: %d", n);
}

#define BUFSZ           4096
#define AUTHSZ          192
#define PAYLOADSZ       1024

#define SENTRY_PUBKEY   "3bebc23f79274f93b6500e3ecf0cf22b"

static void sentry_capture_message(socket_t so, const char *msg)
{
    int e;
    char buf[BUFSZ];
    char auth[AUTHSZ];
    char payload[PAYLOADSZ];

    kassert_nonnull(so);
    kassert_nonnull(msg);

    format_x_sentry_auth(auth, sizeof(auth), 7, SENTRY_PUBKEY);
    format_message_payload(payload, sizeof(payload), msg);

    (void) snprintf(buf, BUFSZ, "POST /api/1/store/ HTTP/1.1\r\n"
                                "User-Agent: " SENTRY_UA "\r\n"
                                "X-Sentry-Auth: %s\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "\r\n%s", auth, strlen(payload), payload);

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
    e = inet_aton(SENTRY_IP, &sin.sin_addr);
    kassertf(e == 1, "inet_aton() fail  endpoint: " SENTRY_IP);

    e = sock_connect(so, (struct sockaddr *) &sin, 0);
    if (e != 0) {
        LOG_ERR("sock_connect() fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_close;
    }

    LOG("Endpoint " SENTRY_IP "  connected: %d nonblocking: %d",
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

    sentry_capture_message(so, "hello world!");

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

