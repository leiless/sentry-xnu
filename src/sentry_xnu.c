/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/errno.h>
#include <sys/time.h>
#include <kern/clock.h>

#include <libkern/OSAtomic.h>

#include <sys/socket.h>     /* PF_INET */
#include <netinet/in.h>     /* IPPROTO_IP */
#include <sys/filio.h>      /* FIONBIO */
#include <netinet/tcp.h>    /* TCP_NODELAY */

#include "utils.h"
#include "sentry.h"

/*
 * DNS A-record of sentry.io
 * TODO: implement a in-kernel gethostbyname()
 */
#define SENTRY_IP           "35.188.42.15"
#define SENTRY_PORT         80

#define SENTRY_XNU_NAME     "sentry-udev"
#define SENTRY_XNU_VER      "0.1"
#define SENTRY_UA           SENTRY_XNU_NAME "/" SENTRY_XNU_VER

/**
 * Send or receive from a socket
 *
 * If you intended to send/recv a full request, please use MSG_WAITALL
 * see: xnu/bsd/kern/uipc_socket.c#soreceive()
 *
 * see:
 *  benavento/mac9p/blob/master/kext/socket.c#recvsendn_9p
 *  https://stackoverflow.com/q/3198049/10725426
 *  https://stackoverflow.com/q/15938022/10725426
 * @return      0 if success, errno otherwise
 */
static int so_send_recv(
        socket_t so,
        char *buf,
        size_t size,
        uint64_t flags,
        bool send)
{
    int e = 0;
    errno_t (*sock_op)(socket_t, /* [const] */ struct msghdr *, int, size_t *);
    struct iovec aio;
    struct msghdr msg;
    size_t i, n = 0;

    kassert_nonnull(so);
    kassert(!!buf | !size);

    sock_op = send ? (__typeof__(sock_op)) sock_send : sock_receive;

    while (n < size) {
        aio.iov_base = buf + n;
        aio.iov_len = size - n;
        bzero(&msg, sizeof(msg));
        msg.msg_iov = &aio;
        msg.msg_iovlen = 1;

        e = sock_op(so, &msg, (int) flags, &i);
        if (e != 0 || i == 0) {
            if (e == 0) e = -EAGAIN; /* Distinguish return value */
            break;
        }

        n += i;
        if (!(flags & MSG_WAITALL)) break;
    }

    if (e == 0 && !send && n < size) {
        buf[n] = '\0';
    }

    LOG_DBG("so_send_recv() %s size: %zu", send ? "send" : "recv", n);

    return e;
}

static inline int so_send(socket_t so, char *buf, size_t size, uint64_t flags)
{
    return so_send_recv(so, buf, size, flags, true);
}

static inline int so_recv(socket_t so, char *buf, size_t size, uint64_t flags)
{
    return so_send_recv(so, buf, size, flags, false);
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

/**
 * NOET: sentry_client not enclose, use User-Agent header instead
 * see: https://docs.sentry.io/development/sdk-dev/overview/#authentication
 */
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

#define EPOCH_DAY_SECS      86400u
#define EPOCH_HOUR_SECS     3600u
#define EPOCH_MINUTE_SECS   60u

struct pseudo_tm {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t sec;
};

#define MONTH_PER_YEAR      12

/* see: https://www.timeanddate.com/calendar/months/ */
static const uint32_t days_of_month[][MONTH_PER_YEAR] = {
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
};

static inline int is_leap_year(uint64_t y)
{
    return !(y % 400) || (!(y & 3) && (y % 100));
}

#define EPOCH_YEAR          1970

static void format_iso8601_time(char *buf, size_t sz)
{
    int n;
    clock_sec_t t;
    struct pseudo_tm tm;
    uint32_t i;
    const uint32_t *p;

    kassert_nonnull(buf);
    kassertf(sz >= ISO8601_TM_BUFSZ,
                "Insufficient ISO-8601 time buffer size  %zu vs %u",
                sz, ISO8601_TM_BUFSZ);

    t = time(NULL);

    tm.sec = (uint32_t) t % EPOCH_MINUTE_SECS;
    t -= tm.sec;

    tm.minute = t % EPOCH_HOUR_SECS / EPOCH_MINUTE_SECS;
    t -= tm.minute * EPOCH_MINUTE_SECS;

    tm.hour = t % EPOCH_DAY_SECS / EPOCH_HOUR_SECS;
    t -= tm.hour * EPOCH_HOUR_SECS;

    kassertf(t % 86400 == 0, "t = %lu", t);
    t /= 86400;     /* Days left */

    i = 0;
    while (t >= 365) {
        t -= 365;
        if (t > 0 && is_leap_year(EPOCH_YEAR + i)) t--;
        kassertf(t >= 0, "t = %lu", t);
        i++;
    }

    p = days_of_month[is_leap_year(EPOCH_YEAR + i)];
    tm.year = i;
    for (i = 0; i < ARRAY_SIZE(*days_of_month); i++) {
        if (t <= p[i]) break;
        t -= p[i];
    }
    kassertf(t <= 31, "t = %lu", t);

    tm.month = i;
    tm.day = (uint32_t) t;

    n = snprintf(buf, sz, "%04u-%02u-%02uT%02u:%02u:%02u",
                    tm.year + EPOCH_YEAR, tm.month + 1, tm.day + 1,
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

#define BUFSZ           2048
#define AUTHSZ          192
#define PAYLOADSZ       1024

#define SENTRY_PROJID   "1533302"
#define SENTRY_PUBKEY   "3bebc23f79274f93b6500e3ecf0cf22b"

static void sentry_capture_message(socket_t so, const char *msg)
{
    int e;
    char buf[BUFSZ];
    char auth[AUTHSZ];
    char payload[PAYLOADSZ];
    uint64_t t;

    kassert_nonnull(so);
    kassert_nonnull(msg);

    format_x_sentry_auth(auth, sizeof(auth), 7, SENTRY_PUBKEY);
    format_message_payload(payload, sizeof(payload), msg);

    (void) snprintf(buf, BUFSZ, "POST /api/" SENTRY_PROJID "/store/ HTTP/1.1\r\n"
                                "Host: sentry.io\r\n"
                                "User-Agent: " SENTRY_UA "\r\n"
                                "X-Sentry-Auth: %s\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "\r\n%s", auth, strlen(payload), payload);

    LOG_DBG("POST size: %zu\n%s", strlen(buf), buf);

    t = utime(NULL);
    LOG_DBG("Sending..");
    e = so_send(so, buf, strlen(buf), MSG_WAITALL);
    if (e != 0) {
        LOG_ERR("so_send() fail  errno: %d", e);
        return;
    }
    LOG_DBG("Sent.. %llu us", utime(NULL) - t);

    LOG_DBG("Receiving..");
    (void) snprintf(buf, BUFSZ, "<no data>");
    e = so_recv(so, buf, BUFSZ, 0);
    if (e != 0) {
        LOG_ERR("so_recv() fail  errno: %d", e);
        return;
    }

    LOG("Response size: %zu\n%s", strlen(buf), buf);
}

static volatile UInt32 so_connected = 0;

/**
 * Socket upcall function will be called:
 *  when there is data more than the low water mark for reading,
 *  or when there is space for a write,
 *  or when there is a connection to accept,
 *  or when a socket is connected,
 *  or when a socket is closed or disconnected
 *
 * @param so        A reference to the socket that's ready.
 * @param cookie    The cookie passed in when the socket was created.
 * @param waitf     Indicates whether or not it's safe to block.
 */
static void so_upcall(socket_t so, void *cookie, int waitf)
{
    int e;
    int optval, optlen;
    char buf[BUFSZ];

    LOG_DBG("so_upcall() called  waitf: %d", waitf);

    kassert_nonnull(so);
    kassert(cookie == NULL);

    if (!sock_isconnected(so)) {
        optval = 0;
        optlen = sizeof(optval);
        /* sock_getsockopt() SO_ERROR should always success */
        (void) sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        LOG_DBG("socket closed or disconnected  errno: %d", optval);
        return;
    } else {
        if (OSCompareAndSwap(0, 1, &so_connected)) {
            LOG_DBG("socket %p is connected!", so);
        }
    }

    optlen = sizeof(optval);
    e = sock_getsockopt(so, SOL_SOCKET, SO_NWRITE, &optval, &optlen);
    if (e != 0) {
        LOG_ERR("sock_getsockopt() SO_NWRITE fail  errno: %d", e);
    } else {
        kassertf(optlen == sizeof(optval),
            "sock_getsockopt() SO_NWRITE optlen = %d?", optlen);

        if (optval == 0) {
            LOG_DBG("SO_NWRITE = 0, nothing to write");
        } else {
            LOG_DBG("SO_NWRITE: %d", optval);
        }
    }

    optlen = sizeof(optval);
    e = sock_getsockopt(so, SOL_SOCKET, SO_NREAD, &optval, &optlen);
    if (e != 0) {
        LOG_ERR("sock_getsockopt() SO_NREAD fail  errno: %d", e);
    } else {
        kassertf(optlen == sizeof(optval),
            "sock_getsockopt() SO_NREAD optlen = %d?", optlen);

        if (optval == 0) {
            LOG_DBG("SO_NREAD = 0, nothing to read");
            return;
        }

        LOG_DBG("SO_NREAD: %d", optval);
    }

    /* We should read only when SO_NREAD return a positive value */
    e = so_recv(so, buf, BUFSZ, 0);
    if (e != 0) {
        LOG_ERR("so_recv() fail  errno: %d", e);
    } else {
        LOG("Response (size: %zu)\n%s", strlen(buf), buf);
    }
}

static int so_set_tcp_no_delay(socket_t so, int on)
{
    int domain;
    int type;
    int proto;
    int e;

    kassert_nonnull(so);

    e = sock_gettype(so, &domain, &type, &proto);
    /* sock_gettype() should always success */
    kassertf(e == 0, "sock_gettype() fail  errno: %d", e);

    if (domain == PF_INET && type == SOCK_STREAM && proto == IPPROTO_TCP) {
        return sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }

    return EINVAL;
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
    ASSURE_TYPE_ALIAS(sin.sin_addr.s_addr, uint32_t);
    ASSURE_TYPE_ALIAS(sin.sin_port, uint16_t);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

    void *handle;
    e = sentry_new(&handle,
            "HTTP://3bebc23f79274f93b6500e3ecf0cf22b@35.188.42.15:80/1533302", 50);
    if (e != 0) LOG_ERR("sentry_new() fail  errno: %d", e);

    e = sock_socket(PF_INET, SOCK_STREAM, IPPROTO_IP, so_upcall, NULL, &so);
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
    sin.sin_port = htons(SENTRY_PORT);
    e = inet_aton(SENTRY_IP, &sin.sin_addr);
    kassertf(e == 1, "inet_aton() fail  endpoint: " SENTRY_IP);
    LOG_DBG("sin.sin_addr: %#010x", ntohl(sin.sin_addr.s_addr));

#if 0
    (void) sock_connect(so, (struct sockaddr *) &sin, MSG_DONTWAIT);
#else
    uint64_t t = utime(NULL);
    e = sock_connect(so, (struct sockaddr *) &sin, 0);
    LOG_DBG("connect time elapsed: %llu us", utime(NULL) - t);
    if (e != 0) {
        LOG_ERR("sock_connect() fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_close;
    }
#endif

    int arg;

    arg = 1;
    e = sock_ioctl(so, FIONBIO, &arg);
    if (e != 0) {
        LOG_ERR("sock_ioctl() FIONBIO fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_close;
    }

    LOG("Endpoint " SENTRY_IP "  isconnected: %d isnonblocking: %d",
            sock_isconnected(so), sock_isnonblocking(so));

    arg = 1;
    /* [sic] Just playin' it safe with upcalls */
    e = sock_setsockopt(so, SOL_SOCKET, SO_UPCALLCLOSEWAIT, &arg, sizeof(arg));
    if (e != 0) {
        LOG_ERR("sock_setsockopt() SO_UPCALLCLOSEWAIT fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    arg = 1;
    /* [sic] Assume that SOCK_STREAM always requires a connection */
    e = sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &arg, sizeof(arg));
    if (e != 0) {
        LOG_ERR("sock_setsockopt() SO_KEEPALIVE fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    arg = 1;
    /* [sic] Set SO_NOADDRERR to detect network changes ASAP */
    e = sock_setsockopt(so, SOL_SOCKET, SO_NOADDRERR, &arg, sizeof(arg));
    if (e != 0) {
        LOG_ERR("sock_setsockopt() SO_NOADDRERR fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    tv.tv_sec = 5;
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

    e = so_set_tcp_no_delay(so, 1);
    if (e != 0) {
        LOG_ERR("so_set_tcp_no_delay() fail  errno: %d", e);
        e = KERN_FAILURE;
        goto out_shutdown;
    }

    char buf[128];
    (void) snprintf(buf, sizeof(buf), "hello world! %u", random() % 100000);
    sentry_capture_message(so, buf);

    (void) snprintf(buf, sizeof(buf), "hello world! %u", random() % 100000);
    sentry_capture_message(so, buf);

    /* Sleep some time  let the upcall got notified */
    (void) usleep(1500 * USEC_PER_MSEC);

out_shutdown:
    e2 = sock_shutdown(so, SHUT_RDWR);
    if (e2 != 0) {
        LOG_ERR("sock_shutdown() RDWR fail  errno: %d", e2);
    } else {
        LOG_DBG("socket %p RDWR shuted down", so);
    }
    /* sock_shutdown() won't reset socket's SS_ISCONNECTED flag? */
out_close:
    sock_close(so);
out_exit:
#ifdef DEBUG
    return KERN_FAILURE;
#else
    return e;
#endif
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

