/*
 * Created 190819 lynnl
 */

#include <stdint.h>

#include <sys/errno.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <uuid/uuid.h>
#include <kern/locks.h>
#include <netinet/in.h>

#include "sentry.h"
#include "utils.h"
#include "sock.h"
#include "cJSON_Helper.h"

#define UUID_BUFSZ              sizeof(uuid_string_t)
/* UUID string buffer size without hyphens */
#define UUID_BUFSZ_COMPACT      (UUID_BUFSZ - 4)

#define SENTRY_DISABLED         0x80u

typedef struct {
    struct in_addr ip;
    uint16_t port;      /* XXX: please wrap with htons() */

    char pubkey[UUID_BUFSZ_COMPACT];
    uint64_t projid;
    uint8_t sample_rate;    /* Range: [0, 100] */

    uuid_t last_event_id;
    cJSON * __nonnull ctx;

    lck_grp_t * __nonnull lck_grp;
    lck_rw_t * __nonnull lck_rw;

    socket_t __nonnull so;
    volatile UInt32 connected;
} sentry_t;

void sentry_debug(void *handle)
{
    sentry_t *h = (sentry_t *) handle;
    uuid_string_t u;
    char * __nullable ctx;

    kassert_nonnull(h);

    uuid_unparse_lower(h->last_event_id, u);
    ctx = cJSON_Print(h->ctx);
    cJSON_Minify(ctx);  /* cJSON_Minify(NULL) do nop */

    LOG_DBG("Sentry handle %p: "
            "ip: %#010x port: %u pubkey: %s "
            "projid: %llu sample_rate: %u "
            "last_event_id: %s "
            "lck_grp: %p lck_rw: %p "
            "socket: %p ctx: %s",
                h, ntohl(h->ip.s_addr), h->port,
                h->pubkey, h->projid,
                h->sample_rate,
                u, h->lck_grp, h->lck_rw,
                h->so, ctx);

    util_zfree(ctx);
}

#define HTTP_PORT       80

#define IPV4_BUFSZ      16

static bool parse_ip(sentry_t *handle, const char *host, size_t n)
{
    char buf[IPV4_BUFSZ];

    kassert_nonnull(handle);
    kassert_nonnull(host);

    if (n < 7 || n > 15) return false;
    (void) strlcpy(buf, host, n + 1);

    return inet_aton(buf, &handle->ip);
}

static bool parse_u16(const char *str, size_t n, uint16_t *out)
{
    char buf[6];
    char *p = NULL;
    u_long ul;

    kassert_nonnull(str);
    kassert_nonnull(out);

    if (n == 0 || n >= sizeof(buf)) return false;
    (void) strlcpy(buf, str, n + 1);
    ul = strtoul(buf, &p, 10);

    kassert_nonnull(p);
    if (*p != '\0') return false;

    if ((ul & ~0xffffUL) != 0) return false;

    *out = (uint16_t) ul;
    return true;
}

static bool parse_u64(const char *str, size_t n, uint64_t *out)
{
    char buf[21];
    char *p = NULL;
    uint64_t u64;

    ASSURE_TYPE_ALIAS(u_quad_t, uint64_t);
    kassert_nonnull(str);
    kassert_nonnull(out);

    if (n == 0 || n >= sizeof(buf)) return false;
    (void) strlcpy(buf, str, n + 1);
    u64 = strtouq(buf, &p, 10);

    kassert_nonnull(p);
    if (*p != '\0') return false;

    *out = u64;
    return true;
}

/**
 * DSN(Client key) format:
 *  SCHEME://PUBKEY@HOST[:PORT]/PROJECT_ID
 */
static bool parse_dsn(sentry_t *handle, const char *dsn)
{
    char *p1, *p2;

    kassert_nonnull(handle);
    kassert_nonnull(dsn);

    /* Currently only HTTP scheme is supported */
    if (!striprefix(dsn, "http://")) return false;
    dsn += STRLEN("http://");   /* PUBKEY@HOST[:PORT]/PROJECT_ID */

    p1 = strchr(dsn, '@');
    if (p1 == NULL || p1 - dsn != UUID_BUFSZ_COMPACT - 1) return false;

    (void) strlcpy(handle->pubkey, dsn, UUID_BUFSZ_COMPACT);
    dsn = p1 + 1;               /* HOST[:PORT]/PROJECT_ID */

    p1 = strchr(dsn, ':');
    p2 = strchr(p1 ? p1 + 1 : dsn, '/');
    if (p2 == NULL) return false;

    if (p1 != NULL) {
        if (!parse_ip(handle, dsn, p1 - dsn)) return false;
        if (!parse_u16(p1 + 1, p2 - p1 - 1, &handle->port)) return false;
    } else {
        if (!parse_ip(handle, dsn, p2 - dsn)) return false;
        handle->port = HTTP_PORT;
    }

    dsn = p2 + 1;               /* PROJECT_ID */
    if (!parse_u64(dsn, strlen(dsn), &handle->projid)) return false;
    if (handle->projid == UINT64_MAX) return false;

    return true;
}

#define BUFSZ           2048

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
    sentry_t *handle;

    kassert_nonnull(so);
    kassert_nonnull(cookie);
    UNUSED(waitf);

    handle = (sentry_t *) cookie;
    kassertf(so == handle->so, "[upcall] Bad cookie  %p vs %p", so, handle->so);

    if (!sock_isconnected(so)) {
        optval = 0;
        optlen = sizeof(optval);
        /* sock_getsockopt() SO_ERROR should always success */
        e = sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        kassertf(e == 0, "[upcall] sock_getsockopt() SO_ERROR fail  errno: %d", e);
        LOG_ERR("[upcall] socket not connected  errno: %d", optval);

        (void) OSBitAndAtomic(0, &handle->connected);
        return;
    } else {
        if (OSCompareAndSwap(0, 1, &handle->connected)) {
            LOG_DBG("[upcall] socket %p is connected!", so);
            return;
        }
    }

    optlen = sizeof(optval);
    e = sock_getsockopt(so, SOL_SOCKET, SO_NREAD, &optval, &optlen);
    if (e != 0) {
        LOG_ERR("[upcall] sock_getsockopt() SO_NREAD fail  errno: %d", e);
    } else {
        kassertf(optlen == sizeof(optval),
            "[upcall] sock_getsockopt() SO_NREAD optlen = %d?", optlen);

        if (optval == 0) {
            LOG_DBG("[upcall] SO_NREAD = 0, nothing to read");
            return;
        }

        LOG_DBG("[upcall] SO_NREAD: %d", optval);
    }

    /* We should read only when SO_NREAD return a positive value */
    e = so_recv(so, buf, BUFSZ, 0);
    if (e != 0) {
        LOG_ERR("[upcall] so_recv() fail  errno: %d", e);
    } else {
        LOG("[upcall] Response (size: %zu)\n%s", strlen(buf), buf);
    }
}

static void ctx_populate(cJSON *ctx)
{
    cJSON *sdk;

    kassert_nonnull(ctx);

    /* see: https://docs.sentry.io/development/sdk-dev/event-payloads/sdk */
    sdk = cJSON_CreateObject();
    if (sdk != NULL) {
        /* name, version both must required */
        (void) cJSON_AddStringToObject(sdk, "name", SENTRY_XNU_NAME);
        (void) cJSON_AddStringToObject(sdk, "version", SENTRY_XNU_VERSION);
        cJSON_AddItemToObjectCS(ctx, "sdk", sdk);
    }

    (void) cJSON_AddStringToObject(ctx, "platform", "c");
    /* see: https://docs.sentry.io/development/sdk-dev/event-payloads */
    (void) cJSON_AddStringToObject(ctx, "logger", "(internal)");

    /* TODO: populate contexts */
    /* see: https://docs.sentry.io/development/sdk-dev/event-payloads/contexts */
}

/**
 * Reinitialize json context of a Sentry handle
 * @return      true if success, false otherwise
 */
static bool sentry_ctx_clear(void *handle)
{
    sentry_t *h = (sentry_t *) handle;
    cJSON *ctx0, *ctx1;

    kassert_nonnull(h);

    ctx1 = cJSON_CreateObject();
    if (ctx1 == NULL) return false;

    ctx_populate(ctx1);

    lck_rw_lock_exclusive(h->lck_rw);
    ctx0 = h->ctx;
    h->ctx = ctx1;
    lck_rw_unlock_exclusive(h->lck_rw);

    cJSON_Delete(ctx0);

    return true;
}

/**
 * Create a Sentry handle
 *
 * DSN(Client key) format:
 *  SCHEME://PUBKEY@HOST[:PORT]/PROJECT_ID
 * Currently only HTTP scheme is supported
 *
 * @param handlep       [OUT] pointer to the Sentry handle
 * @param dsn           The client key
 * @param ctx           Initial cJSON context(nullable)
 * @param sample_rate   Sample rate [0, 100]
 * @return              0 if success, errno otherwise
 *
 * TODO: implement an in-kernel gethostbyname()
 */
int sentry_new(
        void **handlep,
        const char *dsn,
        const cJSON *ctx,
        uint32_t sample_rate)
{
    int e = 0;
    sentry_t *h;
    struct timeval tv;
    struct sockaddr_in sin;

    UNUSED(ctx);    /* TODO */

    if (handlep == NULL || dsn == NULL || sample_rate > 100) {
        e = EINVAL;
        goto out_exit;
    }

    h = util_malloc(sizeof(*h));
    if (h == NULL) {
        e = ENOMEM;
        goto out_oom;
    }
    bzero(h, sizeof(*h));

    if (!parse_dsn(h, dsn)) {
        e = EDOM;
        goto out_free;
    }

    h->sample_rate = sample_rate;

    /* lck_grp_name is a dummy placeholder */
    h->lck_grp = lck_grp_alloc_init("", LCK_GRP_ATTR_NULL);
    if (h->lck_grp == NULL) {
        e = ENOMEM;
        goto out_free;
    }

    h->lck_rw = lck_rw_alloc_init(h->lck_grp, LCK_ATTR_NULL);
    if (h->lck_rw == NULL) {
        e = ENOMEM;
        goto out_lck_grp;
    }

    if (!sentry_ctx_clear(h)) {
        e = ENOMEM;
        goto out_lck_rw;
    }

    e = sock_socket(PF_INET, SOCK_STREAM, IPPROTO_IP, so_upcall, h, &h->so);
    if (e != 0) goto out_cjson;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    e = so_set_common_options(h->so, tv, 1);
    if (e != 0) goto out_socket;

    bzero(&sin, sizeof(sin));
    /*
     * XXX:
     *  (struct sockaddr).sin_len must be sizeof(struct sockaddr)
     *  otherwise sock_connect() will return EINVAL
     *
     * see:
     *  xnu/bsd/kern/kpi_socket.c#sock_connect
     *  xnu/bsd/kern/uipc_socket.c#soconnectlock
     *  xnu/bsd/netinet/raw_ip.c#rip_usrreqs, rip_connect
     */
    sin.sin_len = sizeof(sin);
    sin.sin_family = PF_INET;
    sin.sin_port = htons(h->port);
    sin.sin_addr = h->ip;

#if 1
    e = sock_connect(h->so, (struct sockaddr *) &sin, MSG_DONTWAIT);
    if (e != 0) {
        if (e != EINPROGRESS) goto out_socket;
        e = 0;  /* Reset when errno = EINPROGRESS */
    }

#if 1
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    e = sock_connectwait(h->so, &tv);
    if (e != 0) {
        LOG_ERR("sock_connectwait() fail  errno: %d", e);
        e = 0;  /* Reset errno */
    }
#endif
#else
    e = sock_connect(h->so, (struct sockaddr *) &sin, 0);
    if (e != 0) goto out_socket;
#endif

    sentry_debug(h);
    *handlep = h;

    kassertf(e == 0, "expected errno == 0, got %d", e);
out_exit:
    return e;
out_socket:
    so_destroy(h->so, SHUT_RDWR);
out_cjson:
    cJSON_Delete(h->ctx);
out_lck_rw:
    lck_rw_free(h->lck_rw, h->lck_grp);
out_lck_grp:
    lck_grp_free(h->lck_grp);
out_free:
    util_mfree(h);
out_oom:
    kassertf(e != 0, "expected errno != 0, got 0");
    goto out_exit;
}

void sentry_destroy(void *handle)
{
    sentry_t *h = (sentry_t *) handle;
    if (h != NULL) {
        so_destroy(h->so, SHUT_RDWR);

        cJSON_Delete(h->ctx);
        lck_rw_free(h->lck_rw, h->lck_grp);
        lck_grp_free(h->lck_grp);

        util_mfree(h);
    }
}

static const char * const event_levels[] = {
    /* Default level is error */
    "error", "debug", "info", "warning", "fatal",
};

#define FLAGS_TO_LEVEL(flags)       ((flags) >> 29u)

static void msg_set_level_attr(sentry_t *h, uint32_t flags)
{
    static uint32_t f = CJH_CONST_LHS | CJH_CONST_RHS;
    uint32_t i = FLAGS_TO_LEVEL(flags);
#ifdef DEBUG
    int e;
#endif

    kassert_nonnull(h);

    /* Correct to error level */
    if (i >= ARRAY_SIZE(event_levels)) i = SEL_ERR;

#ifdef DEBUG
    if (cJSON_H_AddStringToObject(h->ctx, f, "level", event_levels[i], &e) == NULL) {
        LOG_ERR("cJSON_H_AddStringToObject() level fail  errno: %d", e);
    }
#else
    (void) cJSON_H_AddStringToObject(h->ctx, f, "level", event_levels[i], NULL);
#endif
}

#define SENTRY_PROTO_VER    7           /* XXX: should be configurable */

static int format_event_data(
        const sentry_t *h,
        const char *ctx,
        size_t ctx_len,
        char * __nullable buf,
        size_t buf_len)
{
    int n;

    kassert(!!buf || !buf_len);

    /*
     * NOET: sentry_client not enclose in X-Sentry-Auth, use User-Agent instead
     * see: https://docs.sentry.io/development/sdk-dev/overview/#authentication
     */
    n = snprintf(buf, buf_len,
            "POST /api/%llu/store/ HTTP/1.1\r\n"
            "Host: sentry.io\r\n"   /* TODO: should be DSN's endpoint */
            "User-Agent: " SENTRY_XNU_UA "\r\n"
            "X-Sentry-Auth: Sentry sentry_version=%u, sentry_timestamp=%lu, sentry_key=%s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "\r\n%s",
            h->projid, SENTRY_PROTO_VER, time(NULL), h->pubkey, ctx_len, ctx);
    kassertf(n > 0, "snprintf() fail  n: %d", n);
    return n;
}

static void post_event(sentry_t *h)
{
    int n, n2;
    char *ctx;
    size_t ctx_len;
    char *data;
    int e;

    kassert_nonnull(h);
    /* Assure h->lck_rw must in exclusive-locked state */
    kassert(!lck_rw_try_lock(h->lck_rw, LCK_RW_TYPE_EXCLUSIVE));

    ctx = cJSON_Print(h->ctx);
    if (ctx == NULL) {
        LOG_ERR("cJSON_Print() fail");
        return;
    }
    cJSON_Minify(ctx);
    ctx_len = strlen(ctx);

out_toctou:
    n = format_event_data(h, ctx, ctx_len, NULL, 0);

    data = util_malloc(n + 1);
    if (data == NULL) {
        /* TODO: we can fallback to use a giant buffer */
        LOG_ERR("util_malloc() fail  size: %d", n);
        util_zfree(ctx);
        return;
    }

    n2 = format_event_data(h, ctx, ctx_len, data, n + 1);
    if (n2 > n) {
        util_mfree(data);
        goto out_toctou;
    }
    n = n2; /* Correct n to its final value, in case we use it later */
    kassertf((size_t) n == strlen(data), "Bad data length  %d vs %zu", n, strlen(data));

    util_zfree(ctx);

    e = so_send(h->so, data, n, 0);
    if (e != 0) {
        LOG_ERR("so_send() fail  errno: %d size: %d", e, n);
    }

    LOG_DBG("data:\n%s", data);
    util_mfree(data);
}

static void sentry_capture_message_ap(
        void *handle,
        uint32_t flags,
        const char *fmt,
        va_list ap_in)
{
    static volatile uint64_t eid = 0, t;

    sentry_t *h = (sentry_t *) handle;
    uuid_string_t uuid;
    char ts[ISO8601_TM_BUFSZ];
    va_list ap;
    int n, n2;
    char *msg;
    int e;

    kassert_nonnull(h);
    kassert_nonnull(fmt);

    if (!h->connected) {
        /*
         * TODO:
         *  we should push messages to a linked list if socket not yet ready?
         *  and linger some time before socket got so_destroy()
         */
        LOG_WARN("Skip capture message since handle %p isn't connected", h);
        return;
    }

    t = eid++;
    if (urand32(0, 100) >= h->sample_rate) {
        LOG_DBG("Event %llx sampled out  flags: %#x fotmat: %s", t, flags, fmt);
        return;
    }

out_toctou:
    va_copy(ap, ap_in);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    kassertf(n >= 0, "vsnprintf() #1 fail  n: %d", n);

    if (strchr(fmt, '%') == NULL) {
        /*
         * If % absent in fmt, it means it's a plain text
         *  we have no need to malloc and formatting
         */
        msg = (char *) fmt;
    } else {
        msg = util_malloc(n + 1);
        if (unlikely(msg == NULL)) {
            /*
             * Fallback XXX:
             *  fmt contains format specifier
             *  can it leads to kernel panic due to luck of adequate argument(s)
             */
            msg = (char *) fmt;
        } else {
            va_copy(ap, ap_in);
            n2 = vsnprintf(msg, n + 1, fmt, ap);
            va_end(ap);
            kassertf(n2 >= 0, "vsnprintf() #2 fail  n: %d", n2);

            if (unlikely(n2 > n)) {
                util_mfree(msg);
                /* NOTE: we may overcommit some bytes to prevent potential TOCTOU attacks */
                goto out_toctou;
            }

            n = n2; /* Correct n to its final value, in case we use it later */
        }
    }

    uuid_string_generate(uuid);
    e = fmt_iso8601_time(ts, sizeof(ts));
    kassertf(e == 0, "fmt_iso8601_time() fail  errno: %d", e);

    lck_rw_lock_exclusive(h->lck_rw);

    msg_set_level_attr(h, flags);

#ifdef DEBUG
    /*
     * [sic] Hexadecimal string representing a uuid4 value.
     * The length is exactly 32 characters. Dashes are not allowed.
     * XXX: as tested, uuid string with dashes is acceptable for Sentry server
     */
    if (cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "event_id", uuid, &e) == NULL) {
        LOG_DBG("cJSON_H_AddStringToObject() event_id fail  errno: %d", e);
    }

    if (cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "timestamp", ts, &e) == NULL) {
        LOG_DBG("cJSON_H_AddStringToObject() timestamp fail  errno: %d", e);
    }

    if (cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "message", msg, &e) == NULL) {
        LOG_ERR("cJSON_H_AddStringToObject() message fail  errno: %d", e);
    }
#else
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "event_id", uuid, NULL);
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "timestamp", ts, NULL);
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "message", msg, NULL);
#endif

    post_event(h);

    lck_rw_unlock_exclusive(h->lck_rw);

    if (msg != fmt) util_mfree(msg);
}

void sentry_capture_message(void *handle, uint32_t flags, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    sentry_capture_message_ap(handle, flags, fmt, ap);
    va_end(ap);
}

