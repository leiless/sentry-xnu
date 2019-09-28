/*
 * Created 190819 lynnl
 */

#include <stdint.h>

#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/sysctl.h>
#include <libkern/version.h>
#include <uuid/uuid.h>
#include <kern/locks.h>
#include <netinet/in.h>

#include <kern/clock.h>
#include <IOKit/IOPlatformExpert.h>

#include <pexpert/pexpert.h>

#include "sentry.h"
#include "utils.h"
#include "sock.h"
#include "cJSON_Helper.h"
#include "macho.h"

#define UUID_BUFSZ              sizeof(uuid_string_t)
/* UUID string buffer size without hyphens */
#define UUID_BUFSZ_COMPACT      (UUID_BUFSZ - 4)

#define SENTRY_DISABLED         0x80u

typedef struct {
    kmod_info_t * __nullable ki;

    struct in_addr ip;
    uint16_t port;      /* XXX: please wrap with htons() */

    char pubkey[UUID_BUFSZ_COMPACT];
    uint64_t projid;
    uint8_t sample_rate;    /* Range: [0, 100] */

    uuid_t last_event_id;
    cJSON * __nonnull ctx;
    hook_func hook[2];
    void *cookie[2];

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

ssize_t sysctlbyname_size(const char *name)
{
    size_t sz = (size_t) -1;
    kassert_nonnull(name);
    int e = sysctlbyname(name, NULL, &sz, NULL, 0);
    if (e != 0) LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    return (ssize_t) sz;
}

static bool sysctlbyname_i32(const char *name, int *out)
{
    int e;
    size_t len = 4;
    kassert_nonnull(name);
    kassert_nonnull(out);
    e = sysctlbyname(name, out, &len, NULL, 0);
    if (e != 0) {
        LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    } else {
        kassertf(len == 4, "bad sysctl %s len  expected 4, got %zu", name, len);
    }
    return e == 0;
}

static bool sysctlbyname_u32(const char *name, uint32_t *out)
{
    int i;
    bool ok;
    kassert_nonnull(out);
    ok = sysctlbyname_i32(name, &i);
    if (ok) *out = (uint32_t) i;
    return ok;
}

static bool sysctlbyname_u64(const char *name, uint64_t *u64)
{
    int e;
    size_t len = sizeof(*u64);
    kassert_nonnull(name);
    kassert_nonnull(u64);
    e = sysctlbyname(name, u64, &len, NULL, 0);
    if (e != 0) {
        LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    } else {
        kassertf(len == sizeof(*u64), "bad sysctl %s len  expected %zu, got %zu", name, sizeof(*u64), len);
    }
    return e == 0;
}

static bool sysctlbyname_string(const char *name, char *buf, size_t buflen)
{
    int e;
    kassert_nonnull(name);
    kassert_nonnull(buf);
    e = sysctlbyname(name, buf, &buflen, NULL, 0);
    if (e != 0) LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    return e == 0;
}

/**
 * Get information about filesystem status backed by root vnode
 * @param out_st    [OUT] filesystem status
 * @return          0 if success
 *                  ENOENT [sic] if the vnode is dead and without existing io-reference
 */
static errno_t vfsstatfs_root(struct vfsstatfs *out_st)
{
    errno_t e = 0;
    vnode_t __nullable rootvn;
    mount_t mnt;
    struct vfsstatfs *st = NULL;

    kassert_nonnull(out_st);

    rootvn = vfs_rootvnode();
    if (rootvn != NULL) {
        mnt = vnode_mount(rootvn);
        st = vfs_statfs(mnt);

        /* Perform atomic vfsstatfs snapshot */
        do {
            (void) memcpy(out_st, st, sizeof(*st));
        } while (memcmp(out_st, st, sizeof(*st)));

        (void) vnode_put(rootvn);
    } else {
        e = ENOENT;
    }

    return e;
}

#define PTR_BUFSZ       19

static void ctx_populate_kmod_info(cJSON *contexts, kmod_info_t * __nullable ki)
{
    cJSON *kext;
    char buf[PTR_BUFSZ];
    kmod_reference_t *kr;
    kmod_info_t *k;
    uuid_string_t uuid;
    size_t i, n;
    char *p;
    errno_t e;

    kassert_nonnull(contexts);
    if (ki == NULL) return;

    kext = cJSON_AddObjectToObject(contexts, "kext");
    if (kext == NULL) return;

    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "info_version", ki->info_version, NULL);
    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "id", ki->id, NULL);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS | CJH_CONST_RHS, "name", ki->name, NULL);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS | CJH_CONST_RHS, "version", ki->version, NULL);

    /* XXX: ki->reference_count is variable */
    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "ref_count", ki->reference_count, NULL);

    n = 0;
    kr = ki->reference_list;
    while (kr != NULL) {
        k = kr->info;
        kassert_nonnull(k);
        (void) find_LC_UUID(k->address, k->size, MACHO_SET_UUID_FAIL, uuid);
        n += snprintf(NULL, 0, "%u: %#lx %#lx %s %s (%s)\n", k->id, k->address, k->size, uuid, k->name, k->version);
        kr = kr->next;
    }

#if 0
    k = ki;
    while (k != NULL) {
        e = find_LC_UUID(k->address, k->size, MACHO_SET_UUID_FAIL, uuid);
        if (e != 0) LOG_ERR("find_LC_UUID() fail  %u %s %s %#lx %#lx", k->id, k->name, k->version, k->address, k->size);
        k = k->next;
    }
#endif

    if (n > 0) {
        p = util_malloc(n + 1);
        if (p != NULL) {
            kr = ki->reference_list;
            i = 0;
            while (kr != NULL && i < n) {
                k = kr->info;
                kassert_nonnull(k);
                (void) find_LC_UUID(k->address, k->size, MACHO_SET_UUID_FAIL, uuid);
                i += snprintf(p + i, n - i, "%u: %#lx %#lx %s %s (%s)\n", k->id, k->address, k->size, uuid, k->name, k->version);
                kr = kr->next;
            }
            kassert(kr == NULL);
            kassertf(i == n, "Bad index  %zu vs %zu", i, n);
            /* ref_list should be a JSON string array */
            (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "ref_list", p, NULL);
            util_mfree(p);
        }
    }

    (void) snprintf(buf, sizeof(buf), "%#llx", (uint64_t) ki->address);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "address_begin", buf, NULL);

    (void) snprintf(buf, sizeof(buf), "%#llx", (uint64_t) ki->address + ki->size);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "address_end", buf, NULL);

    (void) snprintf(buf, sizeof(buf), "%#llx", (uint64_t) ki->size);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "size", buf, NULL);

    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "hdr_size", ki->hdr_size, NULL);

    (void) snprintf(buf, sizeof(buf), "%#llx", (uint64_t) ki->start);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "func_start", buf, NULL);

    (void) snprintf(buf, sizeof(buf), "%#llx", (uint64_t) ki->stop);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "func_stop", buf, NULL);

    e = find_LC_UUID(ki->address, ki->size, MACHO_SET_UUID_FAIL, uuid);
    if (e == 0) {
        (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "LC_UUID", uuid, NULL);
    } else {
        LOG_ERR("find_LC_UUID() fail  errno: %d", e);
    }
}

#define STR_BUFSZ    144     /* Should be enough */

static void ctx_populate(cJSON *ctx, kmod_info_t * __nullable ki)
{
    errno_t e;
    cJSON *contexts;
    cJSON *device;
    cJSON *os;
    char str[STR_BUFSZ];
    int i32;
    uint32_t u32;
    uint64_t u64;
    struct timeval tv;
    size_t sz;
    char ts[ISO8601_TM_BUFSZ];

    kassert_nonnull(ctx);

    (void) cJSON_AddStringToObject(ctx, "platform", "c");
    /* see: https://docs.sentry.io/development/sdk-dev/event-payloads */
    (void) cJSON_AddStringToObject(ctx, "logger", "(internal)");

    /* see: https://docs.sentry.io/development/sdk-dev/event-payloads/contexts */

    contexts = cJSON_AddObjectToObject(ctx, "contexts");
    if (contexts == NULL) {
        LOG_ERR("cJSON_AddObjectToObject() contexts fail");
        return;
    }

    device = cJSON_AddObjectToObject(contexts, "device");
    if (device != NULL) {
        if (sysctlbyname_u64("hw.memsize", &u64)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "memory_size", u64, NULL);
        }

        /* see: xnu/bsd/vm/vm_unix.c */
        if (sysctlbyname_u32("vm.pages", &u32) && sysctlbyname_i32("vm.pagesize", &i32)) {
            /* usable_memory means actual memory size in bytes(slightly less than memory_size) */
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "usable_memory", u32 * i32, NULL);
        }

        /*
         * kext environment doesn't expose hostname to us
         *  sysctlbyname("kern.hostname") return errno EPERM
         *  bsd_hostname() in com.apple.kpi.private framework
         * thus we skip set device.name
         * see: xnu/libkern/libkern/sysctl.h#kernel_sysctlbyname()
         */

        if (sysctlbyname_i32("hw.byteorder", &i32)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "hw.byteorder", i32, NULL);
        }

        if (sysctlbyname_i32("hw.logicalcpu", &i32)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "hw.logicalcpu", i32, NULL);
        }

        if (sysctlbyname_i32("hw.physicalcpu", &i32)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "hw.physicalcpu", i32, NULL);
        }

        if (sysctlbyname_u64("hw.cpufrequency", &u64)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "hw.cpufrequency", u64, NULL);
        }

        if (sysctlbyname_u64("hw.pagesize", &u64)) {
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "hw.pagesize", u64, NULL);
        }

        if (PEGetModelName(str, sizeof(str)) || sysctlbyname_string("hw.model", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "model", str, NULL);

#if 0
            /*
             * System Reports Kernel_*.panic hint:
             *  System model name: MODEL_NAME (hw.targettype-gPlatformECID)
             *
             * see:
             *  xnu/osfmk/arm/model_dep.c#do_print_all_backtraces()
             *  xnu/osfmk/kern/debug.c#panic_display_system_configuration()
             */
            const uint8_t * const u = gPlatformECID;
            (void) snprintf(str, sizeof(str), "%02x%02x%02x%02x%02x%02x%02x%02x",
                        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7]);
            (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "model_id", str, NULL);
#endif
        }

        if (!PEGetMachineName(str, sizeof(str))) populate_model_name(str);
        (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "arch", str, NULL);

        bzero(&tv, sizeof(tv));
        sz = sizeof(tv);
        e = sysctlbyname("kern.boottime", &tv, &sz, NULL, 0);
        if (e == 0) {
            kassertf(sz == sizeof(tv), "Bad kern.boottime size  %zu vs %zu", sz, sizeof(tv));
            e = fmt_iso8601_time0(tv.tv_sec, ts, sizeof(ts));
            kassertf(e == 0, "fmt_iso8601_time0() fail  errno: %d", e);

            (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "boot_time", ts, NULL);
        }

        if (sysctlbyname_string("machdep.cpu.brand_string", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "cpu.brand_string", str, NULL);
        }
    }

    os = cJSON_AddObjectToObject(contexts, "os");
    if (os != NULL) {
        (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS | CJH_CONST_RHS, "name", "macOS", NULL);

        if (sysctlbyname_string("kern.osproductversion", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "version", str, NULL);
        }

        (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS | CJH_CONST_RHS, "kernel_version", version, NULL);

        if (sysctlbyname_string("kern.osversion", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "build", str, NULL);
        }

        if (sysctlbyname_string("kern.uuid", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "kern.uuid", str, NULL);
        }

        if (sysctlbyname_string("kern.bootargs", str, sizeof(str))) {
            (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "kern.bootargs", str, NULL);
        }

        /* TODO: os.rooted, os.raw_description */
    }

    ctx_populate_kmod_info(contexts, ki);
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

    ctx_populate(ctx1, h->ki);

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
        uint32_t sample_rate,
        kmod_info_t * __nullable ki)
{
    int e = 0;
    sentry_t *h;
    struct timeval tv;
    struct sockaddr_in sin;

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

    h->ki = ki;
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

/**
 * Get Sentry's internal context JSON object
 * XXX: MT-Unsafe, if you want to add custom contexts to Sentry
 *      please populate it right after sentry_new()
 *      Or alternatively, do it in sentry_set_*_send_hook()
 * see: https://docs.sentry.io/development/sdk-dev/event-payloads/
 */
cJSON * __nonnull sentry_ctx_get(void * __nonnull handle)
{
    sentry_t *h = (sentry_t *) handle;
    kassert_nonnull(h);
    return h->ctx;
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
    if (i >= ARRAY_SIZE(event_levels)) i = 0;

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

/**
 * @param t     Uptime in microseconds
 */
static void populate_uptime_string(cJSON *os, uint64_t t)
{
    uint64_t us, s, m, h, d;
    int n;
    char buf[32];       /* 32 is sufficient */

    kassert_nonnull(os);
    if (t == 0) return;

    us = t % USEC_PER_SEC;
    t -= us;
    t /= USEC_PER_SEC;

    d = t / 86400;
    t -= d * 86400;

    h = t / 3600;
    t -= h * 3600;

    m = t / 60;
    t -= m * 60;

    kassertf(t < 60, "Bad remaining seconds %llu", t);
    s = t;

    if (d > 0) {
        n = snprintf(buf, sizeof(buf), "%llu:%02llu:%02llu:%02llu.%llu", d, h, m, s, us);
    } else if (h > 0) {
        n = snprintf(buf, sizeof(buf), "%llu:%02llu:%02llu.%llu", h, m, s, us);
    } else if (m > 0) {
        n = snprintf(buf, sizeof(buf), "%llu:%02llu.%llu", m, s, us);
    } else if (s > 0) {
        n = snprintf(buf, sizeof(buf), "%llu.%llu", s, us);
    } else {
        n = snprintf(buf, sizeof(buf), ".%llu", us);
    }
    kassert(n > 0);

    (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "uptime", buf, NULL);
}

static const char *PE_Video_rotations[] = {
    "normal", "right_90_deg", "flip", "left_90_deg"
};

static void populate_PE_Video(cJSON *device, char *buf, size_t sz)
{
    int n;
    PE_Video v = PE_state.video;

    kassert_nonnull(device);
    kassert_nonnull(buf);
    kassert(sz > 0);

    n = snprintf(buf, sz, "%lu x %lu", v.v_width, v.v_height);
    kassert(n > 0);

    (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "screen_resolution", buf, NULL);
    (void) cJSON_H_AddBoolToObject(device, CJH_CONST_LHS, "PE_Video.v_display", !!v.v_display, NULL);

    if (v.v_rotate < ARRAY_SIZE(PE_Video_rotations)) {
        (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS | CJH_CONST_RHS,
                    "PE_Video.v_rotate", PE_Video_rotations[v.v_rotate], NULL);
    } else {
        (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "PE_Video.v_rotate", v.v_rotate, NULL);
    }

    /* [NSScreen backingScaleFactor] > 1.0 means Retina screen */
    (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "PE_Video.v_scale", v.v_scale, NULL);
}

static void builtin_pre_send_hook(sentry_t *h)
{
    errno_t e;
    uint64_t u64;
    struct vfsstatfs st;
    struct timeval tv;
    cJSON *contexts = cJSON_GetObjectItem(h->ctx, "contexts");
    cJSON *device = contexts ? cJSON_GetObjectItem(contexts, "device") : NULL;
    cJSON *os = contexts ? cJSON_GetObjectItem(contexts, "os") : NULL;

    kassert_nonnull(h);
    /* XXX: h->lck_rw already in exclusive-locked state */

    if (device != NULL) {
        /* TODO: free_memory */

        e = vfsstatfs_root(&st);
        if (e == 0) {
            u64 = st.f_bsize * st.f_blocks;
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "storage_size", u64, NULL);

            u64 = st.f_bsize * st.f_bavail;
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "free_storage", u64, NULL);
        } else {
            LOG_ERR("root_vfsstatfs() fail  errno: %d", e);
        }

        populate_PE_Video(device, NULL, 0);
    }

    if (os != NULL) {
        microuptime(&tv);
        u64 = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
        (void) cJSON_H_AddNumberToObject(os, CJH_CONST_LHS, "uptime_us", u64, NULL);

        populate_uptime_string(os, u64);
    }
}

#define PRE_HOOK            0
#define POST_HOOK           1

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

    builtin_pre_send_hook(h);

    if (h->hook[PRE_HOOK] != NULL) {
        h->hook[PRE_HOOK](h, h->ctx, h->cookie[PRE_HOOK]);
    }

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

    if (h->hook[POST_HOOK] != NULL) {
        h->hook[POST_HOOK](h, h->ctx, h->cookie[POST_HOOK]);
    }
}

static void capture_message_ap(
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
    capture_message_ap(handle, flags, fmt, ap);
    va_end(ap);
}

/**
 * @return      Previous send hook
 */
static hook_func __nullable set_send_hook(
        void *handle,
        hook_func hook,
        void *cookie,
        uint32_t index)
{
    sentry_t *h = (sentry_t *) handle;
    hook_func prev;
    kassert_nonnull(h);
    kassertf(index < ARRAY_SIZE(h->hook), "Bad index %u", index);
    lck_rw_lock_exclusive(h->lck_rw);
    prev = h->hook[index];
    h->hook[index] = hook;
    h->cookie[index] = hook ? cookie : NULL;
    lck_rw_unlock_exclusive(h->lck_rw);
    return prev;
}

/**
 * Set pre event send hook
 * @param hook      Event send hook(NULL to deregister)
 * @param cookie    Cookie pass to event send callback
 *                  When hook is NULL, cookie will be ignored
 */
hook_func sentry_set_pre_send_hook(
        void *handle,
        hook_func hook,
        void *cookie)
{
    return set_send_hook(handle, hook, cookie, PRE_HOOK);
}

hook_func sentry_set_post_send_hook(
    void *handle,
    hook_func hook,
    void *cookie)
{
    return set_send_hook(handle, hook, cookie, POST_HOOK);
}

