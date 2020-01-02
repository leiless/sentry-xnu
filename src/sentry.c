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

#include <libkern/OSDebug.h>

#include <mach-o/loader.h>

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

    volatile SInt64 counter;  /* Active counter, -1 means invalidated */
} sentry_t;

/**
 * @return      value before increase
 *              -1 if counter invalidated
 */
static SInt64 sentry_counter_get(sentry_t * __nonnull h)
{
    kassert_nonnull(h);
    if (h->counter < 0) {
        kassertf(h->counter == -1, "Bad counter for get: %lld", h->counter);
        return -1;
    }
    return OSIncrementAtomic64(&h->counter);
}

static void sentry_counter_put(sentry_t * __nonnull h)
{
    SInt64 old;
    kassert_nonnull(h);
    old = OSDecrementAtomic64(&h->counter);
    kassertf(old > 0, "Bad count for put: %lld", old);
}

void sentry_debug(void *handle)
{
    sentry_t *h = (sentry_t *) handle;
    uuid_string_t u;
    char * __nullable ctx;

    kassert_nonnull(h);

    if (sentry_counter_get(h) < 0) return;

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

    sentry_counter_put(h);
}

#define HTTP_PORT       80

#define IPV4_BUFSZ      16

static bool parse_ip(sentry_t *handle, const char *host, size_t n)
{
    char buf[IPV4_BUFSZ];

    kassert_nonnull(handle, host);

    if (n < 7 || n > 15) return false;
    (void) strlcpy(buf, host, n + 1);

    return inet_aton(buf, &handle->ip);
}

static bool parse_u16(const char *str, size_t n, uint16_t *out)
{
    char buf[6];
    char *p = NULL;
    u_long ul;

    kassert_nonnull(str, out);

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
    kassert_nonnull(str, out);

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

    kassert_nonnull(handle, dsn);

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

void sentry_get_last_event_id(void *handle, uuid_t out)
{
    sentry_t *h = (sentry_t *) handle;

    kassert_nonnull(h, out);

    if (sentry_counter_get(h) < 0) {
        (void) memset(out, 0, sizeof(uuid_t));
        return;
    }

    lck_rw_lock_exclusive(h->lck_rw);
    (void) memcpy(out, h->last_event_id, sizeof(uuid_t));
    lck_rw_unlock_exclusive(h->lck_rw);

    sentry_counter_put(h);
}

void sentry_get_last_event_id_string(void *handle, uuid_string_t out)
{
    uuid_t uu;
    kassert_nonnull(out);
    sentry_get_last_event_id(handle, uu);
    uuid_unparse_lower(uu, out);
}

static int char2hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

/**
 * NB: Lame HTTP response parsing
 */
static void parse_http_response(sentry_t *h, const char *str)
{
    const char *s = str;
    const char *t;
    uuid_string_t uuid;
    uuid_t uu;
    int a, b;
    size_t i;

    kassert_nonnull(h, s);

    if (!strprefix(s, "HTTP/1.1 200 OK\r\n")) return;
    s += STRLEN("HTTP/1.1 200 OK\r\n");

    s = kmp_strstr(s, "\r\n\r\n");
    if (s == NULL) return;

    s += STRLEN("\r\n\r\n");
    if (!strprefix(s, "{\"id\":\"")) return;
    s += STRLEN("{\"id\":\"");

    t = kmp_strstr(s, "\"}");
    if (t == NULL || t - s != UUID_BUFSZ_COMPACT-1) return;

    (void) strlcpy(uuid, s, UUID_BUFSZ_COMPACT);

    kassert(strlen(uuid) == sizeof(uu) * 2);

    for (i = 0; uuid[i] != '\0'; i += 2) {
        a = char2hex(uuid[i]);
        b = char2hex(uuid[i+1]);
        if (likely(a >= 0 && b >= 0)) {
            uu[i >> 1] = (a << 4) | b;
        } else {
            return;
        }
    }

    uuid_unparse_lower(uu, uuid);
    LOG_DBG("Event ID: %s", uuid);

    lck_rw_lock_exclusive(h->lck_rw);
    (void) memcpy(h->last_event_id, uu, sizeof(uu));
    lck_rw_unlock_exclusive(h->lck_rw);
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
    sentry_t *h;

    kassert_nonnull(so, cookie);
    UNUSED(waitf);

    h = (sentry_t *) cookie;

    if (sentry_counter_get(h) < 0) return;

    kassertf(so == h->so, "[upcall] Bad cookie  %p vs %p", so, h->so);

    if (!sock_isconnected(so)) {
        optval = 0;
        optlen = sizeof(optval);
        /* sock_getsockopt() SO_ERROR should always success */
        e = sock_getsockopt(so, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        kassertf(e == 0, "[upcall] sock_getsockopt() SO_ERROR fail  errno: %d", e);
        LOG_ERR("[upcall] socket not connected  errno: %d", optval);

        (void) OSBitAndAtomic(0, &h->connected);
        goto out_put;
    } else {
        if (OSCompareAndSwap(0, 1, &h->connected)) {
            LOG_DBG("[upcall] socket %p is connected!", so);
            goto out_put;
        }
    }

    optlen = sizeof(optval);
    e = sock_getsockopt(so, SOL_SOCKET, SO_NREAD, &optval, &optlen);
    if (e != 0) {
        LOG_ERR("[upcall] sock_getsockopt() SO_NREAD fail  errno: %d", e);
    } else {
        kassert_eq(optlen, sizeof(optval), "%d", "%zu");

        if (optval == 0) {
            LOG_DBG("[upcall] SO_NREAD = 0, nothing to read");
            goto out_put;
        }

        LOG_DBG("[upcall] SO_NREAD: %d", optval);
    }

    /* We should read only when SO_NREAD return a positive value */
    e = so_recv(so, buf, BUFSZ, 0);
    if (e != 0) {
        LOG_ERR("[upcall] so_recv() fail  errno: %d", e);
    } else {
        buf[optval] = '\0';     /* Ensure buffer is NULL-terminated */
        LOG("[upcall] Response (size: %zu)\n%s", strlen(buf), buf);
        parse_http_response(h, buf);
    }

out_put:
    sentry_counter_put(h);
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
    size_t len = sizeof(*out);
    kassert_nonnull(name, out);
    e = sysctlbyname(name, out, &len, NULL, 0);
    if (e != 0) {
        LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    } else {
        kassertf(len == sizeof(*out),
            "bad sysctl %s len  expected %zu, got %zu",
            name, sizeof(*out), len);
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
    kassert_nonnull(name, u64);
    e = sysctlbyname(name, u64, &len, NULL, 0);
    if (e != 0) {
        LOG_ERR("sysctlbyname() %s fail  errno: %d", name, e);
    } else {
        kassertf(len == sizeof(*u64),
            "bad sysctl %s len  expected %zu, got %zu",
            name, sizeof(*u64), len);
    }
    return e == 0;
}

static bool sysctlbyname_string(const char *name, char *buf, size_t buflen)
{
    int e;
    kassert_nonnull(name, buf);
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
        /*
         * [sic]
         *  Note that the data in the structure will continue to change
         *  over time and also that it may be quite stale if
         *  vfs_update_vfsstat has not been called recently.
         */
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

#define BUFFER_SIZE     192

static void ctx_populate_kmod_info(cJSON *contexts, kmod_info_t * __nullable ki)
{
    cJSON *kext;
    char buf[BUFFER_SIZE];
    kmod_reference_t *kr;
    kmod_info_t *k;
    uuid_string_t uuid;
    int n;
    errno_t e;
    cJSON *ref_list;

    kassert_nonnull(contexts);
    if (ki == NULL) return;

    kext = cJSON_AddObjectToObject(contexts, "kext");
    if (kext == NULL) return;

    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "info_version", ki->info_version, NULL);
    (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS, "id", ki->id, NULL);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS | CJH_CONST_RHS, "name", ki->name, NULL);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS | CJH_CONST_RHS, "version", ki->version, NULL);

    ref_list = cJSON_CreateArray();
    if (ref_list != NULL) {
        kr = ki->reference_list;
        while (kr != NULL) {
            k = kr->info;
            kassert_nonnull(k);

            (void) find_LC_UUID(k->address, k->size, MACHO_SET_UUID_FAIL, uuid);
            if (uuid_string_is_null(uuid)) {
                (void) strlcpy(uuid, "0", sizeof(uuid));
            }
            n = snprintf(buf, sizeof(buf), "%u: %#lx %#lx %s %s (%s)",
                    k->id, k->address, k->size, uuid, k->name, k->version);
            kassert(n > 0);

            if (!cJSON_H_AddItemToArray(ref_list, cJSON_CreateString(buf))) break;

            kr = kr->next;
        }

        if (kr != NULL || !cJSON_H_AddItemToObjectCS(kext, "ref_list", ref_list)) {
            cJSON_Delete(ref_list);
        }
    }

    (void) snprintf(buf, sizeof(buf),
                "   begin: %#llx\n     end: %#llx\n    size: %#llx\nhdr_size: %#llx",
                        (uint64_t) ki->address,
                        (uint64_t) ki->address + ki->size,
                        (uint64_t) ki->size,
                        (uint64_t) ki->hdr_size);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "address", buf, NULL);

    (void) snprintf(buf, sizeof(buf), "start: %#llx\n stop: %#llx",
                        (uint64_t) ki->start, (uint64_t) ki->stop);
    (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "func", buf, NULL);

    e = find_LC_UUID(ki->address, ki->size, MACHO_SET_UUID_FAIL, uuid);
    if (e == 0) {
        (void) cJSON_H_AddStringToObject(kext, CJH_CONST_LHS, "LC_UUID", uuid, NULL);
    } else {
        LOG_ERR("find_LC_UUID() fail  errno: %d", e);
    }
}

/**
 * XXX: PE_Video seems only denotes primary screen(if you have multiple monitors) and immutable after os booted
 */
static void populate_PE_Video(cJSON *device)
{
    int n;
    char buf[96];
    PE_Video v = PE_state.video;

    kassert_nonnull(device);

    /* [NSScreen backingScaleFactor] > 1.0 means Retina screen */
    n = snprintf(buf, sizeof(buf),
            "resolution: %lu x %lu\n"
            " v_display: %lu\n"
            "    rotate: %d\n"
            "     scale: %d",
                v.v_width, v.v_height, v.v_display, v.v_rotate, v.v_scale);
    kassert(n > 0);
    (void) cJSON_H_AddStringToObject(device, CJH_CONST_LHS, "PE_Video", buf, NULL);
}

#define KERN_ADDR_MASK      0xfffffffffff00000LLU
#define KERN_BASE_STEP      0x100000

/**
 * Try to enclose kernel text bases into Sentry context
 */
static void kernel_get_bases(cJSON *os)
{
    uint64_t __hib, kernel;
    uint32_t t;
    char buf[64];
    int n;

    kassert_nonnull(os);

    __hib = ((uint64_t) bcopy) & KERN_ADDR_MASK;
    kernel = __hib + KERN_BASE_STEP;

    /* XXX: This line may cause kernel panic due to page fault */
    t = *((uint32_t *) kernel);

    /* Only supported 64-bit Mach-O kernel */
    if (t == MH_MAGIC_64 || t == MH_CIGAM_64) {
        n = snprintf(buf, sizeof(buf), " __HIB: %#018llx\nkernel: %#018llx", __hib, kernel);
        kassert(n > 0);
        (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "text_base", buf, NULL);
    } else {
        LOG_ERR("Cannot get kernel slides, kernel memory layout changed?!");
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
        (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "memory_size", max_mem, NULL);

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

        populate_PE_Video(device);
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

        kernel_get_bases(os);
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
        void * __nullable *handlep,
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

    h = util_malloc0(sizeof(*h), M_WAITOK | M_NULL);
    if (unlikely(h == NULL)) {
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

    kassert_eq(e, 0, "%d", "%d");
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
    kassert_ne(e, 0, "%d", "%d");
    goto out_exit;
}

void sentry_destroy(void * __nullable handle)
{
    sentry_t *h = (sentry_t *) handle;

    if (h == NULL) return;

    /* Counter can't get anymore once it invalidated */
    while (!OSCompareAndSwap64(0, (UInt64) -1, (volatile UInt64 *) &h->counter)) {
        while (h->counter > 0) {
            (void) usleep(200 * USEC_PER_MSEC);
        }
    }

    so_destroy(h->so, SHUT_RDWR);

    cJSON_Delete(h->ctx);
    lck_rw_free(h->lck_rw, h->lck_grp);
    lck_grp_free(h->lck_grp);

    util_mfree(h);
}

/**
 * Get Sentry's internal context JSON object
 * XXX: MT-Unsafe, if you want to add custom contexts to Sentry
 *      please populate it right after sentry_new()
 *      Or alternatively, do it in sentry_set_*_send_hook()
 * see: https://docs.sentry.io/development/sdk-dev/event-payloads/
 */
cJSON * __nullable sentry_ctx_get(void * __nonnull handle)
{
    sentry_t *h = (sentry_t *) handle;
    cJSON *ctx;

    kassert_nonnull(h);

    if (sentry_counter_get(h) < 0) return NULL;

    ctx = h->ctx;

    sentry_counter_put(h);

    return ctx;
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

/* TODO: those should be configurable */
#define SENTRY_PROTO_VER    7
#define SENTRY_ENDPOINT     "sentry.io"

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
            "Host: " SENTRY_ENDPOINT "\r\n"   /* TODO: should be DSN's endpoint */
            "User-Agent: " SENTRY_XNU_UA "\r\n"
            "X-Sentry-Auth: Sentry sentry_version=%u, sentry_timestamp=%lu, sentry_key=%s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "\r\n%s",
            h->projid, SENTRY_PROTO_VER, time(NULL), h->pubkey, ctx_len, ctx);

    kassert_gt(n, 0, "%d", "%d");

    return n;
}

/**
 * @param t     Uptime in microseconds
 */
static void populate_uptime_string(cJSON *os, uint64_t t)
{
    uint64_t ts = t, us, s, m, h, d;
    int n;
    char buf[48];       /* Sufficient */

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

    n = snprintf(buf + n, sizeof(buf) - n, " raw: %llu", ts);
    kassert(n > 0);

    (void) cJSON_H_AddStringToObject(os, CJH_CONST_LHS, "uptime_us", buf, NULL);
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
    cJSON *kext = contexts ? cJSON_GetObjectItem(contexts, "kext") : NULL;

    kassert_nonnull(h);
    /* (ditto) Assure h->lck_rw must in exclusive-locked state */
    kassert(!lck_rw_try_lock(h->lck_rw, LCK_RW_TYPE_EXCLUSIVE));

    if (device != NULL) {
        e = vfsstatfs_root(&st);
        if (e == 0) {
            u64 = st.f_bsize * st.f_blocks;
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "storage_size", u64, NULL);

            u64 = st.f_bsize * st.f_bavail;
            (void) cJSON_H_AddNumberToObject(device, CJH_CONST_LHS, "free_storage", u64, NULL);
        } else {
            LOG_ERR("root_vfsstatfs() fail  errno: %d", e);
        }
    }

    if (os != NULL) {
        microuptime(&tv);
        u64 = tv.tv_sec * USEC_PER_SEC + tv.tv_usec;
        populate_uptime_string(os, u64);
    }

    if (kext != NULL && h->ki != NULL) {
        /* # linkage refs to this kext */
        (void) cJSON_H_AddNumberToObject(kext, CJH_CONST_LHS,
                    "ref_count", h->ki->reference_count, NULL);
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

    n = format_event_data(h, ctx, ctx_len, NULL, 0);
    data = util_malloc0(n + 1, M_WAITOK | M_NULL);
    if (unlikely(data == NULL)) {
        LOG_ERR("util_malloc0() fail  size: %d", n + 1);
        util_zfree(ctx);
        return;
    }

    n2 = format_event_data(h, ctx, ctx_len, data, n + 1);
    kassert_eq(n, n2, "%d", "%d");

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

#define BT_BUFSZ                32

static void enclose_backtrace(sentry_t *h)
{
    void *bt[BT_BUFSZ];
    int32_t i, nframe;
    char buf[64];
    int n;
    uint64_t a;
    cJSON *contexts;
    cJSON *backtrace;
    cJSON *frames;

    kassert_nonnull(h);
    kassert_nonnull(h->ctx);

    nframe = OSBacktrace(bt, ARRAY_SIZE(bt));
    if (unlikely(nframe <= 0)) return;

    contexts = cJSON_GetObjectItem(h->ctx, "contexts");
    if (contexts == NULL) return;

    backtrace = cJSON_CreateObject();
    if (unlikely(backtrace == NULL)) return;

    frames = cJSON_AddArrayToObject(backtrace, "frames");
    if (unlikely(frames == NULL)) {
        cJSON_Delete(backtrace);
        return;
    }

    /*
     * Frames sorted from newest to oldest
     * backtrace 0: OSBacktrace()
     * backtrace 1: (this function)
     * see: xnu/libkern/gen/OSDebug.cpp#OSReportWithBacktrace()
     */
    for (i = 0; i < nframe; i++) {
        a = (uint64_t) bt[i];

        if (h->ki != NULL) {
            n = snprintf(buf, sizeof(buf), "frame: %#018llx in_kext: %d",
                    a, a >= h->ki->address && a < h->ki->address + h->ki->size);
        } else {
            n = snprintf(buf, sizeof(buf), "frame: %#018llx in_kext: ?", a);
        }
        kassert(n > 0);

        if (!cJSON_H_AddItemToArray(frames, cJSON_CreateString(buf))) break;
    }

    if (i != nframe) {
        cJSON_Delete(backtrace);
    } else {
        if (!cJSON_H_AddItemToObjectCS(contexts, "backtrace", backtrace)) {
            cJSON_Delete(backtrace);
        }
    }
}

#define FLAG_ENCLOSE_BT         0x00000001

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

    kassert_nonnull(h, fmt);

    if (!h->connected) {
        /* TODO: push messages into a linked list if socket not yet ready? */
        LOG_WARN("Skip capture message since handle %p isn't connected", h);
        return;
    }

    t = eid++;
    if (urand32(0, 100) >= h->sample_rate) {
        LOG_DBG("Event %llx sampled out  flags: %#x fotmat: %s", t, flags, fmt);
        return;
    }

    va_copy(ap, ap_in);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    kassert_ge(n, 0, "%d", "%d");

    if (strchr(fmt, '%') == NULL) {
        /*
         * If % absent in fmt, it means it's a plain text
         *  we have no need to malloc and formatting
         */
        msg = (char *) fmt;
    } else {
        /*
         * M_NULL first introduced in macOS 10.12
         * kernel will panic if kalloc_canblock() failed for macOS < 10.12
         * see: xnu/bsd/kern/kern_malloc.c#__MALLOC()
         */
        msg = util_malloc0(n + 1, M_WAITOK | M_NULL);
        if (unlikely(msg == NULL)) {
            /* Fallback to print format string? */
            msg = (char *) fmt;
            LOG_ERR("util_malloc0() fail  size: %d", n + 1);
        } else {
            va_copy(ap, ap_in);
            n2 = vsnprintf(msg, n + 1, fmt, ap);
            va_end(ap);

            kassert_gt(n2, 0, "%d", "%d");
            /* Currently only possible case is the '%s' format specifier */
            kassertf(n2 == n, "Format arguments got modified in other thread?! %d vs %d", n2, n);
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
        LOG_ERR("cJSON_H_AddStringToObject() event_id fail  errno: %d", e);
    }

    if (cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "timestamp", ts, &e) == NULL) {
        LOG_ERR("cJSON_H_AddStringToObject() timestamp fail  errno: %d", e);
    }

    if (cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "message", msg, &e) == NULL) {
        LOG_ERR("cJSON_H_AddStringToObject() message fail  errno: %d", e);
    }
#else
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "event_id", uuid, NULL);
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "timestamp", ts, NULL);
    (void) cJSON_H_AddStringToObject(h->ctx, CJH_CONST_LHS, "message", msg, NULL);
#endif

    if (flags & FLAG_ENCLOSE_BT) {
        enclose_backtrace(h);
    }

    post_event(h);

    if (flags & FLAG_ENCLOSE_BT) {
        (void) cJSON_H_DeleteItemFromObject(h->ctx, "contexts", "backtrace", NULL);
    }

    lck_rw_unlock_exclusive(h->lck_rw);

    if (msg != fmt) util_mfree(msg);
}

void sentry_capture_message(void *handle, uint32_t flags, const char *fmt, ...)
{
    va_list ap;

    if (sentry_counter_get(handle) < 0) return;

    va_start(ap, fmt);
    capture_message_ap(handle, flags, fmt, ap);
    va_end(ap);

    sentry_counter_put(handle);
}

void sentry_capture_exception(void *handle, uint32_t flags, const char *fmt, ...)
{
    va_list ap;

    if (sentry_counter_get(handle) < 0) return;

    va_start(ap, fmt);
    capture_message_ap(handle, flags | FLAG_ENCLOSE_BT, fmt, ap);
    va_end(ap);

    sentry_counter_put(handle);
}

/**
 * @return      Previous send hook
 */
static hook_func __nullable set_send_hook(
        void *handle,
        hook_func __nullable hook,
        void *cookie,
        uint32_t index)
{
    sentry_t *h = (sentry_t *) handle;
    hook_func prev;
    kassert_nonnull(h);

    if (sentry_counter_get(h) < 0) return NULL;

    kassert_lt(index, ARRAY_SIZE(h->hook), "%u", "%zu");
    lck_rw_lock_exclusive(h->lck_rw);
    prev = h->hook[index];
    h->hook[index] = hook;
    h->cookie[index] = hook ? cookie : NULL;
    lck_rw_unlock_exclusive(h->lck_rw);

    sentry_counter_put(h);

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
        hook_func __nullable hook,
        void * __nullable cookie)
{
    return set_send_hook(handle, hook, cookie, PRE_HOOK);
}

hook_func sentry_set_post_send_hook(
    void *handle,
    hook_func __nullable hook,
    void * __nullable cookie)
{
    return set_send_hook(handle, hook, cookie, POST_HOOK);
}

