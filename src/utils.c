/*
 * Created 190815 lynnl
 */

#include <sys/time.h>
#include <sys/proc.h>

#include <kern/clock.h>

#include <libkern/OSAtomic.h>
#include <libkern/crypto/rand.h>

#include "utils.h"

/**
 * XXX: Must pass _kassert_nonnull at the end of the call, otherwise kernel will panic
 * @return          first argument
 */
void * __nonnull _kassert_nonnull(const void * __nonnull arg, ...)
{
    const void *ptr = arg;
    va_list ap;
    size_t i = 0;

    va_start(ap, arg);
    do {
        i++;
        kassertf(ptr != NULL, "Argument#%zu is NULL", i);
    } while ((ptr = va_arg(ap, void *)) != _kassert_nonnull);
    va_end(ap);

    return (void *) arg;
}

/**
 * Get unix time stamp in microseconds
 */
uint64_t utime(uint64_t * __nullable p)
{
    clock_sec_t s;
    clock_usec_t __unused u;
    clock_get_calendar_microtime(&s, &u);
    if (p != NULL) {
        *p = s * USEC_PER_SEC + u;
    }
    return s * USEC_PER_SEC + u;
}

/**
 * @param t     Microseconds to sleep
 * @return      Reason why got awake
 *              EINTR           got interrupted
 *              ERESTART        ditto. (other signals)
 *              EWOULDBLOCK     timed out(usual cause)
 */
int usleep(uint64_t t)
{
    struct timespec ts = {
        t / USEC_PER_SEC,
        (t % USEC_PER_SEC) * NSEC_PER_USEC
    };
    /* Zero timeout will causes msleep() dead sleep */
    if (t == 0) return EWOULDBLOCK;
    /*
     * `chan' argument cannot be NULL, otherwise it'll return early
     * thus we used an external invisible pseudo-channel
     */
    return msleep(&ts, NULL, PPAUSE, NULL, &ts);
}

static void util_mstat(int opt)
{
    static volatile SInt64 cnt = 0;
    switch (opt) {
    case 0:
        if (OSDecrementAtomic64(&cnt) > 0) return;
        break;
    case 1:
        if (OSIncrementAtomic64(&cnt) >= 0) return;
        break;
    case 2:
        if (cnt == 0) return;
        break;
    }
    panicf("FIXME: potential memleak  opt: %d cnt: %lld", opt, cnt);
}

/* Zero size allocation will return a NULL */
void * __nullable util_malloc0(size_t size, int flags)
{
    /* _MALLOC `type' parameter is a joke */
    void *addr = _MALLOC(size, M_TEMP, flags);
    if (likely(addr != NULL)) util_mstat(1);
    return addr;
}

void * __nullable util_malloc(size_t size)
{
    return util_malloc0(size, M_NOWAIT);
}

void util_mfree(void * __nullable addr)
{
    if (addr != NULL) {
        _FREE(addr, M_TEMP);
        util_mstat(0);
    }
}

/* XXX: call when all memory freed */
void util_massert(void)
{
    util_mstat(2);
}

/*
 * kern_os_*() family functions provides zero-out memory
 * kern_os_malloc(0) will return NULL
 * XXX: kern_os_free(NULL) will cause kernel panic
 * see: xnu/libkern/c++/OSRuntime.cpp
 */
extern void * __nullable kern_os_malloc(size_t);
extern void * __nullable kern_os_realloc(void * __nullable, size_t);
extern void kern_os_free(void * __nonnull);

static void util_zstat(int opt)
{
    static volatile SInt64 cnt = 0;
    switch (opt) {
    case 0:
        if (OSDecrementAtomic64(&cnt) > 0) return;
        break;
    case 1:
        if (OSIncrementAtomic64(&cnt) >= 0) return;
        break;
    case 2:
        if (cnt == 0) return;
        break;
    }
    panicf("FIXME: potential memleak  opt: %d cnt: %lld", opt, cnt);
}

void *util_zmalloc(size_t sz)
{
    void *addr = kern_os_malloc(sz);
    if (likely(addr != NULL)) util_zstat(1);
    return addr;
}

void *util_zrealloc(void *addr0, size_t sz)
{
    void *addr1 = kern_os_realloc(addr0, sz);
    if (!addr0 && addr1) util_zstat(1);
    return addr1;
}

void util_zfree(void *addr)
{
    if (addr != NULL) {
        kern_os_free(addr);
        util_zstat(0);
    }
}

/* XXX: call when all memory freed */
void util_zassert(void)
{
    util_zstat(2);
}

int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/**
 * striprefix(s, "") return true
 */
bool striprefix(const char *s1, const char *s2)
{
    char c;

    kassert_nonnull(s1, s2);

    while ((c = *s2++) != '\0') {
        if (tolower(c) != tolower(*s1++))
            return false;
    }

    return true;
}

/**
 * Get unix time stamp in seconds
 * see:
 *  Miscellaneous Kernel Services - Apple Developer
 *  https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/KernelProgramming/services/services.html
 */
clock_sec_t time(clock_sec_t * __nullable p)
{
    clock_sec_t s;
    clock_usec_t __unused u;
    clock_get_calendar_microtime(&s, &u);
    if (p != NULL) *p = s;
    return s;
}

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

#define EPOCH_YEAR          1970

/**
 * Format an ISO-8601 datetime without trailing time zone
 * @param t         UNIX time stamp in seconds
 * @param buf       Output buffer
 * @param sz        Buffer size
 * @return          0 if success, errno otherwise.
 *                  EINVAL if buffer size less less than ISO8601_TM_BUFSZ
 */
int fmt_iso8601_time0(clock_sec_t t, char *buf, size_t sz)
{
    int e = 0;
    struct pseudo_tm tm;
    uint32_t i;
    const uint32_t *p;
    int n;

    kassert_nonnull(buf);
    if (sz < ISO8601_TM_BUFSZ) {
        e = EINVAL;
        goto out_exit;
    }

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

out_exit:
    return e;
}

/**
 * see: fmt_iso8601_time0()
 */
int fmt_iso8601_time(char *buf, size_t sz)
{
    return fmt_iso8601_time0(time(NULL), buf, sz);
}

void uuid_string_generate(uuid_string_t out)
{
    uuid_t u;
    kassert_nonnull(out);
    uuid_generate_random(u);
    uuid_unparse_lower(u, out);
}

/**
 * Pseudo strtod() in kernel
 * The fractional part always ignored
 */
double pseudo_strtod(const char *nptr, char **restrict endptr)
{
    return (double) strtouq(nptr, endptr, 10);
}

/**
 * Generate a random number in range [lo, hi)
 */
uint32_t urand32(uint32_t lo, uint32_t hi)
{
    uint32_t u;
    int e;
    kassertf(lo < hi, "Misuse of urand32()  %#x vs %#x", lo, hi);
    e = random_buf(&u, sizeof(u));
    /*
     * Fallback to random() if random_buf() failed
     * [sic random()] The result is uniform on [0, 2^31 - 1]
     */
    if (e != 0) u = random();
    return lo + u % (hi - lo);
}

