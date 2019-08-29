/*
 * Created 190815 lynnl
 */

#include <sys/time.h>
#include <sys/proc.h>

#include <kern/clock.h>
#include <libkern/OSAtomic.h>

#include "utils.h"

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
        /* Fall through */
    default:
        break;
    }
    panicf("FIXME: potential memleak  opt: %d cnt: %lld", opt, cnt);
}

/* Zero size allocation will return a NULL */
void * __nullable util_malloc(size_t size, int flags)
{
    /* _MALLOC `type' parameter is a joke */
    void *addr = _MALLOC(size, M_TEMP, flags);
    if (likely(addr != NULL)) util_mstat(1);
    return addr;
}

void * __nullable util_malloc_ez(size_t size)
{
    return util_malloc(size, 0);
}

void util_mfree(void * __nullable addr)
{
    if (addr != NULL) util_mstat(0);
    _FREE(addr, M_TEMP);
}

/* XXX: call when all memory freed */
void util_massert(void)
{
    util_mstat(2);
}

void kern_os_free_safe(void *addr)
{
    if (addr != NULL) kern_os_free(addr);
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

    kassert_nonnull(s1);
    kassert_nonnull(s2);

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
 * @param buf       Output buffer
 * @param sz        buffer size
 * @return          0 if success, errno otherwise.
 *                  EINVAL if buffer size less less than ISO8601_TM_BUFSZ
 */
int format_iso8601_time(char *buf, size_t sz)
{
    int e = 0;
    clock_sec_t t;
    struct pseudo_tm tm;
    uint32_t i;
    const uint32_t *p;
    int n;

    kassert_nonnull(buf);
    if (sz < ISO8601_TM_BUFSZ) {
        e = EINVAL;
        goto out_exit;
    }

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

out_exit:
    return e;
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

