/*
 * Created 190815 lynnl
 */

#ifndef SENTRY_XNU_UTILS_H
#define SENTRY_XNU_UTILS_H

#include <sys/types.h>
#include <libkern/libkern.h>

#include <sys/time.h>
#include <kern/clock.h>

#include <sys/malloc.h>
#include <kern/debug.h>         /* panic() */

#ifndef __kext_makefile__
#define KEXTNAME_S          "sentry-xnu"
#endif

/*
 * Used to indicate unused function parameters
 * see: <sys/cdefs.h>#__unused
 */
#define UNUSED(e, ...)      (void) ((void) (e), ##__VA_ARGS__)

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(*a))

/**
 * Should only used for `char[]'  NOT `char *'
 * Assume ends with null byte('\0')
 */
#define STRLEN(s)           (sizeof(s) - 1)

/**
 * Compile-time assurance  see: linux/arch/x86/boot/boot.h
 * Will fail build if condition yield true
 */
#ifdef DEBUG
#define BUILD_BUG_ON(cond)      UNUSED(sizeof(char[-!!(cond)]))
#else
#define BUILD_BUG_ON(cond)      UNUSED(cond)
#endif

/**
 * Make sure type of two variables are compatible to each other
 */
#define ASSURE_TYPE_ALIAS(a, b) \
    BUILD_BUG_ON(!__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))

/**
 * os_log() is only available on macOS 10.12 or newer
 *  thus os_log do have compatibility issue  use printf instead
 *
 * XNU kernel version of printf() don't recognize some rarely used specifiers
 *  like h, i, j, t  use unrecognized spcifier may raise kernel panic
 *
 * Feel free to print NULL as %s  it checked explicitly by kernel-printf
 *
 * see: xnu/osfmk/kern/printf.c#printf
 */
#define LOG(fmt, ...)        printf(KEXTNAME_S ": " fmt "\n", ##__VA_ARGS__)

#define LOG_WARN(fmt, ...)   LOG("[WARN] " fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)    LOG("[ERR] " fmt, ##__VA_ARGS__)
#define LOG_BUG(fmt, ...)    LOG("[BUG] " fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...)  LOG("[TRACE] " fmt, ##__VA_ARGS__)
#define LOG_OFF(fmt, ...)    UNUSED(fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define LOG_DBG(fmt, ...)    LOG("[DBG] " fmt, ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)    LOG_OFF(fmt, ##__VA_ARGS__)
#endif

#define panicf(fmt, ...) ({                                     \
    panic("\n" fmt "\n%s@%s#L%d\n\n",                           \
        ##__VA_ARGS__, __BASE_FILE__, __FUNCTION__, __LINE__);  \
    __builtin_unreachable();                                    \
})

#ifdef DEBUG
/*
 * NOTE: Do NOT use any multi-nary conditional/logical operator inside assertion
 *       like operators && || ?:  it's extremely EVIL
 *       Separate them  each statement per line
 */
#define kassert(ex) (ex) ? (void) 0 : panicf("Assert `%s' failed", #ex)

/**
 * @ex      the expression
 * @fmt     panic message format
 *
 * Example: kassertf(sz > 0, "Why size %zd non-positive?", sz);
 */
#define kassertf(ex, fmt, ...) \
    (ex) ? (void) 0 : panicf("Assert `%s' failed: " fmt, #ex, ##__VA_ARGS__)
#else
#define kassert(ex) (ex) ? (void) 0 : LOG_BUG("Assert `%s' failed", #ex)

#define kassertf(ex, fmt, ...) \
    (ex) ? (void) 0 : LOG_BUG("Assert `%s' failed: " fmt, #ex, ##__VA_ARGS__)
#endif

#define kassert_nonnull(ptr)    kassert(ptr != NULL)

#define kassert_eq(v1, v2)      kassertf(v1 == v2, "%zd vs %zd", (ssize_t) v1, (ssize_t) v2)

/*
 * non DEVELOPMENT/DEBUG kernel(s) will hide kernel addresses since macOS 10.11
 * see: xnu/osfmk/kern/printf.c#doprnt_hide_pointers
 */
#define PRIptr                  "%#010x%08x"
#define ptr2hex(p)              (uint32_t) ((uint64_t) p >> 32), (uint32_t) p

/**
 * Branch predictions
 * see: linux/include/linux/compiler.h
 */
#define likely(x)               __builtin_expect(!!(x), 1)
#define unlikely(x)             __builtin_expect(!!(x), 0)

uint64_t utime(uint64_t * __nullable);

#ifndef USEC_PER_MSEC
#define USEC_PER_MSEC       1000ULL      /* microseconds per milliseconds */
#endif
int usleep(uint64_t);

void * __nullable util_malloc0(size_t, int);
void * __nullable util_malloc(size_t);
void util_mfree(void * __nullable);
void util_massert(void);

void * __nullable util_zmalloc(size_t);
void * __nullable util_zrealloc(void * __nullable, size_t);
void util_zfree(void * __nullable);
void util_zassert(void);

int tolower(int);
bool striprefix(const char * __nonnull, const char * __nonnull);

clock_sec_t time(clock_sec_t * __nullable);

void uuid_string_generate(uuid_string_t __nonnull);

#define ISO8601_TM_BUFSZ    20u
int fmt_iso8601_time0(clock_sec_t, char * __nonnull, size_t);
int fmt_iso8601_time(char * __nonnull, size_t);

double pseudo_strtod(
    const char * __nonnull,
    char * __nullable * __nullable restrict
);

uint32_t urand32(uint32_t, uint32_t);

#endif /* SENTRY_XNU_UTILS_H */

