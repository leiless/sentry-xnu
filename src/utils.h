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

int printf_no_hide_ptr(const char * __nonnull, ...) __printflike(1, 2);

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
#define LOG(fmt, ...) printf_no_hide_ptr(KEXTNAME_S ": " fmt "\n", ##__VA_ARGS__)

#define ___LOG0(fmt, ...)    \
    LOG(fmt " <%s@%s()#%d>", ##__VA_ARGS__, __BASE_FILE__, __func__, __LINE__)

#define LOG_WARN(fmt, ...)   ___LOG0("[WARN] " fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)    ___LOG0("[ERR] " fmt, ##__VA_ARGS__)
#define LOG_BUG(fmt, ...)    ___LOG0("[BUG] " fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...)  ___LOG0("[TRACE] " fmt, ##__VA_ARGS__)

#define LOG_OFF(fmt, ...)    UNUSED(fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define LOG_DBG(fmt, ...)    LOG("[DBG] " fmt, ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)    LOG_OFF(fmt, ##__VA_ARGS__)
#endif

#define panicf(fmt, ...) ({                                     \
    panic("\n" fmt "\n%s@%s()#%d\n\n",                          \
        ##__VA_ARGS__, __BASE_FILE__, __func__, __LINE__);      \
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
 * Example: kassertf(sz == 4 || sz == 8, "Bad size %zu?!", sz);
 */
#define kassertf(ex, fmt, ...) \
    (ex) ? (void) 0 : panicf("Assert `%s' failed: " fmt, #ex, ##__VA_ARGS__)

#else

#define kassert(ex) (ex) ? (void) 0 : LOG_BUG("Assert `%s' failed", #ex)

#define kassertf(ex, fmt, ...) \
    (ex) ? (void) 0 : LOG_BUG("Assert `%s' failed: " fmt, #ex, ##__VA_ARGS__)

#endif      /* DEBUG */

void * __nonnull _kassert_nonnull(const void * __nonnull, ...)      \
    __deprecated_msg("Use kassert_nonnull() macro");

#define kassert_nonnull(p, ...) {                                   \
    _Pragma("GCC diagnostic push")                                  \
    _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"") \
    _kassert_nonnull(p, ##__VA_ARGS__, _kassert_nonnull);           \
    _Pragma("GCC diagnostic pop")                                   \
}


#define __kassert_cmp(v1, v2, f1, f2, op)   \
    kassertf((v1) op (v2), "left: " f1 " right: " f2, (v1), (v2))

#define kassert_eq(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, ==)
#define kassert_ne(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, !=)
#define kassert_le(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, <=)
#define kassert_ge(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, >=)
#define kassert_lt(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, <)
#define kassert_gt(v1, v2, f1, f2)  __kassert_cmp(v1, v2, f1, f2, >)

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
bool uuid_string_is_null(uuid_string_t __nonnull);

#define ISO8601_TM_BUFSZ    20u
int fmt_iso8601_time0(clock_sec_t, char * __nonnull, size_t);
int fmt_iso8601_time(char * __nonnull, size_t);

double pseudo_strtod(
    const char * __nonnull,
    char * __nullable * __nullable restrict
);

uint32_t urand32(uint32_t, uint32_t);

extern void populate_model_name(char * __nonnull);

char * __nullable kmp_strstr(const char * __nonnull, const char * __nonnull);

int kcb_get(void);
int kcb_put(void);
int kcb_read(void);
void kcb_invalidate(void);

#endif /* SENTRY_XNU_UTILS_H */

