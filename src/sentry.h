/*
 * Created 190819 lynnl
 */

#ifndef SENTRY_H
#define SENTRY_H

#include "cJSON.h"

#define SENTRY_XNU_NAME         "sentry-xnu"
#define SENTRY_XNU_VERSION      "0.3"
#define SENTRY_XNU_UA           SENTRY_XNU_NAME "/" SENTRY_XNU_VERSION

/*
 * Most significant 3 bits denoted Sentry Event Level
 * Hence at most 8 levels can be supported
 */
#define SEL_ERR     0x00000000u     /* (duh) Default level */
#define SEL_DBG     0x20000000u
#define SEL_INF     0x40000000u
#define SEL_WRN     0x60000000u
#define SEL_FTL     0x80000000u

int sentry_new(
    void * __nullable * __nonnull,
    const char * __nonnull,
    const cJSON * __nullable,
    uint32_t
);

void sentry_debug(void * __nonnull);

void sentry_destroy(void * __nullable);

void sentry_capture_message(
    void * __nonnull,
    uint32_t,
    const char * __nonnull,
    ...
);

#endif /* SENTRY_H */

