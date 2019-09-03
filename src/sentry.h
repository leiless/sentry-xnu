/*
 * Created 190819 lynnl
 */

#ifndef SENTRY_H
#define SENTRY_H

#include "cJSON.h"

int sentry_new(
    void * __nullable * __nonnull,
    const char * __nonnull,
    const cJSON * __nullable,
    uint32_t
);

void sentry_destroy(void * __nullable);

#endif /* SENTRY_H */

