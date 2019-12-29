/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <netinet/in.h>         /* struct sockaddr_in */

#include "utils.h"
#include "sentry.h"

#ifdef DEBUG
#include "kauth.h"

#ifndef SENTRY_DSN_TEST
#error Please define SENTRY_DSN_TEST macro in Makefile.inc
#endif
#define SAMPLE_RATE_TEST    100

static void * __nullable sentry_test_new(kmod_info_t * __nullable ki)
{
    void *handle = NULL;
    int e = sentry_new(&handle, SENTRY_DSN_TEST, SAMPLE_RATE_TEST ,ki);
    if (e != 0) LOG_ERR("sentry_new() fail  errno: %d", e);
    return handle;
}

void *sentry_handle;
#endif  /* DEBUG */

kern_return_t sentry_xnu_start(kmod_info_t *ki, void *d)
{
    struct sockaddr_in sin;

    UNUSED(ki, d);

    ASSURE_TYPE_ALIAS(errno_t, int);
    ASSURE_TYPE_ALIAS(kern_return_t, int);
    ASSURE_TYPE_ALIAS(sin.sin_addr.s_addr, uint32_t);
    ASSURE_TYPE_ALIAS(sin.sin_port, uint16_t);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

#ifdef DEBUG
    sentry_handle = sentry_test_new(ki);
    if (sentry_handle == NULL) goto out_fail;

    if (kauth_register() != 0) goto out_sentry;
#endif

    return KERN_SUCCESS;
#ifdef DEBUG
out_sentry:
    sentry_destroy(sentry_handle);
out_fail:
    return KERN_FAILURE;
#endif
}

kern_return_t sentry_xnu_stop(kmod_info_t *ki, void *d)
{
    LOG_DBG("Unloading... ki: %p d: %p", ki, d);

#ifdef DEBUG
    /* Order matters, KAuth must be deregister before Sentry */
    kauth_deregister();
    sentry_destroy(sentry_handle);
#endif

    util_zassert();
    util_massert();

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

