/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <netinet/in.h>         /* struct sockaddr_in */

#include "utils.h"
#include "sentry.h"

kern_return_t sentry_xnu_start(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);

    int e;
    void *handle;
    struct sockaddr_in sin;

    ASSURE_TYPE_ALIAS(errno_t, int);
    ASSURE_TYPE_ALIAS(kern_return_t, int);
    ASSURE_TYPE_ALIAS(sin.sin_addr.s_addr, uint32_t);
    ASSURE_TYPE_ALIAS(sin.sin_port, uint16_t);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

    e = sentry_new(&handle,
            "HttP://3bebc23f79274f93b6500e3ecf0cf22b@35.188.42.15:80/1533302",
            NULL, 100);
    if (e != 0) {
        LOG_ERR("sentry_new() fail  errno: %d", e);
    } else {
        sentry_capture_message(handle, 0, "sentry handle: %p", handle);

        /* Sleep some time  so the message have chance to pushed out */
        (void) usleep(1000 * USEC_PER_MSEC);

        sentry_destroy(handle);
    }

    util_massert();
    util_zassert();

#ifdef DEBUG
    return KERN_FAILURE;
#else
    return e;
#endif
}

kern_return_t sentry_xnu_stop(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);
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

