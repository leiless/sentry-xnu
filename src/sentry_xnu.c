/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/socket.h>     /* PF_INET */
//#include <sys/ubc.h>
#include <sys/un.h>
#include <netinet/in.h>     /* IPPROTO_IP */
//#include <netinet/tcp.h>

#include "utils.h"

/**
 * Make sure type of two variables are compatible to each other
 */
#define ASSURE_TYPE_ALIAS(a, b) \
    BUILD_BUG_ON(!__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))

#define SIN_LEN     __offsetof(struct sockaddr_in, sin_zero)

#define ENDPOINT    "52.20.38.43"

kern_return_t sentry_xnu_start(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);

    int e;
    socket_t so = NULL;
    struct sockaddr_in sin;

    ASSURE_TYPE_ALIAS(errno_t, int);
    ASSURE_TYPE_ALIAS(kern_return_t, int);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

    e = sock_socket(PF_INET, SOCK_STREAM, IPPROTO_IP, NULL, NULL, &so);
    if (e != 0) {
        LOG_ERR("sock_socket() fail  errno: %d", e);
        e = KERN_FAILURE;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_len = SIN_LEN;
    sin.sin_family = PF_INET;
    sin.sin_port = htons(80);
    e = inet_aton(ENDPOINT, &sin.sin_addr);
    kassertf(e == 1, "inet_aton() fail  endpoint: " ENDPOINT);

    e = sock_connect(so, (struct sockaddr *) &sin, 0);
    if (e != 0) {
        LOG_ERR("sock_connect() fail  errno: %d", e);
        e = KERN_FAILURE;
    }

    LOG("Endpoint " ENDPOINT "connected!");

    sock_close(so);
    return KERN_SUCCESS;
}

kern_return_t sentry_xnu_stop(kmod_info_t *ki, void *d)
{
    UNUSED(ki, d);
    LOG(KEXTNAME_S " unloading..");
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

