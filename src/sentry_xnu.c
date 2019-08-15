/*
 * Created 190815 lynnl
 */

#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include <sys/socket.h>     /* PF_INET */
//#include <sys/ubc.h>
//#include <sys/un.h>
#include <netinet/in.h>     /* IPPROTO_IP */
//#include <netinet/tcp.h>

#include "utils.h"

/**
 * Make sure type of two variables are compatible to each other
 */
#define ASSURE_TYPE_ALIAS(a, b) \
    BUILD_BUG_ON(!__builtin_types_compatible_p(__typeof__(a), __typeof__(b)))

kern_return_t sentry_xnu_start(kmod_info_t *ki, void *d)
{
    int e;
    socket_t so = NULL;
    struct sockaddr_in sin = {};     /* Fill me */

    ASSURE_TYPE_ALIAS(errno_t, int);
    ASSURE_TYPE_ALIAS(kern_return_t, int);

    BUILD_BUG_ON(sizeof(struct sockaddr) != sizeof(struct sockaddr_in));

    e = sock_socket(PF_INET, SOCK_STREAM, IPPROTO_IP, NULL, NULL, &so);
    if (e != 0) {
        LOG_ERR("sock_socket() fail  errno: %d", e);
        e = KERN_FAILURE;
    }

    e = sock_connect(so, (struct sockaddr *) &sin, 0);
    if (e != 0) {
        LOG_ERR("sock_connect() fail  errno: %d", e);
        e = KERN_FAILURE;
    }

    sock_close(so);
    return e;
}

kern_return_t sentry_xnu_stop(kmod_info_t *ki, void *d)
{

    return KERN_SUCCESS;
}
