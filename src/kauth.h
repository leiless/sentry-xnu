/*
 * Created 191228 lynnl
 *
 * Mainly used to test Sentry functionalities
 */

#ifndef SENTRY_XNU_KAUTH_H
#define SENTRY_XNU_KAUTH_H

#include <sys/systm.h>

/*
 * __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ is a compiler-predefined macro
 */
#define OS_VER_MIN_REQ      __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#ifndef __MAC_10_14
#define __MAC_10_14         101400
#endif

kern_return_t kauth_register(void);
void kauth_deregister(void);

#endif /* SENTRY_XNU_KAUTH_H */

