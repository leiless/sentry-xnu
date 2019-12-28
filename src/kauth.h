/*
 * Created 191228 lynnl
 *
 * Mainly used to test Sentry functionalities
 */

#ifndef SENTRY_XNU_KAUTH_H
#define SENTRY_XNU_KAUTH_H

#include <sys/systm.h>

kern_return_t kauth_register(void);
void kauth_deregister(void);

#endif /* SENTRY_XNU_KAUTH_H */

