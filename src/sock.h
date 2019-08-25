/*
 * Created 190825 lynnl
 */

#ifndef SENTRY_XNU_SOCK_H
#define SENTRY_XNU_SOCK_H

#include <sys/socket.h>     /* PF_INET */

/**
 * Time-count socket connect
 *
 * @param so    The socket
 * @param tv    Microsecond level time out
 * @return      0 if successfully connected within the timeout
 *              EINVAL if socket in bad state(SS_ISCONNECTING, SS_ISCONNECTED = 0)
 *              EDOM if `tv' is bad
 *              EINPROGRESS if still not connected within the timeout
 *
 * Usually called after MSG_DONTWAIT sock_connect()
 */
extern errno_t sock_connectwait(socket_t so, const struct timeval *tv);

int so_send(socket_t, char *, size_t, uint64_t);
int so_recv(socket_t, char *, size_t, uint64_t);

int so_set_tcp_no_delay(socket_t, int);

#endif /* SENTRY_XNU_SOCK_H */

