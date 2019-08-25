/*
 * Created 190825 lynnl
 */

#ifndef SENTRY_XNU_SOCK_H
#define SENTRY_XNU_SOCK_H

#include <sys/socket.h>     /* PF_INET */

int so_send(socket_t, char *, size_t, uint64_t);
int so_recv(socket_t, char *, size_t, uint64_t);

#endif /* SENTRY_XNU_SOCK_H */

