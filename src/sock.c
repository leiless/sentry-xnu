/*
 * Created 190825 lynnl
 */

#include <sys/errno.h>

#include <netinet/in.h>     /* IPPROTO_IP */
#include <netinet/tcp.h>    /* TCP_NODELAY */

#include "utils.h"
#include "sock.h"

/**
 * Send or receive from a socket
 *
 * If you intended to send/recv a full request, please use MSG_WAITALL
 * see: xnu/bsd/kern/uipc_socket.c#soreceive()
 *
 * see:
 *  benavento/mac9p/blob/master/kext/socket.c#recvsendn_9p
 *  https://stackoverflow.com/q/3198049/10725426
 *  https://stackoverflow.com/q/15938022/10725426
 * @return      0 if success, errno otherwise
 */
static int so_send_recv(
        socket_t so,
        char *buf,
        size_t size,
        uint64_t flags,
        bool send)
{
    int e = 0;
    errno_t (*sock_op)(socket_t, /* [const] */ struct msghdr *, int, size_t *);
    struct iovec aio;
    struct msghdr msg;
    size_t i, n = 0;

    kassert_nonnull(so);
    kassert(!!buf | !size);

    sock_op = send ? (__typeof__(sock_op)) sock_send : sock_receive;

    while (n < size) {
        aio.iov_base = buf + n;
        aio.iov_len = size - n;
        bzero(&msg, sizeof(msg));
        msg.msg_iov = &aio;
        msg.msg_iovlen = 1;

        e = sock_op(so, &msg, (int) flags, &i);
        if (e != 0 || i == 0) {
            if (e == 0) e = -EAGAIN; /* Distinguish return value */
            break;
        }

        n += i;
        if (!(flags & MSG_WAITALL)) break;
    }

    if (e == 0 && !send && n < size) {
        buf[n] = '\0';
    }

    LOG_DBG("so_send_recv() %s size: %zu", send ? "send" : "recv", n);

    return e;
}

int so_send(socket_t so, char *buf, size_t size, uint64_t flags)
{
    return so_send_recv(so, buf, size, flags, true);
}

int so_recv(socket_t so, char *buf, size_t size, uint64_t flags)
{
    return so_send_recv(so, buf, size, flags, false);
}

int so_set_tcp_no_delay(socket_t so, int on)
{
    int domain;
    int type;
    int proto;
    int e;

    kassert_nonnull(so);

    e = sock_gettype(so, &domain, &type, &proto);
    /* sock_gettype() should always success */
    kassertf(e == 0, "sock_gettype() fail  errno: %d", e);

    if (domain == PF_INET && type == SOCK_STREAM && proto == IPPROTO_TCP) {
        return sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    }

    return EINVAL;
}

/**
 * Shutdown and close a socket
 */
void so_destroy(socket_t __nullable so, int how)
{
    int e;
    if (so != NULL) {
        e = sock_shutdown(so, how);
        if (e != 0) LOG_ERR("so_destroy() fail  how: %d errno: %d", how, e);
        sock_close(so);
    }
}

