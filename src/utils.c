/*
 * Created 190815 lynnl
 */

#include <sys/time.h>
#include <sys/proc.h>
#include <sys/socket.h>

#include <kern/clock.h>
#include <libkern/OSAtomic.h>

#include "utils.h"

uint64_t utime(uint64_t * __nullable p)
{
    clock_sec_t s;
    clock_usec_t __unused u;
    clock_get_calendar_microtime(&s, &u);
    if (p != NULL) {
        *p = s * USEC_PER_SEC + u;
    }
    return s * USEC_PER_SEC + u;
}

/**
 * @param t     Microseconds to sleep
 * @return      Reason why got awake
 *              EINTR           got interrupted
 *              ERESTART        ditto. (other signals)
 *              EWOULDBLOCK     timed out(usual cause)
 */
int usleep(uint64_t t)
{
    struct timespec ts = {
        t / USEC_PER_SEC,
        (t % USEC_PER_SEC) * NSEC_PER_USEC
    };
    /* Zero timeout will causes msleep() dead sleep */
    if (t == 0) return EWOULDBLOCK;
    /*
     * `chan' argument cannot be NULL, otherwise it'll return early
     * thus we used an external invisible pseudo-channel
     */
    return msleep(&ts, NULL, PPAUSE, NULL, &ts);
}

static void util_mstat(int opt)
{
    static volatile SInt64 cnt = 0;
    switch (opt) {
    case 0:
        if (OSDecrementAtomic64(&cnt) > 0) return;
        break;
    case 1:
        if (OSIncrementAtomic64(&cnt) >= 0) return;
        break;
    case 2:
        if (cnt == 0) return;
        /* Fall through */
    default:
        break;
    }
    panicf("FIXME: potential memleak  opt: %d cnt: %lld", opt, cnt);
}

/* Zero size allocation will return a NULL */
void * __nullable util_malloc(size_t size, int flags)
{
    /* _MALLOC `type' parameter is a joke */
    void *addr = _MALLOC(size, M_TEMP, flags);
    if (likely(addr != NULL)) util_mstat(1);
    return addr;
}

void util_mfree(void * __nullable addr)
{
    if (addr != NULL) util_mstat(0);
    _FREE(addr, M_TEMP);
}

/* XXX: call when all memory freed */
void util_massert(void)
{
    util_mstat(2);
}

static inline char tolower(char c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/**
 * striprefix(s, "") return true
 */
bool striprefix(const char *s1, const char *s2)
{
    char c;

    kassert_nonnull(s1);
    kassert_nonnull(s2);

    while ((c = *s2++) != '\0') {
        if (tolower(c) != tolower(*s1++))
            return false;
    }

    return true;
}

/**
 * Shutdown and close a socket
 */
void util_sock_destroy(socket_t __nullable so)
{
    if (so != NULL) {
        sock_shutdown(so, SHUT_RDWR);
        sock_close(so);
    }
}

