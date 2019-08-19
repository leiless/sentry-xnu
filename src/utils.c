/*
 * Created 190815 lynnl
 */

#include <sys/time.h>
#include <kern/clock.h>
#include <sys/proc.h>

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

