/*
 * Created 190819 lynnl
 */

#include <stdint.h>
#include <uuid/uuid.h>
#include <kern/locks.h>

#include "sentry.h"
#include "utils.h"

#define UUID_BUFSZ              sizeof(uuid_string_t)
/* UUID string buffer size without hyphens */
#define UUID_BUFSZ_COMPACT      (UUID_BUFSZ - 4)

#define SENTRY_DISABLED         0x80u

typedef struct {
    uint32_t ipv4;
    uint16_t port;

    char pubkey[UUID_BUFSZ_COMPACT];
    uint64_t projid;
    uint8_t sample_rate;    /* Range: [0, 100] */

    lck_grp_t *lck_grp;
    lck_rw_t *lck_rw;
    uuid_t last_event_id;

#if 0
    thread_t thread;
    volatile uint32_t cond_keepalive;
#endif
} sentry_t;

/**
 * Create a Sentry handle
 *
 * DSN(Client key) format:
 *  SCHEME://PUBKEY@HOST[:PORT]/PROJECT_ID
 * Currently only HTTP scheme is supported
 *
 * @param handlep       [OUT] pointer to the Sentry handle
 * @param dsn           The client key
 * @param sample_rate   (literal)
 * @return              0 if success, errno otherwise
 */
int sentry_new(void **handlep, const char *dsn, uint32_t sample_rate)
{
    sentry_t handle;
    UNUSED(handle);
    UNUSED(handlep, dsn, sample_rate);
    return 0;
}

