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
    char pubkey[UUID_BUFSZ_COMPACT];
    uint64_t projid;
    uint8_t sample_rate;    /* Range: [0, 100] */

    lck_grp_t *lck_grp;
    lck_mtx_t *lck_mtx;
    uuid_t last_event_id;

    thread_t thread;
    volatile uint32_t cond_keepalive;
} sentry_t;
