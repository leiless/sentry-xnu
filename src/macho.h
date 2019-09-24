/*
 * Created 190923 lynnl
 */

#ifndef SENTRY_XNU_MACHO_H
#define SENTRY_XNU_MACHO_H

/* Write a default UUID string when fail */
#define MACHO_SET_UUID_FAIL     0x00000001

errno_t find_LC_UUID(vm_address_t, vm_size_t, uint32_t, uuid_string_t);

#endif /* SENTRY_XNU_MACHO_H */

