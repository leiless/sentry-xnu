/*
 * Created 190923 lynnl
 */

#ifndef SENTRY_XNU_MACHO_H
#define SENTRY_XNU_MACHO_H

/* Given Mach-O header is 64-bit */
#define MACHO_ARCH_64BIT        0x00000001
/* Write a default UUID string when fail */
#define MACHO_SET_UUID_FAIL     0x00000002

errno_t find_LC_UUID(vm_address_t, vm_size_t, uint32_t, uuid_string_t);

#endif /* SENTRY_XNU_MACHO_H */

