/*
 * Created 190904 lynnl
 *
 * Use camel-case reluctantly to follow cJSON library naming convention
 */

#ifndef cJSON_HELPER_H
#define cJSON_HELPER_H

#include "cJSON.h"

#define CJH_CONST_LHS       0x00000001u /* Left hand side is a const */
#define CJH_CONST_RHS       0x00000002u /* (ditto, vice versa) */

/*
 * Failure to specify CJH_CREATE or CJH_REPLACE allows creation and replacement
 */
#define CJH_CREATE          0x00000004u /* Fail if the name item already exists */
#define CJH_REPLACE         0x00000008u /* Fail if the name item does not exist */

cJSON * __nullable cJSON_H_AddStringToObject(
    cJSON * __nonnull const,
    uint32_t,
    const char * __nonnull const,
    const char * __nonnull const,
    int * __nullable
);

cJSON * __nullable cJSON_H_AddNumberToObject(
    cJSON *  __nonnull const,
    uint32_t,
    const char *  __nonnull const,
    double,
    int * __nullable
);

#endif /* cJSON_HELPER_H */

