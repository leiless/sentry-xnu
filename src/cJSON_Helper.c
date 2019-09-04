/*
 * Created 190904 lynnl
 */

#include <stdint.h>

#include "cJSON.h"
#include "cJSON_Helper.h"
#include "utils.h"

#define CJH_CONST_NAME      0x00000001u
#define CJH_CONST_STR       0x00000002u

cJSON * cJSON_H_AddStringToObject(
        cJSON * const obj,
        uint32_t flags,
        const char * const name,
        const char * const str)
{
    cJSON *str_item;
    cJSON *found;

    kassert_nonnull(obj);
    kassert_nonnull(name);
    kassert_nonnull(str);

    if (flags & CJH_CONST_STR) {
        str_item = cJSON_CreateStringReference(str);
    } else {
        str_item = cJSON_CreateString(str);
    }

    if (unlikely(str_item == NULL)) goto out_exit;

    if (flags & CJH_CONST_NAME) {
        /* cJSON_AddItemToObjectCS() no fail if `name' key is constant */
        cJSON_AddItemToObjectCS(obj, name, str_item);
    } else {
        cJSON_AddItemToObject(obj, name, str_item);
        found = cJSON_GetObjectItem(obj, name);
        if (found == NULL) {
            /* Internal add_item_to_object() returned false */
            cJSON_Delete(str_item);
            str_item = NULL;
            goto out_exit;
        }
        kassertf(found == str_item, "Concurrent update for name = '%s'?!  %p vs %p", name, found, str_item);
    }

out_exit:
    return str_item;
}

cJSON * __nullable cJSON_H_AddStrToObj(
        cJSON *obj,
        uint32_t flags,
        const char *name,
        const char *str)
{
    if (cJSON_GetObjectItem(obj, name) != NULL) {

    }

    return NULL;
}

