/*
 * Created 190904 lynnl
 */

#include <stdint.h>
#include <sys/errno.h>

#include "cJSON_Helper.h"
#include "utils.h"

/**
 * Better implementation of cJSON_AddStringToObject()
 *
 * @param error     [OUT] error pointer if operation failed
 *                  EEXIST if CJH_CREATE specified and name item already exists
 *                  ENOENT if CJH_REPLACE specified and name item does not exist
 *                  ENOMEM if out of memory temporarily
 *
 * @return          newly created string item, NULL if fail
 */
cJSON * __nullable cJSON_H_AddStringToObject(
        cJSON * const obj,
        uint32_t flags,
        const char * const name,
        const char * const str,
        int * __nullable error)
{
    cJSON *str_item = NULL;
    cJSON *found;

    kassert_nonnull(obj);
    kassert_nonnull(name);
    kassert_nonnull(str);

    if (flags & CJH_CREATE) {
        if (cJSON_GetObjectItem(obj, name) != NULL) {
            if (error != NULL) *error = EEXIST;
            goto out_exit;
        }
    }

    if (flags & CJH_REPLACE) {
        if (cJSON_GetObjectItem(obj, name) == NULL) {
            if (error != NULL) *error = ENOENT;
            goto out_exit;
        }
    }

    if (flags & CJH_CONST_RHS) {
        /*
         * [sic]
         * create a string where valuestring references a string
         *  so it will not be freed by cJSON_Delete
         */
        str_item = cJSON_CreateStringReference(str);
    } else {
        str_item = cJSON_CreateString(str);
    }

    if (unlikely(str_item == NULL)) {
        if (error != NULL) *error = ENOMEM;
        goto out_exit;
    }

    if (flags & CJH_CONST_LHS) {
        if (flags & CJH_REPLACE) {
            cJSON_ReplaceItemInObject(obj, name, str_item);
        } else {
            /* cJSON_AddItemToObjectCS() always success if `name' key is constant */
            cJSON_AddItemToObjectCS(obj, name, str_item);
        }
    } else {
        if (flags & CJH_REPLACE) {
            cJSON_ReplaceItemInObject(obj, name, str_item);
        } else {
            cJSON_AddItemToObject(obj, name, str_item);

            /* cJSON_AddItemToObject()'s call to cJSON_strdup() may fail */
            found = cJSON_GetObjectItem(obj, name);
            if (found == NULL) {
                cJSON_Delete(str_item);
                str_item = NULL;
                if (error != NULL) *error = ENOMEM;
                goto out_exit;
            }
            kassertf(found == str_item, "Concurrent update for name = '%s'?!  %p vs %p", name, found, str_item);
        }
    }

out_exit:
    return str_item;
}

