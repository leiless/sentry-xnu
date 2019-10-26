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

    kassert_nonnull(obj, name, str);

    found = cJSON_GetObjectItem(obj, name);

    if ((flags & CJH_CREATE) && found) {
        if (error != NULL) *error = EEXIST;
        goto out_exit;
    }

    if ((flags & CJH_REPLACE) && !found) {
        if (error != NULL) *error = ENOENT;
        goto out_exit;
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
        if ((flags & CJH_REPLACE) || found) {
            cJSON_ReplaceItemInObject(obj, name, str_item);
        } else {
            /* cJSON_AddItemToObjectCS() always success if `name' key is constant */
            cJSON_AddItemToObjectCS(obj, name, str_item);
        }
    } else {
        if ((flags & CJH_REPLACE) || found) {
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

/**
 * Better implementation of cJSON_AddNumberToObject()
 */
cJSON * __nullable cJSON_H_AddNumberToObject(
        cJSON * const obj,
        uint32_t flags,
        const char * const name,
        double number,
        int * __nullable error)
{
    cJSON *num_item = NULL;
    cJSON *found;

    kassert_nonnull(obj, name);

    found = cJSON_GetObjectItem(obj, name);

    if ((flags & CJH_CREATE) && found) {
        if (error != NULL) *error = EEXIST;
        goto out_exit;
    }

    if ((flags & CJH_REPLACE) && !found) {
        if (error != NULL) *error = ENOENT;
        goto out_exit;
    }

    num_item = cJSON_CreateNumber(number);
    if (unlikely(num_item == NULL)) {
        if (error != NULL) *error = ENOMEM;
        goto out_exit;
    }

    if (flags & CJH_CONST_LHS) {
        if ((flags & CJH_REPLACE) || found) {
            cJSON_ReplaceItemInObject(obj, name, num_item);
        } else {
            /* cJSON_AddItemToObjectCS() always success if `name' key is constant */
            cJSON_AddItemToObjectCS(obj, name, num_item);
        }
    } else {
        if ((flags & CJH_REPLACE) || found) {
            cJSON_ReplaceItemInObject(obj, name, num_item);
        } else {
            cJSON_AddItemToObject(obj, name, num_item);

            /* cJSON_AddItemToObject()'s call to cJSON_strdup() may fail */
            found = cJSON_GetObjectItem(obj, name);
            if (!found) {
                cJSON_Delete(num_item);
                num_item = NULL;
                if (error != NULL) *error = ENOMEM;
                goto out_exit;
            }
            kassertf(found == num_item, "Concurrent update for name = '%s'?!  %p vs %p", name, found, num_item);
        }
    }

out_exit:
    return num_item;
}

bool cJSON_H_AddItemToArray(cJSON *arr, cJSON * __nullable item)
{
    int count;
    kassert_nonnull(arr);
    count = cJSON_GetArraySize(arr);
    /* if `item' equals to NULL, cJSON_AddItemToArray() do nop */
    cJSON_AddItemToArray(arr, item);
    /* XXX: MT-unsafe */
    return cJSON_GetArraySize(arr) == count + 1;
}

bool cJSON_H_AddItemToObjectCS(
        cJSON *object,
        const char *string,
        cJSON * __nullable item)
{
    kassert_nonnull(object, string);
    cJSON_AddItemToObjectCS(object, string, item);
    return cJSON_GetObjectItem(object, string) != NULL;
}

/**
 * XXX: must ends with a NULL, otherwise kernel will panic
 */
bool cJSON_H_DeleteItemFromObject(
        cJSON *object,
        const char *string,
        ...)
{
    size_t i, count = 0;
    va_list ap;
    cJSON *o;
    const char *s;

    kassert_nonnull(object, string);

    o = object;
    s = string;

    va_start(ap, string);
    while (va_arg(ap, const char *) != NULL) count++;
    va_end(ap);

    va_start(ap, string);
    for (i = 0; i < count; s = va_arg(ap, const char *)) {
        kassert_nonnull(s);
        i++;
        o = cJSON_GetObjectItem(o, s);
        if (o == NULL || !cJSON_IsObject(o)) {
            va_end(ap);
            return false;
        }
    }
    va_end(ap);

    kassertf(i == count, "%zu vs %zu", i, count);

    kassert_nonnull(s);
    cJSON_DeleteItemFromObject(o, s);
    return cJSON_GetObjectItem(o, s) == NULL;
}

