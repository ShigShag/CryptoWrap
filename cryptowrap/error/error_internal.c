/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/error/error_internal.h"

#include <openssl/err.h>
#include <string.h>

ERROR_STACK main_error_stack = {0};

int cw_error_stack_full()
{
    return main_error_stack.entry_count >= ERROR_STACK_MAX_COUNT;
}

int cw_error_stack_empty()
{
    return main_error_stack.entry_count == 0;
}

void cw_error_stack_push(ERROR_TYPE err)
{
    // Check if stack is full
    if (cw_error_stack_full() == 1)
        return;

    CW_ERROR_STACK_CRITICAL(main_error_stack, main_error_stack.stack[main_error_stack.entry_count++] = err);
}

int cw_error_stack_pop(ERROR_TYPE *err)
{
    if (err == NULL)
        return ERROR_NO_ERROR;

    CW_ERROR_STACK_LOCK(main_error_stack);

    if (cw_error_stack_empty() == 1)
    {
        CW_ERROR_STACK_UNLOCK(main_error_stack);
        return ERROR_NO_ERROR;
    }

    *err = main_error_stack.stack[--main_error_stack.entry_count];

    CW_ERROR_STACK_UNLOCK(main_error_stack);

    return 1;
}

int cw_error_stack_top(ERROR_TYPE *err)
{
    if (err == NULL)
        return ERROR_NO_ERROR;

    CW_ERROR_STACK_LOCK(main_error_stack);

    if (cw_error_stack_empty() == 1)
    {
        CW_ERROR_STACK_UNLOCK(main_error_stack);
        return ERROR_NO_ERROR;
    }

    *err = main_error_stack.stack[main_error_stack.entry_count - 1];

    CW_ERROR_STACK_UNLOCK(main_error_stack);

    return 1;
}

void cw_error_set_error_ex(const char *file, const char *func, int line, error_id id)
{
    ERROR_TYPE err = {
        .id = id,
        .file = {0},
        .func = {0},
        .line = line,
        .openssl_error_code = 0,
        .openssl_error_string = {0},
        .openssl_error_string_len = 0};

    // In case file or function name exceeds ERROR_TYPE_INTERNALS_LEN
    strncpy(err.file, file, strlen(file) % (ERROR_TYPE_INTERNALS_LEN + 1));
    strncpy(err.func, func, strlen(func) % (ERROR_TYPE_INTERNALS_LEN + 1));

    // Check for openssl error
    if ((err.openssl_error_code = ERR_get_error()) != 0)
    {
        ERR_error_string_n(err.openssl_error_code, err.openssl_error_string, sizeof(err.openssl_error_string));
        err.openssl_error_string_len = strlen(err.openssl_error_string);
    }

    cw_error_stack_push(err);
}

int cw_error_type_construct_string(ERROR_TYPE err, char **out, uint32_t *out_len)
{
    if (out == NULL)
        return 0;

    *out = NULL;

    char *out_buffer = NULL;
    size_t out_buffer_len = 0;
    size_t out_buffer_real_len = 0;

    const char *cw_error_string = cw_error_get_string(err.id);

    size_t error_string_format_size = (err.openssl_error_string_len > 0)
                                          ? (strlen(ERROR_STRING_EXPANDED_OPENSSL))
                                          : (strlen(ERROR_STRING_EXPANDED));

    out_buffer_len = (strlen(err.file) + strlen(err.func) + ((cw_error_string != NULL) ? strlen(cw_error_string) : strlen(ERROR_STRING_NO_ERROR_MSG_GIVEN_STRING)) +
                      err.openssl_error_string_len + error_string_format_size + 5);

    if ((out_buffer = OPENSSL_zalloc(out_buffer_len)) == NULL)
        return 0;

    if (err.openssl_error_string_len > 0)
    {
        snprintf(out_buffer, out_buffer_len, ERROR_STRING_EXPANDED_OPENSSL,
                 err.id, err.file, err.func, err.line, ((cw_error_string != NULL) ? cw_error_string : ERROR_STRING_NO_ERROR_MSG_GIVEN_STRING), err.openssl_error_code, err.openssl_error_string);
    }
    else
    {
        snprintf(out_buffer, out_buffer_len, ERROR_STRING_EXPANDED,
                 err.id, err.file, err.func, err.line, ((cw_error_string != NULL) ? cw_error_string : ERROR_STRING_NO_ERROR_MSG_GIVEN_STRING));
    }

    out_buffer_real_len = strlen(out_buffer);

    if (out_buffer_real_len != out_buffer_len)
    {
        void *temp = realloc(out_buffer, out_buffer_real_len);
        if (temp != NULL)
            out_buffer = (char *)temp;
    }
    *out = out_buffer;

    if (out_len != NULL)
        *out_len = out_buffer_real_len;

    return 1;
}
