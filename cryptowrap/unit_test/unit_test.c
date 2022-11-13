/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/unit_test/cw_uint_test_internal.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

char *get_fail_msg(const char *format, ...)
{
    va_list arg;
    char *fail_msg = NULL;
    int chars_written = 0;

    char *internal_error_msg = NULL;
    uint32_t internal_error_msg_len = 0;

    va_start(arg, format);

    if ((fail_msg = calloc(CW_UNIT_ERROR_MSG_MAX_SIZE, 1)) == NULL)
        return NULL;

    if ((chars_written = vsnprintf(fail_msg, CW_UNIT_CUSTOM_MSG_MAX_SIZE, format, arg)) < 0)
    {
        free(fail_msg);
        va_end(arg);
        return NULL;
    }

    memcpy(fail_msg + chars_written++, "\n", 1);

    if ((internal_error_msg = cw_error_get_last_error_str_ex(&internal_error_msg_len)) != NULL)
    {
        memcpy(fail_msg + chars_written, internal_error_msg, internal_error_msg_len % (CW_UNIT_ERROR_MSG_MAX_SIZE - chars_written));
        free(internal_error_msg);
    }

    va_end(arg);
    return fail_msg;
}

FILE *get_temp_file()
{
    return tmpfile();
}