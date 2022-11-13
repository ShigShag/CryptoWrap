/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#include <internal/error/error_internal.h>
#include <internal/fetching.h>

#define CW_UNIT_CUSTOM_MSG_MAX_SIZE (200)
#define CW_UNIT_ERROR_MSG_MAX_SIZE (200 + ERROR_STRING_SIZE)

// Macro name generation
#define cw_unit_concat_implementation(a, b) a##b
#define cw_unit_concat(a, b) cw_unit_concat_implementation(a, b)
#define cw_unit_var_name(x) cw_unit_concat(estr_macro_name, cw_unit_concat(x, __LINE__))

char *get_fail_msg(const char *format, ...);

FILE *get_temp_file();

#define CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, should_fail, fail_format, ...) \
    do                                                                                              \
    {                                                                                               \
        char *cw_unit_var_name(__local_msg__) = NULL;                                               \
        int cw_unit_var_name(__local_ret__) = (func_call);                                          \
        if ((cw_unit_var_name(__local_ret__))fail_condition)                                        \
        {                                                                                           \
            cw_unit_var_name(__local_msg__) = get_fail_msg(fail_format, __VA_ARGS__);               \
            cr_expect(0, "%s", cw_unit_var_name(__local_msg__));                                    \
            free(cw_unit_var_name(__local_msg__));                                                  \
            goto end_point;                                                                         \
        }                                                                                           \
        if (!!should_fail)                                                                          \
        {                                                                                           \
            cw_error_get_last_error_id();                                                           \
            goto end_point;                                                                         \
        }                                                                                           \
    } while (0)

#endif