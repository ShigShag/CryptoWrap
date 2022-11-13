/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef HELPER_H
#define HELPER_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MEGABYTES(num) (num * (1024 * 1024))

// Misc
int cw_cipher_misc_compare_file_pointers_internal(FILE *one, FILE *two);

uint64_t cw_uint64_t_to_the_power(uint64_t base, uint64_t exponent);

#define CW_HELPER_CLEAR_PARAMS_INTERNAL(params) \
    do                                          \
    {                                           \
        if (params != NULL)                     \
        {                                       \
            memset(params, 0, sizeof(params));  \
        }                                       \
    } while (0)

#endif
