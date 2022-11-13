/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/error.h"

#include "internal/error/error_internal.h"

#include <string.h>
#include <stdlib.h>

int cw_error_get_last_error_id()
{
    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return 0;

    return err.id;
}

int cw_error_get_last_error_id_ex(uint64_t *openssl_error_code)
{
    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return 0;

    if (openssl_error_code != NULL)
        *openssl_error_code = err.openssl_error_code;

    return err.id;
}

const char *cw_error_get_last_error_str()
{
    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return NULL;

    return cw_error_get_string(err.id);
}

char *cw_error_get_last_error_str_ex(uint32_t *out_len)
{
    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return NULL;

    char *buffer = NULL;
    uint32_t buffer_len = 0;

    if (cw_error_type_construct_string(err, &buffer, &buffer_len) != 1)
        return NULL;

    if (out_len != NULL)
        *out_len = buffer_len;

    return buffer;
}

void cw_error_get_last_error_fp(FILE *fp)
{
    if (fp == NULL)
        return;

    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return;

    const char *error_string = cw_error_get_string(err.id);

    if (error_string == NULL)
        return;

    fwrite((const void *)error_string, sizeof(char), strlen(error_string), fp);
    fwrite((const void *)"\n", sizeof(char), 1, fp);
}

void cw_error_get_last_error_fp_ex(FILE *fp)
{
    if (fp == NULL)
        return;

    ERROR_TYPE err;

    if (cw_error_stack_pop(&err) == ERROR_NO_ERROR)
        return;

    char *buffer = NULL;
    uint32_t buffer_len = 0;

    if (cw_error_type_construct_string(err, &buffer, &buffer_len) != 1)
        return;

    fwrite((const void *)buffer, sizeof(char), buffer_len, fp);

    free(buffer);
}

int cw_error_peak_last_error_id()
{
    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return 0;

    return err.id;
}

int cw_error_peak_last_error_id_ex(uint64_t *openssl_error_code)
{
    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return 0;

    if (openssl_error_code != NULL)
        *openssl_error_code = err.openssl_error_code;

    return err.id;
}

const char *cw_error_peak_last_error_str()
{
    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return NULL;

    return cw_error_get_string(err.id);
}

char *cw_error_peak_last_error_str_ex(uint32_t *out_len)
{
    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return NULL;

    char *buffer = NULL;
    uint32_t buffer_len = 0;

    if (cw_error_type_construct_string(err, &buffer, &buffer_len) != 1)
        return NULL;

    if (out_len != NULL)
        *out_len = buffer_len;

    return buffer;
}

void cw_error_peak_write_fp(FILE *fp)
{
    if (fp == NULL)
        return;

    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return;

    const char *error_string = cw_error_get_string(err.id);

    if (error_string == NULL)
        return;

    fwrite((const void *)error_string, sizeof(char), strlen(error_string), fp);
}

void cw_error_peak_write_fp_ex(FILE *fp)
{
    if (fp == NULL)
        return;

    ERROR_TYPE err;

    if (cw_error_stack_top(&err) == ERROR_NO_ERROR)
        return;

    char *buffer = NULL;
    uint32_t buffer_len = 0;

    if (cw_error_type_construct_string(err, &buffer, &buffer_len) != 1)
        return;

    fwrite((const void *)buffer, sizeof(char), buffer_len, fp);

    free(buffer);
}

const char *cw_error_get_str_from_id(int error_id)
{
    return cw_error_get_string(error_id);
}