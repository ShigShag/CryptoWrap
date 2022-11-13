/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/random.h"

#include "internal/error/error_internal.h"

#include <openssl/rand.h>

int cw_random_uint8_t(uint8_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(uint8_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_uint16_t(uint16_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(uint16_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_uint32_t(uint32_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(uint32_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_uint64_t(uint64_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(uint64_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_int8_t(int8_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(int8_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_int16_t(int16_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(int16_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_int32_t(int32_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(int32_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_int64_t(int64_t *num_ptr)
{
    if (num_ptr == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (RAND_bytes((uint8_t *)num_ptr, sizeof(int64_t)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }
    return 1;
}

int cw_random_uint8_t_border(uint8_t *num_ptr, uint8_t lower, uint8_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_uint16_t_border(uint16_t *num_ptr, uint16_t lower, uint16_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_uint32_t_border(uint32_t *num_ptr, uint32_t lower, uint32_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_uint64_t_border(uint64_t *num_ptr, uint64_t lower, uint64_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_int8_t_border(int8_t *num_ptr, int8_t lower, int8_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_int16_t_border(int16_t *num_ptr, int16_t lower, int16_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_int32_t_border(int32_t *num_ptr, int32_t lower, int32_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_int64_t_border(int64_t *num_ptr, int64_t lower, int64_t upper)
{
    if (CW_RANDOM_NUMBER(num_ptr) != 1)
        return 0;

    *num_ptr = ((*num_ptr) % (upper - lower + 1)) + lower;
    return 1;
}

int cw_random_bytes(uint8_t **buffer, const uint64_t len, const uint8_t flags)
{
    if (buffer == NULL || len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int buffer_size = INT_MAX;
    uint64_t len_internal = len;
    uint64_t bytes_generated = 0;

    if (!(flags & RANDOM_NO_ALLOC))
    {
        if ((*buffer = OPENSSL_zalloc(len)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (len >= INT_MAX)
    {
        do
        {
            if (RAND_bytes((*buffer) + bytes_generated, buffer_size) != 1)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
                return 0;
            }
            bytes_generated += buffer_size;
        } while ((len_internal -= buffer_size) > INT_MAX);
    }

    if (RAND_bytes((*buffer) + bytes_generated, len_internal) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return 0;
    }

    return 1;
}
