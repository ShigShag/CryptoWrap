/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/hash.h"

#include "internal/hash_internal.h"
#include "internal/error/error_internal.h"
#include "internal/fetching.h"

#include <stdio.h>
#include <string.h>

int cw_hash_raw_bytes(const uint8_t *in, const uint64_t in_len, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags)
{
    return cw_hash_bytes_internal(in, in_len, algorithm_id, digest_out, digest_out_len, flags);
}

int cw_hash_raw_string(const char *in, hash_algorithm algorithm_id,
                       uint8_t **digest_out, uint32_t *digest_out_len,
                       const uint8_t flags)
{
    if (in == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint64_t in_len = strlen(in);

    if (in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    return cw_hash_bytes_internal((const uint8_t *)in, in_len, algorithm_id, digest_out, digest_out_len, flags);
}

int cw_hash_file(const char *file_path, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags)
{
    if (file_path == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *file = NULL;
    int ret;

    if ((file = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    ret = cw_hash_file_internal(file, algorithm_id, digest_out, digest_out_len, flags);
    fclose(file);
    return ret;
}
int cw_hash_file_fp(FILE *file, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags)
{
    return cw_hash_file_internal(file, algorithm_id, digest_out, digest_out_len, flags);
}

int cw_hash_verify_string(uint8_t *hash, uint32_t hash_len, const char *in, hash_algorithm algorithm_id)
{
    uint8_t *generated_hash;
    uint32_t generated_hash_len;

    if (cw_hash_bytes_internal((const uint8_t *)in, strlen(in), algorithm_id, &generated_hash, &generated_hash_len, 0) != 1)
        return 0;

    if (generated_hash_len != hash_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_VERIFY_LEN_MISMATCH);
        return 0;
    }

    if (CRYPTO_memcmp(hash, generated_hash, hash_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_VERIFY_HASH_MISMATCH);
        return 0;
    }

    free(generated_hash);

    return 1;
}

int cw_hash_verify_bytes(uint8_t *hash, uint32_t hash_len, const uint8_t *in, const uint32_t in_len, hash_algorithm algorithm_id)
{
    uint8_t *generated_hash;
    uint32_t generated_hash_len;

    if (cw_hash_bytes_internal(in, in_len, algorithm_id, &generated_hash, &generated_hash_len, 0) != 1)
        return 0;

    if (generated_hash_len != hash_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_VERIFY_LEN_MISMATCH);
        return 0;
    }

    if (CRYPTO_memcmp(hash, generated_hash, hash_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_VERIFY_HASH_MISMATCH);
        return 0;
    }

    free(generated_hash);

    return 1;
}

uint32_t cw_hash_get_len(hash_algorithm algorithm_id)
{
    return cw_fetch_hash_len_internal(algorithm_id);
}