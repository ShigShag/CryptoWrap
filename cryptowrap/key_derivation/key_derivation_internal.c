/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/key_derivation_internal.h"
#include "internal/helper.h"
#include "internal/error/error_internal.h"
#include "internal/fetching.h"

#include <openssl/kdf.h>

void cw_kdf_cleanup_internal(EVP_KDF_CTX *ctx, EVP_KDF *kdf)
{
    if (kdf != NULL)
        EVP_KDF_free(kdf);

    if (ctx != NULL)
        EVP_KDF_CTX_free(ctx);
}

uint64_t cw_kdf_fetch_output_size_internal(EVP_KDF_CTX *ctx, hash_algorithm hash_algorithm_id)
{
    uint64_t output_size = 0;

    // If algorithm produces a fixed output size
    if ((output_size = EVP_KDF_CTX_get_kdf_size(ctx)) == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_CTX_GET_KDF_SIZE);
        return 0;
    }

    if (output_size == SIZE_MAX)
    {
        // Return size based on digest length
        if ((output_size = cw_fetch_hash_len_internal(hash_algorithm_id)) == 0)
        {
            return 0;
        }
    }
    return output_size;
}

int kdf_aquire_context(EVP_KDF_CTX **ctx, EVP_KDF **kdf, char **digest, hash_algorithm hash_algorithm_id, const char *kdf_mode)
{
    if ((*digest = cw_fetch_hash_str_internal(hash_algorithm_id)) == NULL)
    {
        return 0;
    }

    if ((*kdf = EVP_KDF_fetch(NULL, kdf_mode, NULL)) == NULL)
    {
        return 0;
    }

    if ((*ctx = EVP_KDF_CTX_new(*kdf)) == NULL)
    {
        return 0;
    }
    return 1;
}

int cw_kdf_derive_internal(const char *kdf_mode, hash_algorithm hash_algorithm_id, OSSL_PARAM *params, uint8_t **out, uint64_t *out_len, uint8_t flags)
{
    if ((flags & KDF_FIXED_OUTPUT_SIZE || flags & KEY_DERIVATION_SET_OUTPUT_LEN) && (*out_len) == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & KEY_DERIVATION_NO_ALLOC))
        *out = NULL;

    EVP_KDF *kdf_impl = NULL;
    EVP_KDF_CTX *ctx = NULL;

    uint8_t *out_buffer = NULL;
    uint64_t required_out_len = 0;

    if ((kdf_impl = EVP_KDF_fetch(NULL, kdf_mode, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_FETCH);
        return 0;
    }

    if ((ctx = EVP_KDF_CTX_new(kdf_impl)) == NULL)
    {
        KDF_CLEANUP(ctx, kdf_impl, out_buffer, required_out_len, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_CTX_NEW);
        return 0;
    }

    if (!(flags & KDF_FIXED_OUTPUT_SIZE))
    {
        if ((required_out_len = cw_kdf_fetch_output_size_internal(ctx, hash_algorithm_id)) == 0)
        {
            KDF_CLEANUP(ctx, kdf_impl, out_buffer, required_out_len, flags, 0);
            return 0;
        }
    }
    else
    {
        required_out_len = *out_len;
    }

    if ((out_buffer = OPENSSL_zalloc(required_out_len)) == NULL)
    {
        KDF_CLEANUP(ctx, kdf_impl, out_buffer, required_out_len, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if (EVP_KDF_derive(ctx, out_buffer, required_out_len, params) != 1)
    {
        KDF_CLEANUP(ctx, kdf_impl, out_buffer, required_out_len, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_KDF_DERIVE);
        return 0;
    }

    if (!(flags & KDF_FIXED_OUTPUT_SIZE))
    {
        if (flags & KEY_DERIVATION_SET_OUTPUT_LEN)
        {
            // Dont allow to expand the output over its actual size
            if ((*out_len) < required_out_len && (*out_len) > 0)
            {
                void *temp = OPENSSL_clear_realloc(out_buffer, required_out_len, *out_len);
                if (temp == NULL)
                {
                    CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC);
                    return 0;
                }
                out_buffer = temp;
            }
        }
        else
        {
            *out_len = required_out_len;
        }
    }

    if (flags & KEY_DERIVATION_NO_ALLOC)
    {
        memcpy(*out, out_buffer, *out_len);
        OPENSSL_clear_free(out_buffer, *out_len);
    }
    else
    {
        *out = out_buffer;
    }

    KDF_CLEANUP(ctx, kdf_impl, *out, *out_len, flags, KDF_CLEANUP_NO_OUT);

    return 1;
}

void cw_argon2_handle_error_internal(argon2_error_codes code)
{
    switch (code)
    {
    case ARGON2_OUTPUT_PTR_NULL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_PTR_NULL);
        return;
    case ARGON2_OUTPUT_TOO_SHORT:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_SHORT);
        return;
    case ARGON2_OUTPUT_TOO_LONG:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_LONG);
        return;
    case ARGON2_PWD_TOO_SHORT:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_SHORT);
        return;
    case ARGON2_PWD_TOO_LONG:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_LONG);
        return;
    case ARGON2_SALT_TOO_SHORT:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_SHORT);
        return;
    case ARGON2_SALT_TOO_LONG:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_LONG);
        return;
    case ARGON2_AD_TOO_SHORT:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_SHORT);
        return;
    case ARGON2_AD_TOO_LONG:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_LONG);
        return;
    case ARGON2_SECRET_TOO_SHORT:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_SHORT);
        return;
    case ARGON2_SECRET_TOO_LONG:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_LONG);
        return;
    case ARGON2_TIME_TOO_SMALL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_SMALL);
        return;
    case ARGON2_TIME_TOO_LARGE:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_LARGE);
        return;
    case ARGON2_MEMORY_TOO_LITTLE:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_LITTLE);
        return;
    case ARGON2_MEMORY_TOO_MUCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_MUCH);
        return;
    case ARGON2_LANES_TOO_FEW:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_FEW);
        return;
    case ARGON2_LANES_TOO_MANY:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_MANY);
        return;
    case ARGON2_PWD_PTR_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_PTR_MISMATCH);
        return;
    case ARGON2_SALT_PTR_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_PTR_MISMATCH);
        return;
    case ARGON2_SECRET_PTR_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_PTR_MISMATCH);
        return;
    case ARGON2_AD_PTR_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_PTR_MISMATCH);
        return;
    case ARGON2_MEMORY_ALLOCATION_ERROR:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_ALLOCATION_ERROR);
        return;
    case ARGON2_FREE_MEMORY_CBK_NULL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_FREE_MEMORY_CBK_NULL);
        return;
    case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_ALLOCATE_MEMORY_CBK_NULL);
        return;
    case ARGON2_INCORRECT_PARAMETER:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_PARAMETER);
        return;
    case ARGON2_INCORRECT_TYPE:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_TYPE);
        return;
    case ARGON2_OUT_PTR_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUT_PTR_MISMATCH);
        return;
    case ARGON2_THREADS_TOO_FEW:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_FEW);
        return;
    case ARGON2_THREADS_TOO_MANY:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_MANY);
        return;
    case ARGON2_MISSING_ARGS:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_MISSING_ARGS);
        return;
    case ARGON2_ENCODING_FAIL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_ENCODING_FAIL);
        return;
    case ARGON2_DECODING_FAIL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_FAIL);
        return;
    case ARGON2_THREAD_FAIL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREAD_FAIL);
        return;
    case ARGON2_DECODING_LENGTH_FAIL:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_LENGTH_FAIL);
        return;
    case ARGON2_VERIFY_MISMATCH:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_VERIFY_MISMATCH);
        return;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_UNKNOWN_ERROR_CODE);
        return;
    }
}