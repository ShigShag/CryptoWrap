/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/hash.h"

#include "internal/hash_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>

int cw_hash_stream_create_handle(HASH_STREAM_HANDLE *phash_stream_handle, hash_algorithm algorithm_id)
{
    if (phash_stream_handle == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MD_CTX *ctx = NULL;
    EVP_MD *digest_impl = NULL;

    // Allocate new digest context
    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        cw_cleanup_message_digest_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_MD_CTX_NEW);
        return 0;
    }

    // Get digest implementation
    if ((digest_impl = cw_fetch_hash_impl_internal(algorithm_id)) == NULL)
    {
        cw_cleanup_message_digest_internal(ctx, digest_impl);
        return 0;
    }

    if (EVP_DigestInit_ex2(ctx, digest_impl, NULL) != 1)
    {
        cw_cleanup_message_digest_internal(ctx, digest_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_INIT_EX_2);
        return 0;
    }

    cw_fetch_free_hash_impl_internal(digest_impl);

    *phash_stream_handle = ctx;

    return 1;
}

int cw_hash_stream_update(HASH_STREAM_HANDLE hash_stream_handle, uint8_t *in, const uint64_t in_len)
{
    if (hash_stream_handle == NULL || in == NULL || in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (EVP_DigestUpdate((EVP_MD_CTX *)hash_stream_handle, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_UPDATE);
        return 0;
    }

    return 1;
}

int cw_hash_stream_finalize(HASH_STREAM_HANDLE hash_stream_handle, uint8_t **out, uint32_t *out_len, uint8_t flags)
{
    if (hash_stream_handle == NULL || out == NULL || out_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int hash_size = EVP_MD_CTX_get_size((EVP_MD_CTX *)hash_stream_handle);

    if (!(flags & HASH_NO_ALLOC))
    {
        if ((*out = OPENSSL_zalloc(hash_size)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_DigestFinal_ex((EVP_MD_CTX *)hash_stream_handle, *out, out_len) != 1)
    {
        if (!(flags & HASH_NO_ALLOC))
            OPENSSL_free(*out);

        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_FINAL_EX);
        return 0;
    }

    return 1;
}

void cw_hash_stream_delete_handle(HASH_STREAM_HANDLE hash_stream_handle)
{
    if (hash_stream_handle != NULL)
        cw_cleanup_message_digest_internal((EVP_MD_CTX *)hash_stream_handle, NULL);
}