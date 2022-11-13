/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/hash_internal.h"
#include "internal/fetching.h"
#include "internal/helper.h"
#include "internal/error/error_internal.h"

// 20 Megabyte
#define FILE_READ_BUFFER_SIZE MEGABYTES(20)

void cw_cleanup_message_digest_internal(EVP_MD_CTX *ctx, EVP_MD *digest_impl)
{
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    if (digest_impl != NULL)
        EVP_MD_free(digest_impl);
}

int cw_hash_bytes_internal(const uint8_t *in, uint64_t in_len, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, uint8_t flags)
{
    if (in == NULL || in_len == 0 || digest_out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & HASH_NO_ALLOC))
        *digest_out = NULL;

    EVP_MD_CTX *ctx = NULL;

    EVP_MD *digest_impl = NULL;

    uint32_t hash_size = 0;

    // Allocate new digest context
    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_MD_CTX_NEW);
        return 0;
    }

    // Get digest implementation
    if ((digest_impl = cw_fetch_hash_impl_internal(algorithm_id)) == NULL)
    {
        HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
        return 0;
    }

    if (EVP_DigestInit_ex2(ctx, digest_impl, NULL) != 1)
    {
        HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_INIT_EX_2);
        return 0;
    }

    // Get the hash size
    hash_size = EVP_MD_get_size(digest_impl);

    if (!(flags & HASH_NO_ALLOC))
    {
        if ((*digest_out = OPENSSL_zalloc(hash_size)) == NULL)
        {
            HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_DigestUpdate(ctx, in, in_len) != 1)
    {
        HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_UPDATE);
        return 0;
    }

    if (EVP_DigestFinal_ex(ctx, *digest_out, &hash_size) != 1)
    {
        HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_FINAL_EX);
        return 0;
    }

    if (digest_out_len != NULL)
        *digest_out_len = hash_size;

    HASH_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, flags, HASH_CLEANUP_NO_OUT_HASH);

    return 1;
}

int cw_hash_file_internal(FILE *file, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, uint8_t flags)
{
    if (file == NULL || digest_out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & HASH_NO_ALLOC))
        *digest_out = NULL;

    EVP_MD_CTX *ctx = NULL;
    EVP_MD *digest_impl = NULL;

    uint32_t hash_size = 0;

    uint8_t *file_read_buffer = NULL;
    uint64_t bytes_read = 0;

    if ((file_read_buffer = OPENSSL_zalloc(FILE_READ_BUFFER_SIZE)) == NULL)
    {
        HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // Allocate new digest context
    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_MD_CTX_NEW);
        return 0;
    }

    // Get digest implementation
    if ((digest_impl = cw_fetch_hash_impl_internal(algorithm_id)) == NULL)
    {
        HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
        return 0;
    }

    if (EVP_DigestInit_ex2(ctx, digest_impl, NULL) != 1)
    {
        HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_INIT_EX_2);
        return 0;
    }

    hash_size = EVP_MD_get_size(digest_impl);

    if (!(flags & HASH_NO_ALLOC))
    {
        if ((*digest_out = OPENSSL_zalloc(hash_size)) == NULL)
        {
            HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    bytes_read = fread(file_read_buffer, sizeof(uint8_t), FILE_READ_BUFFER_SIZE, file);
    while (bytes_read != 0)
    {
        if (EVP_DigestUpdate(ctx, file_read_buffer, bytes_read) != 1)
        {
            HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
            CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_UPDATE);
            return 0;
        }
        bytes_read = fread(file_read_buffer, sizeof(uint8_t), FILE_READ_BUFFER_SIZE, file);
    }

    if (EVP_DigestFinal_ex(ctx, *digest_out, &hash_size) != 1)
    {
        HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_HASH_EVP_DIGEST_FINAL_EX);
        return 0;
    }

    if (digest_out_len != NULL)
        *digest_out_len = hash_size;

    HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, *digest_out, hash_size, file_read_buffer, FILE_READ_BUFFER_SIZE, flags, HASH_CLEANUP_NO_OUT_HASH);

    return 1;
}