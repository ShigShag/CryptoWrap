/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef HASH_INTERNAL_H
#define HASH_INTERNAL_H

#include "cryptowrap/hash.h"

#include <openssl/evp.h>

#define HASH_CLEANUP_NO_OUT_HASH 0x00000001

#define HASH_CLEANUP_INTERNAL(ctx, digest_impl, hash, hash_size, flags, flags_internal)                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(flags & HASH_NO_ALLOC) && hash != NULL && hash_size > 0 && !(flags_internal & HASH_CLEANUP_NO_OUT_HASH)) \
        {                                                                                                              \
            OPENSSL_clear_free(hash, hash_size);                                                                       \
            hash = NULL;                                                                                               \
        }                                                                                                              \
        cw_cleanup_message_digest_internal(ctx, digest_impl);                                                             \
    } while (0)

#define HASH_FILE_CLEANUP_INTERNAL(ctx, digest_impl, hash, hash_size, file_read_buffer, file_read_buffer_size, flags, flags_internal) \
    do                                                                                                                                \
    {                                                                                                                                 \
        if (!(flags & HASH_NO_ALLOC) && hash != NULL && hash_size > 0 && !(flags_internal & HASH_CLEANUP_NO_OUT_HASH))                \
        {                                                                                                                             \
            OPENSSL_clear_free(hash, hash_size);                                                                                      \
            hash = NULL;                                                                                                              \
        }                                                                                                                             \
        if (file_read_buffer != NULL && file_read_buffer_size > 0)                                                                    \
        {                                                                                                                             \
            OPENSSL_clear_free(file_read_buffer, file_read_buffer_size);                                                              \
        }                                                                                                                             \
        cw_cleanup_message_digest_internal(ctx, digest_impl);                                                                            \
    } while (0)

void cw_cleanup_message_digest_internal(EVP_MD_CTX *ctx, EVP_MD *digest_impl);

int cw_hash_bytes_internal(const uint8_t *in, uint64_t in_len, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, uint8_t flags);

int cw_hash_file_internal(FILE *file, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, uint8_t flags);

#endif