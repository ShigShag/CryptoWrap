/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef KEY_DERIVATION_INTERNAL_H
#define KEY_DERIVATION_INTERNAL_H

#include "cryptowrap/key_derivation.h"
#include "../../cryptowrap/key_derivation/argon2/argon2.h"

#include <openssl/evp.h>

#define KDF_CLEANUP_NO_OUT 0x00000001
#define KDF_FIXED_OUTPUT_SIZE 0x00000080

#define SCRYPT_OUTPUT_LIMIT 137438953440

#define KDF_CLEANUP(ctx, kdf_impl, out, out_len, flags, flags_internal)                                                 \
    do                                                                                                                  \
    {                                                                                                                   \
        if (!(flags & KEY_DERIVATION_NO_ALLOC) && out != NULL && out_len > 0 && !(flags_internal & KDF_CLEANUP_NO_OUT)) \
        {                                                                                                               \
            OPENSSL_clear_free(out, out_len);                                                                           \
            out = NULL;                                                                                                 \
        }                                                                                                               \
        cw_kdf_cleanup_internal(ctx, kdf_impl);                                                                         \
    } while (0)

void cw_kdf_cleanup_internal(EVP_KDF_CTX *ctx, EVP_KDF *kdf);

uint64_t cw_kdf_fetch_output_size_internal(EVP_KDF_CTX *ctx, hash_algorithm algorithm_id);

int kdf_aquire_context(EVP_KDF_CTX **ctx, EVP_KDF **kdf, char **digest, hash_algorithm algorithm_id, const char *kdf_mode);

int cw_kdf_derive_internal(const char *kdf_mode, hash_algorithm hash_algorithm_id, OSSL_PARAM *params, uint8_t **out, uint64_t *out_len, uint8_t flags);

void cw_argon2_handle_error_internal(argon2_error_codes code);

#endif