/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef AEAD_INTERNAL_H
#define AEAD_INTERNAL_H

#include "cryptowrap/aead.h"

#include <openssl/evp.h>

#define AEAD_ENCRYPT 1
#define AEAD_DECRYPT 0

#define IS_CCM(algorithm_id) (algorithm_id >= CW_AES_128_CCM && algorithm_id <= CW_ARIA_256_CCM)

/* Adding the do while loop to force semicolon in code */
#define AEAD_RAW_CRYPT_CLEANUP(ctx, impl, cipher, cipher_size, tag, tag_size, flags, mode)     \
  do                                                                                           \
  {                                                                                            \
    if (!(flags & (AEAD_TAG_NO_ALLOC | AEAD_NO_ALLOC)) && tag != NULL && mode == AEAD_ENCRYPT) \
    {                                                                                          \
      OPENSSL_clear_free(tag, tag_size);                                                       \
      tag = NULL;                                                                              \
    }                                                                                          \
    if (!(flags & (AEAD_OUT_NO_ALLOC | AEAD_NO_ALLOC)) && cipher != NULL)                      \
    {                                                                                          \
      OPENSSL_clear_free(cipher, cipher_size);                                                 \
      cipher = NULL;                                                                           \
    }                                                                                          \
    cw_aead_cleanup_internal(ctx, impl);                                                       \
  } while (0)

#define AEAD_CHECK_PARAMS_NO_TAG 0x00000001
#define AEAD_CHECK_PARAMS_NO_IV 0x00000002

int cw_aead_check_params_internal(aead_mode algorithm_id, uint64_t plaintext_len, int key_len, int tag_len, uint8_t flags);

void cw_aead_cleanup_internal(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher_impl);

/* Raw crypt */
int cw_aead_raw_pre_crypt_internal(const uint8_t *plaintext, uint64_t plaintext_len, uint8_t **ciphertext, uint64_t *ciphertext_len,
                                   const uint8_t *key, const int key_len,
                                   const uint8_t *iv, const int iv_len,
                                   const uint8_t *aad, const uint32_t aad_len,
                                   uint8_t **tag, const int tag_len, aead_mode algorithm_id, const int mode, const uint8_t flags);

int cw_aead_raw_crypt_internal(const uint8_t *plaintext, const uint64_t plaintext_len,
                               uint8_t **ciphertext, uint64_t *ciphertext_len,
                               const uint8_t *aad, const uint32_t aad_len,
                               const uint8_t *key,
                               const uint8_t *iv, const uint32_t iv_len,
                               uint8_t **tag, int tag_len,
                               int mode, aead_mode algorithm_id, const uint8_t flags);

/* File Crypt */
void cw_aead_file_cleanup_internal(FILE *reader, FILE *writer);

int cw_aead_file_pre_crypt_internal(const char *in_file, const char *out_file,
                                const uint8_t *key, const uint32_t key_len,
                                const uint8_t *iv, const uint32_t iv_len,
                                const uint8_t *aad, const uint32_t aad_len,
                                uint8_t **tag, const int tag_len, const int mode, aead_mode algorithm_id, const uint8_t flags);

void cw_aead_file_crypt_cleanup_internal(uint8_t *read_buffer, uint32_t read_length, uint8_t *write_buffer, uint32_t write_length,
                                         EVP_CIPHER_CTX *ctx, EVP_CIPHER *impl);

int cw_aead_file_crypt_internal(FILE *reader, FILE *writer,
                                const uint8_t *key,
                                const uint8_t *iv, const uint32_t iv_len,
                                const uint8_t *aad, const uint32_t aad_len,
                                uint8_t **tag, const int tag_len,
                                const long file_size, long *new_file_size,
                                int mode, aead_mode algorithm_id, const uint8_t flags);

uint64_t cw_aead_get_encrypt_size_internal(uint64_t plaintext_len);
uint64_t cw_aead_get_encrypt_size_impl_internal(EVP_CIPHER *cipher_impl, uint64_t plaintext_len);
uint64_t cw_aead_get_encrypt_size_ctx_internal(EVP_CIPHER_CTX *ctx, uint64_t plaintext_len);

#define CW_AEAD_GET_ENCRYPT_SIZE(input_type, plaintext_len) _Generic(input_type, aead_mode                     \
                                                                     : cw_aead_get_encrypt_size_internal,      \
                                                                       EVP_CIPHER *                            \
                                                                     : cw_aead_get_encrypt_size_impl_internal, \
                                                                       EVP_CIPHER_CTX *                        \
                                                                     : cw_aead_get_encrypt_size_ctx_internal)(input_type, plaintext_len)
#endif