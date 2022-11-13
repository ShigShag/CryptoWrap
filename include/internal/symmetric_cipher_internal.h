/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef CIPHER_INTERNAL_H
#define CIPHER_INTERNAL_H

#include "cryptowrap/symmetric_cipher.h"

#include <openssl/evp.h>

#define SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) (algorithm_id == CW_AES_256_XTS || algorithm_id == CW_AES_128_XTS)
#define SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) (algorithm_id >= CW_AES_128_WRAP && algorithm_id <= CW_AES_256_WRAP)

#define SYMMETRIC_CIPHER_ENCRYPT 1
#define SYMMETRIC_CIPHER_DECRYPT 0

// Cleanup
void cipher_cleanup_internal(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher_impl);

// Symmetric cipher raw encrypt
#define SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, impl, out, out_size, flags) \
  do                                                                  \
  {                                                                   \
    if (!(flags & SYMMETRIC_CIPHER_NO_ALLOC) && out != NULL)          \
    {                                                                 \
      OPENSSL_clear_free(out, out_size);                              \
      out = NULL;                                                     \
    }                                                                 \
    cipher_cleanup_internal(ctx, impl);                               \
  } while (0)

#define SYM_CIPHER_CHECK_PARAMS_NO_IN_LEN 0x00000001

/* Raw crypt */
int cw_sym_cipher_raw_check_params_internal(cw_symmetric_cipher_algorithm algorithm_id, int key_len, int iv_len, uint64_t in_len, uint8_t flags);

int cw_sym_cipher_raw_pre_crypt_internal(const uint8_t *in, uint64_t in_len,
                                         uint8_t **out, uint64_t *out_len,
                                         const uint8_t *key, uint32_t key_len,
                                         const uint8_t *iv, uint32_t iv_len,
                                         cw_symmetric_cipher_algorithm algorithm_id, uint8_t flags, int mode);

int cw_sym_cipher_raw_crypt_bytes_internal(const uint8_t *in, uint64_t in_len,
                                           uint8_t **out, uint64_t *out_len,
                                           const uint8_t *key,
                                           const uint8_t *iv,
                                           cw_symmetric_cipher_algorithm algorithm_id, int mode, uint8_t flags);

/* File crypt */
void cw_sym_cipher_file_check_cleanup(FILE *reader, FILE *writer);

int cw_sym_cipher_file_check_internal(const char *in_file, const char *out_file,
                                      const uint8_t *key, uint32_t key_len,
                                      const uint8_t *iv, uint32_t iv_len,
                                      int mode, cw_symmetric_cipher_algorithm algorithm_id);

void cw_sym_cipher_file_crypt_cleanup_internal(uint8_t *read_buffer, uint32_t read_length, uint8_t *write_buffer, uint32_t write_length, EVP_CIPHER_CTX *ctx, EVP_CIPHER *impl);

int cw_sym_cipher_file_crypt_internal(FILE *reader, FILE *writer,
                                      const uint8_t *key,
                                      const uint8_t *iv,
                                      long *new_file_size,
                                      int mode, cw_symmetric_cipher_algorithm algorithm_id);

// Misc
int cw_cipher_misc_compare_file_pointers_internal(FILE *one, FILE *two);

// Cipher size
uint64_t cw_cipher_get_cipher_size_internal(cw_symmetric_cipher_algorithm algorithm_id, uint64_t plaintext_len);
uint64_t cw_cipher_get_cipher_size_impl_internal(EVP_CIPHER *cipher_impl, uint64_t plaintext_len);
uint64_t cw_cipher_get_cipher_size_ctx_internal(EVP_CIPHER_CTX *ctx, uint64_t plaintext_len);

#define CW_CIPHER_GET_CIPHER_SIZE(input_type, plaintext_len) _Generic(input_type, symmetric_cipher_algorithm     \
                                                                      : cw_cipher_get_cipher_size_internal,      \
                                                                        EVP_CIPHER *                             \
                                                                      : cw_cipher_get_cipher_size_impl_internal, \
                                                                        EVP_CIPHER_CTX *                         \
                                                                      : cw_cipher_get_cipher_size_ctx_internal)(input_type, plaintext_len)

#endif