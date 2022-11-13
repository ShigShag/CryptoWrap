/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/symmetric_cipher_internal.h"
#include "internal/fetching.h"

int cw_sym_cipher_raw_encrypt_bytes(const uint8_t *plaintext, const uint64_t plaintext_len,
                                    uint8_t **ciphertext, uint64_t *ciphertext_len,
                                    const uint8_t *key, const uint32_t key_len,
                                    const uint8_t *iv, const uint32_t iv_len,
                                    cw_symmetric_cipher_algorithm algorithm_id, const uint8_t flags)
{
    return cw_sym_cipher_raw_pre_crypt_internal(plaintext, plaintext_len, ciphertext, ciphertext_len, key, key_len, iv, iv_len, algorithm_id, flags, SYMMETRIC_CIPHER_ENCRYPT);
}

int cw_sym_cipher_raw_decrypt_bytes(const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                    uint8_t **plaintext, uint64_t *plaintext_len,
                                    const uint8_t *key, const uint32_t key_len,
                                    const uint8_t *iv, const uint32_t iv_len,
                                    cw_symmetric_cipher_algorithm algorithm_id, const uint8_t flags)
{
    return cw_sym_cipher_raw_pre_crypt_internal(ciphertext, ciphertext_len, plaintext, plaintext_len, key, key_len, iv, iv_len, algorithm_id, flags, SYMMETRIC_CIPHER_DECRYPT);
}

int cw_sym_cipher_file_encrypt(const char *in_file, const char *out_file,
                               const uint8_t *key, const uint32_t key_len,
                               const uint8_t *iv, const uint32_t iv_len,
                               cw_symmetric_cipher_algorithm algorithm_id)
{
    return cw_sym_cipher_file_check_internal(in_file, out_file, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_ENCRYPT, algorithm_id);
}

int cw_sym_cipher_file_decrypt(const char *in_file, const char *out_file,
                               const uint8_t *key, const uint32_t key_len,
                               const uint8_t *iv, const uint32_t iv_len,
                               cw_symmetric_cipher_algorithm algorithm_id)
{
    return cw_sym_cipher_file_check_internal(in_file, out_file, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_DECRYPT, algorithm_id);
}

/* Returns the required size of the key for a given algorithm_id */
int cw_sym_cipher_get_key_length(cw_symmetric_cipher_algorithm algorithm_id)
{
    int32_t key_len;

    if (cw_fetch_symmetric_cipher_key_and_iv_length(algorithm_id, &key_len, NULL) != 1)
        return 0;

    return key_len;
}

/* Returns the required size of the iv for a given algorithm_id */
int cw_sym_cipher_get_iv_length(cw_symmetric_cipher_algorithm algorithm_id)
{
    int32_t iv_len;

    if (cw_fetch_symmetric_cipher_key_and_iv_length(algorithm_id, NULL, &iv_len) != 1)
        return 0;

    return iv_len;
}

uint64_t cw_sym_cipher_get_cipher_size(cw_symmetric_cipher_algorithm algorithm_id, const uint64_t plaintext_len)
{
    return cw_cipher_get_cipher_size_internal(algorithm_id, plaintext_len);
}
