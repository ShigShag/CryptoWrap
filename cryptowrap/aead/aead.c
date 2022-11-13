/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/aead_internal.h"
#include "internal/fetching.h"

int cw_aead_raw_encrypt_bytes(const uint8_t *plaintext, const size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len,
                              const uint8_t *key, const int key_len,
                              const uint8_t *iv, const int iv_len,
                              const uint8_t *aad, const uint32_t aad_len,
                              uint8_t **tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags)
{
    return cw_aead_raw_pre_crypt_internal(plaintext, plaintext_len, ciphertext, ciphertext_len,
                                      key, key_len, iv, iv_len, aad, aad_len, tag, tag_len, algorithm_id, AEAD_ENCRYPT, flags);
}

int cw_aead_raw_decrypt_bytes(const uint8_t *ciphertext, const uint64_t ciphertext_len, uint8_t **plaintext, uint64_t *plaintext_len,
                              const uint8_t *key, const int key_len,
                              const uint8_t *iv, const int iv_len,
                              const uint8_t *aad, const uint32_t aad_len,
                              uint8_t *tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags)
{
    return cw_aead_raw_pre_crypt_internal(ciphertext, ciphertext_len, plaintext, plaintext_len,
                                      key, key_len, iv, iv_len, aad, aad_len, &tag, tag_len, algorithm_id, AEAD_DECRYPT, flags);
}

int cw_aead_file_encrypt(const char *in_file, const char *out_file,
                         const uint8_t *key, const uint32_t key_len,
                         const uint8_t *iv, const uint32_t iv_len,
                         const uint8_t *aad, uint32_t aad_len,
                         uint8_t **tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags)
{
    return cw_aead_file_pre_crypt_internal(in_file, out_file, key, key_len, iv, iv_len, aad, aad_len, tag, tag_len, AEAD_ENCRYPT, algorithm_id, flags);
}
int cw_aead_file_decrypt(const char *in_file, const char *out_file, const uint8_t *key, int key_len,
                         const uint8_t *iv, const uint32_t iv_len,
                         const uint8_t *aad, const uint32_t aad_len,
                         uint8_t *tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags)
{
    return cw_aead_file_pre_crypt_internal(in_file, out_file, key, key_len, iv, iv_len, aad, aad_len, &tag, tag_len, AEAD_DECRYPT, algorithm_id, flags);
}

/* Misc */
int cw_aead_get_key_length(aead_mode algorithm_id)
{
    int key_len = 0;

    if (cw_fetch_aead_key_and_iv_length_internal(algorithm_id, &key_len, NULL) != 1)
        return 0;

    return key_len;
}
int cw_aead_get_iv_length(aead_mode algorithm_id)
{
    int iv_len = 0;

    if (cw_fetch_aead_key_and_iv_length_internal(algorithm_id, NULL, &iv_len) != 1)
        return 0;

    return iv_len;
}
uint64_t cw_aead_get_encrypt_size(uint64_t plaintext_len)
{
    return cw_aead_get_encrypt_size_internal(plaintext_len);
}
