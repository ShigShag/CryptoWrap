/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/symmetric_cipher.h"
#include "cryptowrap/mac.h"
#include "cryptowrap/base64.h"

#include "internal/symmetric_cipher_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/rand.h>
#include <string.h>

#define DEFAULT_MAC_LEN 32
#define DEFAULT_MAC CW_HMAC_SHA3_256

/*
    Key header

    ALGORITHM_MODE | KEY_LEN  | KEY
    uint16_t       | uint16_t | KEY_LEN
*/

typedef struct
{
    uint16_t algorithm_mode;
    uint16_t key_len;
    uint16_t iv_len;
    uint8_t *key;
    uint8_t key_allocated;
} SYMMETRIC_KEY_OBJECT_INTERNAL;

typedef struct
{
    uint16_t algorithm_mode;
    uint16_t iv_len;
    uint16_t mac_len;
    uint64_t cipher_len;
} SYMMETRIC_CIPHER_OBJECT_INTERNAL;

SYMMETRIC_KEY_OBJECT cw_sym_cipher_high_generate_symmetric_object(uint8_t **key_in, const int32_t in_key_len, cw_symmetric_cipher_algorithm algorithm, const uint8_t flags)
{
    if (key_in == NULL || in_key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return NULL;
    }

    int32_t required_key_len;
    int32_t required_iv_len;
    SYMMETRIC_KEY_OBJECT_INTERNAL *sym_key;

    if (cw_fetch_symmetric_cipher_key_and_iv_length(algorithm, &required_key_len, &required_iv_len) != 1)
        return NULL;

    if (in_key_len != required_key_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_WRONG_KEY_LEN);
        return NULL;
    }

    if ((sym_key = OPENSSL_zalloc(sizeof(SYMMETRIC_KEY_OBJECT_INTERNAL))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return NULL;
    }

    sym_key->key_len = (uint16_t)in_key_len;
    sym_key->iv_len = (uint16_t)required_iv_len;
    sym_key->algorithm_mode = (uint16_t)algorithm;

    // If key should get copied
    if (!(flags & SYM_CIPHER_HIGH_NO_KEY_COPY))
    {
        if ((sym_key->key = OPENSSL_zalloc(sym_key->key_len * sizeof(uint8_t))) == NULL)
        {
            OPENSSL_clear_free(sym_key, sizeof(SYMMETRIC_KEY_OBJECT_INTERNAL));
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return NULL;
        }
        memcpy(sym_key->key, *key_in, in_key_len * sizeof(uint8_t));
        sym_key->key_allocated = (uint8_t)1;
    }
    else
    {
        sym_key->key = *key_in;
        sym_key->key_allocated = 0;
    }

    return (SYMMETRIC_KEY_OBJECT)sym_key;
}

/* Delete a symetric key object */
void cw_sym_cipher_high_delete_symmetric_key_object(SYMMETRIC_KEY_OBJECT key_obj)
{
    if (key_obj != NULL)
    {
        SYMMETRIC_KEY_OBJECT_INTERNAL *sym_key = (SYMMETRIC_KEY_OBJECT_INTERNAL *)key_obj;

        if (sym_key->key != NULL && sym_key->key_allocated == 1)
        {
            OPENSSL_clear_free(sym_key->key, sym_key->key_len);
        }

        OPENSSL_clear_free(sym_key, sizeof(SYMMETRIC_KEY_OBJECT_INTERNAL));
    }
}
int cw_sym_cipher_high_generate_cipher_text(SYMMETRIC_KEY_OBJECT key_obj, const uint8_t *plaintext, const uint64_t plaintext_len, uint8_t **cipher, uint64_t *cipher_len)
{
    if (key_obj == NULL || plaintext == NULL || plaintext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    SYMMETRIC_KEY_OBJECT_INTERNAL *key_obj_intern = (SYMMETRIC_KEY_OBJECT_INTERNAL *)key_obj;

    SYMMETRIC_CIPHER_OBJECT_INTERNAL sym_cipher_obj_intern = {0};

    uint64_t bytes_copied = 0;

    EVP_CIPHER *cipher_impl = NULL;

    uint8_t *buffer = NULL;
    uint8_t *buffer_offset = NULL;
    uint64_t buffer_size = 0;

    uint64_t mac_len_real = 0;
    uint64_t cipher_len_real = 0;

    if ((cipher_impl = fetch_symmetric_cipher_impl((cw_symmetric_cipher_algorithm)key_obj_intern->algorithm_mode)) == NULL)
        return 0;

    // This can be inaccurate but will be adjusted later
    sym_cipher_obj_intern.cipher_len = cw_cipher_get_cipher_size_impl_internal(cipher_impl, plaintext_len);

    cw_fetch_free_symmetric_cipher_impl_internal(cipher_impl);

    sym_cipher_obj_intern.mac_len = DEFAULT_MAC_LEN;
    sym_cipher_obj_intern.iv_len = key_obj_intern->iv_len;

    sym_cipher_obj_intern.algorithm_mode = key_obj_intern->algorithm_mode;

    // Allocate space for the buffer which will the ciphertext and the data
    buffer_size = sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len) + sizeof(sym_cipher_obj_intern.cipher_len) + sym_cipher_obj_intern.iv_len + sym_cipher_obj_intern.cipher_len + sym_cipher_obj_intern.mac_len;

    if ((buffer = OPENSSL_zalloc(buffer_size)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // Fill the buffer

    // Algorithm algorithm
    memcpy(buffer, &sym_cipher_obj_intern.algorithm_mode, sizeof(sym_cipher_obj_intern.algorithm_mode));
    bytes_copied += sizeof(sym_cipher_obj_intern.algorithm_mode);

    // Iv len
    memcpy(buffer + bytes_copied, &sym_cipher_obj_intern.iv_len, sizeof(sym_cipher_obj_intern.iv_len));
    bytes_copied += sizeof(sym_cipher_obj_intern.iv_len);

    // Mac len
    memcpy(buffer + bytes_copied, &sym_cipher_obj_intern.mac_len, sizeof(sym_cipher_obj_intern.mac_len));
    bytes_copied += sizeof(sym_cipher_obj_intern.mac_len);

    // Write reservation cipher size
    memcpy(buffer + bytes_copied, &sym_cipher_obj_intern.cipher_len, sizeof(sym_cipher_obj_intern.cipher_len));
    bytes_copied += sizeof(sym_cipher_obj_intern.cipher_len);

    // Create iv
    if (sym_cipher_obj_intern.iv_len > 0)
    {
        if (RAND_bytes(buffer + bytes_copied, sym_cipher_obj_intern.iv_len) != 1)
        {
            OPENSSL_clear_free(buffer, buffer_size);
            CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
            return 0;
        }
        bytes_copied += sym_cipher_obj_intern.iv_len;
    }

    buffer_offset = buffer + bytes_copied;

    // Create cipher text and add it to buffer
    if (cw_sym_cipher_raw_pre_crypt_internal(plaintext, plaintext_len, &buffer_offset, &cipher_len_real, key_obj_intern->key, key_obj_intern->key_len,
                                             buffer + (bytes_copied - sym_cipher_obj_intern.iv_len), sym_cipher_obj_intern.iv_len,
                                             (cw_symmetric_cipher_algorithm)key_obj_intern->algorithm_mode, SYMMETRIC_CIPHER_NO_ALLOC, SYMMETRIC_CIPHER_ENCRYPT) != 1)
    {
        OPENSSL_clear_free(buffer, buffer_size);
        return 0;
    }

    bytes_copied += cipher_len_real;

    // Adapt cipher size in case buffer_size does not match bytes_copied
    if (cipher_len_real != sym_cipher_obj_intern.cipher_len)
    {
        uint8_t *temp = OPENSSL_clear_realloc(buffer, buffer_size, bytes_copied);
        if (temp != NULL)
        {
            buffer = temp;
        }

        // Copy real cipher size value into the buffer
        memcpy(buffer + sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len),
               &cipher_len_real, sizeof(sym_cipher_obj_intern.cipher_len));
    }

    buffer_offset = buffer + bytes_copied;

    // Create mac
    if (cw_hmac_raw_ex(buffer, bytes_copied, key_obj_intern->key, key_obj_intern->key_len, DEFAULT_MAC, &buffer_offset, &mac_len_real, MAC_NO_ALLOC) != 1)
    {
        OPENSSL_clear_free(buffer, buffer_size);
        return 0;
    }

    bytes_copied += mac_len_real;

    if (cipher != NULL)
        *cipher = buffer;
    if (cipher_len != NULL)
        *cipher_len = bytes_copied;

    return 1;
}

/* Generate plaintext by decrypting the given ciphertext  */
int cw_sym_cipher_high_generate_plain_text(SYMMETRIC_KEY_OBJECT key_obj,
                                           const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                           uint8_t **plaintext, uint64_t *plaintext_len)
{
    if (key_obj == NULL || ciphertext == NULL || plaintext == NULL || ciphertext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    SYMMETRIC_KEY_OBJECT_INTERNAL *key_obj_intern = (SYMMETRIC_KEY_OBJECT_INTERNAL *)key_obj;

    // Map struct to byte array to get sizes
    SYMMETRIC_CIPHER_OBJECT_INTERNAL sym_cipher_obj_intern = {0};

    // Necessary step to get the size of all vars inside the struct --> calling sizeof(sym_cipher_obj_intern) may lead to different output cause of compiler padding
    uint8_t sym_cipher_obj_intern_len = (uint8_t)(sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len) + sizeof(sym_cipher_obj_intern.cipher_len));

    memcpy(&sym_cipher_obj_intern.algorithm_mode, ciphertext, sizeof(sym_cipher_obj_intern.algorithm_mode));
    memcpy(&sym_cipher_obj_intern.iv_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode), sizeof(sym_cipher_obj_intern.iv_len));
    memcpy(&sym_cipher_obj_intern.mac_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len), sizeof(sym_cipher_obj_intern.mac_len));
    memcpy(&sym_cipher_obj_intern.cipher_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len), sizeof(sym_cipher_obj_intern.mac_len));

    const uint8_t *iv_address = ciphertext + sym_cipher_obj_intern_len;
    const uint8_t *cipher_address = iv_address + sym_cipher_obj_intern.iv_len;
    const uint8_t *mac_address = cipher_address + sym_cipher_obj_intern.cipher_len;

    if (cw_hmac_verify(ciphertext, ciphertext_len - DEFAULT_MAC_LEN, mac_address, DEFAULT_MAC_LEN, key_obj_intern->key, key_obj_intern->key_len, DEFAULT_MAC) != 1)
    {
        return 0;
    }

    // Decrypt
    if (cw_sym_cipher_raw_pre_crypt_internal(cipher_address, sym_cipher_obj_intern.cipher_len, plaintext, plaintext_len, key_obj_intern->key, key_obj_intern->key_len,
                                             iv_address, sym_cipher_obj_intern.iv_len,
                                             (cw_symmetric_cipher_algorithm)sym_cipher_obj_intern.algorithm_mode, 0, SYMMETRIC_CIPHER_DECRYPT) != 1)
    {
        return 0;
    }

    return 1;
}

int cw_sym_cipher_high_generate_plain_text_key_only(const uint8_t *key, const int32_t key_len,
                                                    const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                                    uint8_t **plaintext, uint64_t *plaintext_len)
{
    if (key == NULL || ciphertext == NULL || ciphertext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // Map struct to byte array to get sizes
    SYMMETRIC_CIPHER_OBJECT_INTERNAL sym_cipher_obj_intern = {0};
    int required_key_length = 0;

    // Necessary step to get the size of all vars inside the struct --> calling sizeof(sym_cipher_obj_intern) may lead to different output cause of compiler padding
    uint8_t sym_cipher_obj_intern_len = (uint8_t)(sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len) + sizeof(sym_cipher_obj_intern.cipher_len));

    memcpy(&sym_cipher_obj_intern.algorithm_mode, ciphertext, sizeof(sym_cipher_obj_intern.algorithm_mode));
    memcpy(&sym_cipher_obj_intern.iv_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode), sizeof(sym_cipher_obj_intern.iv_len));
    memcpy(&sym_cipher_obj_intern.mac_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len), sizeof(sym_cipher_obj_intern.mac_len));
    memcpy(&sym_cipher_obj_intern.cipher_len, ciphertext + sizeof(sym_cipher_obj_intern.algorithm_mode) + sizeof(sym_cipher_obj_intern.iv_len) + sizeof(sym_cipher_obj_intern.mac_len), sizeof(sym_cipher_obj_intern.mac_len));

    const uint8_t *iv_address = ciphertext + sym_cipher_obj_intern_len;
    const uint8_t *cipher_address = iv_address + sym_cipher_obj_intern.iv_len;
    const uint8_t *mac_address = cipher_address + sym_cipher_obj_intern.cipher_len;

    // Check if key length is of correct length
    if (cw_fetch_symmetric_cipher_key_and_iv_length(sym_cipher_obj_intern.algorithm_mode, &required_key_length, NULL) != 1)
        return 0;

    if(key_len != required_key_length)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_HIGH_WRONG_KEY_LENGTH);
        return 0;
    }

    if (cw_hmac_verify(ciphertext, ciphertext_len - DEFAULT_MAC_LEN, mac_address, DEFAULT_MAC_LEN, key, key_len, DEFAULT_MAC) != 1)
    {
        return 0;
    }

    // Decrypt
    if (cw_sym_cipher_raw_pre_crypt_internal(cipher_address, sym_cipher_obj_intern.cipher_len, plaintext, plaintext_len, key, key_len,
                                             iv_address, sym_cipher_obj_intern.iv_len,
                                             (cw_symmetric_cipher_algorithm)sym_cipher_obj_intern.algorithm_mode, 0, SYMMETRIC_CIPHER_DECRYPT) != 1)
    {
        return 0;
    }

    return 1;
}