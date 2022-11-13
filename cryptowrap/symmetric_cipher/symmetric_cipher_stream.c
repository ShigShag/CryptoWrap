/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/symmetric_cipher.h"

#include "internal/fetching.h"
#include "internal/symmetric_cipher_internal.h"
#include "internal/error/error_internal.h"

#include <openssl/evp.h>
#include <openssl/err.h>

/* Generate a cipher block handle for later use */
int cw_sym_cipher_stream_create_handle(CIPHER_STREAM_HANDLE *pstream_handle, cw_symmetric_cipher_algorithm algorithm_id,
                                       const uint8_t *key, const int key_len,
                                       const uint8_t *iv, const int iv_len,
                                       int mode)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) || SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_STREAM_MODE_NOT_ALLOWED);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    int crypt_mode = (mode == SYM_CIPHER_STREAM_DECRYPT) ? SYM_CIPHER_STREAM_DECRYPT : SYM_CIPHER_STREAM_ENCRYPT;

    // Create new cipher context
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    // Fetch algorithm implementation
    if ((cipher_impl = fetch_symmetric_cipher_impl(algorithm_id)) == NULL)
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        return 0;
    }

    // Init cipher without key or iv to check lengths
    if (EVP_CipherInit_ex2(ctx, cipher_impl, NULL, NULL, crypt_mode, NULL) != 1)
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    // Check key and iv lengths
    if (key_len != EVP_CIPHER_CTX_get_key_length(ctx))
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        return 0;
    }

    // Check iv length
    if (iv_len != EVP_CIPHER_CTX_get_iv_length(ctx))
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, NULL, key, iv, crypt_mode, NULL) != 1)
    {
        cipher_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    *pstream_handle = ctx;

    cipher_cleanup_internal(NULL, cipher_impl);

    return 1;
}

/* Create ciphertext by providing a block */
int cw_sym_cipher_stream_update(CIPHER_STREAM_HANDLE stream_handle, uint8_t *out, int *bytes_encrypted, const uint8_t *in, const int in_len)
{
    if (stream_handle == NULL || out == NULL || in == NULL || in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int temp_bytes_encrypted;

    if (EVP_CipherUpdate((EVP_CIPHER_CTX *)stream_handle, out, &temp_bytes_encrypted, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE);
        return 0;
    }

    if (bytes_encrypted != NULL)
        *bytes_encrypted = temp_bytes_encrypted;

    return 1;
}

/* Finalize the ciphertext by adding padding */
int cw_sym_cipher_stream_final(CIPHER_STREAM_HANDLE stream_handle, uint8_t *out, int *bytes_encrypted)
{
    if (stream_handle == NULL || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int temp_bytes_encrypted = 0;
    if (EVP_CipherFinal_ex((EVP_CIPHER_CTX *)stream_handle, out, &temp_bytes_encrypted) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHERFINAL_EX);
        return 0;
    }

    if (bytes_encrypted != NULL)
        *bytes_encrypted = temp_bytes_encrypted;

    return 1;
}

/* Cleanup the CIPHER_STREAM_HANDLE */
void cw_sym_cipher_stream_delete_handle(CIPHER_STREAM_HANDLE stream_handle)
{
    if (stream_handle != NULL)
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)stream_handle);
}