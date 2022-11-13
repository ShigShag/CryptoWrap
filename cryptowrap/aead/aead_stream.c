/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/aead.h"
#include "internal/aead_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/evp.h>

/* Stream */
int cw_aead_stream_create_handle(AEAD_STREAM_HANDLE *pstream_handle,
                                 const uint8_t *key, const uint32_t key_len,
                                 const uint8_t *iv, const uint32_t iv_len,
                                 const uint8_t *aad, const uint32_t aad_len,
                                 aead_mode algorithm_id, const int mode)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0 || iv == NULL || iv_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    int temp_len;

    // CCM does not support multiple calls to update
    if (IS_CCM(algorithm_id) == 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_CCM_NOT_SUPPORTED_FOR_STREAM);
        return 0;
    }

    // Plaintext len can be set to zero since is is only required to be checked for ccm
    if (cw_aead_check_params_internal(algorithm_id, 0, key_len, 0, AEAD_CHECK_PARAMS_NO_TAG) != 1)
        return 0;

    if ((cipher_impl = cw_fetch_aead_impl_internal(algorithm_id)) == NULL)
        return 0;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        cw_aead_cleanup_internal(ctx, cipher_impl);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, cipher_impl, NULL, NULL, mode, NULL) != 1)
    {
        cw_aead_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    // Set iv length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) != 1)
    {
        cw_aead_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, NULL, key, iv, mode, NULL) != 1)
    {
        cw_aead_cleanup_internal(ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    // Set AAD if set
    if (aad != NULL && aad_len > 0)
    {
        if (EVP_CipherUpdate(ctx, NULL, &temp_len, aad, aad_len) != 1)
        {
            cw_aead_cleanup_internal(ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE_AAD);
            return 0;
        }
    }

    *pstream_handle = (AEAD_STREAM_HANDLE *)ctx;

    cw_aead_cleanup_internal(NULL, cipher_impl);

    return 1;
}

int cw_aead_stream_update(const AEAD_STREAM_HANDLE stream_handle,
                          uint8_t *out, int *bytes_processed,
                          const uint8_t *in, const int in_len)
{
    if (stream_handle == NULL || out == NULL || in == NULL || in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int temp_size = 0;
    if (EVP_CipherUpdate((EVP_CIPHER_CTX *)stream_handle, out, &temp_size, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
        return 0;
    }

    if (bytes_processed != NULL)
        *bytes_processed = temp_size;

    return 1;
}

int cw_aead_stream_final(const AEAD_STREAM_HANDLE stream_handle,
                         uint8_t *out, int *bytes_processed,
                         uint8_t **tag, const int tag_len, uint8_t flags)
{
    if (stream_handle == NULL || out == NULL || tag == NULL || tag_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int mode = 0;
    int temp_len = 0;

    // Check if stream is encrypting or decrypting
    mode = EVP_CIPHER_CTX_is_encrypting((EVP_CIPHER_CTX *)stream_handle);

    // Set the tag if decrypting
    if (mode == AEAD_DECRYPT)
    {
        if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)stream_handle, EVP_CTRL_AEAD_SET_TAG, tag_len, *tag) != 1)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG);
            return 0;
        }
    }

    if (EVP_CipherFinal_ex((EVP_CIPHER_CTX *)stream_handle, out, &temp_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_FINAL_EX);
        return 0;
    }

    if (mode == AEAD_ENCRYPT)
    {
        if (!(flags & (AEAD_TAG_NO_ALLOC | AEAD_NO_ALLOC)))
        {
            if ((*tag = OPENSSL_zalloc(tag_len)) == NULL)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
                return 0;
            }
        }

        if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)stream_handle, EVP_CTRL_AEAD_GET_TAG, tag_len, *tag) != 1)
        {
            if (!(flags & (AEAD_TAG_NO_ALLOC | AEAD_NO_ALLOC)))
            {
                OPENSSL_clear_free(*tag, tag_len);
                *tag = NULL;
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG);
            }
            return 0;
        }
    }

    if (bytes_processed != NULL)
        *bytes_processed = temp_len;

    return 1;
}

void cw_aead_stream_delete_handle(AEAD_STREAM_HANDLE stream_handle)
{
    if (stream_handle != NULL)
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)stream_handle);
}