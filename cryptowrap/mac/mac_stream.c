/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/mac.h"
#include "internal/fetching.h"
#include "internal/mac_internal.h"
#include "internal/error/error_internal.h"

#include <string.h>

#include <openssl/obj_mac.h>
#include <openssl/core_names.h>

int cw_mac_stream_update(MAC_STREAM_HANDLE pstream_handle, uint8_t *in, const uint32_t in_len)
{
    if (pstream_handle == NULL || in == NULL || in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (EVP_MAC_update((EVP_MAC_CTX *)pstream_handle, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_UPDATE);
        return 0;
    }

    return 1;
}

int cw_mac_stream_final(MAC_STREAM_HANDLE pstream_handle, uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    if (pstream_handle == NULL || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint64_t out_len_required_intern = 0;
    uint64_t real_out_len_intern = 0;
    uint8_t *out_buffer;
    OSSL_PARAM params[2];
    OSSL_PARAM *p_params = params;

    if (flags & MAC_SET_OUT_LEN)
    {
        // Check if setting custom output length is allowed
        const OSSL_PARAM *p = EVP_MAC_CTX_settable_params((EVP_MAC_CTX *)pstream_handle);
        for (int i = 0; p[i].key != NULL; i++)
        {
            if (strncmp(p[i].key, OSSL_MAC_PARAM_SIZE, strlen(OSSL_MAC_PARAM_SIZE)) == 0)
            {
                *p_params++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, out_len);
                *p_params = OSSL_PARAM_construct_end();

                if (EVP_MAC_CTX_set_params((EVP_MAC_CTX *)pstream_handle, params) != 1)
                {
                    CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_SET_PARAMS);
                    return 0;
                }
                break;
            }
        }
    }

    if ((EVP_MAC_final((EVP_MAC_CTX *)pstream_handle, NULL, &out_len_required_intern, 0)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    if ((out_buffer = OPENSSL_zalloc(out_len_required_intern)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((EVP_MAC_final((EVP_MAC_CTX *)pstream_handle, out_buffer, &real_out_len_intern, out_len_required_intern)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    // if custom output size is set
    if (flags & MAC_SET_OUT_LEN)
    {
        // Dont allow to expand the mac over its actual size
        if (*out_len < real_out_len_intern)
        {
            // Realloc and clear old buffer
            void *temp = OPENSSL_clear_realloc(out_buffer, real_out_len_intern, *out_len);
            if (temp != NULL)
            {
                out_buffer = temp;
            }
        }
    }
    else
    {
        *out_len = real_out_len_intern;
    }

    // If space was allocated by user
    if (flags & MAC_NO_ALLOC)
    {
        memcpy(*out, out_buffer, *out_len);
        OPENSSL_clear_free(out_buffer, *out_len);
    }
    else
    {
        *out = out_buffer;
    }

    return 1;
}

int cw_hmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        cw_hmac_digest algorithm_id)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *pstream_handle = NULL;

    EVP_MAC_CTX *ctx = NULL;
    char *hmac_digest_str = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((hmac_digest_str = cw_fetch_hmac_internal_internal(algorithm_id)) == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, hmac_digest_str, 0);
    *p = OSSL_PARAM_construct_end();

    if ((ctx = cw_mac_stream_init_ctx_internal(SN_hmac, key, key_len, params)) == NULL)
        return 0;

    *pstream_handle = ctx;

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return 1;
}

int cw_cmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        cw_cmac_cipher algorithm_id)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *pstream_handle = NULL;

    EVP_MAC_CTX *ctx = NULL;
    char *cw_cmac_cipher = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((cw_cmac_cipher = cw_fetch_symmetric_cipher_str_internal((cw_symmetric_cipher_algorithm) algorithm_id)) == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_cmac_cipher, 0);
    *p = OSSL_PARAM_construct_end();

    if ((ctx = cw_mac_stream_init_ctx_internal(SN_cmac, key, key_len, params)) == NULL)
        return 0;

    *pstream_handle = ctx;

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return 1;
}

int cw_gmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, uint32_t key_len,
                        uint8_t *iv, uint32_t iv_len,
                        cw_gmac_cipher algorithm_id)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *pstream_handle = NULL;

    EVP_MAC_CTX *ctx = NULL;
    char *cw_gmac_cipher = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((cw_gmac_cipher = cw_fetch_gmac_internal(algorithm_id)) == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_gmac_cipher, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, iv, iv_len);
    *p = OSSL_PARAM_construct_end();

    if ((ctx = cw_mac_stream_init_ctx_internal(SN_gmac, key, key_len, params)) == NULL)
        return 0;

    *pstream_handle = ctx;

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return 1;
}

int cw_siphash_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                           const uint8_t *key, const uint32_t key_len,
                           uint32_t c_compression_rounds, uint32_t d_finalization_rounds)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *pstream_handle = NULL;

    EVP_MAC_CTX *ctx = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    // Check if key size is equal to 16
    if (key_len != SIPHASH_REQUIRED_KEY_SIZE)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_SIPHASH_WRONG_KEY_LENGTH);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c_compression_rounds);
    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d_finalization_rounds);
    *p = OSSL_PARAM_construct_end();

    if ((ctx = cw_mac_stream_init_ctx_internal(SN_siphash, key, key_len, params)) == NULL)
        return 0;

    *pstream_handle = ctx;

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return 1;
}

int cw_kmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        uint8_t *custom_value, const uint32_t custom_value_len,
                        cw_kmac_mode algorithm_id)
{
    if (pstream_handle == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *pstream_handle = NULL;

    EVP_MAC_CTX *ctx = NULL;
    char *kmac_algorithm = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((kmac_algorithm = cw_fetch_kmac_internal(algorithm_id)) == NULL)
        return 0;

    if (custom_value != NULL || custom_value_len > 0)
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)custom_value, custom_value_len);
    }
    *p = OSSL_PARAM_construct_end();

    if ((ctx = cw_mac_stream_init_ctx_internal(kmac_algorithm, key, key_len, params)) == NULL)
        return 0;

    *pstream_handle = ctx;

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return 1;
}

void cw_mac_stream_delete(MAC_STREAM_HANDLE pstream_handle)
{
    if (pstream_handle != NULL)
        EVP_MAC_CTX_free((EVP_MAC_CTX *)pstream_handle);
}