/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/mac_internal.h"
#include "internal/error/error_internal.h"
#include "cryptowrap/mac.h"

#include <string.h>

void cw_mac_cleanup_internal(EVP_MAC_CTX *ctx, EVP_MAC *mac)
{
    if (mac != NULL)
        EVP_MAC_free(mac);

    if (ctx != NULL)
        EVP_MAC_CTX_free(ctx);
}

int cw_mac_process_internal(EVP_MAC_CTX *ctx,
                            const uint8_t *in, const uint64_t in_len,
                            uint8_t **out, uint64_t *out_len,
                            const uint8_t flags)
{
    // Check if required values are set
    if (in == NULL || in_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // Zero initialize local variables
    uint8_t *out_buffer = NULL;
    uint64_t required_out_len = 0;
    uint64_t real_out_len = 0;

    // Set out variable to NULL if it is not allocated by the user
    if (!(flags & MAC_NO_ALLOC))
    {
        *out = NULL;
    }

    if ((EVP_MAC_update(ctx, in, in_len)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_UPDATE);
        return 0;
    }

    if ((EVP_MAC_final(ctx, NULL, &required_out_len, 0)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    if ((out_buffer = OPENSSL_zalloc(required_out_len)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((EVP_MAC_final(ctx, out_buffer, &real_out_len, required_out_len)) != 1)
    {
        OPENSSL_clear_free(out_buffer, required_out_len);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    // if custom output size is set
    if (flags & MAC_SET_OUT_LEN)
    {
        // Dont allow to expand the mac over its actual size
        if (*out_len<real_out_len && * out_len> 0)
        {
            void *temp = OPENSSL_clear_realloc(out_buffer, real_out_len, *out_len);
            if (temp != NULL)
            {
                out_buffer = temp;
            }
        }
    }
    else
    {
        *out_len = real_out_len;
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

int cw_mac_process_file_internal(EVP_MAC_CTX *ctx, FILE *reader,
                                 uint8_t **out, uint64_t *out_len,
                                 const uint8_t flags)
{
    // Check if required values are set
    if (out == NULL || out_len == NULL || reader == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // Zero initialize local variables
    uint8_t *out_buffer = NULL;
    uint64_t required_out_len = 0;
    uint64_t real_out_len = 0;

    uint8_t *read_buffer = NULL;
    uint64_t read_buffer_size = MEGABYTES(10);
    size_t bytes_read = 0;

    // Set out variable to NULL if it is not allocated by the user
    if (!(flags & MAC_NO_ALLOC))
    {
        *out = NULL;
    }

    if ((read_buffer = OPENSSL_zalloc(read_buffer_size * sizeof(uint8_t))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    while (1)
    {
        bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_size, reader);

        if (bytes_read == 0)
            break;

        if (EVP_MAC_update(ctx, read_buffer, bytes_read) != 1)
        {
            OPENSSL_clear_free(read_buffer, read_buffer_size);
            CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_UPDATE);
            return 0;
        }
    }

    if ((EVP_MAC_final(ctx, NULL, &required_out_len, 0)) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    if ((out_buffer = OPENSSL_zalloc(required_out_len)) == NULL)
    {
        OPENSSL_clear_free(read_buffer, read_buffer_size);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((EVP_MAC_final(ctx, out_buffer, &real_out_len, required_out_len)) != 1)
    {
        OPENSSL_clear_free(read_buffer, read_buffer_size);
        OPENSSL_clear_free(out_buffer, required_out_len);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FINAL);
        return 0;
    }

    // if custom output size is set
    if (flags & MAC_SET_OUT_LEN)
    {
        // Dont allow to expand the mac over its actual size
        if ((*out_len) < real_out_len && (*out_len) > 0)
        {
            void *temp = OPENSSL_clear_realloc(out_buffer, real_out_len, *out_len);
            if (temp != NULL)
            {
                out_buffer = temp;
            }
        }
    }
    else
    {
        *out_len = real_out_len;
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

    OPENSSL_clear_free(read_buffer, read_buffer_size);

    return 1;
}

EVP_MAC_CTX *cw_mac_stream_init_ctx_internal(const char *algorithm,
                                             const uint8_t *key, const uint32_t key_len,
                                             OSSL_PARAM *params)
{
    if (algorithm == NULL || key == NULL || key_len == 0 || params == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;

    if ((mac = EVP_MAC_fetch(NULL, algorithm, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        cw_mac_cleanup_internal(ctx, mac);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        cw_mac_cleanup_internal(ctx, mac);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    cw_mac_cleanup_internal(NULL, mac);

    return ctx;
}