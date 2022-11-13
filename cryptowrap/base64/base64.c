/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/base64_internal.h"
#include "internal/error/error_internal.h"

int cw_base64_raw_encode(const uint8_t *plaintext, const uint64_t plaintext_len, uint8_t **encoded, uint64_t *encoded_len, const uint8_t flags)
{
    if (plaintext == NULL || plaintext_len == 0 || encoded == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
        *encoded = NULL;

    EVP_ENCODE_CTX *ctx = NULL;
    uint64_t output_len_real = 0;
    int temp_len = 0;
    uint64_t plaintext_len_copy = plaintext_len;

    // Since output size is about 4/3 to original size one cant use full integer size since output cannot be fit in integer
    uint64_t buffer_size = INT_MAX / 2;

    uint32_t adjustment = ((plaintext_len % 3) ? (3 - (plaintext_len % 3)) : 0);
    uint64_t code_padded_size = ((plaintext_len + adjustment) / 3) * 4;
    uint64_t newline_size = ((code_padded_size) / 72) * 2;
    uint64_t output_len_expected = code_padded_size + newline_size + 1;

    if (!(flags & BASE64_NO_ALLOC))
    {
        if ((*encoded = OPENSSL_zalloc(output_len_expected)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL)
    {
        BASE64_CLEANUP_INTERNAL(*encoded, output_len_expected, flags, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW);
        return 0;
    }

    // Returns void
    EVP_EncodeInit(ctx);

    if (plaintext_len > buffer_size)
    {
        do
        {
            if (EVP_EncodeUpdate(ctx, *encoded + output_len_real, &temp_len, plaintext, (int)buffer_size) != 1)
            {
                BASE64_CLEANUP_INTERNAL(*encoded, output_len_expected, flags, ctx);
                CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE);
                return 0;
            }
            output_len_real += temp_len;
            plaintext += buffer_size;
        } while ((plaintext_len_copy -= buffer_size) > buffer_size);
    }

    if (EVP_EncodeUpdate(ctx, *encoded + output_len_real, &temp_len, plaintext, plaintext_len_copy) != 1)
    {
        BASE64_CLEANUP_INTERNAL(*encoded, output_len_expected, flags, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE);
        return 0;
    }

    output_len_real += temp_len;

    // void
    EVP_EncodeFinal(ctx, *encoded + output_len_real, &temp_len);
    output_len_real += temp_len;

    // printf("Expected output len: %lu\nReal output len: %lu\n\n", output_len_expected, output_len_real);

    if (output_len_real < output_len_expected && !(flags & BASE64_NO_ALLOC))
    {
        void *temp = OPENSSL_clear_realloc(*encoded, output_len_expected, output_len_real);
        if (temp == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC);
            BASE64_CLEANUP_INTERNAL(temp, output_len_expected, flags, ctx);
            return 0;
        }
        *encoded = temp;
    }

    if (encoded_len != NULL)
        *encoded_len = output_len_real;

    EVP_ENCODE_CTX_free(ctx);

    return 1;
}

int cw_base64_raw_decode(const uint8_t *encoded, const uint64_t encoded_len, uint8_t **plaintext, uint64_t *plaintext_len, const uint8_t flags)
{
    if (encoded == NULL || encoded_len == 0 || plaintext == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
        *plaintext = NULL;

    EVP_ENCODE_CTX *ctx = NULL;
    uint64_t output_len_real = 0;
    int temp_len = 0;
    uint64_t encode_len_copy = encoded_len;

    // Since output len is smaller than input len INT_MAX is applicable
    uint64_t buffer_size = INT_MAX;

    int padding_signs = 0;

    for (uint64_t i = encoded_len - 2; i < encoded_len; i++)
    {
        if (encoded[i] == '=')
            padding_signs++;
    }

    uint64_t output_len_expected = (3 * (encoded_len) / 4) - padding_signs;

    if (!(flags & BASE64_NO_ALLOC))
    {
        if ((*plaintext = OPENSSL_zalloc(output_len_expected)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL)
    {
        BASE64_CLEANUP_INTERNAL(*plaintext, output_len_expected, flags, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW);
        return 0;
    }

    // Returns void
    EVP_DecodeInit(ctx);

    if (encoded_len > INT_MAX)
    {
        do
        {
            // DecodeUpdate returns 0 or 1 at success
            if (EVP_DecodeUpdate(ctx, *plaintext + output_len_real, &temp_len, encoded, (int)buffer_size) < 0)
            {
                BASE64_CLEANUP_INTERNAL(*plaintext, output_len_expected, flags, ctx);
                CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE);
                return 0;
            }
            output_len_real += temp_len;
            encoded += buffer_size;
        } while ((encode_len_copy -= buffer_size) > buffer_size);
    }

    if (EVP_DecodeUpdate(ctx, *plaintext + output_len_real, &temp_len, encoded, encode_len_copy) < 0)
    {
        BASE64_CLEANUP_INTERNAL(*plaintext, output_len_expected, flags, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE);
        return 0;
    }

    output_len_real += temp_len;

    if (EVP_DecodeFinal(ctx, *plaintext + output_len_real, &temp_len) != 1)
    {
        BASE64_CLEANUP_INTERNAL(*plaintext, output_len_expected, flags, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_FINAL);
        return 0;
    }

    output_len_real += temp_len;

    if (output_len_real < output_len_expected && !(flags & BASE64_NO_ALLOC))
    {
        void *temp = realloc(*plaintext, output_len_real);
        if (temp != NULL)
        {
            *plaintext = temp;
        }
    }

    if (plaintext_len != NULL)
        *plaintext_len = output_len_real;

    EVP_ENCODE_CTX_free(ctx);

    return 1;
}
