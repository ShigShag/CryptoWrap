/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/base64_internal.h"
#include "internal/error/error_internal.h"

int cw_base64_stream_init(BASE64_STREAM_HANDLE *p_stream_handle, int mode)
{
    if (p_stream_handle == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    ENCODE_STREAM_STRUCT *encode_struct = NULL;

    if ((encode_struct = (ENCODE_STREAM_STRUCT *)OPENSSL_zalloc(sizeof(ENCODE_STREAM_STRUCT))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((encode_struct->ctx = EVP_ENCODE_CTX_new()) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW);
        return 0;
    }

    switch (mode)
    {
    case BASE64_STREAM_ENCODE:
        EVP_EncodeInit(encode_struct->ctx);
        break;

    case BASE64_STREAM_DECODE:
        EVP_DecodeInit(encode_struct->ctx);
        break;

    default:
        cw_encode_stream_struct_delete_internal(encode_struct);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_STREAM_WRONG_MODE);
        return 0;
    }

    encode_struct->mode = mode;

    *p_stream_handle = (BASE64_STREAM_HANDLE)encode_struct;

    return 1;
}

int cw_base64_stream_update(BASE64_STREAM_HANDLE stream_handle, uint8_t *out, int *out_len, const uint8_t *in, const int in_len)
{
    if (stream_handle == NULL || out == NULL || in == NULL || in_len <= 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int out_len_internal = 0;
    ENCODE_STREAM_STRUCT *encode_struct = (ENCODE_STREAM_STRUCT *)stream_handle;

    if (encode_struct->mode == BASE64_STREAM_ENCODE)
    {
        if (EVP_EncodeUpdate(encode_struct->ctx, out, &out_len_internal, in, in_len) != 1)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE);
            return 0;
        }
    }
    else
    {
        if (EVP_DecodeUpdate(encode_struct->ctx, out, &out_len_internal, in, in_len) < 0)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE);
            return 0;
        }
    }

    if (out_len != NULL)
        *out_len = out_len_internal;

    return 1;
}

int cw_base64_stream_final(BASE64_STREAM_HANDLE stream_handle, unsigned char *out, int *out_len)
{
    if (stream_handle == NULL || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int out_len_internal = 0;
    ENCODE_STREAM_STRUCT *encode_struct = (ENCODE_STREAM_STRUCT *)stream_handle;

    if (encode_struct->mode == BASE64_STREAM_ENCODE)
        EVP_EncodeFinal(encode_struct->ctx, out, &out_len_internal);
    else
    {
        if (EVP_DecodeFinal(encode_struct->ctx, out, &out_len_internal) != 1)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_FINAL);
            return 0;
        }
    }

    if (out_len != NULL)
        *out_len = out_len_internal;

    return 1;
}

void cw_base64_stream_delete(BASE64_STREAM_HANDLE stream_handle)
{
    cw_encode_stream_struct_delete_internal((ENCODE_STREAM_STRUCT *)stream_handle);
}
