/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/base64_internal.h"

#include "internal/error/error_internal.h"
#include "internal/helper.h"

int cw_base64_file_encode(const char *in_file, const char *out_file)
{
    return cw_encode_file_check_internal(in_file, out_file, BASE64_STREAM_ENCODE);
}

int cw_base64_file_decode(const char *in_file, const char *out_file)
{
    return cw_encode_file_check_internal(in_file, out_file, BASE64_STREAM_DECODE);
}

int cw_base64_file_encode_out(const char *in_file, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (in_file == NULL || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
        *out = NULL;

    FILE *reader = NULL;
    long file_size = 0;
    uint64_t bytes_read = 0;
    uint8_t *read_buffer;
    uint64_t read_buffer_size = MEGABYTES(2);

    int bytes_processed = 0;
    uint64_t total_bytes_processed = 0;

    BASE64_STREAM_HANDLE stream_handle = NULL;

    if ((reader = fopen(in_file, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    fseek(reader, 0, SEEK_END);
    file_size = ftell(reader);
    rewind(reader);

    // Calculate encoded size
    uint32_t adjustment = ((file_size % 3) ? (3 - (file_size % 3)) : 0);
    uint64_t code_padded_size = ((file_size + adjustment) / 3) * 4;
    uint64_t newline_size = ((code_padded_size) / 72) * 2;
    uint64_t output_len_expected = code_padded_size + newline_size + 1;

    if ((read_buffer = OPENSSL_zalloc(read_buffer_size)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
    {
        if ((*out = OPENSSL_zalloc(output_len_expected)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
            return 0;
        }
    }

    if (cw_base64_stream_init(&stream_handle, BASE64_STREAM_ENCODE) != 1)
    {
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    while (1)
    {
        if ((bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_size, reader)) == 0)
            break;

        if (cw_base64_stream_update(stream_handle, *out + total_bytes_processed, &bytes_processed, read_buffer, bytes_read) != 1)
        {
            BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
            return 0;
        }

        total_bytes_processed += bytes_processed;
    }

    if (cw_base64_stream_final(stream_handle, *out + total_bytes_processed, &bytes_processed) != 1)
    {
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    total_bytes_processed += bytes_processed;

    if (!(flags & BASE64_NO_ALLOC))
    {
        if (total_bytes_processed < output_len_expected)
        {
            uint8_t *temp = OPENSSL_clear_realloc(*out, output_len_expected, total_bytes_processed);
            if (temp == NULL)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC);
                BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
                return 0;
            }
        }
    }

    // Trick the cleanup function by setting the flag, so out is not freed
    BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, BASE64_NO_ALLOC, read_buffer, read_buffer_size);

    if (out_len != NULL)
        *out_len = total_bytes_processed;

    return 1;
}

int cw_base64_file_decode_out(const char *in_file, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
if (in_file == NULL || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
        *out = NULL;

    FILE *reader = NULL;
    long file_size = 0;
    uint64_t bytes_read = 0;
    uint8_t *read_buffer;
    uint64_t read_buffer_size = MEGABYTES(2);

    int bytes_processed = 0;
    uint64_t total_bytes_processed = 0;

    BASE64_STREAM_HANDLE stream_handle = NULL;

    if ((reader = fopen(in_file, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    fseek(reader, 0, SEEK_END);
    file_size = ftell(reader);
    rewind(reader);

    uint64_t output_len_expected = file_size;

    if ((read_buffer = OPENSSL_zalloc(read_buffer_size)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    if (!(flags & BASE64_NO_ALLOC))
    {
        if ((*out = OPENSSL_zalloc(output_len_expected)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
            return 0;
        }
    }

    if (cw_base64_stream_init(&stream_handle, BASE64_STREAM_DECODE) != 1)
    {
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    while (1)
    {
        if ((bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_size, reader)) == 0)
            break;

        if (cw_base64_stream_update(stream_handle, *out + total_bytes_processed, &bytes_processed, read_buffer, bytes_read) != 1)
        {
            BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
            return 0;
        }

        total_bytes_processed += bytes_processed;
    }

    if (cw_base64_stream_final(stream_handle, *out + total_bytes_processed, &bytes_processed) != 1)
    {
        BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
        return 0;
    }

    total_bytes_processed += bytes_processed;

    if (!(flags & BASE64_NO_ALLOC))
    {
        if (total_bytes_processed < output_len_expected)
        {
            uint8_t *temp = OPENSSL_clear_realloc(*out, output_len_expected, total_bytes_processed);
            if (temp == NULL)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC);
                BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, flags, read_buffer, read_buffer_size);
                return 0;
            }
        }
    }

    // Trick the cleanup function by setting the flag, so out is not freed
    BASE64_CLEANUP_FILE_OUT(reader, *out, output_len_expected, stream_handle, BASE64_NO_ALLOC, read_buffer, read_buffer_size);

    if (out_len != NULL)
        *out_len = total_bytes_processed;

    return 1;
}