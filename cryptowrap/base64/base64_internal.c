/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/base64_internal.h"

#include "internal/helper.h"
#include "internal/error/error_internal.h"

#include <unistd.h>
#include <sys/types.h>

void cw_encode_stream_struct_delete_internal(ENCODE_STREAM_STRUCT *s_struct)
{
    if (s_struct == NULL)
        return;

    if (s_struct->ctx != NULL)
        EVP_ENCODE_CTX_free(s_struct->ctx);

    OPENSSL_free(s_struct);
}

void cw_encode_file_cleanup_internal(FILE *reader, FILE *writer)
{
    if (reader != NULL)
        fclose(reader);

    if (writer != NULL)
        fclose(writer);
}

int cw_encode_file_check_internal(const char *in_file, const char *out_file, int mode)
{
    if (in_file == NULL || out_file == NULL || (mode != BASE64_STREAM_ENCODE && mode != BASE64_STREAM_DECODE))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *reader = NULL;
    FILE *writer = NULL;

    long file_size;
    long new_file_size;

    int in_place_crypt = 0;

    int ret = 0;

    if ((reader = fopen(in_file, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    // If out_file == NULL assume in place crypt
    if (out_file == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_NO_FILE_IN_PLACE_ALLOWED);
        cw_encode_file_cleanup_internal(reader, writer);
        return 0;
    }

    // Open with rb+ first to prevent overwriting reader file which was set with different path
    if ((writer = fopen(out_file, "rb+")) == NULL)
    {
        // Try open with wb to create the file --- at this point one can assume that the files are different
        if ((writer = fopen(out_file, "wb")) == NULL)
        {
            cw_encode_file_cleanup_internal(reader, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
            return 0;
        }
    }

    // Check if reader and writer are equal
    if ((in_place_crypt = cw_cipher_misc_compare_file_pointers_internal(reader, writer)) == 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_NO_FILE_IN_PLACE_ALLOWED);
        cw_encode_file_cleanup_internal(reader, writer);
        return 0;
    }

    fseek(reader, 0, SEEK_END);
    file_size = ftell(reader);
    rewind(reader);

    ret = cw_encode_file_encode_internal(reader, writer, &new_file_size, mode);

    if (ret == 1 && (in_place_crypt == 1 && mode == BASE64_STREAM_DECODE && new_file_size < file_size))
        truncate(in_file, new_file_size);

    cw_encode_file_cleanup_internal(reader, writer);

    return ret;
}

void cw_encode_file_encode_cleanup_internal(EVP_ENCODE_CTX *ctx, uint8_t *read_buffer, uint8_t read_buffer_len, uint8_t *write_buffer, uint8_t write_buffer_len)
{
    if (ctx != NULL)
        EVP_ENCODE_CTX_free(ctx);

    if (read_buffer != NULL)
        OPENSSL_clear_free(read_buffer, read_buffer_len);

    if (write_buffer != NULL)
        OPENSSL_clear_free(write_buffer, write_buffer_len);
}

int cw_encode_file_encode_internal(FILE *reader, FILE *writer, long *new_file_size, int mode)
{
    long total_bytes_written = 0;
    int temp_bytes_written = 0;
    size_t bytes_read = 0;

    uint8_t *read_buffer = NULL;
    size_t read_buffer_len = MEGABYTES(10);

    uint8_t *write_buffer = NULL;
    size_t write_buffer_len = MEGABYTES(15);

    EVP_ENCODE_CTX *ctx = NULL;

    if ((read_buffer = OPENSSL_zalloc(read_buffer_len)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((write_buffer = OPENSSL_zalloc(write_buffer_len)) == NULL)
    {
        cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, NULL, 0);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL)
    {
        cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, write_buffer, write_buffer_len);
        CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW);
        return 0;
    }

    if (mode == BASE64_STREAM_ENCODE)
    {
        EVP_EncodeInit(ctx);

        while (1)
        {
            if ((bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_len, reader)) == 0)
                break;

            if (EVP_EncodeUpdate(ctx, write_buffer, &temp_bytes_written, read_buffer, bytes_read) != 1)
            {
                cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, write_buffer, write_buffer_len);
                CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE);
                return 0;
            }

            total_bytes_written += temp_bytes_written;

            fwrite(write_buffer, sizeof(uint8_t), temp_bytes_written, writer);

            // TEST

            // TEST
        }

        EVP_EncodeFinal(ctx, write_buffer, &temp_bytes_written);

        total_bytes_written += temp_bytes_written;
        fwrite(write_buffer, sizeof(uint8_t), temp_bytes_written, writer);
    }
    else
    {
        EVP_DecodeInit(ctx);

        while (1)
        {
            if ((bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_len, reader)) == 0)
                break;

            if (EVP_DecodeUpdate(ctx, write_buffer, &temp_bytes_written, read_buffer, bytes_read) < 0)
            {
                cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, write_buffer, write_buffer_len);
                CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE);
                return 0;
            }

            total_bytes_written += temp_bytes_written;

            fwrite(write_buffer, sizeof(uint8_t), temp_bytes_written, writer);
        }

        if (EVP_DecodeFinal(ctx, write_buffer, &temp_bytes_written) != 1)
        {
            cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, write_buffer, write_buffer_len);
            CW_ERROR_RAISE(CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE);
            return 0;
        }

        total_bytes_written += temp_bytes_written;
        fwrite(write_buffer, sizeof(uint8_t), temp_bytes_written, writer);
    }

    if (new_file_size != NULL)
        *new_file_size = total_bytes_written;

    cw_encode_file_encode_cleanup_internal(ctx, read_buffer, read_buffer_len, write_buffer, write_buffer_len);

    return 1;
}