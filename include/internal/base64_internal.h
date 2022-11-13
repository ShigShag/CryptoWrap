/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef ENCODE_INTERNAL_H
#define ENCODE_INTERNAL_H

#include "cryptowrap/base64.h"

#include <openssl/evp.h>

#define BASE64_CLEANUP_INTERNAL(out, out_len, flags, ctx) \
    do                                                    \
    {                                                     \
        if (out != NULL && !(flags & BASE64_NO_ALLOC))    \
            OPENSSL_clear_free(out, out_len);             \
        if (ctx != NULL)                                  \
        {                                                 \
            EVP_ENCODE_CTX_free(ctx);                     \
        }                                                 \
    } while (0)

#define BASE64_CLEANUP_FILE_OUT(fp, out, out_len, stream_handle, flags, read_buffer, read_buffer_length) \
    do                                                                                                   \
    {                                                                                                    \
        if (read_buffer != NULL)                                                                         \
            OPENSSL_clear_free(read_buffer, read_buffer_length);                                         \
        if (out != NULL && !(flags & BASE64_NO_ALLOC))                                                   \
            OPENSSL_clear_free(out, out_len);                                                            \
        if (fp == NULL)                                                                                  \
            fclose(fp);                                                                                  \
        if (stream_handle != NULL)                                                                       \
            cw_base64_stream_delete(stream_handle);                                                      \
                                                                                                         \
    } while (0)

typedef struct
{
    EVP_ENCODE_CTX *ctx;
    int mode;
} ENCODE_STREAM_STRUCT;

void cw_encode_stream_struct_delete_internal(ENCODE_STREAM_STRUCT *s_struct);

void cw_encode_file_cleanup_internal(FILE *reader, FILE *writer);

int cw_encode_file_check_internal(const char *in_file, const char *out_file, int mode);

void cw_encode_file_encode_cleanup_internal(EVP_ENCODE_CTX *ctx, uint8_t *read_buffer, uint8_t read_buffer_len, uint8_t *write_buffer, uint8_t write_buffer_len);

int cw_encode_file_encode_internal(FILE *reader, FILE *writer, long *new_file_size, int mode);

#endif
