/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/symmetric_cipher_internal.h"
#include "internal/fetching.h"
#include "internal/helper.h"
#include "internal/error/error_internal.h"

#include <openssl/rand.h>

#include <unistd.h>
#include <sys/types.h>

#define CRYPT_BUFFER_SIZE (INT_MAX - (16 * 4))

#define MEGABYTES(num) (num * (1024 * 1024))

/* Internal function declarations END*/

void cipher_cleanup_internal(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher_impl)
{
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    if (cipher_impl != NULL)
        EVP_CIPHER_free(cipher_impl);
}

int cw_sym_cipher_raw_check_params_internal(cw_symmetric_cipher_algorithm algorithm_id, int key_len, int iv_len, uint64_t in_len, uint8_t flags)
{
    int required_key_len = 0;
    int required_iv_len = 0;

    if (cw_fetch_symmetric_cipher_key_and_iv_length(algorithm_id, &required_key_len, &required_iv_len) != 1)
        return 0;

    if (required_key_len != key_len || key_len > (uint8_t)INT_MAX)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_WRONG_KEY_LEN);
        return 0;
    }

    // Protect from overflow when compare signed to unsigned
    if (required_iv_len != iv_len || iv_len > (uint8_t)INT_MAX)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_WRONG_IV_LEN);
        return 0;
    }

    if (!(flags & SYM_CIPHER_CHECK_PARAMS_NO_IN_LEN))
    {
        if ((algorithm_id == CW_AES_128_XTS || algorithm_id == CW_AES_256_XTS) && in_len < 16)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_INPUT_SIZE_TOO_SHORT_FOR_XTS);
            return 0;
        }
    }

    return 1;
}

int cw_sym_cipher_raw_pre_crypt_internal(const uint8_t *in, uint64_t in_len,
                                         uint8_t **out, uint64_t *out_len,
                                         const uint8_t *key, uint32_t key_len,
                                         const uint8_t *iv, uint32_t iv_len,
                                         cw_symmetric_cipher_algorithm algorithm_id, uint8_t flags, int mode)
{
    if (in == NULL || in_len == 0 || out == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (cw_sym_cipher_raw_check_params_internal(algorithm_id, key_len, iv_len, in_len, 0) != 1)
        return 0;

    return cw_sym_cipher_raw_crypt_bytes_internal(in, in_len, out, out_len, key, iv, algorithm_id, mode, flags);
}

int cw_sym_cipher_raw_crypt_bytes_internal(const uint8_t *in, uint64_t in_len,
                                           uint8_t **out, uint64_t *out_len,
                                           const uint8_t *key,
                                           const uint8_t *iv,
                                           cw_symmetric_cipher_algorithm algorithm_id, int mode, uint8_t flags)
{
    if (!(flags & SYMMETRIC_CIPHER_NO_ALLOC))
        *out = NULL;

    uint64_t out_len_internal = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    uint64_t expected_cipher_size;
    int temp_len = 0;
    const uint64_t buffer_len = INT_MAX;

    if ((cipher_impl = fetch_symmetric_cipher_impl(algorithm_id)) == NULL)
        return 0;

    // If out needs to be allocated
    if (!(flags & SYMMETRIC_CIPHER_NO_ALLOC))
    {
        expected_cipher_size = cw_cipher_get_cipher_size_impl_internal(cipher_impl, in_len);

        if ((*out = OPENSSL_zalloc(expected_cipher_size)) == NULL)
        {
            SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    // Init cipher
    if (EVP_CipherInit_ex2(ctx, cipher_impl, key, iv, mode, NULL) != 1)
    {
        SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    if (in_len > buffer_len)
    {
        do
        {
            if (EVP_CipherUpdate(ctx, *out + out_len_internal, &temp_len, in, (int)buffer_len) != 1)
            {
                SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
                CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE);
                return 0;
            }

            out_len_internal += temp_len;
            in += buffer_len;
        } while ((in_len -= buffer_len) > buffer_len);
    }

    if (EVP_CipherUpdate(ctx, *out + out_len_internal, &temp_len, in, (int)in_len) != 1)
    {
        SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE);
        return 0;
    }

    out_len_internal += temp_len;

    if (EVP_CipherFinal_ex(ctx, *out + out_len_internal, &temp_len) != 1)
    {
        SYM_CIPHER_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *out, expected_cipher_size, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHERFINAL_EX);
        return 0;
    }

    out_len_internal += temp_len;

    // When decrypting block cipher to much memory could be allocated --- use realloc to adapt --- only if allocated internal
    if (mode == SYMMETRIC_CIPHER_DECRYPT && !(flags & SYMMETRIC_CIPHER_NO_ALLOC) && out_len_internal != expected_cipher_size)
    {
        uint8_t *temp = realloc(*out, out_len_internal);
        if (temp != NULL)
        {
            *out = temp;
        }
    }

    cipher_cleanup_internal(ctx, cipher_impl);

    if (out_len != NULL)
        *out_len = out_len_internal;

    return 1;
}

void cw_sym_cipher_file_check_cleanup(FILE *reader, FILE *writer)
{
    if (reader != NULL)
        fclose(reader);

    if (writer != NULL)
        fclose(writer);
}

int cw_sym_cipher_file_check_internal(const char *in_file, const char *out_file,
                                      const uint8_t *key, uint32_t key_len,
                                      const uint8_t *iv, uint32_t iv_len,
                                      int mode, cw_symmetric_cipher_algorithm algorithm_id)
{
    if (in_file == NULL || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *reader = NULL;
    FILE *writer = NULL;

    int ret = 0;
    int in_place_crypt = 0;
    long file_size = 0;
    long new_file_size = 0;

    if (cw_sym_cipher_raw_check_params_internal(algorithm_id, key_len, iv_len, 0, SYM_CIPHER_CHECK_PARAMS_NO_IN_LEN) != 1)
        return 0;

    if ((reader = fopen(in_file, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    // If out_file == NULL assume in place crypt
    if (out_file == NULL)
        in_place_crypt = 1;

    // If this fails
    if (in_place_crypt == 1)
    {
        // If this fails in place encryption is not possible
        if ((writer = fopen(in_file, "rb+")) == NULL)
        {
            cw_sym_cipher_file_check_cleanup(reader, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
            return 0;
        }
    }
    else
    {
        // Open with rb+ first to prevent overwriting reader file which was set with different path
        if ((writer = fopen(out_file, "rb+")) == NULL)
        {
            // Try open with wb to create the file --- at this point one can assume that the files are different
            if ((writer = fopen(out_file, "wb")) == NULL)
            {
                cw_sym_cipher_file_check_cleanup(reader, NULL);
                CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
                return 0;
            }
        }

        // Check if reader and writer are equal
        if ((in_place_crypt = cw_cipher_misc_compare_file_pointers_internal(reader, writer)) != 1)
        {
            // Open in wb mode
            fclose(writer);
            writer = NULL;

            if ((writer = fopen(out_file, "wb")) == NULL)
            {
                cw_sym_cipher_file_check_cleanup(reader, NULL);
                CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
                return 0;
            }
        }
    }

    // Get file size
    fseek(reader, 0, SEEK_END);
    file_size = ftell(reader);
    rewind(reader);

    ret = cw_sym_cipher_file_crypt_internal(reader, writer, key, iv, &new_file_size, mode, algorithm_id);

    // Check if file size differs when decrypting
    if (ret == 1 && (in_place_crypt == 1 && mode == SYMMETRIC_CIPHER_DECRYPT && new_file_size < file_size))
        truncate(in_file, new_file_size);

    cw_sym_cipher_file_check_cleanup(reader, writer);

    return ret;
}

void cw_sym_cipher_file_crypt_cleanup_internal(uint8_t *read_buffer, uint32_t read_length, uint8_t *write_buffer,
                                               uint32_t write_length, EVP_CIPHER_CTX *ctx, EVP_CIPHER *impl)
{
    if (read_buffer != NULL)
        OPENSSL_clear_free(read_buffer, read_length);

    if (write_buffer != NULL)
        OPENSSL_clear_free(write_buffer, write_length);

    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    if (impl != NULL)
        EVP_CIPHER_free(impl);
}

int cw_sym_cipher_file_crypt_internal(FILE *reader, FILE *writer,
                                      const uint8_t *key,
                                      const uint8_t *iv,
                                      long *new_file_size,
                                      int mode, cw_symmetric_cipher_algorithm algorithm_id)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    uint8_t *read_buffer = NULL;
    uint8_t *write_buffer = NULL;

    uint32_t read_buffer_size = MEGABYTES(10);
    uint32_t write_buffer_size = MEGABYTES(11);

    uint64_t new_file_size_internal = 0;

    size_t bytes_read = 0;
    int bytes_crypted;

    if ((cipher_impl = fetch_symmetric_cipher_impl(algorithm_id)) == NULL)
        return 0;

    if ((read_buffer = (uint8_t *)OPENSSL_zalloc(read_buffer_size)) == NULL)
    {
        cw_sym_cipher_file_crypt_cleanup_internal(NULL, 0, NULL, 0, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((write_buffer = (uint8_t *)OPENSSL_zalloc(write_buffer_size)) == NULL)
    {
        cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, NULL, 0, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, cipher_impl, key, iv, mode, NULL) != 1)
    {
        cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    while (1)
    {
        bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_size, reader);

        if (bytes_read == 0)
            break;

        if (EVP_CipherUpdate(ctx, write_buffer, &bytes_crypted, read_buffer, bytes_read) != 1)
        {
            cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE);
            return 0;
        }
        new_file_size_internal += bytes_crypted;

        fwrite(write_buffer, sizeof(uint8_t), bytes_crypted, writer);
    }

    if (EVP_CipherFinal_ex(ctx, write_buffer, &bytes_crypted) != 1)
    {
        cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_SYM_CIPHER_EVP_CIPHERFINAL_EX);
        return 0;
    }

    fwrite(write_buffer, sizeof(uint8_t), bytes_crypted, writer);

    new_file_size_internal += bytes_crypted;

    cw_sym_cipher_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);

    if (new_file_size != NULL)
        *new_file_size = new_file_size_internal;

    return 1;
}

uint64_t cw_cipher_get_cipher_size_internal(cw_symmetric_cipher_algorithm algorithm_id, uint64_t plaintext_len)
{
    if (plaintext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }
    EVP_CIPHER *cipher_impl;
    int32_t block_size;

    if ((cipher_impl = fetch_symmetric_cipher_impl(algorithm_id)) == NULL)
        return 0;

    block_size = EVP_CIPHER_get_block_size(cipher_impl);

    // If cipher is a stream cipher
    if (block_size == 1)
        return plaintext_len;

    return plaintext_len + (block_size - (plaintext_len % block_size));
}

uint64_t cw_cipher_get_cipher_size_impl_internal(EVP_CIPHER *cipher_impl, uint64_t plaintext_len)
{
    if (cipher_impl == NULL || plaintext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int32_t block_size = EVP_CIPHER_get_block_size(cipher_impl);

    // If cipher is a stream cipher
    if (block_size == 1)
        return plaintext_len;

    return plaintext_len + (block_size - (plaintext_len % block_size));
}

uint64_t cw_cipher_get_cipher_size_ctx_internal(EVP_CIPHER_CTX *ctx, uint64_t plaintext_len)
{
    if (ctx == NULL || plaintext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int32_t block_size = EVP_CIPHER_CTX_get_block_size(ctx);

    // If cipher is a stream cipher
    if (block_size == 1)
        return plaintext_len;

    return plaintext_len + (block_size - (plaintext_len % block_size));
}

uint8_t *cw_sym_cipher_generate_symmetric_key(cw_symmetric_cipher_algorithm algorithm_id, int *key_len)
{
    int required_key_len;
    uint8_t *buffer;

    if (cw_fetch_symmetric_cipher_key_and_iv_length(algorithm_id, &required_key_len, NULL) != 1)
        return NULL;

    if ((buffer = OPENSSL_zalloc(required_key_len * sizeof(uint8_t))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return NULL;
    }

    if (RAND_bytes(buffer, required_key_len) != 1)
    {
        OPENSSL_clear_free(buffer, required_key_len * sizeof(uint8_t));
        CW_ERROR_RAISE(CW_ERROR_ID_RANDOM_RAND_BYTES);
        return NULL;
    }

    if (key_len != NULL)
        *key_len = required_key_len;

    return buffer;
}