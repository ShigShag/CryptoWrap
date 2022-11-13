/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/aead_internal.h"
#include "internal/fetching.h"
#include "internal/helper.h"
#include "internal/error/error_internal.h"

#include <unistd.h>
#include <sys/types.h>

int cw_aead_check_params_internal(aead_mode algorithm_id, uint64_t plaintext_len, int key_len, int tag_len, uint8_t flags)
{
    int required_key_len = 0;

    if (cw_fetch_aead_key_and_iv_length_internal(algorithm_id, &required_key_len, NULL) != 1)
        return 0;

    if (required_key_len != key_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_WRONG_KEY_LEN);
        return 0;
    }

    switch (algorithm_id)
    {
    case CW_AES_128_GCM ... CW_ARIA_256_GCM:
        if (!(flags & AEAD_CHECK_PARAMS_NO_TAG))
        {
            if (tag_len < 1 || tag_len > 16)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_GCM_TAG_LEN_WRONG);
                return 0;
            }
        }
        break;

    case CW_AES_128_CCM ... CW_ARIA_256_CCM:
        if (!(flags & AEAD_CHECK_PARAMS_NO_TAG))
        {
            if (tag_len < 4 || tag_len > 16 || tag_len % 2 != 0)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_CCM_TAG_LEN_WRONG);
                return 0;
            }
        }

        if (plaintext_len > INT_MAX)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_CCM_INPUT_TOO_LARGE);
            return 0;
        }
        break;

    case CW_AES_128_OCB ... CW_AES_256_OCB:
        if (!(flags & AEAD_CHECK_PARAMS_NO_TAG))
        {
            if (tag_len != 16)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_OCB_TAG_LEN_WRONG);
                return 0;
            }
        }
        break;

    case CW_CHACHA_20_POLY_1305:
        if (!(flags & AEAD_CHECK_PARAMS_NO_TAG))
        {
            if (tag_len > 16)
            {
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_CHACHA_20_TAG_LEN_WRONG);
                return 0;
            }
        }
        break;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_UNKNOWN_ALGORITHM);
        return 0;
    }

    return 1;
}

void cw_aead_cleanup_internal(EVP_CIPHER_CTX *ctx, EVP_CIPHER *cipher_impl)
{
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    if (cipher_impl != NULL)
        EVP_CIPHER_free(cipher_impl);
}

int cw_aead_raw_pre_crypt_internal(const uint8_t *plaintext, uint64_t plaintext_len, uint8_t **ciphertext, uint64_t *ciphertext_len,
                                   const uint8_t *key, const int key_len,
                                   const uint8_t *iv, const int iv_len,
                                   const uint8_t *aad, const uint32_t aad_len,
                                   uint8_t **tag, const int tag_len, aead_mode algorithm_id, const int mode, const uint8_t flags)
{
    if (plaintext == NULL || plaintext_len == 0 || ciphertext == NULL ||
        key == NULL || iv == NULL || tag == NULL || tag_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // No need to raise error since it is raised within the function
    if (cw_aead_check_params_internal(algorithm_id, plaintext_len, key_len, tag_len, 0) != 1)
        return 0;

    return cw_aead_raw_crypt_internal(plaintext, plaintext_len, ciphertext, ciphertext_len, aad, aad_len, key, iv, iv_len, tag, tag_len, mode, algorithm_id, flags);
}

int cw_aead_raw_crypt_internal(const uint8_t *plaintext, const uint64_t plaintext_len,
                               uint8_t **ciphertext, uint64_t *ciphertext_len,
                               const uint8_t *aad, const uint32_t aad_len,
                               const uint8_t *key,
                               const uint8_t *iv, const uint32_t iv_len,
                               uint8_t **tag, int tag_len,
                               int mode, aead_mode algorithm_id, const uint8_t flags)
{
    // Only set to NULL if not allcoated by user
    if (!(flags & (AEAD_NO_ALLOC | AEAD_OUT_NO_ALLOC)))
        *ciphertext = NULL;

    if (!(flags & (AEAD_NO_ALLOC | AEAD_TAG_NO_ALLOC)) && mode == AEAD_ENCRYPT)
        *tag = NULL;

    uint64_t ciphertext_len_internal = 0;
    *ciphertext_len = 0;

    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    int temp_len;
    uint64_t expected_cipher_size = 0;
    uint64_t plaintext_len_copy = plaintext_len;

    const uint64_t buffer_len = INT_MAX;

    if ((cipher_impl = cw_fetch_aead_impl_internal(algorithm_id)) == NULL)
        return 0;

    // If ciphertext needs to be allocated
    if (!(flags & (AEAD_NO_ALLOC | AEAD_OUT_NO_ALLOC)))
    {
        expected_cipher_size = cw_aead_get_encrypt_size_impl_internal(cipher_impl, plaintext_len_copy);

        if ((*ciphertext = OPENSSL_zalloc(expected_cipher_size)) == NULL)
        {
            AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, cipher_impl, NULL, NULL, mode, NULL) != 1)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    // Set iv length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) != 1)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN);
        return 0;
    }

    // Set expected Tag len in ccm when encrypting or set tag when decrypting
    if (mode == AEAD_DECRYPT || IS_CCM(algorithm_id))
    {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (mode == AEAD_ENCRYPT) ? NULL : *tag) != 1)
        {
            AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG);
            return 0;
        }
    }

    if (EVP_CipherInit_ex2(ctx, NULL, key, iv, mode, NULL) != 1)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    // Set CCM plaintext_len_copy
    if (IS_CCM(algorithm_id))
    {
        if (EVP_CipherUpdate(ctx, NULL, &temp_len, NULL, (int)plaintext_len_copy) != 1)
        {
            AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
            return 0;
        }
    }

    // Set AAD if set
    if (aad != NULL && aad_len > 0)
    {
        if (EVP_CipherUpdate(ctx, NULL, &temp_len, aad, aad_len) != 1)
        {
            AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE_AAD);
            return 0;
        }
    }

    // CCM only supports one call to EVP_CipherUpdate for data en-decryption
    if (plaintext_len_copy > buffer_len && !IS_CCM(algorithm_id))
    {
        do
        {
            if (EVP_CipherUpdate(ctx, *ciphertext + ciphertext_len_internal, &temp_len, plaintext, (int)buffer_len) != 1)
            {
                AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
                return 0;
            }

            ciphertext_len_internal += temp_len;
            plaintext += buffer_len;
        } while ((plaintext_len_copy -= buffer_len) > buffer_len);
    }

    if (EVP_CipherUpdate(ctx, *ciphertext + ciphertext_len_internal, &temp_len, plaintext, (int)plaintext_len_copy) != 1)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
        return 0;
    }

    ciphertext_len_internal += temp_len;

    if (EVP_CipherFinal_ex(ctx, *ciphertext + ciphertext_len_internal, &temp_len) != 1)
    {
        AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_FINAL_EX);
        return 0;
    }

    ciphertext_len_internal += temp_len;

    // Get the tag
    if (mode == AEAD_ENCRYPT)
    {
        // If tag needs to be allocated
        if (!(flags & (AEAD_TAG_NO_ALLOC | AEAD_NO_ALLOC)))
        {
            if ((*tag = OPENSSL_zalloc(tag_len)) == NULL)
            {
                AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
                CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
                return 0;
            }
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, *tag) != 1)
        {
            AEAD_RAW_CRYPT_CLEANUP(ctx, cipher_impl, *ciphertext, expected_cipher_size, *tag, tag_len, flags, mode);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG);
            return 0;
        }
    }

    // If Decryption length differs from cipher_size realloc it given that *ciphertext is not allocated by user
    if (mode == AEAD_DECRYPT && !(flags & (AEAD_NO_ALLOC | AEAD_OUT_NO_ALLOC)) && ciphertext_len_internal != expected_cipher_size)
    {
        uint8_t *temp = realloc(*ciphertext, ciphertext_len_internal);
        if (temp != NULL)
        {
            *ciphertext = temp;
        }
    }

    cw_aead_cleanup_internal(ctx, cipher_impl);

    if (ciphertext_len != NULL)
        *ciphertext_len = ciphertext_len_internal;

    return 1;
}
/* FILE */
void cw_aead_file_cleanup_internal(FILE *reader, FILE *writer)
{
    if (reader != NULL)
        fclose(reader);

    if (writer != NULL)
        fclose(writer);
}

int cw_aead_file_pre_crypt_internal(const char *in_file, const char *out_file,
                                    const uint8_t *key, const uint32_t key_len,
                                    const uint8_t *iv, const uint32_t iv_len,
                                    const uint8_t *aad, const uint32_t aad_len,
                                    uint8_t **tag, const int tag_len, const int mode, aead_mode algorithm_id, const uint8_t flags)
{
    if (in_file == NULL || key == NULL || iv == NULL || tag == NULL || tag_len == 0)
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

    if (cw_aead_check_params_internal(algorithm_id, 0, key_len, tag_len, 0) != 1)
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
            cw_aead_file_cleanup_internal(reader, NULL);
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
                cw_aead_file_cleanup_internal(reader, NULL);
                CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
                return 0;
            }
        }

        // Check if reader and writer are equal
        if ((in_place_crypt = cw_cipher_misc_compare_file_pointers_internal(reader, writer)) != 1)
        {
            // Close writer to open it again in wb mode
            fclose(writer);
            writer = NULL;

            if ((writer = fopen(out_file, "wb")) == NULL)
            {
                cw_aead_file_cleanup_internal(reader, NULL);
                CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
                return 0;
            }
        }
    }

    // Get file size
    fseek(reader, 0, SEEK_END);
    file_size = ftell(reader);
    rewind(reader);

    if (!(file_size > INT_MAX && IS_CCM(algorithm_id)))
        ret = cw_aead_file_crypt_internal(reader, writer, key, iv, iv_len, aad, aad_len, tag, tag_len, file_size, &new_file_size, mode, algorithm_id, flags);

    // Check if file size differs when decrypting
    if (ret == 1 && (in_place_crypt == 1 && mode == AEAD_DECRYPT && new_file_size < file_size))
        truncate(in_file, new_file_size);

    cw_aead_file_cleanup_internal(reader, writer);

    return ret;
}

void cw_aead_file_crypt_cleanup_internal(uint8_t *read_buffer, uint32_t read_length, uint8_t *write_buffer, uint32_t write_length,
                                         EVP_CIPHER_CTX *ctx, EVP_CIPHER *impl)
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

int cw_aead_file_crypt_internal(FILE *reader, FILE *writer,
                                const uint8_t *key,
                                const uint8_t *iv, const uint32_t iv_len,
                                const uint8_t *aad, const uint32_t aad_len,
                                uint8_t **tag, const int tag_len,
                                const long file_size, long *new_file_size,
                                int mode, aead_mode algorithm_id, const uint8_t flags)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher_impl = NULL;

    uint8_t *read_buffer = NULL;
    uint8_t *write_buffer = NULL;

    uint32_t read_buffer_size = MEGABYTES(10);
    uint32_t write_buffer_size = MEGABYTES(11);

    unsigned long new_file_size_internal = 0;

    size_t bytes_read = 0;
    int bytes_crypted;

    if ((cipher_impl = cw_fetch_aead_impl_internal(algorithm_id)) == NULL)
        return 0;

    if ((read_buffer = (uint8_t *)OPENSSL_zalloc(read_buffer_size)) == NULL)
    {
        cw_aead_file_crypt_cleanup_internal(NULL, 0, NULL, 0, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((write_buffer = (uint8_t *)OPENSSL_zalloc(write_buffer_size)) == NULL)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, NULL, 0, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, NULL, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW);
        return 0;
    }

    if (EVP_CipherInit_ex2(ctx, cipher_impl, NULL, NULL, mode, NULL) != 1)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    // Set iv length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL) != 1)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN);
        return 0;
    }

    // Set expected Tag len in ccm when encrypting or set tag when decrypting
    if (mode == AEAD_DECRYPT || IS_CCM(algorithm_id))
    {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (mode == AEAD_ENCRYPT) ? NULL : *tag) != 1)
        {
            cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG);
            return 0;
        }
    }

    if (EVP_CipherInit_ex2(ctx, NULL, key, iv, mode, NULL) != 1)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2);
        return 0;
    }

    // Set CCM plaintext_len
    if (IS_CCM(algorithm_id))
    {
        if (EVP_CipherUpdate(ctx, NULL, &bytes_crypted, NULL, (int)file_size) != 1)
        {
            cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
            return 0;
        }
    }

    // Set AAD if set
    if (aad != NULL || aad_len != 0)
    {
        if (EVP_CipherUpdate(ctx, NULL, &bytes_crypted, aad, aad_len) != 1)
        {
            cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE_AAD);
            return 0;
        }
    }

    while (1)
    {
        bytes_read = fread(read_buffer, sizeof(uint8_t), read_buffer_size, reader);

        if (bytes_read == 0)
            break;

        if (EVP_CipherUpdate(ctx, write_buffer, &bytes_crypted, read_buffer, bytes_read) != 1)
        {
            {
                cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
                CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE);
                return 0;
            }
        }
        new_file_size_internal += bytes_crypted;

        fwrite(write_buffer, sizeof(uint8_t), bytes_crypted, writer);
    }

    if (EVP_CipherFinal_ex(ctx, write_buffer, &bytes_crypted) != 1)
    {
        cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_FINAL_EX);
        return 0;
    }

    fwrite(write_buffer, sizeof(uint8_t), bytes_crypted, writer);

    new_file_size_internal += bytes_crypted;

    if (mode == AEAD_ENCRYPT)
    {
        // If tag needs to be allocated
        if (!(flags & (AEAD_TAG_NO_ALLOC | AEAD_NO_ALLOC)))
        {
            if ((*tag = OPENSSL_zalloc(tag_len)) == NULL)
            {
                cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
                CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
                return 0;
            }
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, *tag) != 1)
        {
            cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);
            CW_ERROR_RAISE(CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG);
            return 0;
        }
    }

    cw_aead_file_crypt_cleanup_internal(read_buffer, read_buffer_size, write_buffer, write_buffer_size, ctx, cipher_impl);

    if (new_file_size != NULL)
        *new_file_size = new_file_size_internal;

    return 1;
}

uint64_t cw_aead_get_encrypt_size_internal(uint64_t plaintext_len)
{
    if (plaintext_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // Testing proved this to be sufficient
    return plaintext_len;

    // This method does not work for OCB
    // EVP_CIPHER *cipher_impl;
    // int32_t block_size;

    // if ((cipher_impl = cw_fetch_aead_impl_internal(algorithm_id)) == NULL)
    // {
    //     return 0;
    // }

    // block_size = EVP_CIPHER_get_block_size(cipher_impl);

    // cw_fetch_free_aead_impl_internal(cipher_impl);

    // // If cipher is a stream cipher
    // if (block_size == 1)
    //     return plaintext_len;

    // return plaintext_len + (block_size - (plaintext_len % block_size));
}

uint64_t cw_aead_get_encrypt_size_impl_internal(EVP_CIPHER *cipher_impl, uint64_t plaintext_len)
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

uint64_t cw_aead_get_encrypt_size_ctx_internal(EVP_CIPHER_CTX *ctx, uint64_t plaintext_len)
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

    return plaintext_len + ((uint64_t)block_size - (plaintext_len % block_size));
}