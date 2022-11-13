/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/rsa_internal.h"
#include "internal/error/error_internal.h"
#include "internal/fetching.h"

#include <string.h>
#include <openssl/rsa.h>

int cw_rsa_generate_key_pair(CW_RSA_KEY_PAIR *key_pair, int bits)
{
    if (key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    // This is necessary otherwise EVP_PKEY_generate will run infinite
    *key_pair = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    // if (bits < 512)
    // {
    //     CW_ERROR_RAISE(CW_ERROR_ID_RSA_KEY_SIZE_TOO_SMALL);
    //     return 0;
    // }

    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW_ID);
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_KEYGEN_INIT);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_BITS);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES);
        return 0;
    }

    if (EVP_PKEY_generate(ctx, (EVP_PKEY **)key_pair) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_GENERATE);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

void cw_rsa_delete_key_pair(CW_RSA_KEY_PAIR key_pair)
{
    if (key_pair != NULL)
        EVP_PKEY_free((EVP_PKEY *)key_pair);
}

int cw_rsa_write_public_key(const char *file_path, CW_RSA_KEY_PAIR key_pair, cw_rsa_serialization_type serialization_mode)
{
    if (file_path == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *fp = NULL;
    int ret;

    if ((fp = fopen(file_path, "wb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    ret = cw_rsa_write_key_internal(fp, (EVP_PKEY *)key_pair, NULL, serialization_mode, RSA_PUBLIC_KEY);

    fclose(fp);
    return ret;
}
int cw_rsa_write_public_key_fp(FILE *fp, CW_RSA_KEY_PAIR key_pair, cw_rsa_serialization_type serialization_mode)
{
    return cw_rsa_write_key_internal(fp, (EVP_PKEY *)key_pair, NULL, serialization_mode, RSA_PUBLIC_KEY);
}

int cw_rsa_write_private_key(const char *file_path, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode)
{
    if (file_path == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *fp = NULL;
    int ret;

    if ((fp = fopen(file_path, "wb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    ret = cw_rsa_write_key_internal(fp, (EVP_PKEY *)key_pair, passphrase, serialization_mode, RSA_PRIVATE_KEY);

    fclose(fp);
    return ret;
}
int cw_rsa_write_private_key_fp(FILE *fp, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode)
{
    return cw_rsa_write_key_internal(fp, (EVP_PKEY *)key_pair, passphrase, serialization_mode, RSA_PRIVATE_KEY);
}

int cw_rsa_load_public_key(const char *file_path, CW_RSA_KEY_PAIR *key_pair, cw_rsa_serialization_type serialization_mode)
{
    if (file_path == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *fp = NULL;
    int ret;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    ret = cw_rsa_load_key_internal(fp, NULL, serialization_mode, key_pair, RSA_PUBLIC_KEY);

    fclose(fp);
    return ret;
}
int cw_rsa_load_public_key_fp(FILE *fp, CW_RSA_KEY_PAIR *key_pair, cw_rsa_serialization_type serialization_mode)
{
    return cw_rsa_load_key_internal(fp, NULL, serialization_mode, key_pair, RSA_PUBLIC_KEY);
}
int cw_rsa_load_private_key(const char *file_path, CW_RSA_KEY_PAIR *key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode)
{
    if (file_path == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    FILE *fp = NULL;
    int ret;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    ret = cw_rsa_load_key_internal(fp, passphrase, serialization_mode, key_pair, RSA_PRIVATE_KEY);

    fclose(fp);
    return ret;
}
int cw_rsa_load_private_key_fp(FILE *fp, CW_RSA_KEY_PAIR *key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode)
{
    return cw_rsa_load_key_internal(fp, passphrase, serialization_mode, key_pair, RSA_PRIVATE_KEY);
}

int cw_rsa_sign_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *message, const uint32_t message_len,
                      cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode, uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    // if (padding_mode == CW_RSA_X931_PADDING)
    // {
    //     if (!(hash == CW_RSA_SIG_HASH_SHA_1 || hash == CW_RSA_SIG_HASH_SHA_256 || hash == CW_RSA_SIG_HASH_SHA_384 || hash == CW_RSA_SIG_HASH_SHA_512))
    //     {
    //         CW_ERROR_RAISE(CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931);
    //         return 0;
    //     }
    // }
    if (RSA_IS_OAEP(padding_mode) == 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING);
        return 0;
    }

    return cw_rsa_sign_bytes_internal(key_pair, message, message_len, hash, padding_mode, signature, signature_len, flags);
}

int cw_rsa_sign_string(CW_RSA_KEY_PAIR key_pair, const char *message,
                       cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode, uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    // if (padding_mode == CW_RSA_X931_PADDING)
    // {
    //     if (!(hash == CW_RSA_SIG_HASH_SHA_1 || hash == CW_RSA_SIG_HASH_SHA_256 || hash == CW_RSA_SIG_HASH_SHA_384 || hash == CW_RSA_SIG_HASH_SHA_512))
    //     {
    //         CW_ERROR_RAISE(CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931);
    //         return 0;
    //     }
    // }
    if (RSA_IS_OAEP(padding_mode) == 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING);
        return 0;
    }

    uint32_t in_len = strlen(message);
    if (in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_SIGN_MESSAGE_TO_SHORT);
        return 0;
    }

    return cw_rsa_sign_bytes_internal(key_pair, (const void *)message, in_len, hash, padding_mode, signature, signature_len, flags);
}

int cw_rsa_verify_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *message, const uint32_t message_len,
                        const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode)
{
    // if (padding_mode == CW_RSA_X931_PADDING)
    // {
    //     if (!(hash == CW_RSA_SIG_HASH_SHA_1 || hash == CW_RSA_SIG_HASH_SHA_256 || hash == CW_RSA_SIG_HASH_SHA_384 || hash == CW_RSA_SIG_HASH_SHA_512))
    //     {
    //         CW_ERROR_RAISE(CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931);
    //         return 0;
    //     }
    // }
    if (RSA_IS_OAEP(padding_mode))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING);
        return 0;
    }

    return cw_rsa_verify_signature_internal(key_pair, message, message_len, signature, signature_len, hash, padding_mode);
}

int cw_rsa_verify_string(CW_RSA_KEY_PAIR key_pair, const char *message,
                         const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode)
{
    // if (padding_mode == CW_RSA_X931_PADDING)
    // {
    //     if (!(hash == CW_RSA_SIG_HASH_SHA_1 || hash == CW_RSA_SIG_HASH_SHA_256 || hash == CW_RSA_SIG_HASH_SHA_384 || hash == CW_RSA_SIG_HASH_SHA_512))
    //     {
    //         CW_ERROR_RAISE(CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931);
    //         return 0;
    //     }
    // }
    if (RSA_IS_OAEP(padding_mode))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING);
        return 0;
    }

    uint32_t in_len = strlen(message);

    if (in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_VERIFY_MESSAGE_TO_SHORT);
        return 0;
    }

    return cw_rsa_verify_signature_internal(key_pair, message, in_len, signature, signature_len, hash, padding_mode);
}

int cw_rsa_encrypt_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *plaintext, const uint64_t plaintext_len, uint8_t **ciphertext,
                         uint64_t *ciphertext_len, cw_rsa_padding_mode padding_mode, const uint8_t flags)
{
    if (key_pair == NULL || plaintext == NULL || plaintext_len == 0 || ciphertext == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (padding_mode == CW_RSA_PKCS1_PSS_PADDING)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PSS_PADDING_MODE_NOT_ALLOWED_FOR_ENCRYPTION);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
        *ciphertext = NULL;

    EVP_PKEY_CTX *ctx = NULL;
    int padding_mode_ = 0;

    EVP_MD *md = NULL;
    char *md_id = 0;

    uint64_t ciphertext_len_internal = 0;

    if ((ctx = EVP_PKEY_CTX_new((EVP_PKEY *)key_pair, NULL)) == NULL)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW);
        return 0;
    }

    if (EVP_PKEY_encrypt_init_ex(ctx, NULL) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT_INIT_EX);
        return 0;
    }

    if ((padding_mode_ = cw_fetch_rsa_padding_mode_internal(padding_mode)) == 0)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding_mode_) <= 0)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING);
        return 0;
    }

    if (padding_mode_ == RSA_PKCS1_OAEP_PADDING)
    {
        switch (padding_mode)
        {
        case CW_RSA_PKCS1_OAEP_SHA1_PADDING:
            md_id = SN_sha1;
            break;

        case CW_RSA_PKCS1_OAEP_SHA224_PADDING:
            md_id = SN_sha224;
            break;

        case CW_RSA_PKCS1_OAEP_SHA256_PADDING:
            md_id = SN_sha256;
            break;

        case CW_RSA_PKCS1_OAEP_SHA512_PADDING:
            md_id = SN_sha512;
            break;

        // This can never be reached
        default:
            md_id = SN_sha256;
            break;
        }

        if ((md = EVP_MD_fetch(NULL, md_id, NULL)) == NULL)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_FETCH_EVP_MD_fetch);
            return 0;
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_OAEP_MD);
            return 0;
        }
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len_internal, plaintext, plaintext_len) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
    {
        if ((*ciphertext = OPENSSL_zalloc(ciphertext_len_internal)) == NULL)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_PKEY_encrypt(ctx, *ciphertext, &ciphertext_len_internal, plaintext, plaintext_len) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, ciphertext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT);
        return 0;
    }

    // This does not cleanup ciphertext
    RSA_CRYPT_CLEANUP(ctx, md, *ciphertext, 0, 0);

    if (ciphertext_len != NULL)
        *ciphertext_len = ciphertext_len_internal;

    return 1;
}

int cw_rsa_decrypt_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *ciphertext, const uint64_t ciphertext_len, uint8_t **plaintext,
                         uint64_t *plaintext_len, cw_rsa_padding_mode padding_mode, const uint8_t flags)
{
    if (key_pair == NULL || plaintext == NULL || ciphertext_len == 0 || ciphertext == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (padding_mode == CW_RSA_PKCS1_PSS_PADDING)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_PSS_PADDING_MODE_NOT_ALLOWED_FOR_ENCRYPTION);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
        *plaintext = NULL;

    EVP_PKEY_CTX *ctx = NULL;
    int padding_mode_;

    EVP_MD *md = NULL;
    char *md_id = 0;

    uint64_t plaintext_len_internal = 0;

    if ((ctx = EVP_PKEY_CTX_new((EVP_PKEY *)key_pair, NULL)) == NULL)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW);
        return 0;
    }

    if (EVP_PKEY_decrypt_init_ex(ctx, NULL) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT_INIT_EX);
        return 0;
    }

    if ((padding_mode_ = cw_fetch_rsa_padding_mode_internal(padding_mode)) == 0)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding_mode_) <= 0)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING);
        return 0;
    }

    if (padding_mode_ == RSA_PKCS1_OAEP_PADDING)
    {
        switch (padding_mode)
        {
        case CW_RSA_PKCS1_OAEP_SHA1_PADDING:
            md_id = SN_sha1;
            break;

        case CW_RSA_PKCS1_OAEP_SHA224_PADDING:
            md_id = SN_sha224;
            break;

        case CW_RSA_PKCS1_OAEP_SHA256_PADDING:
            md_id = SN_sha256;
            break;

        case CW_RSA_PKCS1_OAEP_SHA512_PADDING:
            md_id = SN_sha512;
            break;

        // This can never be reached
        default:
            md_id = SN_sha256;
            break;
        }

        if ((md = EVP_MD_fetch(NULL, md_id, NULL)) == NULL)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_FETCH_EVP_MD_fetch);
            return 0;
        }

        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_OAEP_MD);
            return 0;
        }
    }

    if (EVP_PKEY_decrypt(ctx, NULL, &plaintext_len_internal, ciphertext, ciphertext_len) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_DECRYPT);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
    {
        if ((*plaintext = OPENSSL_zalloc(plaintext_len_internal)) == NULL)
        {
            RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_PKEY_decrypt(ctx, *plaintext, &plaintext_len_internal, ciphertext, ciphertext_len) != 1)
    {
        RSA_CRYPT_CLEANUP(ctx, md, *plaintext, plaintext_len_internal, flags);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_DECRYPT);
        return 0;
    }

    // This does not cleanup plaintext
    RSA_CRYPT_CLEANUP(ctx, md, *plaintext, 0, 0);

    if (plaintext_len != NULL)
        *plaintext_len = plaintext_len_internal;

    return 1;
}
