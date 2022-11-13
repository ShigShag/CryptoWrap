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
#include <openssl/obj_mac.h>

void cw_rsa_encoder_cleanup_internal(OSSL_ENCODER_CTX *encoder, OSSL_DECODER_CTX *decoder)
{
    if (encoder != NULL)
        OSSL_ENCODER_CTX_free(encoder);

    if (decoder != NULL)
        OSSL_DECODER_CTX_free(decoder);
}

int cw_rsa_write_key_internal(FILE *fp, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type output_type, int key_type)
{
    if (fp == NULL || key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    const char *output_type_str = NULL;
    OSSL_ENCODER_CTX *ctx = NULL;

    if ((output_type_str = cw_fetch_rsa_serialization_type_internal(output_type)) == NULL)
        return 0;

    if ((ctx = OSSL_ENCODER_CTX_new_for_pkey((EVP_PKEY *)key_pair, (key_type == RSA_PRIVATE_KEY) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                                             output_type_str, (key_type == RSA_PRIVATE_KEY) ? "PrivateKeyInfo" : "SubjectPublicKeyInfo", NULL)) == NULL)
    {
        cw_rsa_encoder_cleanup_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_NEW_FOR_PKEY);
        return 0;
    }

    if (passphrase != NULL && RSA_IS_DER(output_type))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_DER_PASSPHRASE_NOT_ALLOWED);
        return 0;
    }

    if (passphrase != NULL && key_type == RSA_PRIVATE_KEY)
    {
        if (OSSL_ENCODER_CTX_set_cipher(ctx, SN_aes_256_cbc, NULL) == 0)
        {
            cw_rsa_encoder_cleanup_internal(ctx, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_CIPHER);
            return 0;
        }

        if (OSSL_ENCODER_CTX_set_passphrase(ctx, (const uint8_t *)passphrase, strlen(passphrase)) == 0)
        {
            cw_rsa_encoder_cleanup_internal(ctx, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_PASSPHRASE);
            return 0;
        }
    }

    if (OSSL_ENCODER_to_fp(ctx, fp) == 0)
    {
        cw_rsa_encoder_cleanup_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_ENCODER_TO_FP);
        return 0;
    }

    cw_rsa_encoder_cleanup_internal(ctx, NULL);

    return 1;
}

int cw_rsa_load_key_internal(FILE *fp, const char *passphrase, const char output_type, CW_RSA_KEY_PAIR *key_pair, int key_type)
{
    if (fp == NULL || key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    OSSL_DECODER_CTX *ctx = NULL;
    const char *input_type_str = NULL;

    if ((input_type_str = cw_fetch_rsa_serialization_type_internal(output_type)) == NULL)
        return 0;

    if ((ctx = OSSL_DECODER_CTX_new_for_pkey((EVP_PKEY **)key_pair, input_type_str, NULL, NULL, (key_type == RSA_PRIVATE_KEY) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                                             NULL, NULL)) == NULL)
    {
        cw_rsa_encoder_cleanup_internal(NULL, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_DECODER_CTX_NEW_FOR_PKEY);
        return 0;
    }

    if (passphrase != NULL && RSA_IS_DER(output_type))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_DER_PASSPHRASE_NOT_ALLOWED);
        return 0;
    }

    if (passphrase != NULL && key_type == RSA_PRIVATE_KEY)
    {
        if (OSSL_DECODER_CTX_set_passphrase(ctx, (const uint8_t *)passphrase, strlen(passphrase)) == 0)
        {
            cw_rsa_encoder_cleanup_internal(NULL, ctx);
            CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_DECODER_CTX_SET_PASSPHRASE);
            return 0;
        }
    }

    if (OSSL_DECODER_from_fp(ctx, fp) == 0)
    {
        cw_rsa_encoder_cleanup_internal(NULL, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_OSSL_OSSL_DECODER_FROM_FP);
        return 0;
    }

    cw_rsa_encoder_cleanup_internal(NULL, ctx);

    return 1;
}

int cw_rsa_sign_bytes_internal(CW_RSA_KEY_PAIR key_pair, const void *in, const uint32_t in_len, cw_rsa_signature_hash hash, int padding_mode,
                               uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    if (key_pair == NULL || in == NULL || in_len == 0 || signature == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
        *signature = NULL;

    EVP_MD_CTX *ctx = NULL;

    // Does not need to be freed
    EVP_PKEY_CTX *pkey_ctx = NULL;
    char *mdname = NULL;
    int padding_mode_ = 0;

    uint64_t signature_size_internal = 0;

    if ((mdname = cw_fetch_hash_str_internal((hash_algorithm)hash)) == NULL)
        return 0;

    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_MD_CTX_NEW);
        return 0;
    }

    if ((padding_mode_ = cw_fetch_rsa_padding_mode_internal(padding_mode)) == 0)
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestSignInit_ex(ctx, &pkey_ctx, mdname, NULL, NULL, (EVP_PKEY *)key_pair, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_INIT_EX);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode_) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING);
        return 0;
    }

    if (EVP_DigestSignUpdate(ctx, in, in_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_UPDATE);
        return 0;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &signature_size_internal) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_FINAL);
        return 0;
    }

    if (!(flags & RSA_NO_ALLOC))
    {
        if ((*signature = OPENSSL_zalloc(signature_size_internal)) == NULL)
        {
            EVP_MD_CTX_free(ctx);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_DigestSignFinal(ctx, *signature, &signature_size_internal) != 1)
    {
        if (!(flags & RSA_NO_ALLOC))
        {
            OPENSSL_free(*signature);
            *signature = NULL;
        }
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_FINAL);
        return 0;
    }

    EVP_MD_CTX_free(ctx);

    if (signature_len != NULL)
        *signature_len = signature_size_internal;

    return 1;
}
int cw_rsa_verify_signature_internal(CW_RSA_KEY_PAIR key_pair, const void *in, const uint32_t in_len,
                                     const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, int padding_mode)
{
    if (key_pair == NULL || in == NULL || in_len == 0 || signature == NULL || signature_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MD_CTX *ctx = NULL;
    char *mdname = NULL;

    // Does not need to be freed
    EVP_PKEY_CTX *pkey_ctx = NULL;

    int padding_mode_;

    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_MD_CTX_NEW);
        return 0;
    }

    if ((mdname = cw_fetch_hash_str_internal((hash_algorithm)hash)) == NULL)
        return 0;

    if ((padding_mode_ = cw_fetch_rsa_padding_mode_internal(padding_mode)) == 0)
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    if (EVP_DigestVerifyInit_ex(ctx, &pkey_ctx, mdname, NULL, NULL, (EVP_PKEY *)key_pair, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_INIT_EX);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_mode_) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING);
        return 0;
    }

    if (EVP_DigestVerifyUpdate(ctx, in, in_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_UPDATE);
        return 0;
    }

    if (EVP_DigestVerifyFinal(ctx, signature, signature_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_FINAL);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

void cw_rsa_crypt_bytes_cleanup_internal(EVP_PKEY_CTX *ctx, EVP_MD *md)
{
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    if (md != NULL)
        EVP_MD_free(md);
}