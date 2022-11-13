/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/ecc_internal.h"
#include "internal/hash_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <string.h>

void cw_ecc_encoder_cleanup_internal(OSSL_ENCODER_CTX *encoder, OSSL_DECODER_CTX *decoder)
{
    if (encoder != NULL)
        OSSL_ENCODER_CTX_free(encoder);

    if (decoder != NULL)
        OSSL_DECODER_CTX_free(decoder);
}

int cw_ecc_write_key_internal(FILE *fp, EVP_PKEY *pkey, const char *passphrase, cw_ecc_serialization_type output_type, int key_type)
{
    if (fp == NULL || pkey == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    const char *output_type_str = NULL;
    OSSL_ENCODER_CTX *ctx = NULL;

    if ((output_type_str = cw_fetch_ec_serialization_type_str_internal(output_type)) == NULL)
        return 0;

    if ((ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, (key_type == ECC_PRIVATE_KEY) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                                             output_type_str, (key_type == ECC_PRIVATE_KEY) ? "PrivateKeyInfo" : "SubjectPublicKeyInfo", NULL)) == NULL)
    {
        cw_ecc_encoder_cleanup_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_NEW_FOR_PKEY);
        return 0;
    }

    if (passphrase != NULL && EC_IS_DER(output_type))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_DER_PASSPHRASE_NOT_ALLOWED);
        return 0;
    }

    if (passphrase != NULL && key_type == ECC_PRIVATE_KEY)
    {
        if (OSSL_ENCODER_CTX_set_cipher(ctx, "AES-256-CBC", NULL) == 0)
        {
            cw_ecc_encoder_cleanup_internal(ctx, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_CIPHER);
            return 0;
        }

        if (OSSL_ENCODER_CTX_set_passphrase(ctx, (const unsigned char *)passphrase, strlen(passphrase)) == 0)
        {
            cw_ecc_encoder_cleanup_internal(ctx, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_PASSPHRASE);
            return 0;
        }
    }

    if (OSSL_ENCODER_to_fp(ctx, fp) == 0)
    {
        cw_ecc_encoder_cleanup_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_ENCODER_TO_FP);
        return 0;
    }

    cw_ecc_encoder_cleanup_internal(ctx, NULL);

    return 1;
}

int cw_ecc_load_key_internal(FILE *fp, const char *passphrase, cw_ecc_serialization_type output_type, EVP_PKEY **pkey, int key_type)
{
    if (fp == NULL || pkey == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    OSSL_DECODER_CTX *ctx = NULL;
    const char *input_type_str = NULL;

    if ((input_type_str = cw_fetch_ec_serialization_type_str_internal(output_type)) == NULL)
        return 0;

    if ((ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, input_type_str, NULL, NULL, (key_type == ECC_PRIVATE_KEY) ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, NULL, NULL)) == NULL)
    {
        cw_ecc_encoder_cleanup_internal(NULL, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_DECODER_CTX_NEW_FOR_PKEY);
        return 0;
    }

    if (passphrase != NULL && EC_IS_DER(output_type))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_DER_PASSPHRASE_NOT_ALLOWED);
        return 0;
    }

    if (passphrase != NULL && key_type == ECC_PRIVATE_KEY)
    {
        if (OSSL_DECODER_CTX_set_passphrase(ctx, (const unsigned char *)passphrase, strlen(passphrase)) == 0)
        {
            cw_ecc_encoder_cleanup_internal(NULL, ctx);
            CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_DECODER_CTX_SET_PASSPHRASE);
            return 0;
        }
    }

    if (OSSL_DECODER_from_fp(ctx, fp) == 0)
    {
        cw_ecc_encoder_cleanup_internal(NULL, ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_OSSL_DECODER_FROM_FP);
        return 0;
    }

    cw_ecc_encoder_cleanup_internal(NULL, ctx);

    return 1;
}

int cw_ecc_sign_bytes_internal(EVP_PKEY *pkey, const uint8_t *in, const uint64_t in_len, cw_ecc_signature_hash hash,
                               uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    if (pkey == NULL || in == NULL || in_len == 0 || signature == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & ECC_NO_ALLOC))
        *signature = NULL;

    EVP_MD_CTX *ctx = NULL;
    char *mdname = NULL;

    uint64_t signature_len_intern = 0;

    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_MD_CTX_NEW);
        return 0;
    }

    if ((mdname = cw_fetch_ec_signature_str_internal(hash)) == NULL)
        return 0;

    if (EVP_DigestSignInit_ex(ctx, NULL, mdname, NULL, NULL, pkey, NULL) != 1)
    {
        cw_cleanup_message_digest_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_INIT_EX);
        return 0;
    }

    if (EVP_DigestSignUpdate(ctx, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_UPDATE);
        return 0;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &signature_len_intern) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_FINAL);
        return 0;
    }

    if (!(flags & ECC_NO_ALLOC))
    {
        if ((*signature = OPENSSL_zalloc(signature_len_intern)) == NULL)
        {
            cw_cleanup_message_digest_internal(ctx, NULL);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if (EVP_DigestSignFinal(ctx, *signature, &signature_len_intern) != 1)
    {
        OPENSSL_free(*signature);
        cw_cleanup_message_digest_internal(ctx, NULL);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_FINAL);
        return 0;
    }

    if (signature_len != NULL)
        *signature_len = signature_len_intern;

    cw_cleanup_message_digest_internal(ctx, NULL);

    return 1;
}

int cw_ecc_verify_signature_internal(EVP_PKEY *pkey, const uint8_t *in, const uint64_t in_len,
                                     uint8_t *signature, const uint64_t signature_len, cw_ecc_signature_hash hash)
{
    if (pkey == NULL || in == NULL || in_len == 0 || signature == NULL || signature_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MD_CTX *ctx = NULL;
    char *mdname = NULL;

    if ((ctx = EVP_MD_CTX_new()) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_MD_CTX_NEW);
        return 0;
    }

    if ((mdname = cw_fetch_ec_signature_str_internal(hash)) == NULL)
        return 0;

    if (EVP_DigestVerifyInit_ex(ctx, NULL, mdname, NULL, NULL, pkey, NULL) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_INIT_EX);
        return 0;
    }

    if (EVP_DigestVerifyUpdate(ctx, in, in_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_UPDATE);
        return 0;
    }

    if (EVP_DigestVerifyFinal(ctx, signature, signature_len) != 1)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_FINAL);
        return 0;
    }

    cw_cleanup_message_digest_internal(ctx, NULL);

    return 1;
}