/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/ecc.h"

#include "internal/fetching.h"
#include "internal/ecc_internal.h"
#include "internal/error/error_internal.h"

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

int cw_ecc_generate_key_pair(ECC_KEY_PAIR *key_pair, cw_elliptic_curve_type curve_type)
{
    if (key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    *key_pair = NULL;

    EVP_PKEY_CTX *ctx = NULL;
    int curve_nid = 0;

    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_PKEY_CTX_NEW_ID);
        return 0;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_PKEY_KEYGEN_INIT);
        return 0;
    }

    // Get curve id
    if ((curve_nid = cw_fetch_ec_curve_nid_internal(curve_type)) == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID);
        return 0;
    }

    if (EVP_PKEY_generate(ctx, (EVP_PKEY **)key_pair) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_EVP_PKEY_GENERATE);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

void cw_ecc_delete_key_pair(ECC_KEY_PAIR key_pair)
{
    if (key_pair != NULL)
        EVP_PKEY_free((EVP_PKEY *)key_pair);
}

int cw_ecc_write_public_key(const char *file_path, ECC_KEY_PAIR key_pair, cw_ecc_serialization_type serialization_mode)
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

    ret = cw_ecc_write_key_internal(fp, (EVP_PKEY *)key_pair, NULL, serialization_mode, ECC_PUBLIC_KEY);

    fclose(fp);
    return ret;
}
int cw_ecc_write_public_key_fp(FILE *fp, ECC_KEY_PAIR key_pair, cw_ecc_serialization_type serialization_mode)
{
    return cw_ecc_write_key_internal(fp, (EVP_PKEY *)key_pair, NULL, serialization_mode, ECC_PUBLIC_KEY);
}

int cw_ecc_write_private_key(const char *file_path, ECC_KEY_PAIR key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode)
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

    ret = cw_ecc_write_key_internal(fp, (EVP_PKEY *)key_pair, passphrase, serialization_mode, ECC_PRIVATE_KEY);

    fclose(fp);
    return ret;
}
int cw_ecc_write_private_key_fp(FILE *fp, ECC_KEY_PAIR key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode)
{
    return cw_ecc_write_key_internal(fp, (EVP_PKEY *)key_pair, passphrase, serialization_mode, ECC_PRIVATE_KEY);
}

int cw_ecc_load_public_key(const char *file_path, ECC_KEY_PAIR *key_pair, cw_ecc_serialization_type serialization_mode)
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

    ret = cw_ecc_load_key_internal(fp, NULL, serialization_mode, (EVP_PKEY **)key_pair, ECC_PUBLIC_KEY);

    fclose(fp);
    return ret;
}
int cw_ecc_load_public_key_fp(FILE *fp, ECC_KEY_PAIR *key_pair, cw_ecc_serialization_type serialization_mode)
{
    return cw_ecc_load_key_internal(fp, NULL, serialization_mode, (EVP_PKEY **)key_pair, ECC_PUBLIC_KEY);
}

int cw_ecc_load_private_key(const char *file_path, ECC_KEY_PAIR *key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode)
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

    ret = cw_ecc_load_key_internal(fp, passphrase, serialization_mode, (EVP_PKEY **)key_pair, ECC_PRIVATE_KEY);

    fclose(fp);
    return ret;
}

int cw_ecc_load_private_key_fp(FILE *fp, ECC_KEY_PAIR *key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode)
{
    return cw_ecc_load_key_internal(fp, passphrase, serialization_mode, (EVP_PKEY **)key_pair, ECC_PRIVATE_KEY);
}

int cw_ecc_sign_bytes(ECC_KEY_PAIR key_pair, const uint8_t *input, const uint64_t message_len,
                     cw_ecc_signature_hash hash_algorithm, uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    return cw_ecc_sign_bytes_internal((EVP_PKEY *)key_pair, input, message_len, hash_algorithm, signature, signature_len, flags);
}

int cw_ecc_sign_string(ECC_KEY_PAIR key_pair, const char *input, cw_ecc_signature_hash hash_algorithm, uint8_t **signature, uint64_t *signature_len, const uint8_t flags)
{
    if (input == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint64_t in_len = strlen(input);

    if (in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_SIGN_MESSAGE_TO_SHORT);
        return 0;
    }

    return cw_ecc_sign_bytes_internal((EVP_PKEY *)key_pair, (const uint8_t *)input, in_len, hash_algorithm, signature, signature_len, flags);
}

int cw_ecc_verify_bytes(ECC_KEY_PAIR key_pair, const uint8_t *input, const uint64_t message_len,
                       uint8_t *signature, const uint64_t signature_len, cw_ecc_signature_hash hash_algorithm)
{
    return cw_ecc_verify_signature_internal((EVP_PKEY *)key_pair, input, message_len, signature, signature_len, hash_algorithm);
}

int cw_ecc_verify_string(ECC_KEY_PAIR key_pair, const char *input, uint8_t *signature, const uint64_t signature_len, cw_ecc_signature_hash hash_algorithm)
{
    if (input == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint64_t in_len = strlen(input);

    if (in_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ECC_VERIFY_MESSAGE_TO_SHORT);
        return 0;
    }

    return cw_ecc_verify_signature_internal((EVP_PKEY *)key_pair, (const uint8_t *)input, in_len, signature, signature_len, hash_algorithm);
}