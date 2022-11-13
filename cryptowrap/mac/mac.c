/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/mac.h"
#include "internal/mac_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/obj_mac.h>

int cw_hmac_raw(const uint8_t *in, const uint64_t in_len,
                const uint8_t *key, const uint32_t key_len,
                uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    return cw_hmac_raw_ex(in, in_len, key, key_len, HMAC_STANDARD_DIGEST, out, out_len, flags);
}

int cw_hmac_raw_ex(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_hmac_digest algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (in == NULL || in_len == 0 || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_hmac_digest = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((cw_hmac_digest = cw_fetch_hmac_internal_internal(algorithm_id)) == NULL)
        return 0;

    if ((mac = EVP_MAC_fetch(NULL, SN_hmac, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, cw_hmac_digest, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_internal(ctx, in, in_len, out, out_len, flags) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        return 0;
    }

    MAC_CLEANUP(ctx, mac, params);

    return 1;
}

int cw_hmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_hmac_digest algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (file_path == NULL || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_hmac_digest = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    FILE *fp = NULL;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    if ((cw_hmac_digest = cw_fetch_hmac_internal_internal(algorithm_id)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, SN_hmac, NULL)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, cw_hmac_digest, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_file_internal(ctx, fp, out, out_len, flags) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    MAC_FILE_CLEANUP(ctx, mac, params, fp);

    return 1;
}

int cw_hmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_hmac_digest algorithm_id)
{
    if (in == NULL || in_len == 0 || mac == NULL || mac_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *compare_mac;

    // Set given mac length since mac could be of custom length
    uint64_t compare_mac_size = mac_len;

    if (cw_hmac_raw_ex(in, in_len, key, key_len, algorithm_id, &compare_mac, &compare_mac_size, MAC_SET_OUT_LEN) != 1)
        return 0;

    if (compare_mac_size != mac_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH);
        return 0;
    }
    if (CRYPTO_memcmp(mac, compare_mac, mac_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH);
        return 0;
    }

    OPENSSL_clear_free(compare_mac, compare_mac_size);

    return 1;
}

int cw_cmac_raw(const uint8_t *in, const uint64_t in_len,
                const uint8_t *key, const uint32_t key_len,
                uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    return cw_cmac_raw_ex(in, in_len, key, key_len, CMAC_STANDARD_CIPHER, out, out_len, flags);
}

int cw_cmac_raw_ex(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_cmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (in == NULL || in_len == 0 || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_cmac_cipher = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((cw_cmac_cipher = cw_fetch_symmetric_cipher_str_internal((cw_symmetric_cipher_algorithm) algorithm_id)) == NULL)
        return 0;

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_CMAC, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_cmac_cipher, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_internal(ctx, in, in_len, out, out_len, flags) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        return 0;
    }

    MAC_CLEANUP(ctx, mac, params);

    return 1;
}

int cw_cmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_cmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (file_path == NULL || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_cmac_cipher = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    FILE *fp = NULL;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    if ((cw_cmac_cipher = cw_fetch_symmetric_cipher_str_internal((cw_symmetric_cipher_algorithm) algorithm_id)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_CMAC, NULL)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_cmac_cipher, 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_file_internal(ctx, fp, out, out_len, flags) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    MAC_FILE_CLEANUP(ctx, mac, params, fp);

    return 1;
}

int cw_cmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_cmac_cipher algorithm_id)
{
    if (in == NULL || in_len == 0 || mac == NULL || mac_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *compare_mac;

    // Set given mac length since mac could be of custom length
    uint64_t compare_mac_size = mac_len;

    if (cw_cmac_raw_ex(in, in_len, key, key_len, algorithm_id, &compare_mac, &compare_mac_size, MAC_SET_OUT_LEN) != 1)
        return 0;

    if (compare_mac_size != mac_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH);
        return 0;
    }
    if (CRYPTO_memcmp(mac, compare_mac, mac_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH);
        return 0;
    }

    OPENSSL_clear_free(compare_mac, compare_mac_size);

    return 1;
}

int cw_gmac(const uint8_t *in, const uint64_t in_len,
            const uint8_t *key, const uint32_t key_len,
            uint8_t *iv, const uint32_t iv_len,
            uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    return cw_gmac_raw_ex(in, in_len, key, key_len, iv, iv_len, GMAC_STANDARD_CIPHER, out, out_len, flags);
}

int cw_gmac_raw_ex(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   uint8_t *iv, const uint32_t iv_len,
                   cw_gmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (in == NULL || in_len == 0 || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_gmac_cipher = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    if ((cw_gmac_cipher = cw_fetch_gmac_internal(algorithm_id)) == NULL)
        return 0;

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_GMAC, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_gmac_cipher, 0);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, iv, iv_len);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_internal(ctx, in, in_len, out, out_len, flags) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        return 0;
    }

    MAC_CLEANUP(ctx, mac, params);

    return 1;
}

int cw_gmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    uint8_t *iv, const uint32_t iv_len,
                    cw_gmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (file_path == NULL || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char *cw_gmac_cipher = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    FILE *fp = NULL;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    if ((cw_gmac_cipher = cw_fetch_gmac_internal(algorithm_id)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_GMAC, NULL)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cw_gmac_cipher, 0);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, iv, iv_len);
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    if (cw_mac_process_file_internal(ctx, fp, out, out_len, flags) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    MAC_FILE_CLEANUP(ctx, mac, params, fp);

    return 1;
}

int cw_gmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   uint8_t *iv, uint32_t iv_len,
                   cw_gmac_cipher algorithm_id)
{
    if (in == NULL || in_len == 0 || mac == NULL || mac_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }
    uint8_t *compare_mac;

    // Set given mac length since mac could be of custom length
    uint64_t compare_mac_size = mac_len;

    if (cw_gmac_raw_ex(in, in_len, key, key_len, iv, iv_len, algorithm_id, &compare_mac, &compare_mac_size, MAC_SET_OUT_LEN) != 1)
        return 0;

    if (compare_mac_size != mac_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH);
        return 0;
    }
    if (CRYPTO_memcmp(mac, compare_mac, mac_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH);
        return 0;
    }

    OPENSSL_clear_free(compare_mac, compare_mac_size);

    return 1;
}

int cw_siphash_raw(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    return cw_siphash_raw_ex(in, in_len, key, key_len, SIPHASH_COMPRESSION_ROUNDS, SIPHASH_FINALIZATION_ROUNDS, out, out_len, flags);
}

int cw_siphash_raw_ex(const uint8_t *in, const uint64_t in_len,
                      const uint8_t *key, const uint32_t key_len,
                      uint32_t c_compression_rounds, uint32_t d_finalization_rounds,
                      uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    if (in == NULL || in_len == 0 || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    // Variable to contain the size in uint64_t format required for calling cw_mac_process_internal
    uint64_t temp_size;

    // Check if key size is equal to 16
    if (key_len != SIPHASH_REQUIRED_KEY_SIZE)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_SIPHASH_WRONG_KEY_LENGTH);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_SIPHASH, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    if (flags & MAC_SET_OUT_LEN)
    {
        // 8 and 16 are the only allowed output sizes
        if (*out_len != 8 && *out_len != 16)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_MAC_SIPHASH_WRONG_OUTPUT_LENGTH);
            return 0;
        }
        *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, out_len);
    }

    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c_compression_rounds);
    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d_finalization_rounds);

    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    temp_size = *out_len;

    if (cw_mac_process_internal(ctx, in, in_len, out, &temp_size, flags) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        return 0;
    }

    // Overflow will not occur since cw_mac_process_internal does not raise temp_size
    *out_len = temp_size;

    MAC_CLEANUP(ctx, mac, params);

    return 1;
}

int cw_siphash_file_ex(const char *file_path,
                       const uint8_t *key, const uint32_t key_len,
                       uint32_t c_compression_rounds, uint32_t d_finalization_rounds,
                       uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    if (file_path == NULL || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    // Variable to contain the size in uint64_t format required for calling cw_mac_process_internal
    uint64_t temp_size;

    FILE *fp = NULL;

    // Check if key size is equal to 16
    if (key_len != SIPHASH_REQUIRED_KEY_SIZE)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_SIPHASH_WRONG_KEY_LENGTH);
        return 0;
    }

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_SIPHASH, NULL)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    if (flags & MAC_SET_OUT_LEN)
    {
        // 8 and 16 are the only allowed output sizes
        if (*out_len != 8 && *out_len != 16)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_MAC_SIPHASH_WRONG_OUTPUT_LENGTH);
            return 0;
        }
        *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, out_len);
    }

    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_C_ROUNDS, &c_compression_rounds);
    *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_D_ROUNDS, &d_finalization_rounds);

    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    temp_size = *out_len;

    if (cw_mac_process_file_internal(ctx, fp, out, &temp_size, flags) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    // Overflow will not occur since CW_mac_file_process_internal does not raise temp_size
    *out_len = temp_size;

    MAC_FILE_CLEANUP(ctx, mac, params, fp);

    return 1;
}

int cw_siphash_verify(const uint8_t *in, const uint64_t in_len,
                      const uint8_t *mac, const uint32_t mac_len,
                      const uint8_t *key, const uint32_t key_len,
                      uint32_t c_compression_rounds, uint32_t d_finalization_rounds)
{
    if (in == NULL || in_len == 0 || mac == NULL || mac_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *compare_mac;

    // Set given mac length since mac could be of custom length
    uint32_t compare_mac_size = mac_len;

    if (cw_siphash_raw_ex(in, in_len, key, key_len, c_compression_rounds, d_finalization_rounds, &compare_mac, &compare_mac_size, MAC_SET_OUT_LEN) != 1)
        return 0;

    if (compare_mac_size != mac_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH);
        return 0;
    }
    if (CRYPTO_memcmp(mac, compare_mac, mac_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH);
        return 0;
    }

    OPENSSL_clear_free(compare_mac, compare_mac_size);

    return 1;
}

int cw_kmac_raw(const uint8_t *in, const uint64_t in_len,
                const uint8_t *key, const uint32_t key_len,
                uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    return cw_kmac_raw_ex(in, in_len, key, key_len, KMAC_STANDARD_MODE, NULL, 0, out, out_len, flags);
}

int cw_kmac_raw_ex(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_kmac_mode algorithm_id, uint8_t *custom_value, const uint32_t custom_value_len,
                   uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    if (in == NULL || in_len == 0 || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    char *cw_kmac_mode = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    // Variable to contain the size in uint64_t format required for calling cw_mac_process_internal
    uint64_t temp_size;

    if ((cw_kmac_mode = cw_fetch_kmac_internal(algorithm_id)) == NULL)
        return 0;

    if ((mac = EVP_MAC_fetch(NULL, cw_kmac_mode, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    if (flags & MAC_SET_OUT_LEN)
    {
        *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, out_len);
    }

    if (custom_value != NULL || custom_value_len > 0)
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)custom_value, custom_value_len);
    }
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    temp_size = *out_len;

    if (cw_mac_process_internal(ctx, in, in_len, out, &temp_size, flags) != 1)
    {
        MAC_CLEANUP(ctx, mac, params);
        return 0;
    }

    // Overflow will not occur since cw_mac_process_internal does not raise temp_size
    *out_len = temp_size;

    MAC_CLEANUP(ctx, mac, params);

    return 1;
}

int cw_kmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_kmac_mode algorithm_id, uint8_t *custom_value, const uint32_t custom_value_len,
                    uint8_t **out, uint32_t *out_len, const uint8_t flags)
{
    if (file_path == NULL || key == NULL || key_len == 0 || out == NULL || out_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    char *cw_kmac_mode = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    // Variable to contain the size in uint64_t format required for calling cw_mac_process_internal
    uint64_t temp_size;

    FILE *fp = NULL;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FILE_COULD_NOT_OPEN);
        return 0;
    }

    if ((cw_kmac_mode = cw_fetch_kmac_internal(algorithm_id)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    if ((mac = EVP_MAC_fetch(NULL, cw_kmac_mode, NULL)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_FETCH);
        return 0;
    }

    if ((ctx = EVP_MAC_CTX_new(mac)) == NULL)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW);
        return 0;
    }

    if (flags & MAC_SET_OUT_LEN)
    {
        *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, out_len);
    }

    if (custom_value != NULL || custom_value_len > 0)
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, (void *)custom_value, custom_value_len);
    }
    *p = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT);
        return 0;
    }

    temp_size = *out_len;

    if (cw_mac_process_file_internal(ctx, fp, out, &temp_size, flags) != 1)
    {
        MAC_FILE_CLEANUP(ctx, mac, params, fp);
        return 0;
    }

    // Overflow will not occur since cw_mac_process_internal does not raise temp_size
    *out_len = temp_size;

    MAC_FILE_CLEANUP(ctx, mac, params, fp);

    return 1;
}

int cw_kmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint32_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   uint8_t *custom_value, const uint32_t custom_value_len, cw_kmac_mode algorithm_id)
{
    if (in == NULL || in_len == 0 || mac == NULL || mac_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *compare_mac;

    // Set given mac length since mac could be of custom length
    uint32_t compare_mac_size = mac_len;

    if (cw_kmac_raw_ex(in, in_len, key, key_len, algorithm_id, custom_value, custom_value_len, &compare_mac, &compare_mac_size, MAC_SET_OUT_LEN) != 1)
        return 0;

    if (compare_mac_size != mac_len)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH);
        return 0;
    }
    if (CRYPTO_memcmp(mac, compare_mac, mac_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH);
        return 0;
    }

    OPENSSL_clear_free(compare_mac, compare_mac_size);

    return 1;
}