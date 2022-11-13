/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/key_derivation_internal.h"
#include "internal/helper.h"
#include "internal/error/error_internal.h"
#include "internal/fetching.h"

#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>
#include <string.h>

int cw_pbkdf2(uint8_t *password, const uint64_t password_len,
              uint8_t *salt, const uint64_t salt_len,
              uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    return cw_pbkdf2_ex(password, password_len, salt, salt_len, PBKDF2_DEFAULT_ITERATIONS, KDF_DEFAULT_ALGORITHM, out, out_len, flags);
}

int cw_pbkdf2_ex(uint8_t *password, const uint64_t password_len,
                 uint8_t *salt, const uint64_t salt_len,
                 uint32_t iterations, key_derivation_hash algorithm_id,
                 uint8_t **out, uint64_t *out_len, const uint8_t flags)
{
    if (password == NULL || password_len == 0 || salt == NULL || salt_len == 0 || iterations == 0 || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;

    char *digest = NULL;

    if ((digest = cw_fetch_hash_str_internal((hash_algorithm)algorithm_id)) == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    *p = OSSL_PARAM_construct_end();

    int ret = cw_kdf_derive_internal(LN_id_pbkdf2, algorithm_id, params, out, out_len, flags);

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return ret;
}

int cw_pbkdf2_verify(const uint8_t *key, const uint64_t key_len,
                     uint8_t *password, const uint64_t password_len,
                     uint8_t *salt, const uint64_t salt_len,
                     uint32_t iterations, key_derivation_hash algorithm_id)
{
    if (key == NULL || key_len == 0 || password == NULL || password_len == 0 || salt == NULL || salt_len == 0 || iterations == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *out_key = NULL;
    uint64_t out_key_len = key_len;
    int verification_success = 0;

    if (cw_pbkdf2_ex(password, password_len, salt, salt_len, iterations, algorithm_id, &out_key, &out_key_len, KEY_DERIVATION_SET_OUTPUT_LEN) != 1)
    {
        goto END;
    }

    if (out_key_len != key_len || CRYPTO_memcmp(out_key, key, out_key_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_PBKDF2_VERIFY);
        goto END;
    }

    verification_success = 1;

END:
    if (out_key != NULL)
        OPENSSL_clear_free(out_key, key_len);

    return verification_success;
}

int cw_hkdf(uint8_t *password, const uint64_t password_len,
            uint8_t *salt, const uint64_t salt_len,
            key_derivation_hash algorithm_id,
            uint8_t **out, uint64_t out_len, const uint8_t flags)
{
    return cw_hkdf_ex(password, password_len, salt, salt_len, NULL, 0, algorithm_id, out, out_len, flags);
}

// https://datatracker.ietf.org/doc/html/rfc5869
int cw_hkdf_ex(uint8_t *password, const uint64_t password_len,
               uint8_t *salt, const uint64_t salt_len,
               uint8_t *info, const uint32_t info_size,
               key_derivation_hash algorithm_id,
               uint8_t **out, uint64_t out_len, const uint8_t flags)
{
    // if (password == NULL || password_len == 0 || salt == NULL || salt_len == 0 || out == NULL)
    if (password == NULL || password_len == 0 || out == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;

    char *digest = NULL;

    if ((digest = cw_fetch_hash_str_internal((hash_algorithm)algorithm_id)) == NULL)
        return 0;

    // Check outlen
    if (out_len > ((uint64_t)cw_fetch_hash_len_internal((hash_algorithm)algorithm_id) * 255))
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_HKDF_WRONG_OUTPUT_LEN);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, password, password_len);

    if (salt != NULL && salt_len > 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);

    if (info != NULL && info_size <= 1024 && info_size > 0)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_size);
    *p = OSSL_PARAM_construct_end();

    int ret = cw_kdf_derive_internal(SN_hkdf, algorithm_id, params, out, &out_len, flags | KDF_FIXED_OUTPUT_SIZE);

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return ret;
}

int cw_hkdf_verify(const uint8_t *key, const uint64_t key_len,
                   uint8_t *password, const uint64_t password_len,
                   uint8_t *salt, const uint64_t salt_len,
                   uint8_t *info, const uint32_t info_size,
                   key_derivation_hash algorithm_id)
{
    if (key == NULL || key_len == 0 || password == NULL || password_len == 0 || salt == NULL || salt_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *out_key = NULL;
    int verification_success = 0;

    if (cw_hkdf_ex(password, password_len, salt, salt_len, info, info_size, algorithm_id, &out_key, key_len, 0) != 1)
    {
        goto END;
    }

    if (CRYPTO_memcmp(out_key, key, key_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_HKDF_VERIFY);
        goto END;
    }
    verification_success = 1;

END:
    if (out_key != NULL)
        OPENSSL_clear_free(out_key, key_len);

    return verification_success;
}

int cw_scrypt(uint8_t *password, const uint64_t password_len,
              uint8_t *salt, const uint64_t salt_len,
              uint8_t **out, uint64_t out_len, const uint8_t flags)
{
    return cw_scrypt_ex(password, password_len, salt, salt_len, SCRYPT_DEFAULT_N, SCRYPT_DEFAULT_R, SCRYPT_DEFAULT_P, out, out_len, flags);
}
int cw_scrypt_ex(uint8_t *password, const uint64_t password_len,
                 uint8_t *salt, const uint64_t salt_len,
                 uint32_t N_cost, uint32_t r_blockSize, uint32_t p_parallelization,
                 uint8_t **out, uint64_t out_len, const uint8_t flags)
{
    if (password == NULL || password_len == 0 || salt == NULL || salt_len == 0 || out == NULL || out_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    OSSL_PARAM params[6];
    OSSL_PARAM *p = params;

    // https://www.rfc-editor.org/rfc/rfc7914.html#page-3

    // Testing n and p max size limited due to overflow problems
    if (N_cost <= 1 || N_cost % 2 != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_SCRYPT_N_NOT_VALID);
        return 0;
    }

    if (out_len > (cw_uint64_t_to_the_power(2, 32) - 1) * 32)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_SCRYPT_OUPUT_SIZE_TOO_LARGE);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_N, &N_cost);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_R, &r_blockSize);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_P, &p_parallelization);
    *p = OSSL_PARAM_construct_end();

    int ret = cw_kdf_derive_internal(LN_id_scrypt, 0, params, out, &out_len, flags | KDF_FIXED_OUTPUT_SIZE);

    CW_HELPER_CLEAR_PARAMS_INTERNAL(params);

    return ret;
}

int cw_scrypt_verify(const uint8_t *key, const uint64_t key_len,
                     uint8_t *password, const uint64_t password_len,
                     uint8_t *salt, const uint64_t salt_len,
                     uint32_t N_cost, uint32_t r_blockSize, uint32_t p_parallelization)
{
    if (key == NULL || key_len == 0 || password == NULL || password_len == 0 || salt == NULL || salt_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *out_key = NULL;
    int verification_success = 0;

    if (cw_scrypt_ex(password, password_len, salt, salt_len, N_cost, r_blockSize, p_parallelization, &out_key, key_len, 0) != 1)
    {
        goto END;
    }

    if (CRYPTO_memcmp(out_key, key, key_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_SCRYPT_VERIFY);
        goto END;
    }
    verification_success = 1;

END:
    if (out_key != NULL)
        OPENSSL_clear_free(out_key, key_len);

    return verification_success;
}

int cw_argon2_raw(const uint32_t t_cost,
                  const uint32_t m_cost,
                  const uint32_t parallelism,
                  const void *pwd, const size_t pwd_len,
                  const void *salt, const size_t salt_len,
                  uint8_t **hash, const size_t hash_len, cw_argon2_mode mode, const uint8_t flags)
{
    if (pwd == NULL || pwd_len == 0 || salt == NULL || salt_len == 0 || hash == NULL || hash_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int argon2_id;
    argon2_error_codes argon2_err_code = 1;

    if ((argon2_id = cw_fetch_key_derivation_argon2_mode_internal(mode)) == FETCH_ARGON2_INVALID)
        return 0;

    // If hash should be allocated
    if (!(flags & KEY_DERIVATION_NO_ALLOC))
    {
        if ((*hash = OPENSSL_zalloc(hash_len)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((argon2_err_code = argon2_hash(t_cost, m_cost, parallelism, pwd, pwd_len, salt, salt_len, (void *)*hash, hash_len, NULL, 0, argon2_id, ARGON2_VERSION_NUMBER)) != ARGON2_OK)
    {
        if (!(flags & KEY_DERIVATION_NO_ALLOC))
        {
            OPENSSL_clear_free(*hash, hash_len);
        }

        cw_argon2_handle_error_internal(argon2_err_code);
        return 0;
    }
    return 1;
}

int cw_argon2_raw_verify(const uint8_t *key, const size_t key_len,
                         const uint32_t t_cost,
                         const uint32_t m_cost,
                         const uint32_t parallelism,
                         const void *pwd, const size_t pwd_len,
                         const void *salt, const size_t salt_len,
                         cw_argon2_mode mode)
{
    if (pwd == NULL || pwd_len == 0 || salt == NULL || salt_len == 0 || key == NULL || key_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    uint8_t *out_key = NULL;
    int verification_success = 0;

    argon2_error_codes argon2_err_code = 1;

    if ((argon2_err_code = cw_argon2_raw(t_cost, m_cost, parallelism, pwd, pwd_len, salt, salt_len, &out_key, key_len, mode, 0)) != 1)
    {
        cw_argon2_handle_error_internal(argon2_err_code);
        return 0;
    }

    if (CRYPTO_memcmp(out_key, key, key_len) != 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_DERIVATION_ARGON2_VERIFY_MISMATCH);
        goto END;
    }

    verification_success = 1;

END:
    if (out_key != NULL)
        OPENSSL_clear_free(out_key, key_len);

    return verification_success;
}

int cw_argon2_encoded(const uint32_t t_cost,
                      const uint32_t m_cost,
                      const uint32_t parallelism,
                      const void *pwd, const size_t pwd_len,
                      const void *salt, const size_t salt_len,
                      const size_t hash_len, char **encoded, size_t *encoded_len, cw_argon2_mode mode, const uint8_t flags)
{
    if (pwd == NULL || pwd_len == 0 || salt == NULL || salt_len == 0 || encoded == NULL || hash_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int argon2_id;

    uint64_t encoded_len_internal = 0;
    argon2_error_codes argon2_err_code;

    if ((argon2_id = cw_fetch_key_derivation_argon2_mode_internal(mode)) == FETCH_ARGON2_INVALID)
        return 0;

    encoded_len_internal = argon2_encodedlen(t_cost, m_cost, parallelism, salt_len, hash_len, argon2_id);

    // If hash should be allocated
    if (!(flags & KEY_DERIVATION_NO_ALLOC))
    {
        if ((*encoded = OPENSSL_zalloc(encoded_len_internal)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    if ((argon2_err_code = argon2_hash(t_cost, m_cost, parallelism, pwd, pwd_len, salt, salt_len, NULL, hash_len, *encoded, encoded_len_internal, argon2_id, ARGON2_VERSION_NUMBER)) != ARGON2_OK)
    {
        if (!(flags & KEY_DERIVATION_NO_ALLOC))
        {
            OPENSSL_clear_free(*encoded, encoded_len_internal);
        }

        cw_argon2_handle_error_internal(argon2_err_code);
        return 0;
    }

    if (encoded_len != NULL)
        *encoded_len = encoded_len_internal;

    return 1;
}

int cw_argon2_verify(const char *encoded, const void *pwd, const size_t pwd_len, cw_argon2_mode mode)
{
    if (encoded == NULL || pwd == NULL || pwd_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    int argon2_id;
    argon2_error_codes argon2_err_code;

    if ((argon2_id = cw_fetch_key_derivation_argon2_mode_internal(mode)) == FETCH_ARGON2_INVALID)
        return 0;

    if ((argon2_err_code = argon2_verify(encoded, pwd, pwd_len, argon2_id)) != ARGON2_OK)
    {
        cw_argon2_handle_error_internal(argon2_err_code);
        return 0;
    }

    return 1;
}

uint64_t cw_argon2_get_encoded_len(const uint32_t t_cost,
                                   const uint32_t m_cost,
                                   const uint32_t parallelism,
                                   uint32_t salt_len, uint32_t hash_len, cw_argon2_mode mode)
{
    int argon2_id;

    if ((argon2_id = cw_fetch_key_derivation_argon2_mode_internal(mode)) == FETCH_ARGON2_INVALID)
        return 0;

    return argon2_encodedlen(t_cost, m_cost, parallelism, salt_len, hash_len, argon2_id);
}