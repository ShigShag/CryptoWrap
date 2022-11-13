/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "../key_derivation/argon2/argon2.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/obj_mac.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>

char *cw_fetch_hash_str_internal(hash_algorithm algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_MD5:
        return SN_md5;
    case CW_SHA_1:
        return SN_sha1;
    case CW_SHA_224:
        return SN_sha224;
    case CW_SHA_256:
        return SN_sha256;
    case CW_SHA_384:
        return SN_sha384;
    case CW_SHA_512:
        return SN_sha512;
    case CW_SHA_512_224:
        return SN_sha512_224;
    case CW_SHA_512_256:
        return SN_sha512_256;
    case CW_SHA3_224:
        return SN_sha3_224;
    case CW_SHA3_256:
        return SN_sha3_256;
    case CW_SHA3_384:
        return SN_sha3_384;
    case CW_SHA3_512:
        return SN_sha3_512;
    case CW_SHAKE_128:
        return SN_shake128;
    case CW_SHAKE_256:
        return SN_shake256;
    case CW_SM_3:
        return SN_sm3;
    case CW_MD4:
        return SN_md4;
    case CW_WHIRLPOOL:
        return SN_whirlpool;
    case CW_RIPEMD_160:
        return SN_ripemd160;
    case CW_BLAKE2S_256:
        return SN_blake2s256;
    case CW_BLAKE2B_512:
        return SN_blake2b512;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_HASH_ALGORITHM);
        return NULL;
    }
}

int cw_fetch_hash_nid_internal(hash_algorithm algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_MD5:
        return NID_md5;
    case CW_SHA_1:
        return NID_sha1;
    case CW_SHA_224:
        return NID_sha224;
    case CW_SHA_256:
        return NID_sha256;
    case CW_SHA_384:
        return NID_sha384;
    case CW_SHA_512:
        return NID_sha512;
    case CW_SHA_512_224:
        return NID_sha512_224;
    case CW_SHA_512_256:
        return NID_sha512_256;
    case CW_SHA3_224:
        return NID_sha3_224;
    case CW_SHA3_256:
        return NID_sha3_256;
    case CW_SHA3_384:
        return NID_sha3_384;
    case CW_SHA3_512:
        return NID_sha3_512;
    case CW_SHAKE_128:
        return NID_shake128;
    case CW_SHAKE_256:
        return NID_shake256;
    case CW_SM_3:
        return NID_sm3;
    case CW_MD4:
        return NID_md4;
    case CW_WHIRLPOOL:
        return NID_whirlpool;
    case CW_RIPEMD_160:
        return NID_ripemd160;
    case CW_BLAKE2S_256:
        return NID_blake2s256;
    case CW_BLAKE2B_512:
        return NID_blake2b512;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_HASH_ALGORITHM);
        return NID_undef;
    }
}

int cw_fetch_hash_len_internal(hash_algorithm algorithm_id)
{
    EVP_MD *md;
    int len;

    if ((md = cw_fetch_hash_impl_internal(algorithm_id)) == NULL)
    {
        return 0;
    }

    len = EVP_MD_get_size(md);

    cw_fetch_free_hash_impl_internal(md);

    return len;
}

EVP_MD *cw_fetch_hash_impl_internal(hash_algorithm algorithm_id)
{
    char *algorithm;
    char *properties = NULL;

    int algorithm_is_legacy = 0;
    OSSL_PROVIDER *provider = NULL;
    EVP_MD *digest_impl = NULL;

    switch (algorithm_id)
    {
    case CW_MD4:
        algorithm_is_legacy = 1;
        break;
    case CW_WHIRLPOOL:
        algorithm_is_legacy = 1;
        break;
    case CW_RIPEMD_160:
        algorithm_is_legacy = 1;
        break;

    default:
        algorithm_is_legacy = 0;
    }

    if ((algorithm = cw_fetch_hash_str_internal(algorithm_id)) == NULL)
    {
        return NULL;
    }

    if (algorithm_is_legacy == 1)
    {
        if ((provider = OSSL_PROVIDER_load(NULL, "legacy")) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_FETCH_OSSL_PROVIDER_LOAD_LEGACY);
            return NULL;
        }

        properties = "provider=legacy";
    }

    if ((digest_impl = EVP_MD_fetch(NULL, algorithm, properties)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_EVP_MD_fetch);
        return NULL;
    }

    if (provider != NULL)
        OSSL_PROVIDER_unload(provider);

    return digest_impl;
}

void cw_fetch_free_hash_impl_internal(EVP_MD *digest_impl)
{
    if (digest_impl != NULL)
        EVP_MD_free(digest_impl);
}

/* Symmetric cipher fetching */
char *cw_fetch_symmetric_cipher_str_internal(cw_symmetric_cipher_algorithm algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_AES_128_CBC:
        return SN_aes_128_cbc;
    case CW_AES_128_ECB:
        return SN_aes_128_ecb;
    case CW_AES_128_CFB1:
        return SN_aes_128_cfb1;
    case CW_AES_128_CFB8:
        return SN_aes_128_cfb8;
    case CW_AES_128_CFB:
        return SN_aes_128_cfb128;
    case CW_AES_128_OFB:
        return SN_aes_128_ofb128;
    case CW_AES_128_CTR:
        return SN_aes_128_ctr;
    case CW_AES_128_XTS:
        return SN_aes_128_xts;
    case CW_AES_192_ECB:
        return SN_aes_192_ecb;
    case CW_AES_192_CBC:
        return SN_aes_192_cbc;
    case CW_AES_192_CFB1:
        return SN_aes_192_cfb1;
    case CW_AES_192_CFB8:
        return SN_aes_192_cfb8;
    case CW_AES_192_CFB:
        return SN_aes_192_cfb128;
    case CW_AES_192_OFB:
        return SN_aes_192_ofb128;
    case CW_AES_192_CTR:
        return SN_aes_192_ctr;
    case CW_AES_256_ECB:
        return SN_aes_256_ecb;
    case CW_AES_256_CBC:
        return SN_aes_256_cbc;
    case CW_AES_256_CFB1:
        return SN_aes_256_cfb1;
    case CW_AES_256_CFB8:
        return SN_aes_256_cfb8;
    case CW_AES_256_CFB:
        return SN_aes_256_cfb128;
    case CW_AES_256_OFB:
        return SN_aes_256_ofb128;
    case CW_AES_256_CTR:
        return SN_aes_256_ctr;
    case CW_AES_256_XTS:
        return SN_aes_256_xts;
    case CW_AES_128_WRAP:
        return SN_id_aes128_wrap;
    case CW_AES_192_WRAP:
        return SN_id_aes192_wrap;
    case CW_AES_256_WRAP:
        return SN_id_aes256_wrap;

        // case CW_AES_128_WRAP_PAD:
        //     return SN_id_aes128_wrap_pad;
        // case CW_AES_192_WRAP_PAD:
        //     return SN_id_aes192_wrap_pad;
        // case CW_AES_256_WRAP_PAD:
        //     return SN_id_aes256_wrap_pad;

    case CW_ARIA_128_ECB:
        return SN_aria_128_ecb;
    case CW_ARIA_128_CBC:
        return SN_aria_128_cbc;
    case CW_ARIA_128_CFB1:
        return SN_aria_128_cfb1;
    case CW_ARIA_128_CFB8:
        return SN_aria_128_cfb8;
    case CW_ARIA_128_CFB:
        return SN_aria_128_cfb128;
    case CW_ARIA_128_CTR:
        return SN_aria_128_ctr;
    case CW_ARIA_128_OFB:
        return SN_aria_128_ofb128;
    case CW_ARIA_192_ECB:
        return SN_aria_192_ecb;
    case CW_ARIA_192_CBC:
        return SN_aria_192_cbc;
    case CW_ARIA_192_CFB1:
        return SN_aria_192_cfb1;
    case CW_ARIA_192_CFB8:
        return SN_aria_192_cfb8;
    case CW_ARIA_192_CFB:
        return SN_aria_192_cfb128;
    case CW_ARIA_192_CTR:
        return SN_aria_192_ctr;
    case CW_ARIA_192_OFB:
        return SN_aria_192_ofb128;
    case CW_ARIA_256_ECB:
        return SN_aria_256_ecb;
    case CW_ARIA_256_CBC:
        return SN_aria_256_cbc;
    case CW_ARIA_256_CFB1:
        return SN_aria_256_cfb1;
    case CW_ARIA_256_CFB8:
        return SN_aria_256_cfb8;
    case CW_ARIA_256_CFB:
        return SN_aria_256_cfb128;
    case CW_ARIA_256_CTR:
        return SN_aria_256_ctr;
    case CW_ARIA_256_OFB:
        return SN_aria_256_ofb128;
    case CW_CAMELLIA_128_ECB:

        return SN_camellia_128_ecb;
    case CW_CAMELLIA_128_CBC:
        return SN_camellia_128_cbc;
    case CW_CAMELLIA_128_CFB1:
        return SN_camellia_128_cfb1;
    case CW_CAMELLIA_128_CFB8:
        return SN_camellia_128_cfb8;
    case CW_CAMELLIA_128_CFB:
        return SN_camellia_128_cfb128;
    case CW_CAMELLIA_128_OFB:
        return SN_camellia_128_ofb128;
    case CW_CAMELLIA_128_CTR:
        return SN_camellia_128_ctr;
    case CW_CAMELLIA_192_ECB:
        return SN_camellia_192_ecb;
    case CW_CAMELLIA_192_CBC:
        return SN_camellia_192_cbc;
    case CW_CAMELLIA_192_CFB1:
        return SN_camellia_192_cfb1;
    case CW_CAMELLIA_192_CFB8:
        return SN_camellia_192_cfb8;
    case CW_CAMELLIA_192_CFB:
        return SN_camellia_192_cfb128;
    case CW_CAMELLIA_192_OFB:
        return SN_camellia_192_ofb128;
    case CW_CAMELLIA_192_CTR:
        return SN_camellia_192_ctr;
    case CW_CAMELLIA_256_ECB:
        return SN_camellia_256_ecb;
    case CW_CAMELLIA_256_CBC:
        return SN_camellia_256_cbc;
    case CW_CAMELLIA_256_CFB1:
        return SN_camellia_256_cfb1;
    case CW_CAMELLIA_256_CFB8:
        return SN_camellia_256_cfb8;
    case CW_CAMELLIA_256_CFB:
        return SN_camellia_256_cfb128;
    case CW_CAMELLIA_256_OFB:
        return SN_camellia_256_ofb128;
    case CW_CAMELLIA_256_CTR:
        return SN_camellia_256_ctr;

    case CW_CHACHA_20:
        return SN_chacha20;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_SYMETRIC_CIPHER_MODE);
        return NULL;
    }
}

// Fetch id identifier
int cw_fetch_symmetric_cipher_nid_internal(cw_symmetric_cipher_algorithm algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_AES_128_CBC:
        return NID_aes_128_cbc;
    case CW_AES_128_ECB:
        return NID_aes_128_ecb;
    case CW_AES_128_CFB1:
        return NID_aes_128_cfb1;
    case CW_AES_128_CFB8:
        return NID_aes_128_cfb8;
    case CW_AES_128_CFB:
        return NID_aes_128_cfb128;
    case CW_AES_128_OFB:
        return NID_aes_128_ofb128;
    case CW_AES_128_CTR:
        return NID_aes_128_ctr;
    case CW_AES_128_XTS:
        return NID_aes_128_xts;
    case CW_AES_192_ECB:
        return NID_aes_192_ecb;
    case CW_AES_192_CBC:
        return NID_aes_192_cbc;
    case CW_AES_192_CFB1:
        return NID_aes_192_cfb1;
    case CW_AES_192_CFB8:
        return NID_aes_192_cfb8;
    case CW_AES_192_CFB:
        return NID_aes_192_cfb128;
    case CW_AES_192_OFB:
        return NID_aes_192_ofb128;
    case CW_AES_192_CTR:
        return NID_aes_192_ctr;
    case CW_AES_256_ECB:
        return NID_aes_256_ecb;
    case CW_AES_256_CBC:
        return NID_aes_256_cbc;
    case CW_AES_256_CFB1:
        return NID_aes_256_cfb1;
    case CW_AES_256_CFB8:
        return NID_aes_256_cfb8;
    case CW_AES_256_CFB:
        return NID_aes_256_cfb128;
    case CW_AES_256_OFB:
        return NID_aes_256_ofb128;
    case CW_AES_256_CTR:
        return NID_aes_256_ctr;
    case CW_AES_256_XTS:
        return NID_aes_256_xts;

    case CW_AES_128_WRAP:
        return NID_id_aes128_wrap;
    case CW_AES_192_WRAP:
        return NID_id_aes192_wrap;
    case CW_AES_256_WRAP:
        return NID_id_aes256_wrap;
        // case CW_AES_128_WRAP_PAD:
        //     return NID_id_aes128_wrap_pad;
        // case CW_AES_192_WRAP_PAD:
        //     return NID_id_aes192_wrap_pad;
        // case CW_AES_256_WRAP_PAD:
        //     return NID_id_aes256_wrap_pad;

    case CW_ARIA_128_ECB:
        return NID_aria_128_ecb;
    case CW_ARIA_128_CBC:
        return NID_aria_128_cbc;
    case CW_ARIA_128_CFB1:
        return NID_aria_128_cfb1;
    case CW_ARIA_128_CFB8:
        return NID_aria_128_cfb8;
    case CW_ARIA_128_CFB:
        return NID_aria_128_cfb128;
    case CW_ARIA_128_CTR:
        return NID_aria_128_ctr;
    case CW_ARIA_128_OFB:
        return NID_aria_128_ofb128;
    case CW_ARIA_192_ECB:
        return NID_aria_192_ecb;
    case CW_ARIA_192_CBC:
        return NID_aria_192_cbc;
    case CW_ARIA_192_CFB1:
        return NID_aria_192_cfb1;
    case CW_ARIA_192_CFB8:
        return NID_aria_192_cfb8;
    case CW_ARIA_192_CFB:
        return NID_aria_192_cfb128;
    case CW_ARIA_192_CTR:
        return NID_aria_192_ctr;
    case CW_ARIA_192_OFB:
        return NID_aria_192_ofb128;
    case CW_ARIA_256_ECB:
        return NID_aria_256_ecb;
    case CW_ARIA_256_CBC:
        return NID_aria_256_cbc;
    case CW_ARIA_256_CFB1:
        return NID_aria_256_cfb1;
    case CW_ARIA_256_CFB8:
        return NID_aria_256_cfb8;
    case CW_ARIA_256_CFB:
        return NID_aria_256_cfb128;
    case CW_ARIA_256_CTR:
        return NID_aria_256_ctr;
    case CW_ARIA_256_OFB:
        return NID_aria_256_ofb128;

    case CW_CAMELLIA_128_ECB:
        return NID_camellia_128_ecb;
    case CW_CAMELLIA_128_CBC:
        return NID_camellia_128_cbc;
    case CW_CAMELLIA_128_CFB1:
        return NID_camellia_128_cfb1;
    case CW_CAMELLIA_128_CFB8:
        return NID_camellia_128_cfb8;
    case CW_CAMELLIA_128_CFB:
        return NID_camellia_128_cfb128;
    case CW_CAMELLIA_128_OFB:
        return NID_camellia_128_ofb128;
    case CW_CAMELLIA_128_CTR:
        return NID_camellia_128_ctr;
    case CW_CAMELLIA_192_ECB:
        return NID_camellia_192_ecb;
    case CW_CAMELLIA_192_CBC:
        return NID_camellia_192_cbc;
    case CW_CAMELLIA_192_CFB1:
        return NID_camellia_192_cfb1;
    case CW_CAMELLIA_192_CFB8:
        return NID_camellia_192_cfb8;
    case CW_CAMELLIA_192_CFB:
        return NID_camellia_192_cfb128;
    case CW_CAMELLIA_192_OFB:
        return NID_camellia_192_ofb128;
    case CW_CAMELLIA_192_CTR:
        return NID_camellia_192_ctr;
    case CW_CAMELLIA_256_ECB:
        return NID_camellia_256_ecb;
    case CW_CAMELLIA_256_CBC:
        return NID_camellia_256_cbc;
    case CW_CAMELLIA_256_CFB1:
        return NID_camellia_256_cfb1;
    case CW_CAMELLIA_256_CFB8:
        return NID_camellia_256_cfb8;
    case CW_CAMELLIA_256_CFB:
        return NID_camellia_256_cfb128;
    case CW_CAMELLIA_256_OFB:
        return NID_camellia_256_ofb128;
    case CW_CAMELLIA_256_CTR:
        return NID_camellia_256_ctr;

    case CW_CHACHA_20:
        return NID_chacha20;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_SYMETRIC_CIPHER_MODE);
        return NID_undef;
    }
}

// Fetch implementation
EVP_CIPHER *fetch_symmetric_cipher_impl(cw_symmetric_cipher_algorithm algorithm_id)
{
    char *algorithm;
    EVP_CIPHER *cipher_impl;

    if ((algorithm = cw_fetch_symmetric_cipher_str_internal(algorithm_id)) == NULL)
        return NULL;

    if ((cipher_impl = EVP_CIPHER_fetch(NULL, algorithm, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_EVP_CIPHER_FETCH);
        return NULL;
    }

    return cipher_impl;
}

// Fetch required key and iv length
int cw_fetch_symmetric_cipher_key_and_iv_length(cw_symmetric_cipher_algorithm algorithm_id, int *key_len, int *iv_len)
{
    if (key_len == NULL && iv_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_CIPHER *impl;

    if ((impl = fetch_symmetric_cipher_impl(algorithm_id)) == NULL)
        return 0;

    if (key_len != NULL)
        *key_len = EVP_CIPHER_get_key_length(impl);

    if (iv_len != NULL)
        *iv_len = EVP_CIPHER_get_iv_length(impl);

    cw_fetch_free_symmetric_cipher_impl_internal(impl);

    return 1;
}

// Free digest
void cw_fetch_free_symmetric_cipher_impl_internal(EVP_CIPHER *symmetric_cipher_impl)
{
    if (symmetric_cipher_impl != NULL)
        EVP_CIPHER_free(symmetric_cipher_impl);
}

/* Symmetric cipher authentication fetching */

// Fetch str identifier
char *cw_fetch_aead_str_internal(aead_mode algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_AES_128_GCM:
        return SN_aes_128_gcm;
    case CW_AES_192_GCM:
        return SN_aes_192_gcm;
    case CW_AES_256_GCM:
        return SN_aes_256_gcm;
    case CW_ARIA_128_GCM:
        return SN_aria_128_gcm;
    case CW_ARIA_192_GCM:
        return SN_aria_192_gcm;
    case CW_ARIA_256_GCM:
        return SN_aria_256_gcm;
    case CW_AES_128_CCM:
        return SN_aes_128_ccm;
    case CW_AES_192_CCM:
        return SN_aes_192_ccm;
    case CW_AES_256_CCM:
        return SN_aes_256_ccm;
    case CW_ARIA_128_CCM:
        return SN_aria_128_ccm;
    case CW_ARIA_192_CCM:
        return SN_aria_192_ccm;
    case CW_ARIA_256_CCM:
        return SN_aria_256_ccm;
    case CW_AES_128_OCB:
        return SN_aes_128_ocb;
    case CW_AES_192_OCB:
        return SN_aes_192_ocb;
    case CW_AES_256_OCB:
        return SN_aes_256_ocb;
    case CW_CHACHA_20_POLY_1305:
        return SN_chacha20_poly1305;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_UNKNOWN_ALGORITHM);
        return NULL;
    }
}

// Fetch id identifier
int cw_fetch_aead_nid_internal(aead_mode algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_AES_128_GCM:
        return NID_aes_128_gcm;
    case CW_AES_192_GCM:
        return NID_aes_192_gcm;
    case CW_AES_256_GCM:
        return NID_aes_256_gcm;
    case CW_ARIA_128_GCM:
        return NID_aria_128_gcm;
    case CW_ARIA_192_GCM:
        return NID_aria_192_gcm;
    case CW_ARIA_256_GCM:
        return NID_aria_256_gcm;
    case CW_AES_128_CCM:
        return NID_aes_128_ccm;
    case CW_AES_192_CCM:
        return NID_aes_192_ccm;
    case CW_AES_256_CCM:
        return NID_aes_256_ccm;
    case CW_ARIA_128_CCM:
        return NID_aria_128_ccm;
    case CW_ARIA_192_CCM:
        return NID_aria_192_ccm;
    case CW_ARIA_256_CCM:
        return NID_aria_256_ccm;
    case CW_AES_128_OCB:
        return NID_aes_128_ocb;
    case CW_AES_192_OCB:
        return NID_aes_192_ocb;
    case CW_AES_256_OCB:
        return NID_aes_256_ocb;
    case CW_CHACHA_20_POLY_1305:
        return NID_chacha20_poly1305;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_AEAD_UNKNOWN_ALGORITHM);
        return NID_undef;
    }
}

// Fetch implementation
EVP_CIPHER *cw_fetch_aead_impl_internal(aead_mode algorithm_id)
{
    char *algorithm;
    EVP_CIPHER *cipher;

    if ((algorithm = cw_fetch_aead_str_internal(algorithm_id)) == NULL)
        return NULL;

    if ((cipher = EVP_CIPHER_fetch(NULL, algorithm, NULL)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_EVP_CIPHER_FETCH);
        return 0;
    }

    return cipher;
}

// Fetch required key and iv length
int cw_fetch_aead_key_and_iv_length_internal(aead_mode algorithm_id, int *key_len, int *iv_len)
{
    if (key_len == NULL && iv_len == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_CIPHER *impl;

    if ((impl = cw_fetch_aead_impl_internal(algorithm_id)) == NULL)
        return 0;

    if (key_len != NULL)
        *key_len = EVP_CIPHER_get_key_length(impl);

    if (iv_len != NULL)
        *iv_len = EVP_CIPHER_get_iv_length(impl);

    cw_fetch_free_aead_impl_internal(impl);

    return 1;
}

// Free digest
void cw_fetch_free_aead_impl_internal(EVP_CIPHER *symmetric_cipher_authentication_impl)
{
    if (symmetric_cipher_authentication_impl != NULL)
        EVP_CIPHER_free(symmetric_cipher_authentication_impl);
}

/* MAC FETCHING */

char *cw_fetch_hmac_internal_internal(cw_hmac_digest algorithm_id)
{
    return cw_fetch_hash_str_internal((hash_algorithm)algorithm_id);
}

char *cw_fetch_gmac_internal(cw_gmac_cipher algorithm_id)
{
    return cw_fetch_aead_str_internal((cw_symmetric_cipher_algorithm)algorithm_id);
}

char *cw_fetch_kmac_internal(cw_kmac_mode algorithm_id)
{
    switch (algorithm_id)
    {
    case CW_KMAC_128:
        return SN_kmac128;
    case CW_KMAC_256:
        return SN_kmac256;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_KMAC_MODE);
        return NULL;
    }
}

/* Elliptic curves */
int cw_fetch_ec_curve_nid_internal(cw_elliptic_curve_type curve_type)
{
    switch (curve_type)
    {
    case CW_SECP224K1:
        return NID_secp224k1;
    case CW_SECP224R1:
        return NID_secp224r1;
    case CW_SECP256K1:
        return NID_secp256k1;
    case CW_SECP384R1:
        return NID_secp384r1;
    case CW_SECP521R1:
        return NID_secp521r1;
    case CW_PRIME239V1:
        return NID_X9_62_prime239v1;
    case CW_PRIME239V2:
        return NID_X9_62_prime239v2;
    case CW_PRIME239V3:
        return NID_X9_62_prime239v3;
    case CW_PRIME256V1:
        return NID_X9_62_prime256v1;
    case CW_SECT233K1:
        return NID_sect233k1;
    case CW_SECT233R1:
        return NID_sect233r1;
    case CW_SECT239K1:
        return NID_sect239k1;
    case CW_SECT283K1:
        return NID_sect283k1;
    case CW_SECT283R1:
        return NID_sect283r1;
    case CW_SECT409K1:
        return NID_sect409k1;
    case CW_SECT409R1:
        return NID_sect409r1;
    case CW_SECT571K1:
        return NID_sect571k1;
    case CW_SECT571R1:
        return NID_sect571r1;
    case CW_C2TNB239V1:
        return NID_X9_62_c2tnb239v1;
    case CW_C2TNB239V2:
        return NID_X9_62_c2tnb239v2;
    case CW_C2TNB239V3:
        return NID_X9_62_c2tnb239v3;
    case CW_C2PNB272W1:
        return NID_X9_62_c2pnb272w1;
    case CW_C2PNB304W1:
        return NID_X9_62_c2pnb304w1;
    case CW_C2TNB359V1:
        return NID_X9_62_c2tnb359v1;
    case CW_C2PNB368W1:
        return NID_X9_62_c2pnb368w1;
    case CW_C2TNB431R1:
        return NID_X9_62_c2tnb431r1;
    case CW_BRAINPOOLP224R1:
        return NID_brainpoolP224r1;
    case CW_BRAINPOOLP224T1:
        return NID_brainpoolP224t1;
    case CW_BRAINPOOLP256R1:
        return NID_brainpoolP256r1;
    case CW_BRAINPOOLP256T1:
        return NID_brainpoolP256t1;
    case CW_BRAINPOOLP320R1:
        return NID_brainpoolP320r1;
    case CW_BRAINPOOLP320T1:
        return NID_brainpoolP320t1;
    case CW_BRAINPOOLP384R1:
        return NID_brainpoolP384r1;
    case CW_BRAINPOOLP384T1:
        return NID_brainpoolP384t1;
    case CW_BRAINPOOLP512R1:
        return NID_brainpoolP512r1;
    case CW_BRAINPOOLP512T1:
        return NID_brainpoolP512t1;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_EC_CURVE);
        return NID_undef;
    }
}

char *cw_fetch_ec_curve_str_internal(cw_elliptic_curve_type curve_type)
{
    switch (curve_type)
    {
    case CW_SECP224K1:
        return SN_secp224k1;
    case CW_SECP224R1:
        return SN_secp224r1;
    case CW_SECP256K1:
        return SN_secp256k1;
    case CW_SECP384R1:
        return SN_secp384r1;
    case CW_SECP521R1:
        return SN_secp521r1;
    case CW_PRIME239V1:
        return SN_X9_62_prime239v1;
    case CW_PRIME239V2:
        return SN_X9_62_prime239v2;
    case CW_PRIME239V3:
        return SN_X9_62_prime239v3;
    case CW_PRIME256V1:
        return SN_X9_62_prime256v1;
    case CW_SECT233K1:
        return SN_sect233k1;
    case CW_SECT233R1:
        return SN_sect233r1;
    case CW_SECT239K1:
        return SN_sect239k1;
    case CW_SECT283K1:
        return SN_sect283k1;
    case CW_SECT283R1:
        return SN_sect283r1;
    case CW_SECT409K1:
        return SN_sect409k1;
    case CW_SECT409R1:
        return SN_sect409r1;
    case CW_SECT571K1:
        return SN_sect571k1;
    case CW_SECT571R1:
        return SN_sect571r1;
    case CW_C2TNB239V1:
        return SN_X9_62_c2tnb239v1;
    case CW_C2TNB239V2:
        return SN_X9_62_c2tnb239v2;
    case CW_C2TNB239V3:
        return SN_X9_62_c2tnb239v3;
    case CW_C2PNB272W1:
        return SN_X9_62_c2pnb272w1;
    case CW_C2PNB304W1:
        return SN_X9_62_c2pnb304w1;
    case CW_C2TNB359V1:
        return SN_X9_62_c2tnb359v1;
    case CW_C2PNB368W1:
        return SN_X9_62_c2pnb368w1;
    case CW_C2TNB431R1:
        return SN_X9_62_c2tnb431r1;
    case CW_BRAINPOOLP224R1:
        return SN_brainpoolP224r1;
    case CW_BRAINPOOLP224T1:
        return SN_brainpoolP224t1;
    case CW_BRAINPOOLP256R1:
        return SN_brainpoolP256r1;
    case CW_BRAINPOOLP256T1:
        return SN_brainpoolP256t1;
    case CW_BRAINPOOLP320R1:
        return SN_brainpoolP320r1;
    case CW_BRAINPOOLP320T1:
        return SN_brainpoolP320t1;
    case CW_BRAINPOOLP384R1:
        return SN_brainpoolP384r1;
    case CW_BRAINPOOLP384T1:
        return SN_brainpoolP384t1;
    case CW_BRAINPOOLP512R1:
        return SN_brainpoolP512r1;
    case CW_BRAINPOOLP512T1:
        return SN_brainpoolP512t1;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_EC_CURVE);
        return NULL;
    }
}

char *cw_fetch_ec_serialization_type_str_internal(cw_ecc_serialization_type output_type)
{
    switch (output_type)
    {
    case CW_ECC_DER:
        return "DER";

    case CW_ECC_PEM:
        return "PEM";

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_EC_SERIALIZATION_TYPE);
        return NULL;
    }
}

char *cw_fetch_ec_signature_str_internal(cw_ecc_signature_hash signature_id)
{
    return cw_fetch_hash_str_internal((hash_algorithm)signature_id);
}

/* RSA */
int cw_fetch_rsa_padding_mode_internal(cw_rsa_padding_mode padding_mode)
{
    switch (padding_mode)
    {
    case CW_RSA_PKCS1_PADDING:
        return RSA_PKCS1_PADDING;
    case CW_RSA_PKCS1_OAEP_SHA1_PADDING:
        return RSA_PKCS1_OAEP_PADDING;
    case CW_RSA_PKCS1_OAEP_SHA224_PADDING:
        return RSA_PKCS1_OAEP_PADDING;
    case CW_RSA_PKCS1_OAEP_SHA256_PADDING:
        return RSA_PKCS1_OAEP_PADDING;
    case CW_RSA_PKCS1_OAEP_SHA512_PADDING:
        return RSA_PKCS1_OAEP_PADDING;
    // case CW_RSA_X931_PADDING:
    //     return RSA_X931_PADDING;
    case CW_RSA_PKCS1_PSS_PADDING:
        return RSA_PKCS1_PSS_PADDING;

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_WRONG_PADDING_MODE);
        return 0;
    }
}

char *cw_fetch_rsa_serialization_type_internal(cw_rsa_serialization_type output_mode)
{
    switch (output_mode)
    {
    case CW_RSA_DER:
        return "DER";

    case CW_RSA_PEM:
        return "PEM";

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_RSA_WRONG_SERIALIZATION_TYPE);
        return NULL;
    }
}

/* Key derivation */
int cw_fetch_key_derivation_argon2_mode_internal(cw_argon2_mode mode)
{
    switch (mode)
    {
    case CW_ARGON2_D:
        return Argon2_d;
    case CW_ARGON2_I:
        return Argon2_i;
    case CW_ARGON2_ID:
        return Argon2_id;
    default:
        CW_ERROR_RAISE(CW_ERROR_ID_FETCH_WRONG_ARGON_2_MODE);
        return FETCH_ARGON2_INVALID;
    }
}
