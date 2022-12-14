/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/error/error_internal.h"
#include "internal/error/error_strings.h"

const char *cw_error_get_string(error_id id)
{
    switch (id)
    {
    case CW_ERROR_ID_TEST:
        return CW_ERROR_STR_TEST;
    case CW_ERROR_ID_PARAM_MISSING:
        return CW_ERROR_STR_PARAM_MISSING_STR;
    case CW_ERROR_ID_AEAD_GCM_IV_NOT_SET:
        return CW_ERROR_STR_AEAD_GCM_IV_NOT_SET;
    case CW_ERROR_ID_AEAD_GCM_TAG_LEN_WRONG:
        return CW_ERROR_STR_AEAD_GCM_TAG_LEN_WRONG;
    case CW_ERROR_ID_AEAD_CCM_IV_LEN_WRONG:
        return CW_ERROR_STR_AEAD_CCM_IV_LEN_WRONG;
    case CW_ERROR_ID_AEAD_CCM_TAG_LEN_WRONG:
        return CW_ERROR_STR_AEAD_CCM_TAG_LEN_WRONG;
    case CW_ERROR_ID_AEAD_CCM_INPUT_TOO_LARGE:
        return CW_ERROR_STR_AEAD_CCM_INPUT_TOO_LARGE;
    case CW_ERROR_ID_AEAD_OCB_IV_LEN_WRONG:
        return CW_ERROR_STR_AEAD_OCB_IV_LEN_WRONG;
    case CW_ERROR_ID_AEAD_OCB_TAG_LEN_WRONG:
        return CW_ERROR_STR_AEAD_OCB_TAG_LEN_WRONG;
    case CW_ERROR_ID_AEAD_CHACHA_20_IV_LEN_WRONG:
        return CW_ERROR_STR_AEAD_CHACHA_20_IV_LEN_WRONG;
    case CW_ERROR_ID_AEAD_CHACHA_20_TAG_LEN_WRONG:
        return CW_ERROR_STR_AEAD_CHACHA_20_TAG_LEN_WRONG;
    case CW_ERROR_ID_AEAD_UNKNOWN_ALGORITHM:
        return CW_ERROR_STR_AEAD_UNKNOWN_ALGORITHM;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_CTX_NEW;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_INIT_EX2;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_UPDATE;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE_AAD:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_UPDATE_AAD;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_FINAL_EX:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_FINAL_EX;
    case CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG:
        return CW_ERROR_STR_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG;
    case CW_ERROR_ID_AEAD_WRONG_KEY_LEN:
        return CW_ERROR_STR_AEAD_WRONG_KEY_LEN;
    case CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_NEW_FOR_PKEY:
        return CW_ERROR_STR_ECC_OSSL_ENCODER_CTX_NEW_FOR_PKEY;
    case CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_CIPHER:
        return CW_ERROR_STR_ECC_OSSL_ENCODER_CTX_SET_CIPHER;
    case CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_PASSPHRASE:
        return CW_ERROR_STR_ECC_OSSL_ENCODER_CTX_SET_PASSPHRASE;
    case CW_ERROR_ID_ECC_OSSL_ENCODER_TO_FP:
        return CW_ERROR_STR_ECC_OSSL_ENCODER_TO_FP;
    case CW_ERROR_ID_ECC_OSSL_DECODER_CTX_NEW_FOR_PKEY:
        return CW_ERROR_STR_ECC_OSSL_DECODER_CTX_NEW_FOR_PKEY;
    case CW_ERROR_ID_ECC_OSSL_DECODER_CTX_SET_PASSPHRASE:
        return CW_ERROR_STR_ECC_OSSL_DECODER_CTX_SET_PASSPHRASE;
    case CW_ERROR_ID_ECC_OSSL_DECODER_FROM_FP:
        return CW_ERROR_STR_ECC_OSSL_DECODER_FROM_FP;
    case CW_ERROR_ID_ECC_EVP_MD_CTX_NEW:
        return CW_ERROR_STR_ECC_EVP_MD_CTX_NEW;
    case CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_INIT_EX:
        return CW_ERROR_STR_ECC_EVP_DIGEST_SIGN_INIT_EX;
    case CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_UPDATE:
        return CW_ERROR_STR_ECC_EVP_DIGEST_SIGN_UPDATE;
    case CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_FINAL:
        return CW_ERROR_STR_ECC_EVP_DIGEST_SIGN_FINAL;
    case CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_INIT_EX:
        return CW_ERROR_STR_ECC_EVP_DIGEST_VERIFY_INIT_EX;
    case CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_UPDATE:
        return CW_ERROR_STR_ECC_EVP_DIGEST_VERIFY_UPDATE;
    case CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_FINAL:
        return CW_ERROR_STR_ECC_EVP_DIGEST_VERIFY_FINAL;
    case CW_ERROR_ID_ECC_EVP_PKEY_CTX_NEW_ID:
        return CW_ERROR_STR_ECC_EVP_PKEY_CTX_NEW_ID;
    case CW_ERROR_ID_ECC_EVP_PKEY_KEYGEN_INIT:
        return CW_ERROR_STR_ECC_EVP_PKEY_KEYGEN_INIT;
    case CW_ERROR_ID_ECC_EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID:
        return CW_ERROR_STR_ECC_EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID;
    case CW_ERROR_ID_ECC_EVP_PKEY_GENERATE:
        return CW_ERROR_STR_ECC_EVP_PKEY_GENERATE;
    case CW_ERROR_ID_ECC_SIGN_MESSAGE_TO_SHORT:
        return CW_ERROR_STR_ECC_SIGN_MESSAGE_TO_SHORT;
    case CW_ERROR_ID_ECC_VERIFY_MESSAGE_TO_SHORT:
        return CW_ERROR_STR_ECC_VERIFY_MESSAGE_TO_SHORT;
    case CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW:
        return CW_ERROR_STR_ENCODE_EVP_ENCODE_CTX_NEW;
    case CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE:
        return CW_ERROR_STR_ENCODE_EVP_ENCODE_UPDATE;
    case CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE:
        return CW_ERROR_STR_ENCODE_EVP_DECODE_UPDATE;
    case CW_ERROR_ID_ENCODE_EVP_DECODE_FINAL:
        return CW_ERROR_STR_ENCODE_EVP_DECODE_FINAL;
    case CW_ERROR_ID_ENCODE_STREAM_WRONG_MODE:
        return CW_ERROR_STR_ENCODE_STREAM_WRONG_MODE;
    case CW_ERROR_ID_HASH_EVP_MD_CTX_NEW:
        return CW_ERROR_STR_HASH_EVP_MD_CTX_NEW;
    case CW_ERROR_ID_HASH_EVP_DIGEST_INIT_EX_2:
        return CW_ERROR_STR_HASH_EVP_DIGEST_INIT_EX_2;
    case CW_ERROR_ID_HASH_EVP_DIGEST_UPDATE:
        return CW_ERROR_STR_HASH_EVP_DIGEST_UPDATE;
    case CW_ERROR_ID_HASH_EVP_DIGEST_FINAL_EX:
        return CW_ERROR_STR_HASH_EVP_DIGEST_FINAL_EX;
    case CW_ERROR_ID_HASH_VERIFY_LEN_MISMATCH:
        return CW_ERROR_STR_HASH_VERIFY_LEN_MISMATCH;
    case CW_ERROR_ID_HASH_VERIFY_HASH_MISMATCH:
        return CW_ERROR_STR_HASH_VERIFY_HASH_MISMATCH;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X25519:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X25519;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X448:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X448;
    case CW_ERROR_ID_KEY_EXCH_ECDH_GET_PEER_PUBLIC_KEY:
        return CW_ERROR_STR_KEY_EXCH_ECDH_GET_PEER_PUBLIC_KEY;
    case CW_ERROR_ID_KEY_EXCH_DERIVE_PUBLIC_KEY_WRONG_MODE:
        return CW_ERROR_STR_KEY_EXCH_DERIVE_PUBLIC_KEY_WRONG_MODE;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_CTX_NEW_FROM_PKEY:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_CTX_NEW_FROM_PKEY;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_INIT:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_DERIVE_INIT;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_SET_PEER:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_DERIVE_SET_PEER;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_DERIVE;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X25519:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X25519;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X25519:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X25519;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X448:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X448;
    case CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X448:
        return CW_ERROR_STR_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X448;
    case CW_ERROR_ID_MAC_EVP_MAC_UPDATE:
        return CW_ERROR_STR_MAC_EVP_MAC_UPDATE;
    case CW_ERROR_ID_MAC_EVP_MAC_FINAL:
        return CW_ERROR_STR_MAC_EVP_MAC_FINAL;
    case CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW:
        return CW_ERROR_STR_MAC_EVP_MAC_CTX_NEW;
    case CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT:
        return CW_ERROR_STR_MAC_EVP_MAC_CTX_INIT;
    case CW_ERROR_ID_MAC_EVP_MAC_CTX_SET_PARAMS:
        return CW_ERROR_STR_MAC_EVP_MAC_CTX_SET_PARAMS;
    case CW_ERROR_ID_MAC_EVP_MAC_FETCH:
        return CW_ERROR_STR_MAC_EVP_MAC_FETCH;
    case CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH:
        return CW_ERROR_STR_MAC_VERIFY_LEN_MISMATCH;
    case CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH:
        return CW_ERROR_STR_MAC_VERIFY_MAC_MISMATCH;
    case CW_ERROR_ID_SYM_CIPHER_WRONG_KEY_LEN:
        return CW_ERROR_STR_SYM_CIPHER_WRONG_KEY_LEN;
    case CW_ERROR_ID_SYM_CIPHER_WRONG_IV_LEN:
        return CW_ERROR_STR_SYM_CIPHER_WRONG_IV_LEN;
    case CW_ERROR_ID_SYM_CIPHER_INPUT_SIZE_TOO_SHORT_FOR_XTS:
        return CW_ERROR_STR_SYM_CIPHER_INPUT_SIZE_TOO_SHORT_FOR_XTS;
    case CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_CTX_NEW:
        return CW_ERROR_STR_SYM_CIPHER_EVP_CIPHER_CTX_NEW;
    case CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2:
        return CW_ERROR_STR_SYM_CIPHER_EVP_CIPHER_INIT_EX2;
    case CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE:
        return CW_ERROR_STR_SYM_CIPHER_EVP_CIPHER_UPDATE;
    case CW_ERROR_ID_SYM_CIPHER_EVP_CIPHERFINAL_EX:
        return CW_ERROR_STR_SYM_CIPHER_EVP_CIPHERFINAL_EX;
    case CW_ERROR_ID_SYM_CIPHER_HIGH_MAC_MISMATCH:
        return CW_ERROR_STR_SYM_CIPHER_HIGH_MAC_MISMATCH;
    case CW_ERROR_ID_RSA_WRONG_PADDING_MODE:
        return CW_ERROR_STR_RSA_WRONG_PADDING_MODE;
    case CW_ERROR_ID_RSA_KEY_SIZE_TOO_SMALL:
        return CW_ERROR_STR_RSA_KEY_SIZE_TOO_SMALL;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW_ID:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_NEW_ID;
    case CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_NEW_FOR_PKEY:
        return CW_ERROR_STR_RSA_OSSL_ENCODER_CTX_NEW_FOR_PKEY;
    case CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_CIPHER:
        return CW_ERROR_STR_RSA_OSSL_ENCODER_CTX_SET_CIPHER;
    case CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_PASSPHRASE:
        return CW_ERROR_STR_RSA_OSSL_ENCODER_CTX_SET_PASSPHRASE;
    case CW_ERROR_ID_RSA_OSSL_ENCODER_TO_FP:
        return CW_ERROR_STR_RSA_OSSL_ENCODER_TO_FP;
    case CW_ERROR_ID_RSA_OSSL_DECODER_CTX_NEW_FOR_PKEY:
        return CW_ERROR_STR_RSA_OSSL_DECODER_CTX_NEW_FOR_PKEY;
    case CW_ERROR_ID_RSA_OSSL_DECODER_CTX_SET_PASSPHRASE:
        return CW_ERROR_STR_RSA_OSSL_DECODER_CTX_SET_PASSPHRASE;
    case CW_ERROR_ID_RSA_OSSL_OSSL_DECODER_FROM_FP:
        return CW_ERROR_STR_RSA_OSSL_OSSL_DECODER_FROM_FP;
    case CW_ERROR_ID_RSA_EVP_MD_CTX_NEW:
        return CW_ERROR_STR_RSA_EVP_MD_CTX_NEW;
    case CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_INIT_EX:
        return CW_ERROR_STR_RSA_EVP_DIGEST_SIGN_INIT_EX;
    case CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_UPDATE:
        return CW_ERROR_STR_RSA_EVP_DIGEST_SIGN_UPDATE;
    case CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_FINAL:
        return CW_ERROR_STR_RSA_EVP_DIGEST_SIGN_FINAL;
    case CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_INIT_EX:
        return CW_ERROR_STR_RSA_EVP_DIGEST_VERIFY_INIT_EX;
    case CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_UPDATE:
        return CW_ERROR_STR_RSA_EVP_DIGEST_VERIFY_UPDATE;
    case CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_FINAL:
        return CW_ERROR_STR_RSA_EVP_DIGEST_VERIFY_FINAL;
    case CW_ERROR_ID_RSA_EVP_PKEY_KEYGEN_INIT:
        return CW_ERROR_STR_RSA_EVP_PKEY_KEYGEN_INIT;
    case CW_ERROR_ID_RSA_EVP_PKEY_GENERATE:
        return CW_ERROR_STR_RSA_EVP_PKEY_GENERATE;
    case CW_ERROR_ID_RSA_SIGN_MESSAGE_TO_SHORT:
        return CW_ERROR_STR_RSA_SIGN_MESSAGE_TO_SHORT;
    case CW_ERROR_ID_RSA_VERIFY_MESSAGE_TO_SHORT:
        return CW_ERROR_STR_RSA_VERIFY_MESSAGE_TO_SHORT;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_BITS:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_BITS;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES;
    case CW_ERROR_ID_RSA_WRONG_SERIALIZATION_TYPE:
        return CW_ERROR_STR_RSA_WRONG_SERIALIZATION_TYPE;
    case CW_ERROR_ID_RSA_WRONG_SIGN_ALGORITHM:
        return CW_ERROR_STR_RSA_WRONG_SIGN_ALGORITHM;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_SET_RSA_PADDING;
    case CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931:
        return CW_ERROR_STR_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931;
    case CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING:
        return CW_ERROR_STR_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_NEW;
    case CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT_INIT_EX:
        return CW_ERROR_STR_RSA_EVP_PKEY_ENCRYPT_INIT_EX;
    case CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_OAEP_MD:
        return CW_ERROR_STR_RSA_EVP_PKEY_CTX_SET_RSA_OAEP_MD;
    case CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT:
        return CW_ERROR_STR_RSA_EVP_PKEY_ENCRYPT;
    case CW_ERROR_ID_RSA_EVP_PKEY_DECRYPT:
        return CW_ERROR_STR_RSA_EVP_PKEY_DECRYPT;
    case CW_ERROR_ID_FETCH_EVP_CIPHER_FETCH:
        return CW_ERROR_STR_FETCH_EVP_CIPHER_FETCH;
    case CW_ERROR_ID_FETCH_WRONG_EC_SERIALIZATION_TYPE:
        return CW_ERROR_STR_FETCH_WRONG_EC_SERIALIZATION_TYPE;
    case CW_ERROR_ID_FETCH_WRONG_HASH_ALGORITHM:
        return CW_ERROR_STR_FETCH_WRONG_HASH_ALGORITHM;
    case CW_ERROR_ID_FETCH_WRONG_EC_CURVE:
        return CW_ERROR_STR_FETCH_WRONG_EC_CURVE;
    case CW_ERROR_ID_FETCH_OSSL_PROVIDER_LOAD_LEGACY:
        return CW_ERROR_STR_FETCH_OSSL_PROVIDER_LOAD_LEGACY;
    case CW_ERROR_ID_FETCH_EVP_MD_fetch:
        return CW_ERROR_STR_FETCH_EVP_MD_fetch;
    case CW_ERROR_ID_FETCH_WRONG_SYMETRIC_CIPHER_MODE:
        return CW_ERROR_STR_FETCH_WRONG_SYMETRIC_CIPHER_MODE;
    case CW_ERROR_ID_FETCH_WRONG_CMAC_MODE:
        return CW_ERROR_STR_FETCH_WRONG_CMAC_MODE;
    case CW_ERROR_ID_FETCH_WRONG_KMAC_MODE:
        return CW_ERROR_STR_FETCH_WRONG_KMAC_MODE;
    case CW_ERROR_ID_FETCH_WRONG_ARGON_2_MODE:
        return CW_ERROR_STR_FETCH_WRONG_ARGON_2_MODE;
    case CW_ERROR_ID_RANDOM_RAND_BYTES:
        return CW_ERROR_STR_RANDOM_RAND_BYTES;
    case CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC:
        return CW_ERROR_STR_ALLOC_OPENSSL_ZALLOC;
    case CW_ERROR_ID_FILE_COULD_NOT_OPEN:
        return CW_ERROR_STR_FILE_COULD_NOT_OPEN;
    case CW_ERROR_ID_KEY_DERIVATION_KDF_AQUIRE_CONTEXT:
        return CW_ERROR_STR_KEY_DERIVATION_KDF_AQUIRE_CONTEXT;
    case CW_ERROR_ID_KEY_DERIVATION_KDF_DERIVE:
        return CW_ERROR_STR_KEY_DERIVATION_KDF_DERIVE;
    case CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_CTX_NEW:
        return CW_ERROR_STR_KEY_DERIVATION_EVP_KDF_CTX_NEW;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_PTR_NULL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_OUTPUT_PTR_NULL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_SHORT:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_OUTPUT_TOO_SHORT;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_LONG:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_OUTPUT_TOO_LONG;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_SHORT:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_PWD_TOO_SHORT;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_LONG:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_PWD_TOO_LONG;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_SHORT:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SALT_TOO_SHORT;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_LONG:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SALT_TOO_LONG;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_SHORT:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_AD_TOO_SHORT;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_LONG:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_AD_TOO_LONG;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_SHORT:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SECRET_TOO_SHORT;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_LONG:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SECRET_TOO_LONG;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_SMALL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_TIME_TOO_SMALL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_LARGE:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_TIME_TOO_LARGE;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_LITTLE:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_MEMORY_TOO_LITTLE;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_MUCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_MEMORY_TOO_MUCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_FEW:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_LANES_TOO_FEW;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_MANY:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_LANES_TOO_MANY;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_PTR_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_PWD_PTR_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_PTR_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SALT_PTR_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_PTR_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_SECRET_PTR_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_PTR_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_AD_PTR_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_ALLOCATION_ERROR:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_MEMORY_ALLOCATION_ERROR;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_FREE_MEMORY_CBK_NULL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_FREE_MEMORY_CBK_NULL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_ALLOCATE_MEMORY_CBK_NULL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_ALLOCATE_MEMORY_CBK_NULL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_PARAMETER:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_INCORRECT_PARAMETER;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_TYPE:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_INCORRECT_TYPE;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUT_PTR_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_OUT_PTR_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_FEW:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_THREADS_TOO_FEW;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_MANY:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_THREADS_TOO_MANY;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_MISSING_ARGS:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_MISSING_ARGS;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_ENCODING_FAIL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_ENCODING_FAIL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_FAIL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_DECODING_FAIL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREAD_FAIL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_THREAD_FAIL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_LENGTH_FAIL:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_DECODING_LENGTH_FAIL;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_VERIFY_MISMATCH:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_VERIFY_MISMATCH;
    case CW_ERROR_ID_KEY_DERIVATION_ARGON2_UNKNOWN_ERROR_CODE:
        return CW_ERROR_STR_KEY_DERIVATION_ARGON2_UNKNOWN_ERROR_CODE;
    case CW_ERROR_ID_SYM_CIPHER_STREAM_MODE_NOT_ALLOWED:
        return CW_ERROR_STR_SYM_CIPHER_STREAM_MODE_NOT_ALLOWED;
    case CW_ERROR_ID_AEAD_CCM_NOT_SUPPORTED_FOR_STREAM:
        return CW_ERROR_STR_AEAD_CCM_NOT_SUPPORTED_FOR_STREAM;
    case CW_ERROR_ID_ECC_DER_PASSPHRASE_NOT_ALLOWED:
        return CW_ERROR_STR_ECC_DER_PASSPHRASE_NOT_ALLOWED;
    case CW_ERROR_ID_RSA_DER_PASSPHRASE_NOT_ALLOWED:
        return CW_ERROR_STR_RSA_DER_PASSPHRASE_NOT_ALLOWED;
    case CW_ERROR_ID_HASH_STRING_TOO_LARGE:
        return CW_ERROR_STR_HASH_STRING_TOO_LARGE;
    case CW_ERROR_ID_KEY_DERIVATION_PBKDF2_VERIFY:
        return CW_ERROR_STR_KEY_DERIVATION_PBKDF2_VERIFY;
    case CW_ERROR_ID_KEY_DERIVATION_HKDF_VERIFY:
        return CW_ERROR_STR_KEY_DERIVATION_HKDF_VERIFY;
    case CW_ERROR_ID_KEY_DERIVATION_HKDF_WRONG_OUTPUT_LEN:
        return CW_ERROR_STR_KEY_DERIVATION_HKDF_WRONG_OUTPUT_LEN;
    case CW_ERROR_ID_KEY_DERIVATION_SCRYPT_VERIFY:
        return CW_ERROR_STR_KEY_DERIVATION_SCRYPT_VERIFY;
    case CW_ERROR_ID_KEY_DERIVATION_SCRYPT_N_NOT_VALID:
        return CW_ERROR_STR_KEY_DERIVATION_SCRYPT_N_NOT_VALID;
    case CW_ERROR_ID_KEY_DERIVATION_SCRYPT_OUPUT_SIZE_TOO_LARGE:
        return CW_ERROR_STR_KEY_DERIVATION_SCRYPT_OUPUT_SIZE_TOO_LARGE;
    case CW_ERROR_ID_FETCH_WRONG_ARGON_2_VERSION:
        return CW_ERROR_STR_FETCH_WRONG_ARGON_2_VERSION;
    case CW_ERROR_ID_SYM_CIPHER_HIGH_WRONG_KEY_LENGTH:
        return CW_ERROR_STR_SYM_CIPHER_HIGH_WRONG_KEY_LENGTH;
    case CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC:
        return CW_ERROR_STR_ALLOC_OPENSSL_CLEAR_REALLOC;
    case CW_ERROR_ID_RSA_PSS_PADDING_MODE_NOT_ALLOWED_FOR_ENCRYPTION:
        return CW_ERROR_STR_RSA_PSS_PADDING_MODE_NOT_ALLOWED_FOR_ENCRYPTION;
    case CW_ERROR_ID_ENCODE_NO_FILE_IN_PLACE_ALLOWED:
        return CW_ERROR_STR_ENCODE_NO_FILE_IN_PLACE_ALLOWED;
    case CW_ERROR_ID_MAC_SIPHASH_WRONG_KEY_LENGTH:
        return CW_ERROR_STR_MAC_SIPHASH_WRONG_KEY_LENGTH;
    case CW_ERROR_ID_MAC_SIPHASH_WRONG_OUTPUT_LENGTH:
        return CW_ERROR_STR_MAC_SIPHASH_WRONG_OUTPUT_LENGTH;
    default:
        return NULL;
    }
}