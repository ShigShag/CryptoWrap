/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef ERROR_INTERNAL_H
#define ERROR_INTERNAL_H

#include "cryptowrap/error.h"

typedef int error_id;

/* Error id´s */
#define CW_ERROR_ID_TEST                                                     0x01
#define CW_ERROR_ID_PARAM_MISSING                                            0x02
#define CW_ERROR_ID_AEAD_GCM_IV_NOT_SET                                      0x03
#define CW_ERROR_ID_AEAD_GCM_TAG_LEN_WRONG                                   0x04
#define CW_ERROR_ID_AEAD_CCM_IV_LEN_WRONG                                    0x05
#define CW_ERROR_ID_AEAD_CCM_TAG_LEN_WRONG                                   0x06
#define CW_ERROR_ID_AEAD_CCM_INPUT_TOO_LARGE                                 0x07
#define CW_ERROR_ID_AEAD_OCB_IV_LEN_WRONG                                    0x08
#define CW_ERROR_ID_AEAD_OCB_TAG_LEN_WRONG                                   0x09
#define CW_ERROR_ID_AEAD_CHACHA_20_IV_LEN_WRONG                              0x0a
#define CW_ERROR_ID_AEAD_CHACHA_20_TAG_LEN_WRONG                             0x0b
#define CW_ERROR_ID_AEAD_UNKNOWN_ALGORITHM                                   0x0c
#define CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_NEW                                  0x0d
#define CW_ERROR_ID_AEAD_EVP_CIPHER_INIT_EX2                                 0x0e
#define CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_IV_LEN                           0x0f
#define CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_SET_TAG                          0x10
#define CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE                                   0x11
#define CW_ERROR_ID_AEAD_EVP_CIPHER_UPDATE_AAD                               0x12
#define CW_ERROR_ID_AEAD_EVP_CIPHER_FINAL_EX                                 0x13
#define CW_ERROR_ID_AEAD_EVP_CIPHER_CTX_CTR_GET_TAG                          0x14
#define CW_ERROR_ID_AEAD_WRONG_KEY_LEN                                       0x15
#define CW_ERROR_ID_AEAD_CCM_NOT_SUPPORTED_FOR_STREAM                        0x16
#define CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_NEW_FOR_PKEY                        0x17
#define CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_CIPHER                          0x18
#define CW_ERROR_ID_ECC_OSSL_ENCODER_CTX_SET_PASSPHRASE                      0x19
#define CW_ERROR_ID_ECC_OSSL_ENCODER_TO_FP                                   0x1a
#define CW_ERROR_ID_ECC_OSSL_DECODER_CTX_NEW_FOR_PKEY                        0x1b
#define CW_ERROR_ID_ECC_OSSL_DECODER_CTX_SET_PASSPHRASE                      0x1c
#define CW_ERROR_ID_ECC_OSSL_DECODER_FROM_FP                                 0x1d
#define CW_ERROR_ID_ECC_EVP_MD_CTX_NEW                                       0x1e
#define CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_INIT_EX                              0x1f
#define CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_UPDATE                               0x20
#define CW_ERROR_ID_ECC_EVP_DIGEST_SIGN_FINAL                                0x21
#define CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_INIT_EX                            0x22
#define CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_UPDATE                             0x23
#define CW_ERROR_ID_ECC_EVP_DIGEST_VERIFY_FINAL                              0x24
#define CW_ERROR_ID_ECC_EVP_PKEY_CTX_NEW_ID                                  0x25
#define CW_ERROR_ID_ECC_EVP_PKEY_KEYGEN_INIT                                 0x26
#define CW_ERROR_ID_ECC_EVP_PKEY_CTX_SET_EC_PARAMGEN_CURVE_NID               0x27
#define CW_ERROR_ID_ECC_EVP_PKEY_GENERATE                                    0x28
#define CW_ERROR_ID_ECC_SIGN_MESSAGE_TO_SHORT                                0x29
#define CW_ERROR_ID_ECC_VERIFY_MESSAGE_TO_SHORT                              0x2a
#define CW_ERROR_ID_ECC_DER_PASSPHRASE_NOT_ALLOWED                           0x2b
#define CW_ERROR_ID_ENCODE_EVP_ENCODE_CTX_NEW                                0x2c
#define CW_ERROR_ID_ENCODE_EVP_ENCODE_UPDATE                                 0x2d
#define CW_ERROR_ID_ENCODE_EVP_DECODE_UPDATE                                 0x2e
#define CW_ERROR_ID_ENCODE_EVP_DECODE_FINAL                                  0x2f
#define CW_ERROR_ID_ENCODE_STREAM_WRONG_MODE                                 0x30
#define CW_ERROR_ID_ENCODE_NO_FILE_IN_PLACE_ALLOWED                          0x31
#define CW_ERROR_ID_HASH_EVP_MD_CTX_NEW                                      0x32
#define CW_ERROR_ID_HASH_EVP_DIGEST_INIT_EX_2                                0x33
#define CW_ERROR_ID_HASH_EVP_DIGEST_UPDATE                                   0x34
#define CW_ERROR_ID_HASH_EVP_DIGEST_FINAL_EX                                 0x35
#define CW_ERROR_ID_HASH_VERIFY_LEN_MISMATCH                                 0x36
#define CW_ERROR_ID_HASH_VERIFY_HASH_MISMATCH                                0x37
#define CW_ERROR_ID_HASH_STRING_TOO_LARGE                                    0x38
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X25519           0x39
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X448             0x3a
#define CW_ERROR_ID_KEY_EXCH_ECDH_GET_PEER_PUBLIC_KEY                        0x3b
#define CW_ERROR_ID_KEY_EXCH_DERIVE_PUBLIC_KEY_WRONG_MODE                    0x3c
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_CTX_NEW_FROM_PKEY                      0x3d
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_INIT                            0x3e
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_SET_PEER                        0x3f
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE                                 0x40
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM                 0x41
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X25519                        0x42
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X25519   0x43
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X448                          0x44
#define CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X448     0x45
#define CW_ERROR_ID_MAC_EVP_MAC_UPDATE                                       0x46
#define CW_ERROR_ID_MAC_EVP_MAC_FINAL                                        0x47
#define CW_ERROR_ID_MAC_EVP_MAC_CTX_NEW                                      0x48
#define CW_ERROR_ID_MAC_EVP_MAC_CTX_INIT                                     0x49
#define CW_ERROR_ID_MAC_EVP_MAC_CTX_SET_PARAMS                               0x4a
#define CW_ERROR_ID_MAC_EVP_MAC_FETCH                                        0x4b
#define CW_ERROR_ID_MAC_VERIFY_LEN_MISMATCH                                  0x4c
#define CW_ERROR_ID_MAC_VERIFY_MAC_MISMATCH                                  0x4d
#define CW_ERROR_ID_MAC_SIPHASH_WRONG_KEY_LENGTH                             0x4e
#define CW_ERROR_ID_MAC_SIPHASH_WRONG_OUTPUT_LENGTH                          0x4f
#define CW_ERROR_ID_SYM_CIPHER_WRONG_KEY_LEN                                 0x50
#define CW_ERROR_ID_SYM_CIPHER_WRONG_IV_LEN                                  0x51
#define CW_ERROR_ID_SYM_CIPHER_INPUT_SIZE_TOO_SHORT_FOR_XTS                  0x52
#define CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_CTX_NEW                            0x53
#define CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_INIT_EX2                           0x54
#define CW_ERROR_ID_SYM_CIPHER_EVP_CIPHER_UPDATE                             0x55
#define CW_ERROR_ID_SYM_CIPHER_EVP_CIPHERFINAL_EX                            0x56
#define CW_ERROR_ID_SYM_CIPHER_HIGH_MAC_MISMATCH                             0x57
#define CW_ERROR_ID_SYM_CIPHER_STREAM_MODE_NOT_ALLOWED                       0x58
#define CW_ERROR_ID_SYM_CIPHER_HIGH_WRONG_KEY_LENGTH                         0x59
#define CW_ERROR_ID_RSA_WRONG_PADDING_MODE                                   0x5a
#define CW_ERROR_ID_RSA_KEY_SIZE_TOO_SMALL                                   0x5b
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW_ID                                  0x5c
#define CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_NEW_FOR_PKEY                        0x5d
#define CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_CIPHER                          0x5e
#define CW_ERROR_ID_RSA_OSSL_ENCODER_CTX_SET_PASSPHRASE                      0x5f
#define CW_ERROR_ID_RSA_OSSL_ENCODER_TO_FP                                   0x60
#define CW_ERROR_ID_RSA_OSSL_DECODER_CTX_NEW_FOR_PKEY                        0x61
#define CW_ERROR_ID_RSA_OSSL_DECODER_CTX_SET_PASSPHRASE                      0x62
#define CW_ERROR_ID_RSA_OSSL_OSSL_DECODER_FROM_FP                            0x63
#define CW_ERROR_ID_RSA_EVP_MD_CTX_NEW                                       0x64
#define CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_INIT_EX                              0x65
#define CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_UPDATE                               0x66
#define CW_ERROR_ID_RSA_EVP_DIGEST_SIGN_FINAL                                0x67
#define CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_INIT_EX                            0x68
#define CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_UPDATE                             0x69
#define CW_ERROR_ID_RSA_EVP_DIGEST_VERIFY_FINAL                              0x6a
#define CW_ERROR_ID_RSA_EVP_PKEY_KEYGEN_INIT                                 0x6b
#define CW_ERROR_ID_RSA_EVP_PKEY_GENERATE                                    0x6c
#define CW_ERROR_ID_RSA_SIGN_MESSAGE_TO_SHORT                                0x6d
#define CW_ERROR_ID_RSA_VERIFY_MESSAGE_TO_SHORT                              0x6e
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_BITS                     0x6f
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES                   0x70
#define CW_ERROR_ID_RSA_WRONG_SERIALIZATION_TYPE                             0x71
#define CW_ERROR_ID_RSA_WRONG_SIGN_ALGORITHM                                 0x72
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_PADDING                         0x73
#define CW_ERROR_ID_RSA_SIGNATURE_MODE_NOT_ALLOWED_FOR_X931                  0x74
#define CW_ERROR_ID_RSA_PADDING_MODE_NOT_ALLOWED_FOR_SIGNING                 0x75
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_NEW                                     0x76
#define CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT_INIT_EX                             0x77
#define CW_ERROR_ID_RSA_EVP_PKEY_CTX_SET_RSA_OAEP_MD                         0x78
#define CW_ERROR_ID_RSA_EVP_PKEY_ENCRYPT                                     0x79
#define CW_ERROR_ID_RSA_EVP_PKEY_DECRYPT                                     0x7a
#define CW_ERROR_ID_RSA_DER_PASSPHRASE_NOT_ALLOWED                           0x7b
#define CW_ERROR_ID_RSA_PSS_PADDING_MODE_NOT_ALLOWED_FOR_ENCRYPTION          0x7c
#define CW_ERROR_ID_FETCH_EVP_CIPHER_FETCH                                   0x7d
#define CW_ERROR_ID_FETCH_WRONG_EC_SERIALIZATION_TYPE                        0x7e
#define CW_ERROR_ID_FETCH_WRONG_HASH_ALGORITHM                               0x7f
#define CW_ERROR_ID_FETCH_WRONG_EC_CURVE                                     0x80
#define CW_ERROR_ID_FETCH_OSSL_PROVIDER_LOAD_LEGACY                          0x81
#define CW_ERROR_ID_FETCH_EVP_MD_fetch                                       0x82
#define CW_ERROR_ID_FETCH_WRONG_SYMETRIC_CIPHER_MODE                         0x83
#define CW_ERROR_ID_FETCH_WRONG_CMAC_MODE                                    0x84
#define CW_ERROR_ID_FETCH_WRONG_KMAC_MODE                                    0x85
#define CW_ERROR_ID_FETCH_WRONG_ARGON_2_MODE                                 0x86
#define CW_ERROR_ID_FETCH_WRONG_ARGON_2_VERSION                              0x87
#define CW_ERROR_ID_RANDOM_RAND_BYTES                                        0x88
#define CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC                                     0x89
#define CW_ERROR_ID_ALLOC_OPENSSL_CLEAR_REALLOC                              0x8a
#define CW_ERROR_ID_FILE_COULD_NOT_OPEN                                      0x8b
#define CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_CTX_GET_KDF_SIZE                  0x8c
#define CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_FETCH                             0x8d
#define CW_ERROR_ID_KEY_DERIVATION_PBKDF2_VERIFY                             0x8e
#define CW_ERROR_ID_KEY_DERIVATION_HKDF_VERIFY                               0x8f
#define CW_ERROR_ID_KEY_DERIVATION_KDF_AQUIRE_CONTEXT                        0x90
#define CW_ERROR_ID_KEY_DERIVATION_KDF_DERIVE                                0x91
#define CW_ERROR_ID_KEY_DERIVATION_EVP_KDF_CTX_NEW                           0x92
#define CW_ERROR_ID_KEY_DERIVATION_HKDF_WRONG_OUTPUT_LEN                     0x93
#define CW_ERROR_ID_KEY_DERIVATION_SCRYPT_VERIFY                             0x94
#define CW_ERROR_ID_KEY_DERIVATION_SCRYPT_N_NOT_VALID                        0x95
#define CW_ERROR_ID_KEY_DERIVATION_SCRYPT_OUPUT_SIZE_TOO_LARGE               0x96
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_PTR_NULL                    0x97
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_SHORT                   0x98
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUTPUT_TOO_LONG                    0x99
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_SHORT                      0x9a
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_TOO_LONG                       0x9b
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_SHORT                     0x9c
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_TOO_LONG                      0x9d
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_SHORT                       0x9e
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_TOO_LONG                        0x9f
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_SHORT                   0xa0
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_TOO_LONG                    0xa1
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_SMALL                     0xa2
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_TIME_TOO_LARGE                     0xa3
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_LITTLE                  0xa4
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_TOO_MUCH                    0xa5
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_FEW                      0xa6
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_LANES_TOO_MANY                     0xa7
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_PWD_PTR_MISMATCH                   0xa8
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SALT_PTR_MISMATCH                  0xa9
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_SECRET_PTR_MISMATCH                0xaa
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_AD_PTR_MISMATCH                    0xab
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_MEMORY_ALLOCATION_ERROR            0xac
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_FREE_MEMORY_CBK_NULL               0xad
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_ALLOCATE_MEMORY_CBK_NULL           0xae
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_PARAMETER                0xaf
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_INCORRECT_TYPE                     0xb0
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_OUT_PTR_MISMATCH                   0xb1
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_FEW                    0xb2
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREADS_TOO_MANY                   0xb3
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_MISSING_ARGS                       0xb4
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_ENCODING_FAIL                      0xb5
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_FAIL                      0xb6
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_THREAD_FAIL                        0xb7
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_DECODING_LENGTH_FAIL               0xb8
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_VERIFY_MISMATCH                    0xb9
#define CW_ERROR_ID_KEY_DERIVATION_ARGON2_UNKNOWN_ERROR_CODE                 0xba

#define ERROR_TYPE_INTERNALS_LEN (50)
#define ERROR_OPENSSL_ERROR_STRING_LEN (256)

#define ERROR_STRING_SIZE ((ERROR_TYPE_INTERNALS_LEN * 2) + ERROR_OPENSSL_ERROR_STRING_LEN + 256)

#define ERROR_STRING_EXPANDED "CW_ERROR --> [Code:%x][File:%s][Func:%s][Line:%d][Msg:%s]\n"
#define ERROR_STRING_EXPANDED_OPENSSL "     CW_ERROR --> [Code:%x][File:%s][Func:%s][Line:%d][Msg:%s]\n" \
                                      "OPENSSL_ERROR --> [Code:%ld][Msg:%s]\n"

#define ERROR_STRING_NO_ERROR_MSG_GIVEN_STRING "No error message available"                                      

typedef struct
{
    error_id id;
    char file[ERROR_TYPE_INTERNALS_LEN];
    char func[ERROR_TYPE_INTERNALS_LEN];
    int line;

    uint64_t openssl_error_code;
    char openssl_error_string[ERROR_OPENSSL_ERROR_STRING_LEN];
    uint32_t openssl_error_string_len;
} ERROR_TYPE;

#define ERROR_STACK_MAX_COUNT 30

typedef struct
{
    ERROR_TYPE stack[ERROR_STACK_MAX_COUNT];

    uint32_t entry_count;
    int is_locked;
} ERROR_STACK;

#define CW_ERROR_STACK_LOCK(stack) \
    while (stack.is_locked != 0)   \
    {                              \
    }                              \
    stack.is_locked = 1

#define CW_ERROR_STACK_UNLOCK(stack) \
    if (stack.is_locked == 1)        \
    stack.is_locked = 0

#define CW_ERROR_STACK_CRITICAL(stack, exp) \
    CW_ERROR_STACK_LOCK(stack);             \
    exp;                                    \
    CW_ERROR_STACK_UNLOCK(stack)

#define ERROR_NO_ERROR 0xff

int cw_error_stack_full();
int cw_error_stack_empty();
void cw_error_stack_push(ERROR_TYPE err);
int cw_error_stack_pop(ERROR_TYPE *err);
int cw_error_stack_top(ERROR_TYPE *err);

int cw_error_type_construct_string(ERROR_TYPE err, char **out, uint32_t *out_len);

const char *cw_error_get_string(error_id id);

#define CW_ERROR_RAISE(id) (cw_error_set_error_ex(__FILE__, __func__, __LINE__, id))

void cw_error_set_error_ex(const char *file, const char *func, int line, error_id id);

// void CW_error_set_error(error_id id);

#endif