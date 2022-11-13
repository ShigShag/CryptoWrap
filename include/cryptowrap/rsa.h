/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file rsa.h
 * @author Shig Shag
 * @brief RSA
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef RSA_H
#define RSA_H

#include "cryptowrap/hash.h"

#include <stdio.h>

/**
 * @brief RSA serialization modes
 * 
 */
typedef enum
{
    CW_RSA_DER,
    CW_RSA_PEM
} cw_rsa_serialization_type;

/**
 * @brief RSA signature hashes
 * 
 */
typedef enum
{
    CW_RSA_SIG_HASH_SHA_1 = CW_SHA_1,
    CW_RSA_SIG_HASH_SHA_224 = CW_SHA_224,
    CW_RSA_SIG_HASH_SHA_256 = CW_SHA_256,
    CW_RSA_SIG_HASH_SHA_384 = CW_SHA_384,
    CW_RSA_SIG_HASH_SHA_512 = CW_SHA_512,
    CW_RSA_SIG_HASH_MD5 = CW_MD5,
    CW_RSA_SIG_HASH_SHA3_224 = CW_SHA3_224,
    CW_RSA_SIG_HASH_SHA3_256 = CW_SHA3_256,
    CW_RSA_SIG_HASH_SHA3_384 = CW_SHA3_384,
    CW_RSA_SIG_HASH_SHA3_512 = CW_SHA3_512
} cw_rsa_signature_hash;

/**
 * @brief RSA padding modes
 * 
 */
typedef enum
{
    CW_RSA_PKCS1_PADDING,

    // Encrypt and decrypt only
    CW_RSA_PKCS1_OAEP_SHA1_PADDING,
    CW_RSA_PKCS1_OAEP_SHA224_PADDING,
    CW_RSA_PKCS1_OAEP_SHA256_PADDING,
    CW_RSA_PKCS1_OAEP_SHA512_PADDING,

    // Sign and verify only
    CW_RSA_PKCS1_PSS_PADDING
} cw_rsa_padding_mode;

/**
 * @brief RSA key pair datatype
 * 
 */
typedef void *CW_RSA_KEY_PAIR;

/**
 * @brief Generate a rsa key pair.
 * @details Bits must not be smaller than 512
 * @param[out] key_pair Where to save the key pair
 * @param[in] bits Size of the key in bits
 * @return int 
 */
int cw_rsa_generate_key_pair(CW_RSA_KEY_PAIR *key_pair, int bits);

/**
 * @brief Delete a key pair
 * 
 * @param[in] key_pair RSA key pair to be deleted
 */
void cw_rsa_delete_key_pair(CW_RSA_KEY_PAIR key_pair);

/**
 * @brief Serialize a rsa public key
 * @details Requires a path to a given file. The file will be created if it does not already exists
 * 
 * @param[in] file_path Where to store the public key
 * @param[in] key_pair Key pair to serialize its public key
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_write_public_key(const char *file_path, CW_RSA_KEY_PAIR key_pair, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Serialize a rsa public key
 * @details Requires a valid file pointer which points to a file in which to save the key
 * 
 * @param[in] fp File Pointer to a file in which to store the public key
 * @param[in] key_pair key pair to serialize its public key
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_write_public_key_fp(FILE *fp, CW_RSA_KEY_PAIR key_pair, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Serialize a rsa key pair
 * @details Requires a path to a given file. The file will be created if it does not already exists. If desired, a passphrase my be used.
 * If a passphrase is given, the contents will be encrypted with AES 256 CBC
 * 
 * @param[in] file_path Where to store the key pair
 * @param[in] key_pair key pair to serialize
 * @param[in] passphrase Optional: Passphrase to encrypt the key pair
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_write_private_key(const char *file_path, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Serialize a rsa key pair
* @details Required a valid file pointer which points to a file in which to save the key. If desired, a passphrase my be used.
 * If a passphrase is given, the contents will be encrypted with AES 256 CBC
 * 
 * @param[in] fp File Pointer to a file in which to store the key pair
 * @param[in] key_pair key pair to serialize
 * @param[in] passphrase Optional: Passphrase to encrypt the key pair
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_write_private_key_fp(FILE *fp, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Deserialize a public key from a file
 * @details Requires a valid path to a file.
 * 
 * @param[in] file_path From which file to deserialize the key
 * @param[out] key_pair Where to store the key
 * @param[in] serialization_mode Serialization format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_load_public_key(const char *file_path, CW_RSA_KEY_PAIR *key_pair, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Deserialize a public key from a file
 * @details Required a valid file pointer which points to a file which holds the key.
 * 
 * @param[in] fp File Pointer to a file which stores the key
 * @param[out] key_pair Where to store the key
 * @param[in] serialization_mode Serialization format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_load_public_key_fp(FILE *fp, CW_RSA_KEY_PAIR *key_pair, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Deserialize an rsa key pair
 * @details Requires a path to a file which holds the key pair. If the file was encrypted with AES 256 CBC,
 * the passphrase parameter can be used to decrypt it.
 * 
 * @param[in] file_path From which file to deserialize the key
 * @param[out] key_pair Where to store the key
 * @param[in] passphrase Optional: Passphrase to decrypt the key pair
 * @param[in] serialization_mode Serialization format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_load_private_key(const char *file_path, CW_RSA_KEY_PAIR *key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode);

/**
 * @brief Deserialize an rsa key pair
 * @details Requires a valid file pointer which points to a file which holds the key pair. 
 * If the file was encrypted with AES 256 CBC,
 * the passphrase parameter can be used to decrypt it.
 * 
 * @param[in] fp File Pointer to a file in which stores the key pair
 * @param[out] key_pair Where to store the key
 * @param[in] passphrase Optional: Passphrase to decrypt the key pair
 * @param[in] serialization_mode Serialization format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_load_private_key_fp(FILE *fp, CW_RSA_KEY_PAIR *key_pair, const char *passphrase, cw_rsa_serialization_type serialization_mode);


/**
 * @brief Output is not allocated within the function
 * 
 */
#define RSA_NO_ALLOC 0x00000001

/**
 * @brief Sign a byte sequence with a rsa private key
 * @details A hash and padding algorithm needs to be set for signature.
 * 
 * @param[in] key_pair Key pair to be used for signing
 * @param[in] message Message to be signed
 * @param[in] message_len Length of message
 * @param[in] hash Hash algorithm to use for signing
 * @param[in] padding_mode Padding mode for signing:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_PSS_PADDING
 * @param[out] signature Where to save the signature
 * @param[out] signature_len Optional: Where to save the signature length
 * @param[in] flags 
 *      - RSA_NO_ALLOC Output is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_sign_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *message, const uint32_t message_len,
                      cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode, uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

/**
 * @brief Sign a string with a rsa private key
 * @details A hash and padding algorithm needs to be set for signature.
 * 
 * @param[in] key_pair Key pair to be used for signing
 * @param[in] message Message to be signed 
 * @param[in] hash Hash algorithm to use for signing
 * @param[in] padding_mode Padding mode for signing:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_PSS_PADDING
 * @param[out] signature Where to save the signature
 * @param[out] signature_len Optional: Where to save the signature length
 * @param[in] flags 
 *      - RSA_NO_ALLOC Output is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_sign_string(CW_RSA_KEY_PAIR key_pair, const char *message,
                       cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode, uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

/**
 * @brief Verify a signature to a given byte sequence with a rsa private key
 * @details Hash and padding algorithm needs to be the same used for signing
 * 
 * @param[in] key_pair Key pair to be used for verification
 * @param[in] message Message to be verified
 * @param[in] message_len Length of message
 * @param[in] signature Given signature which is used for verification
 * @param[in] signature_len Signature length
 * @param[in] hash Hash algorithm to use for signing
 * @param[in] padding_mode Padding mode for signing:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_PSS_PADDING
 * @return int Returns 1 if verification was successful, zero for failure
 */
int cw_rsa_verify_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *message, const uint32_t message_len,
                        const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode);

/**
 * @brief Verify a signature to a given string with a rsa private key
 * @details Hash and padding algorithm needs to be the same used for signing
 * 
 * @param[in] key_pair Key pair to be used for verification
 * @param[in] message Message to be verified
 * @param[in] signature Given signature which is used for verification
 * @param[in] signature_len Signature length
 * @param[in] hash Hash algorithm to use for signing
 * @param[in] padding_mode Padding mode for signing:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_PSS_PADDING
 * @return int Returns 1 if verification was successful, zero for failure
 */
int cw_rsa_verify_string(CW_RSA_KEY_PAIR key_pair, const char *message,
                         const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, cw_rsa_padding_mode padding_mode);

/**
 * @brief Encrypt bytes with a rsa key pair
 * 
 * @param[in] key_pair Key pair to use for encryption
 * @param[in] plaintext Plaintext to be encrypted
 * @param[in] plaintext_len Plaintext length
 * @param[out] ciphertext Where to save the ciphertext
 * @param[out] ciphertext_len Optional: Where to save the ciphertext length
 * @param[in] padding_mode Padding mode for encryption:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA1_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA224_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA256_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA512_PADDING
 * @param[in] flags 
 *      - RSA_NO_ALLOC Output is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_encrypt_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *plaintext, const uint64_t plaintext_len, uint8_t **ciphertext,
                         uint64_t *ciphertext_len, cw_rsa_padding_mode padding_mode, const uint8_t flags);

/**
 * @brief Decrypt bytes with a rsa key pair
 * 
 * @param[in] key_pair Key pair to use for encryption
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertext_len Ciphertext length
 * @param[out] plaintext Where to save the plaintext
 * @param[out] plaintext_len Optional: Where to save the plaintext length
 * @param[in] padding_mode Padding mode for encryption:
 *      - CW_RSA_PKCS1_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA1_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA224_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA256_PADDING
 *      - CW_RSA_PKCS1_OAEP_SHA512_PADDING
 * @param[in] flags 
 *      - RSA_NO_ALLOC Output is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_rsa_decrypt_bytes(CW_RSA_KEY_PAIR key_pair, const uint8_t *ciphertext, const uint64_t ciphertext_len, uint8_t **plaintext,
                         uint64_t *plaintext_len, cw_rsa_padding_mode padding_mode, const uint8_t flags);

#endif
