/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file ecc.h
 * @author Shig Shag
 * @brief Elliptic curve cryptography
 * @version 0.1
 * @date 2022-11-01
 *
 * @copyright Copyright (c) 2022 Leon Weinmann
 *
 */

#ifndef ECC_H
#define ECC_H

#include "cryptowrap/hash.h"

/**
 * @brief Elliptic curves which can be used in the interface
 *
 */
typedef enum
{
    // 224-bit prime field Weierstrass curve
    CW_SECP224K1,
    CW_ANSIP224K1 = CW_SECP224K1,

    // 224-bit prime field Weierstrass curve
    CW_SECP224R1,
    CW_NIST_P_224 = CW_SECP224R1,
    CW_ANSIP224R1 = CW_SECP224R1,
    CW_WAP_WSG_IDM_ECID_WTLS12 = CW_SECP224R1,

    // 256-bit prime field Weierstrass curve
    CW_SECP256K1,
    CW_ANSIP256K1 = CW_SECP256K1,

    // 384-bit prime field Weierstrass curve
    CW_SECP384R1,
    CW_NIST_P_384 = CW_SECP384R1,
    CW_ANSIP384R1 = CW_SECP384R1,

    // 521-bit prime field Weierstrass curve.
    CW_SECP521R1,
    CW_NIST_P_512 = CW_SECP521R1,
    CW_ANSIP521R1 = CW_SECP521R1,

    // 239-bit prime field Weierstrass curve
    CW_PRIME239V1,

    // 239-bit prime field Weierstrass curve
    CW_PRIME239V2,

    // 239-bit prime field Weierstrass curve
    CW_PRIME239V3,

    // 256-bit prime field Weierstrass curve
    CW_PRIME256V1,
    CW_NIST_P_256 = CW_PRIME256V1,
    CW_SECP256R1 = CW_PRIME256V1,

    // 233-bit binary field Weierstrass curve
    CW_SECT233K1,
    CW_NIST_K_233 = CW_SECT233K1,
    CW_ANSIT233K1 = CW_SECT233K1,
    CW_WAP_WSG_IDM_ECID_WTLS10 = CW_SECT233K1,

    // 233-bit binary field Weierstrass curve
    CW_SECT233R1,
    CW_ANSIT233R1 = CW_SECT233R1,
    CW_WAP_WSG_IDM_ECID_WTLS11 = CW_SECT233R1,

    // 239-bit binary field Weierstrass curve
    CW_SECT239K1,
    CW_ANSIT239K1 = CW_SECT239K1,

    // 283-bit binary field Weierstrass curve
    CW_SECT283K1,
    CW_ANSIT283K1 = CW_SECT283K1,

    // 283-bit binary field Weierstrass curve
    CW_SECT283R1,
    CW_ANSIT283R1 = CW_SECT283R1,

    // 409-bit binary field Weierstrass curve
    CW_SECT409K1,
    CW_ANSIT409K1 = CW_SECT409K1,

    // 409-bit binary field Weierstrass curve
    CW_SECT409R1,
    CW_ANSIT409R1 = CW_SECT409R1,

    // 571-bit binary field Weierstrass curve
    CW_SECT571K1,
    CW_ANSIT571K1 = CW_SECT571K1,

    // 571-bit binary field Weierstrass curve
    CW_SECT571R1,
    CW_ANSIT571R1 = CW_SECT571R1,

    // 239-bit binary field Weierstrass curve
    CW_C2TNB239V1,

    // 239-bit binary field Weierstrass curve
    CW_C2TNB239V2,

    // 239-bit binary field Weierstrass curve
    CW_C2TNB239V3,

    // 272-bit binary field Weierstrass curve
    CW_C2PNB272W1,

    // 304-bit binary field Weierstrass curve
    CW_C2PNB304W1,

    // 359-bit binary field Weierstrass curve
    CW_C2TNB359V1,

    // 368-bit binary field Weierstrass curve
    CW_C2PNB368W1,

    // 431-bit binary field Weierstrass curve
    CW_C2TNB431R1,

    // 224-bit prime field Weierstrass curve
    CW_BRAINPOOLP224R1,
    CW_BRAINPOOLP224T1,

    // 256-bit prime field Weierstrass curve
    CW_BRAINPOOLP256R1,
    CW_BRAINPOOLP256T1,

    // 320-bit prime field Weierstrass curve
    CW_BRAINPOOLP320R1,
    CW_BRAINPOOLP320T1,

    // 384-bit prime field Weierstrass curve
    CW_BRAINPOOLP384R1,
    CW_BRAINPOOLP384T1,

    // 512-bit prime field Weierstrass curve
    CW_BRAINPOOLP512R1,
    CW_BRAINPOOLP512T1
} cw_elliptic_curve_type;

/**
 * @brief Serialization formats to store keys
 *
 */
typedef enum
{
    CW_ECC_DER,
    CW_ECC_PEM,
} cw_ecc_serialization_type;

/**
 * @brief Signature hashes which can be used to sign messages
 *
 */
typedef enum
{
    CW_ECC_SIG_HASH_SHA1 = CW_SHA_1,
    CW_ECC_SIG_HASH_SHA224 = CW_SHA_224,
    CW_ECC_SIG_HASH_SHA256 = CW_SHA_256,
    CW_ECC_SIG_HASH_SHA384 = CW_SHA_384,
    CW_ECC_SIG_HASH_SHA512 = CW_SHA_512,
    CW_ECC_SIG_HASH_MD5 = CW_MD5,
    CW_ECC_SIG_HASH_SHA3_224 = CW_SHA3_224,
    CW_ECC_SIG_HASH_SHA3_256 = CW_SHA3_256,
    CW_ECC_SIG_HASH_SHA3_384 = CW_SHA3_384,
    CW_ECC_SIG_HASH_SHA3_512 = CW_SHA3_512,
} cw_ecc_signature_hash;

/**
 * @brief Type to store elliptic curve key pairs
 *
 */
typedef void *ECC_KEY_PAIR;

/**
 * @brief Generate an elliptic curve key pair
 *
 * @param[out] key_pair Where to store the key pair
 * @param[in] curve_type Curve to be used for key generation
 * @return int Returns 1 for success and 0 for failure
 */
int cw_ecc_generate_key_pair(ECC_KEY_PAIR *key_pair, cw_elliptic_curve_type curve_type);

/**
 * @brief Delete an elliptic curve key pair
 *
 * @param[in] key_pair Key pair to be deleted
 */
void cw_ecc_delete_key_pair(ECC_KEY_PAIR key_pair);

/**
 * @brief Serialize an elliptic curve public key
 * @details Requires a path to a given file. The file will be created if it does not already exists
 *
 * @param[in] file_path Where to store the public key
 * @param[in] key_pair Key pair to serialize its public key
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_ecc_write_public_key(const char *file_path, ECC_KEY_PAIR key_pair, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Serialize an elliptic curve public key
 * @details Requires a valid file pointer which points to a file in which to save the key
 *
 * @param[in] fp File Pointer to a file in which to store the public key
 * @param[in] key_pair key pair to serialize its public key
 * @param[in] serialization_mode Output format
 *      - DER
 *      - PEM
 * @return int Returns 1 for success and 0 for failure
 */
int cw_ecc_write_public_key_fp(FILE *fp, ECC_KEY_PAIR key_pair, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Serialize an elliptic curve key pair
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
int cw_ecc_write_private_key(const char *file_path, ECC_KEY_PAIR key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Serialize an elliptic curve key pair
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
int cw_ecc_write_private_key_fp(FILE *fp, ECC_KEY_PAIR key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode);
// serialization_mode
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
int cw_ecc_load_public_key(const char *file_path, ECC_KEY_PAIR *key_pair, cw_ecc_serialization_type serialization_mode);

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
int cw_ecc_load_public_key_fp(FILE *fp, ECC_KEY_PAIR *key_pair, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Deserialize an elliptic curve key pair
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
int cw_ecc_load_private_key(const char *file_path, ECC_KEY_PAIR *key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Deserialize an elliptic curve key pair
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
int cw_ecc_load_private_key_fp(FILE *fp, ECC_KEY_PAIR *key_pair, const char *passphrase, cw_ecc_serialization_type serialization_mode);

/**
 * @brief Do not allocate signature
 * 
 */
#define ECC_NO_ALLOC 0x00000001

/**
 * @brief Sign a byte sequence with an elliptic curve key pair
 * @details A hash algorithm needs to be set for signature.
 * 
 * @param[in] key_pair Key pair to be used for signing
 * @param[in] input Byte sequence to be signed
 * @param[in] message_len Length of byte sequence
 * @param[in] hash_algorithm Hash algorithm to use for signature
 * @param[out] signature Where to save the signature
 * @param[out] signature_len Optional: Where to save the signature length
 * @param[in] flags Flags
 *      - ECC_NO_ALLOC Do not allocate signature
 * @return int Returns 1 for success and 0 for failure
 */
int cw_ecc_sign_bytes(ECC_KEY_PAIR key_pair, const uint8_t *input, const uint64_t message_len,
                     cw_ecc_signature_hash hash_algorithm, uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

/**
 * @brief Sign a string with an elliptic curve key pair
 * @details A hash algorithm needs to be set for signature.
 *
 * @param[in] key_pair Key pair to be used for signing
 * @param[in] input Byte sequence to be signed
 * @param[in] hash_algorithm Hash algorithm to use for signature
 * @param[out] signature Where to save the signature
 * @param[out] signature_len Optional: Where to save the signature length
 * @param[in] flags Flags
 *      - ECC_NO_ALLOC Do not allocate signature
 * @return int Returns 1 for success and 0 for failure
 */
int cw_ecc_sign_string(ECC_KEY_PAIR key_pair, const char *input, cw_ecc_signature_hash hash_algorithm,
                      uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

/**
 * @brief Verify a signature to a given byte sequence with an elliptic curve key pair
 * @details Hash algorithm needs to be the same used for signing
 * 
 * @param[in] key_pair Key pair to be used for verification
 * @param[in] input Byte sequence to be verified
 * @param[in] message_len Byte sequence length
 * @param[in] signature Given signature which is used for verification
 * @param[in] signature_len Signature length
 * @param[in] hash_algorithm Hash algorithm to use for signature
 * @return int Returns 1 if verification was successful, zero for failure
 */
int cw_ecc_verify_bytes(ECC_KEY_PAIR key_pair, const uint8_t *input, const uint64_t message_len,
                       uint8_t *signature, const uint64_t signature_len, cw_ecc_signature_hash hash_algorithm);

/**
 * @brief Verify a signature to a given string with an elliptic curve key pair
 * @details Hash algorithm needs to be the same used for signing
 * 
 * @param[in] key_pair Key pair to be used for verification 
 * @param[in] input Byte sequence to be verified
 * @param[in] signature Given signature which is used for verification
 * @param[in] signature_len Signature length
 * @param[in] hash_algorithm Hash algorithm to use for signature
 * @return int Returns 1 if verification was successful, zero for failure
 */
int cw_ecc_verify_string(ECC_KEY_PAIR key_pair, const char *input, uint8_t *signature, const uint64_t signature_len,
                        cw_ecc_signature_hash hash_algorithm);

#endif