/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file key_derivation.h
 * @author Shig Shag
 * @brief Key derivation
 * @version 0.1
 * @date 2022-11-01
 *
 * @copyright Copyright (c) 2022 Leon Weinmann
 *
 */

#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include "cryptowrap/hash.h"

#include <stdint.h>

/**
 * @brief Output is not allocated within the function
 *
 */
#define KEY_DERIVATION_NO_ALLOC 0x00000001

/**
 * @brief Set output length of output
 * Only relevant for PBKDF2
 *
 */
#define KEY_DERIVATION_SET_OUTPUT_LEN 0x00000002

/* PBKDF2 */
/**
 * @brief Default iterations for PBKDF2
 *
 */
#define PBKDF2_DEFAULT_ITERATIONS 2000000

/**
 * @brief Default hash algorithm for PBKDF2
 *
 */
#define KDF_DEFAULT_ALGORITHM CW_KDH_SHA3_256

/**
 * @brief Available hash functions for PBKDF2 and HKDF
 *
 */
typedef enum
{
    CW_KDH_MD5 = CW_MD5,
    CW_KDH_SHA_1 = CW_SHA_1,
    CW_KDH_SHA_224 = CW_SHA_224,
    CW_KDH_SHA_256 = CW_SHA_256,
    CW_KDH_SHA_384 = CW_SHA_384,
    CW_KDH_SHA_512 = CW_SHA_512,
    CW_KDH_SHA_512_224 = CW_SHA_512_224,
    CW_KDH_SHA_512_256 = CW_SHA_512_256,
    CW_KDH_SHA3_224 = CW_SHA3_224,
    CW_KDH_SHA3_256 = CW_SHA3_256,
    CW_KDH_SHA3_384 = CW_SHA3_384,
    CW_KDH_SHA3_512 = CW_SHA3_512,
    CW_KDH_SM_3 = CW_SM_3,
    CW_KDH_BLAKE2S_256 = CW_BLAKE2S_256,
    CW_KDH_BLAKE2B_512 = CW_BLAKE2B_512
} key_derivation_hash;

/**
 * @brief PBKDF2
 * @details Iterations and algorithm are handled by the interface
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[out] out Where to save the result
 * @param[out] out_len Where to save the result length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 *      - KEY_DERIVATION_SET_OUTPUT_LEN Set the output length. Values larger than the hash itself are ignored
 * @return int Returns 1 for success and 0 for failure
 */
int cw_pbkdf2(uint8_t *password, const uint64_t password_len,
              uint8_t *salt, const uint64_t salt_len,
              uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief PBKDF2
 * @details Expanded version allows user to set every parameter
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] iterations Iterations
 * @param[in] algorithm_id Hash algorithm
 * @param[out] out Where to save the result
 * @param[out] out_len Where to save the result length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 *      - KEY_DERIVATION_SET_OUTPUT_LEN Set the output length. Values larger than the hash itself are ignored
 * @return int Returns 1 for success and 0 for failure
 */
int cw_pbkdf2_ex(uint8_t *password, const uint64_t password_len,
                 uint8_t *salt, const uint64_t salt_len,
                 uint32_t iterations, key_derivation_hash algorithm_id,
                 uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Verify a generated PBKDF2 output against a given key
 *
 * @param[in] key Key to verify against
 * @param[in] key_len Key length
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] iterations Iterations
 * @param[in] algorithm_id Hash algorithm
 * @return Returns 1 if verification was successful and 0 for failure
 */
int cw_pbkdf2_verify(const uint8_t *key, const uint64_t key_len,
                     uint8_t *password, const uint64_t password_len,
                     uint8_t *salt, const uint64_t salt_len,
                     uint32_t iterations, key_derivation_hash algorithm_id);

/**
 * @brief HKDF
 * @details Information parameter is not set
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] algorithm_id Hash algorithm
 * @param[out] out Where to store the result
 * @param[in] out_len Desired out length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hkdf(uint8_t *password, const uint64_t password_len,
            uint8_t *salt, const uint64_t salt_len,
            key_derivation_hash algorithm_id,
            uint8_t **out, uint64_t out_len, const uint8_t flags);

/**
 * @brief HKDF
 * @details Expanded version allows user to set every parameter
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] info Additional information
 * @param[in] info_size Additional information length
 * @param[in] algorithm_id Hash algorithm
 * @param[out] out Where to store the result
 * @param[in] out_len Desired result length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hkdf_ex(uint8_t *password, const uint64_t password_len,
               uint8_t *salt, const uint64_t salt_len,
               uint8_t *info, const uint32_t info_size,
               key_derivation_hash algorithm_id,
               uint8_t **out, uint64_t out_len, const uint8_t flags);

/**
 * @brief Verify a generated HKDF output against a given key
 *
 * @param[in] key Key to verify against
 * @param[in] key_len Key length
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] info Additional information
 * @param[in] info_size Additional information length
 * @param[in] algorithm_id Hash algorithm
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_hkdf_verify(const uint8_t *key, const uint64_t key_len,
                   uint8_t *password, const uint64_t password_len,
                   uint8_t *salt, const uint64_t salt_len,
                   uint8_t *info, const uint32_t info_size,
                   key_derivation_hash algorithm_id);

/**
 * @brief Default value for scrypt N
 *
 */
#define SCRYPT_DEFAULT_N 2048

/**
 * @brief Default value for scrypt r
 *
 */
#define SCRYPT_DEFAULT_R 8

/**
 * @brief Default value for scrypt p
 *
 */
#define SCRYPT_DEFAULT_P 16

/**
 * @brief SCRYPT
 * @details CostFactor(N) BlockSizeFactor (r) and ParallelizationFactor(p) are managed by the interface
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[out] out Where to save the result
 * @param[in] out_len Desired result length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_scrypt(uint8_t *password, const uint64_t password_len,
              uint8_t *salt, const uint64_t salt_len,
              uint8_t **out, uint64_t out_len, const uint8_t flags);

/**
 * @brief SCRYPT
 * @details Expanded version allows user to set every parameter
 *
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] N_cost CostFactor
 * @param[in] r_blockSize BlockSizeFactor
 * @param[in] p_parallelization ParallelizationFactor
 * @param[out] out Where to save the result
 * @param[in] out_len Desired result length
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_scrypt_ex(uint8_t *password, const uint64_t password_len,
                 uint8_t *salt, const uint64_t salt_len,
                 uint32_t N_cost, uint32_t r_blockSize, uint32_t p_parallelization,
                 uint8_t **out, uint64_t out_len, const uint8_t flags);

/**
 * @brief Verify a generated HKDF result against a given key
 *
 * @param[in] key Key to verify against
 * @param[in] key_len Key length
 * @param[in] password Password
 * @param[in] password_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] N_cost CostFactor
 * @param[in] r_blockSize BlockSizeFactor
 * @param[in] p_parallelization ParallelizationFactor
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_scrypt_verify(const uint8_t *key, const uint64_t key_len,
                     uint8_t *password, const uint64_t password_len,
                     uint8_t *salt, const uint64_t salt_len,
                     uint32_t N_cost, uint32_t r_blockSize, uint32_t p_parallelization);

/* Argon2 */

#define ARGON2_PARALLELISM_DEFAULT 1

#define ARGON2_MEMORY_DFAULT (1 << 16)

#define ARGON2_TIME_COST 2

/**
 * @brief Argon2 modes
 *
 */
typedef enum
{
    CW_ARGON2_D,
    CW_ARGON2_I,
    CW_ARGON2_ID
} cw_argon2_mode;

/**
 * @brief Creates a raw argon2 hash
 *
 * @param[in] t_cost Time cost
 * @param[in] m_cost Memory cost
 * @param[in] parallelism Parallelism degree
 * @param[in] pwd Password
 * @param[in] pwd_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[out] hash Where to store the hash
 * @param[in] hash_len Desired hash size
 * @param[in] mode Argon2 mode
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_argon2_raw(const uint32_t t_cost,
                  const uint32_t m_cost,
                  const uint32_t parallelism,
                  const void *pwd, const size_t pwd_len,
                  const void *salt, const size_t salt_len,
                  uint8_t **hash, const size_t hash_len, cw_argon2_mode mode, const uint8_t flags);

/**
 * @brief Verifies a argon2 raw hash against a set of parameters
 * 
 * @param[in] key Key to verify against
 * @param[in] key_len Key length
 * @param[in] t_cost Time cost
 * @param[in] m_cost Memory cost
 * @param[in] parallelism Parallelism degree
 * @param[in] pwd Password
 * @param[in] pwd_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] mode Argon2 mode
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_argon2_raw_verify(const uint8_t *key, const size_t key_len,
                         const uint32_t t_cost,
                         const uint32_t m_cost,
                         const uint32_t parallelism,
                         const void *pwd, const size_t pwd_len,
                         const void *salt, const size_t salt_len,
                         cw_argon2_mode mode);


/**
 * @brief Creates a argon2 encoded hash
 *
 * @param[in] t_cost Time cost
 * @param[in] m_cost Memory cost
 * @param[in] parallelism Parallelism degree
 * @param[in] pwd Password
 * @param[in] pwd_len Password length
 * @param[in] salt Salt
 * @param[in] salt_len Salt length
 * @param[in] hash_len Desired hash size
 * @param[out] encoded Where to store the encoded string
 * @param[out] encoded_len Optional: Length of the encoded string
 * @param[in] mode Argon2 mode
 * @param[in] flags
 *      - KEY_DERIVATION_NO_ALLOC Do not allocate result within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_argon2_encoded(const uint32_t t_cost,
                      const uint32_t m_cost,
                      const uint32_t parallelism,
                      const void *pwd, const size_t pwd_len,
                      const void *salt, const size_t salt_len,
                      const size_t hash_len, char **encoded, size_t *encoded_len, cw_argon2_mode mode, const uint8_t flags);

/**
 * @brief Verify a generated argon2 hash against a given encoded argon2 hash
 *
 * @param[in] encoded Encoded argon2 hash
 * @param[in] pwd Argon2 raw hash
 * @param[in] pwd_len Length of Argon2 raw hash
 * @param[in] mode Argon2 mode
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_argon2_verify(const char *encoded, const void *pwd, const size_t pwd_len, cw_argon2_mode mode);

/**
 * @brief Get the expected encoded length of an Argon2 hash
 *
 * @param[in] t_cost Time cost
 * @param[in] m_cost Memory cost
 * @param[in] parallelism Parallelism degree
 * @param[in] salt_len Salt length
 * @param[in] hash_len Desired hash length
 * @param[in] mode Argon2 mode
 * @return size_t Returns the expected encoded length
 */
size_t cw_argon2_get_encoded_len(const uint32_t t_cost,
                                 const uint32_t m_cost,
                                 const uint32_t parallelism,
                                 uint32_t salt_len, uint32_t hash_len, cw_argon2_mode mode);

#endif