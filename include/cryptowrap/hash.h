/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file hash.h
 * @author Shig Shag
 * @brief Hashing functions
 * @version 0.1
 * @date 2022-11-01
 *
 * @copyright Copyright (c) 2022 Leon Weinmann
 *
 */

#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include <stdint.h>

/**
 * @brief Hashing algorithms available in the interface
 *
 */
typedef enum hash_algorithm
{
    CW_MD5,
    CW_SHA_1,
    CW_SHA_224,
    CW_SHA_256,
    CW_SHA_384,
    CW_SHA_512,
    CW_SHA_512_224,
    CW_SHA_512_256,
    CW_SHA3_224,
    CW_SHA3_256,
    CW_SHA3_384,
    CW_SHA3_512,
    CW_SHAKE_128,
    CW_SHAKE_256,
    CW_SM_3,
    CW_MD4,
    CW_WHIRLPOOL,
    CW_RIPEMD_160,
    CW_BLAKE2S_256,
    CW_BLAKE2B_512
} hash_algorithm;

/**
 * @brief Hash does not get allocated within the function
 *
 */
#define HASH_NO_ALLOC 0x00000001

/**
 * @brief Generate a hash from a given byte sequence
 *
 * @param[in] in Byte sequence which is to be hashed
 * @param[in] in_len Length of byte sequence
 * @param[in] algorithm_id Hash algorithm
 * @param[out] digest_out Where to store the hash
 * @param[out] digest_out_len Optional: Where to store the hash length
 * @param[in] flags
 *      - HASH_NO_ALLOC Hash is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_raw_bytes(const uint8_t *in, const uint64_t in_len, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags);

/**
 * @brief Generate a hash from a given string
 *
 * @param[in] in
 * @param[in] algorithm_id Hash algorithm
 * @param[out] digest_out Where to store the hash
 * @param[out] digest_out_len Optional: Where to store the hash length
 * @param[in] flags
 *      - HASH_NO_ALLOC Hash is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_raw_string(const char *in, hash_algorithm algorithm_id,
                       uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags);

/**
 * @brief Generate a hash from file contents
 *
 * @param[in] file_path Path to the file
 * @param[in] algorithm_id Hash algorithm
 * @param[out] digest_out Where to store the hash
 * @param[out] digest_out_len Optional: Where to store the hash length
 * @param[in] flags
 *      - HASH_NO_ALLOC Hash is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_file(const char *file_path, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags);

/**
 * @brief Generate a hash from a file pointer
 * 
 * @param[in] file File pointer to a file stream
 * @param[in] algorithm_id Hash algorithm
 * @param[out] digest_out Where to store the hash
 * @param[out] digest_out_len Optional: Where to store the hash length
 * @param[in] flags
 *      - HASH_NO_ALLOC Hash is not allocated within the function
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_file_fp(FILE *file, hash_algorithm algorithm_id, uint8_t **digest_out, uint32_t *digest_out_len, const uint8_t flags);

/**
 * @brief Type to store a stream handle which can be used for updating and finalizing a stream
 * 
 */
typedef void *HASH_STREAM_HANDLE;

/**
 * @brief Create a hash stream handle
 * 
 * @param[out] phash_stream_handle Where to store the handle
 * @param[in] algorithm_id Hash algorithm
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_stream_create_handle(HASH_STREAM_HANDLE *phash_stream_handle, hash_algorithm algorithm_id);

/**
 * @brief Update a stream context with data
 * @details This function can be called multiple times to add data for the hash generation
 * 
 * @param[in] hash_stream_handle Stream handle
 * @param[in] in Data to be processed for hashing
 * @param[in] in_len Length of data
 * @return int Returns 1 for success and 0 for failure
 */
int cw_hash_stream_update(HASH_STREAM_HANDLE hash_stream_handle, uint8_t *in, const uint64_t in_len);

/**
 * @brief Finalize a stream and retrieve the hash value
 * @details After this function is called no more updates can be made
 * 
 * @param[in] hash_stream_handle Stream handle
 * @param[out] out Where to store the hash
 * @param[out] out_len Optional: Hash length
 * @param[in] flags 
 *      - HASH_NO_ALLOC do not allocate the hash within the function
 * @return int 
 */
int cw_hash_stream_finalize(HASH_STREAM_HANDLE hash_stream_handle, uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Delete an hash stream handle
 * 
 * @param[in] hash_stream_handle Stream handle to be deleted
 */
void cw_hash_stream_delete_handle(HASH_STREAM_HANDLE hash_stream_handle);

/**
 * @brief Verify a given hash against a given string
 * 
 * @param[in] hash Hash
 * @param[in] hash_len Hash length
 * @param[in] in Sequence which should be verified against the hash
 * @param[in] algorithm_id Hash algorithm
 * @return int Returns 1 if verification is successful and zero for failure
 */
int cw_hash_verify_string(uint8_t *hash, uint32_t hash_len, const char *in, hash_algorithm algorithm_id);

/**
 * @brief Verify a given hash against a given byte sequence
 * 
 * @param[in] hash Hash
 * @param[in] hash_len Hash length
 * @param[in] in Sequence which should be verified against the hash
 * @param[in] in_len Length of the sequence
 * @param[in] algorithm_id Hash algorithm
 * @return int Returns 1 if verification is successful and zero for failure
 */
int cw_hash_verify_bytes(uint8_t *hash, uint32_t hash_len, const uint8_t *in, const uint32_t in_len, hash_algorithm algorithm_id);

/**
 * @brief Get the hash length for a hash algorithm
 * 
 * @param[in] algorithm_id Hash algorithm
 * @return uint32_t Returns the size of a hash for a hash algorithm
 */
uint32_t cw_hash_get_len(hash_algorithm algorithm_id);

#endif
