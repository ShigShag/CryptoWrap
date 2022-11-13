/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file mac.h
 * @author Shig Shag
 * @brief Message authentication Code
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef MAC_H
#define MAC_H

#include "cryptowrap/hash.h"
#include "cryptowrap/symmetric_cipher.h"
#include "cryptowrap/aead.h"

/**
 * @brief Mac is not allocated within the function
 * 
 */
#define MAC_NO_ALLOC 0x00000001

/**
 * @brief Set the output length of the mac
 * 
 */
#define MAC_SET_OUT_LEN 0x00000002

/**
 * @brief Standard HMAC hash
 * 
 */
#define HMAC_STANDARD_DIGEST CW_HMAC_SHA3_256

/**
 * @brief Standard CMAC hash
 * 
 */
#define CMAC_STANDARD_CIPHER CW_CMAC_AES_256_CBC

/**
 * @brief Standard GMAC hash
 * 
 */
#define GMAC_STANDARD_CIPHER CW_GMAC_AES_GCM_256

/**
 * @brief Standard KMAC hash
 * 
 */
#define KMAC_STANDARD_MODE CW_KMAC_256

/**
 * @brief Mac stream handle which can be used for updating and finalizing a stream
 * 
 */
typedef void *MAC_STREAM_HANDLE;

/**
 * @brief Update a mac stream
 * @details This function can be called multiple times too add more data
 * 
 * @param[in] stream_handle stream handle
 * @param[in] in Data to be processed
 * @param[in] in_len Length of data to be processed
 * @return int Returns 1 for success and 0 for failure
 */
int cw_mac_stream_update(MAC_STREAM_HANDLE stream_handle, uint8_t *in, const uint32_t in_len);

/**
 * @brief Finalize a mac stream
 * @details This function finalizes an aead stream. After this function was called not further updates can be made.
 * 
 * @param[in] stream_handle Stream handle
 * @param[in] out Where to save the mac
 * @param[in, out] out_len Where to save the mac length.
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure
 */
int cw_mac_stream_final(MAC_STREAM_HANDLE stream_handle, uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Delete a mac stream handle
 * 
 * @param[in] stream_handle Stream handle to be deleted
 */
void cw_mac_stream_delete(MAC_STREAM_HANDLE stream_handle);

/**
 * @brief HMAC algorithms available
 * 
 */
typedef enum
{
    CW_HMAC_MD5 = CW_MD5,
    CW_HMAC_SHA_1 = CW_SHA_1,
    CW_HMAC_SHA_224 = CW_SHA_224,
    CW_HMAC_SHA_256 = CW_SHA_256,
    CW_HMAC_SHA_384 = CW_SHA_384,
    CW_HMAC_SHA_512 = CW_SHA_512,
    CW_HMAC_SHA_512_224 = CW_SHA_512_224,
    CW_HMAC_SHA_512_256 = CW_SHA_512_256,
    CW_HMAC_SHA3_224 = CW_SHA3_224,
    CW_HMAC_SHA3_256 = CW_SHA3_256,
    CW_HMAC_SHA3_384 = CW_SHA3_384,
    CW_HMAC_SHA3_512 = CW_SHA3_512,
    CW_HMAC_SM_3 = CW_SM_3,
} cw_hmac_digest;

/**
 * @brief HMAC
 * @details Hash algorithm selection is handled by the interface
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_hmac_raw(const uint8_t *in, const uint64_t in_len,
                const uint8_t *key, const uint32_t key_len,
                uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief HMAC
 * @details Expanded version allows user to set every parameter 
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Hash algorithm to use
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size.
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_hmac_raw_ex(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_hmac_digest algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Create a HMAC based on file contents
 * 
 * @param[in] file_path Path to a file which contents should be processed
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Hash algorithm to use
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size.
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_hmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_hmac_digest algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Initialize a HMAC stream
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Hash algorithm to use
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_hmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        cw_hmac_digest algorithm_id);

/**
 * @brief Verify data against a HMAC
 * 
 * @param[in] in Data which should be verified
 * @param[in] in_len Data length
 * @param[in] mac HMAC to verify against
 * @param[in] mac_len HMAC length
 * @param[in] key Key for creating the HMAC
 * @param[in] key_len Key length
 * @param[in] algorithm_id Hash algorithm to use
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_hmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_hmac_digest algorithm_id);

/**
 * @brief CMAC cipher modes available
 * 
 */
typedef enum
{
    CW_CMAC_AES_128_ECB = CW_AES_128_ECB,
    CW_CMAC_AES_128_CBC = CW_AES_128_CBC,
    CW_CMAC_AES_192_ECB = CW_AES_192_ECB,
    CW_CMAC_AES_192_CBC = CW_AES_192_CBC,    
    CW_CMAC_AES_256_ECB = CW_AES_256_ECB,
    CW_CMAC_AES_256_CBC = CW_AES_256_CBC,

    CW_CMAC_ARIA_128_ECB = CW_ARIA_128_ECB,
    CW_CMAC_ARIA_128_CBC = CW_ARIA_128_CBC,
    CW_CMAC_ARIA_192_ECB = CW_ARIA_192_ECB,
    CW_CMAC_ARIA_192_CBC = CW_ARIA_192_CBC,    
    CW_CMAC_ARIA_256_ECB = CW_ARIA_256_ECB,
    CW_CMAC_ARIA_256_CBC = CW_ARIA_256_CBC,

    CW_CMAC_CAMELLIA_128_ECB = CW_CAMELLIA_128_ECB,
    CW_CMAC_CAMELLIA_128_CBC = CW_CAMELLIA_128_CBC,
    CW_CMAC_CAMELLIA_192_ECB = CW_CAMELLIA_192_ECB,
    CW_CMAC_CAMELLIA_192_CBC = CW_CAMELLIA_192_CBC,    
    CW_CMAC_CAMELLIA_256_ECB = CW_CAMELLIA_256_ECB,
    CW_CMAC_CAMELLIA_256_CBC = CW_CAMELLIA_256_CBC,
} cw_cmac_cipher;

/**
 * @brief CMAC
 * @details Cipher algorithm selection is handled by the interface
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_cmac_raw(const uint8_t *in, const uint64_t in_len,
            const uint8_t *key, const uint32_t key_len,
            uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief CMAC
 * @details Expanded version allows user to set every parameter 
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Cipher algorithm
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_cmac_raw_ex(const uint8_t *in, const uint64_t in_len,
               const uint8_t *key, const uint32_t key_len,
               cw_cmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Create a CMAC based on file content
 * 
 * @param[in] file_path Path to a file which contents should be processed
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Cipher algorithm to use
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size.
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_cmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_cmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Initialize a CMAC stream
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id Hash algorithm to use
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_cmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        cw_cmac_cipher algorithm_id);

/**
 * @brief Verify data against a CMAC
 * 
 * @param[in] in Data which should be verified
 * @param[in] in_len Data length
 * @param[in] mac CMAC to verify against
 * @param[in] mac_len CMAC length
 * @param[in] key Key for creating the CMAC
 * @param[in] key_len Key length
 * @param[in] algorithm_id Cipher algorithm to use
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_cmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   cw_cmac_cipher algorithm_id);

/**
 * @brief GMAC mods available
 * 
 */
typedef enum
{
    CW_GMAC_AES_GCM_128 = CW_AES_128_GCM,
    CW_GMAC_AES_GCM_192 = CW_AES_192_GCM,
    CW_GMAC_AES_GCM_256 = CW_AES_256_GCM,
} cw_gmac_cipher;

/**
 * @brief GMAC
 * @details GMAC mode selection is handled by the interface
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] iv Iv
 * @param[in] iv_len Iv length
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_gmac(const uint8_t *in, const uint64_t in_len,
            const uint8_t *key, const uint32_t key_len,
            uint8_t *iv, const uint32_t iv_len,
            uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief GMAC
 * @details Expanded version allows user to set every parameter 
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] iv Iv
 * @param[in] iv_len Iv length
 * @param[in] algorithm_id GMAC cipher
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_gmac_raw_ex(const uint8_t *in, const uint64_t in_len,
               const uint8_t *key, const uint32_t key_len,
               uint8_t *iv, const uint32_t iv_len,
               cw_gmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Create a GMAC based on file content
 * 
 * @param[in] file_path Path to a file which contents should be processed
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] iv Iv
 * @param[in] iv_len Iv length
 * @param[in] algorithm_id GMAC cipher
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size.
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_gmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    uint8_t *iv, const uint32_t iv_len,
                    cw_gmac_cipher algorithm_id, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Initialize a GMAC stream
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] iv Iv
 * @param[in] iv_len Iv length 
 * @param[in] algorithm_id GMAC cipher
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_gmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        uint8_t *iv, const uint32_t iv_len,
                        cw_gmac_cipher algorithm_id);

/**
 * @brief Verify data against a GMAC
 * 
 * @param[in] in Data which should be verified
 * @param[in] in_len Data length
 * @param[in] mac GMAC to verify against
 * @param[in] mac_len GMAC length
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] iv Iv
 * @param[in] iv_len Iv length  
 * @param[in] algorithm_id GMAC cipher
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_gmac_verify(const uint8_t *in, const uint64_t in_len,
                   const uint8_t *mac, const uint64_t mac_len,
                   const uint8_t *key, const uint32_t key_len,
                   uint8_t *iv, uint32_t iv_len,
                   cw_gmac_cipher algorithm_id);

#define SIPHASH_COMPRESSION_ROUNDS 2
#define SIPHASH_FINALIZATION_ROUNDS 4
/**
 * @brief SIPHASH
 * @details Compression and finalization rounds are handled by the interface
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_siphash_raw(const uint8_t *in, const uint64_t in_len,
               const uint8_t *key, const uint32_t key_len,
               uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief SIPHASH
 * @details Expanded version allows user to set every parameter 
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] c_compression_rounds Compression rounds
 * @param[in] d_finalization_rounds Finalization rounds
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_siphash_raw_ex(const uint8_t *in, const uint64_t in_len,
                  const uint8_t *key, const uint32_t key_len,
                  uint32_t c_compression_rounds, uint32_t d_finalization_rounds,
                  uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Create a SIPHASH based on file content
 * 
 * @param[in] file_path Path to a file which contents should be processed
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] c_compression_rounds Compression rounds
 * @param[in] d_finalization_rounds Finalization rounds
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size.
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_siphash_file_ex(const char *file_path,
                       const uint8_t *key, const uint32_t key_len,
                       uint32_t c_compression_rounds, uint32_t d_finalization_rounds,
                       uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Initialize a SIPHASH stream
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] c_compression_rounds Compression rounds
 * @param[in] d_finalization_rounds Finalization rounds
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_siphash_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                           const uint8_t *key, const uint32_t key_len,
                           uint32_t c_compression_rounds, uint32_t d_finalization_rounds);

/**
 * @brief Verify data against a SIPHASH
 * 
 * @param[in] in Data which should be verified
 * @param[in] in_len Data length
 * @param[in] mac CMAC to verify against
 * @param[in] mac_len CMAC length
 * @param[in] key Key for creating the CMAC
 * @param[in] key_len Key length
 * @param[in] c_compression_rounds Compression rounds
 * @param[in] d_finalization_rounds Finalization rounds
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_siphash_verify(const uint8_t *in, const uint64_t in_len,
                      const uint8_t *mac, const uint32_t mac_len,
                      const uint8_t *key, const uint32_t key_len,
                      uint32_t c_compression_rounds, uint32_t d_finalization_rounds);

/**
 * @brief KMAC modes available
 * 
 */
typedef enum
{
    CW_KMAC_128,
    CW_KMAC_256,
} cw_kmac_mode;

/**
 * @brief KMAC
 * @details KMAC mode selection and custom value is handled by the interface
 * 
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length  
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_kmac_raw(const uint8_t *in, const uint64_t in_len,
            const uint8_t *key, const uint32_t key_len,
            uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief KMAC
 * @details Expanded version allows user to set every parameter 
 *
 * @param[in] in Input byte sequence
 * @param[in] in_len Length of byte sequence
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id KMAC mode
 * @param[in] custom_value Custom value
 * @param[in] custom_value_len Custom value length
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_kmac_raw_ex(const uint8_t *in, const uint64_t in_len,
               const uint8_t *key, const uint32_t key_len,
               cw_kmac_mode algorithm_id, uint8_t *custom_value, const uint32_t custom_value_len,
               uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Create a KMAC based on file content
 * 
 * @param[in] file_path Path to a file which contents should be processed
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] algorithm_id KMAC mode
 * @param[in] custom_value Custom value
 * @param[in] custom_value_len Custom value length
 * @param[out] out Where to save the mac
 * @param[in, out] out_len Optional: Where to save the mac size
 * If MAC_SET_OUT_LEN is set then this parameter sets the output size
 * @param[in] flags 
 *      - MAC_NO_ALLOC Mac is not allocated within the function
 *      - MAC_SET_OUT_LEN Set a custom mac length with the out_len parameter
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_kmac_file_ex(const char *file_path,
                    const uint8_t *key, const uint32_t key_len,
                    cw_kmac_mode algorithm_id, uint8_t *custom_value, const uint32_t custom_value_len,
                    uint8_t **out, uint32_t *out_len, const uint8_t flags);

/**
 * @brief Initialize a KMAC stream
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key
 * @param[in] key_len Key length 
 * @param[in] custom_value Custom value
 * @param[in] custom_value_len Custom value length 
 * @param[in] algorithm_id KMAC mode
 * @return int Returns 1 for success and 0 for failure
 */
int cw_kmac_stream_init(MAC_STREAM_HANDLE *pstream_handle,
                        const uint8_t *key, const uint32_t key_len,
                        uint8_t *custom_value, const uint32_t custom_value_len,
                        cw_kmac_mode algorithm_id);

/**
 * @brief Verify data against a KMAC
 * 
 * @param[in] in Data which should be verified
 * @param[in] in_len Data length
 * @param[in] mac GMAC to verify against
 * @param[in] mac_len GMAC length
 * @param[in] key Key
 * @param[in] key_len Key length  
 * @param[in] custom_value Custom value
 * @param[in] custom_value_len Custom value length 
 * @param[in] algorithm_id KMAC mode
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_kmac_verify(const uint8_t *in, const uint64_t in_len,
                  const uint8_t *mac, const uint32_t mac_len,
                  const uint8_t *key, const uint32_t key_len,
                  uint8_t *custom_value, const uint32_t custom_value_len, cw_kmac_mode algorithm_id);

#endif
